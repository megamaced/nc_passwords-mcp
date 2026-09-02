import { z, type ZodTypeAny } from 'zod';
import type { CallToolResult, Tool } from '@modelcontextprotocol/sdk/types.js';

import {
  AlreadyTrashedError,
  createFolder,
  createPassword,
  HttpError,
  listFolders,
  listPasswords,
  NotTrashedError,
  passwordMatches,
  restoreFolder,
  restorePassword,
  showFolder,
  showPassword,
  trashFolder,
  trashPassword,
  updateFolder,
  updatePassword,
} from './api.js';
import {
  CseUnsupportedError,
  WriteOutcomeUnknownError,
  type PasswordsClient,
} from './http.js';
import { CUSTOM_FIELD_TYPES, CustomFieldError, toFolderMeta, toPasswordMeta } from './types.js';

export interface Context {
  client: PasswordsClient;
  configSummary: string;
  /** When true, write tools are hidden and refused. */
  readOnly: boolean;
}

interface ToolDef<S extends ZodTypeAny> {
  tool: Tool;
  argsSchema: S;
  handler: (args: z.infer<S>, ctx: Context) => Promise<CallToolResult>;
  /** Mutating tool — excluded from the tool list and refused when readOnly. */
  write?: boolean;
}

const Empty = z.object({}).strict();

/**
 * Custom fields are accepted as structured objects rather than a pre-serialized
 * JSON string, so a malformed or oversized blob can never reach the vault —
 * `serializeCustomFields` validates and encodes them centrally.
 */
const CustomFieldsArg = z
  .array(
    z
      .object({
        label: z.string().min(1, 'label is required'),
        type: z.enum(CUSTOM_FIELD_TYPES),
        value: z.string(),
      })
      .strict(),
  )
  .describe('Replaces ALL custom fields on the entry — send the full set, not a delta.');

const CUSTOM_FIELDS_SCHEMA = {
  type: 'array',
  description:
    'User-defined fields. Replaces ALL existing custom fields, so send the ' +
    'complete set. Max 20 fields; label <= 48 chars, value <= 320 chars.',
  items: {
    type: 'object',
    properties: {
      label: { type: 'string', description: 'Field name.' },
      type: {
        type: 'string',
        enum: [...CUSTOM_FIELD_TYPES],
        description: "Field kind; 'secret' marks password-grade material.",
      },
      value: { type: 'string' },
    },
    required: ['label', 'type', 'value'],
    additionalProperties: false,
  },
} as const;

function jsonResult(data: unknown): CallToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
}

function textResult(text: string): CallToolResult {
  return { content: [{ type: 'text', text }] };
}

// -----------------------------------------------------------------------------
// Read tools
// -----------------------------------------------------------------------------

/**
 * Connectivity check only.
 *
 * This deliberately does NOT list passwords. With CSE disabled the
 * `password/list` model carries decrypted `password`, `notes` and
 * `customFields` for every entry, so counting the vault would pull the entire
 * plaintext store into this process for a result that reports no counts at all.
 * The session handshake plus `session/keepalive` proves URL, credentials, app
 * availability and CSE state without reading a single secret. Use
 * list_passwords / list_folders if counts are actually wanted.
 */
const ping: ToolDef<typeof Empty> = {
  argsSchema: Empty,
  tool: {
    name: 'ping',
    description:
      'Verify connectivity to the configured Nextcloud Passwords instance: ' +
      'that the URL and app-password work, the Passwords app is installed, and ' +
      'client-side encryption is disabled. Reads no vault data.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    annotations: {
      title: 'Check Passwords connectivity',
      readOnlyHint: true,
      openWorldHint: true,
    },
  },
  handler: async (_args, ctx) => {
    await ctx.client.checkConnectivity();
    return textResult(
      `OK — connected to ${ctx.configSummary} (${ctx.readOnly ? 'read-only' : 'read/write'}); ` +
        `client-side encryption is disabled.`,
    );
  },
};

const ListPasswordsArgs = z
  .object({
    folder: z
      .string()
      .optional()
      .describe('Optional folder id; if given, only passwords in that folder are returned.'),
  })
  .strict();

const listPasswordsTool: ToolDef<typeof ListPasswordsArgs> = {
  argsSchema: ListPasswordsArgs,
  tool: {
    name: 'list_passwords',
    description:
      'List saved passwords as METADATA ONLY (id, label, username, url, folder, ' +
      'timestamps). The secret value is never included — use get_password with a ' +
      'specific id to reveal one. Optionally filter by folder id.',
    inputSchema: {
      type: 'object',
      properties: {
        folder: { type: 'string', description: 'Optional folder id to filter by.' },
      },
      additionalProperties: false,
    },
    annotations: {
      title: 'List passwords (metadata only)',
      readOnlyHint: true,
      openWorldHint: true,
    },
  },
  handler: async (args, ctx) => {
    let all = await listPasswords(ctx.client);
    if (args.folder) all = all.filter((p) => p.folder === args.folder);
    return jsonResult(all.map(toPasswordMeta));
  },
};

const SearchPasswordsArgs = z
  .object({
    query: z.string().min(1, 'query is required'),
  })
  .strict();

const searchPasswordsTool: ToolDef<typeof SearchPasswordsArgs> = {
  argsSchema: SearchPasswordsArgs,
  tool: {
    name: 'search_passwords',
    description:
      'Search saved passwords by a case-insensitive substring of their label, ' +
      'username or URL. Returns METADATA ONLY (no secret values). Use ' +
      'get_password with an id from the results to reveal a single secret.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Substring to match on label / username / url.' },
      },
      required: ['query'],
      additionalProperties: false,
    },
    annotations: {
      title: 'Search passwords (metadata only)',
      readOnlyHint: true,
      openWorldHint: true,
    },
  },
  handler: async (args, ctx) => {
    const all = await listPasswords(ctx.client);
    const hits = all.filter((p) => passwordMatches(p, args.query));
    return jsonResult(hits.map(toPasswordMeta));
  },
};

const GetPasswordArgs = z
  .object({
    id: z.string().min(1, 'id is required'),
  })
  .strict();

const getPasswordTool: ToolDef<typeof GetPasswordArgs> = {
  argsSchema: GetPasswordArgs,
  tool: {
    name: 'get_password',
    description:
      'Reveal a SINGLE password entry by its id, including the plaintext secret, ' +
      'notes and any custom fields. This exposes sensitive credentials — only ' +
      'call it for a specific id the user has asked to see, never to bulk-export. ' +
      'Get ids from list_passwords or search_passwords.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'The password id to reveal.' },
      },
      required: ['id'],
      additionalProperties: false,
    },
    // readOnlyHint is about side effects, not sensitivity: this reads without
    // mutating, but it is the one tool that discloses a plaintext secret. The
    // warning belongs in the description, which clients show to the user.
    annotations: {
      title: 'Reveal one password (plaintext secret)',
      readOnlyHint: true,
      openWorldHint: true,
    },
  },
  handler: async (args, ctx) => {
    const p = await showPassword(ctx.client, args.id);
    return jsonResult({
      id: p.id,
      label: p.label,
      username: p.username,
      password: p.password,
      url: p.url,
      notes: p.notes,
      customFields: p.customFields,
      folder: p.folder,
      favorite: p.favorite,
      edited: p.edited,
      updated: p.updated,
    });
  },
};

const listFoldersTool: ToolDef<typeof Empty> = {
  argsSchema: Empty,
  tool: {
    name: 'list_folders',
    description:
      'List all folders (id, label, parent folder id, timestamps). Folders hold ' +
      'no secret material. Use a folder id with list_passwords to filter.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    annotations: { title: 'List folders', readOnlyHint: true, openWorldHint: true },
  },
  handler: async (_args, ctx) =>
    jsonResult((await listFolders(ctx.client)).map(toFolderMeta)),
};

const GetFolderArgs = z.object({ id: z.string().min(1, 'id is required') }).strict();

const getFolderTool: ToolDef<typeof GetFolderArgs> = {
  argsSchema: GetFolderArgs,
  tool: {
    name: 'get_folder',
    description: 'Fetch a single folder by its id.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string', description: 'The folder id.' } },
      required: ['id'],
      additionalProperties: false,
    },
    annotations: { title: 'Get one folder', readOnlyHint: true, openWorldHint: true },
  },
  handler: async (args, ctx) => jsonResult(toFolderMeta(await showFolder(ctx.client, args.id))),
};

// -----------------------------------------------------------------------------
// Write tools
// -----------------------------------------------------------------------------

const CreatePasswordArgs = z
  .object({
    label: z.string().min(1, 'label is required'),
    password: z.string().min(1, 'password is required'),
    username: z.string().optional(),
    url: z.string().optional(),
    notes: z.string().optional(),
    folder: z.string().optional().describe('Folder id to file it under; omit for the base folder.'),
    favorite: z.boolean().optional(),
    hidden: z.boolean().optional().describe('Hide the entry from list/search actions.'),
    customFields: CustomFieldsArg.optional(),
  })
  .strict();

const createPasswordTool: ToolDef<typeof CreatePasswordArgs> = {
  write: true,
  argsSchema: CreatePasswordArgs,
  tool: {
    name: 'create_password',
    description:
      'Create a new password entry. Requires a label and the secret value; ' +
      'username, url, notes, folder id and favorite are optional. Stored with ' +
      'server-side encryption (cseType none).',
    inputSchema: {
      type: 'object',
      properties: {
        label: { type: 'string', description: 'Display label (required).' },
        password: { type: 'string', description: 'The secret value (required).' },
        username: { type: 'string' },
        url: { type: 'string' },
        notes: { type: 'string' },
        folder: { type: 'string', description: 'Folder id; omit for the base folder.' },
        favorite: { type: 'boolean' },
        hidden: {
          type: 'boolean',
          description: 'Hide the entry from list/search actions (default false).',
        },
        customFields: CUSTOM_FIELDS_SCHEMA,
      },
      required: ['label', 'password'],
      additionalProperties: false,
    },
    annotations: {
      title: 'Create a password',
      readOnlyHint: false,
      // Additive: it never overwrites or removes an existing entry, but calling
      // it twice creates two entries.
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  handler: async (args, ctx) => jsonResult(await createPassword(ctx.client, args)),
};

const UpdatePasswordArgs = z
  .object({
    id: z.string().min(1, 'id is required'),
    label: z.string().optional(),
    password: z.string().optional(),
    username: z.string().optional(),
    url: z.string().optional(),
    notes: z.string().optional(),
    folder: z.string().optional(),
    favorite: z.boolean().optional(),
    hidden: z.boolean().optional(),
    customFields: CustomFieldsArg.optional(),
  })
  .strict()
  .refine((a) => Object.keys(a).some((k) => k !== 'id'), {
    message: 'provide at least one field to change besides id',
  });

const updatePasswordTool: ToolDef<typeof UpdatePasswordArgs> = {
  write: true,
  argsSchema: UpdatePasswordArgs,
  tool: {
    name: 'update_password',
    description:
      'Update fields of an existing password by id. Only the fields you pass are ' +
      'changed; all others — including hidden/favorite state and custom fields — ' +
      'are preserved (the server rejects the write if the entry changed ' +
      'underneath us). Note that customFields REPLACES the whole set. Tags are ' +
      'left untouched and cannot be edited through this server. Provide at ' +
      'least one field besides id.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Id of the password to update (required).' },
        label: { type: 'string' },
        password: { type: 'string' },
        username: { type: 'string' },
        url: { type: 'string' },
        notes: { type: 'string' },
        folder: { type: 'string' },
        favorite: { type: 'boolean' },
        hidden: { type: 'boolean', description: 'Hide/unhide the entry.' },
        customFields: CUSTOM_FIELDS_SCHEMA,
      },
      required: ['id'],
      additionalProperties: false,
    },
    annotations: {
      title: 'Update a password',
      readOnlyHint: false,
      // Overwrites values the user may not be able to recover from the UI, and
      // each call consumes the revision it was built against.
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  handler: async (args, ctx) => {
    const { id, ...changes } = args;
    return jsonResult(await updatePassword(ctx.client, id, changes));
  },
};

const DeletePasswordArgs = z.object({ id: z.string().min(1, 'id is required') }).strict();

const deletePasswordTool: ToolDef<typeof DeletePasswordArgs> = {
  write: true,
  argsSchema: DeletePasswordArgs,
  tool: {
    name: 'delete_password',
    description:
      'Move a password to the trash (a reversible, soft delete — restore it from ' +
      'the Passwords app). Refuses if the entry is already trashed, so it can ' +
      'never permanently delete anything.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string', description: 'Id of the password to trash.' } },
      required: ['id'],
      additionalProperties: false,
    },
    annotations: {
      title: 'Move a password to the trash',
      readOnlyHint: false,
      // Reversible via restore_password, but it removes the entry from every
      // list/search until someone restores it — treat it as destructive.
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  handler: async (args, ctx) => {
    await trashPassword(ctx.client, args.id);
    return textResult(`Moved password ${args.id} to the trash (reversible).`);
  },
};

const CreateFolderArgs = z
  .object({
    label: z.string().min(1, 'label is required'),
    parent: z.string().optional().describe('Parent folder id; omit for the base folder.'),
    favorite: z.boolean().optional(),
    hidden: z.boolean().optional().describe('Hide the folder and its contents from list actions.'),
  })
  .strict();

const createFolderTool: ToolDef<typeof CreateFolderArgs> = {
  write: true,
  argsSchema: CreateFolderArgs,
  tool: {
    name: 'create_folder',
    description: 'Create a new folder. Requires a label; parent folder id is optional.',
    inputSchema: {
      type: 'object',
      properties: {
        label: { type: 'string', description: 'Folder label (required).' },
        parent: { type: 'string', description: 'Parent folder id; omit for the base folder.' },
        favorite: { type: 'boolean' },
        hidden: {
          type: 'boolean',
          description: 'Hide the folder and its contents from list actions (default false).',
        },
      },
      required: ['label'],
      additionalProperties: false,
    },
    annotations: {
      title: 'Create a folder',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  handler: async (args, ctx) => jsonResult(await createFolder(ctx.client, args)),
};

const UpdateFolderArgs = z
  .object({
    id: z.string().min(1, 'id is required'),
    label: z.string().optional(),
    parent: z.string().optional(),
    favorite: z.boolean().optional(),
    hidden: z.boolean().optional(),
  })
  .strict()
  .refine((a) => Object.keys(a).some((k) => k !== 'id'), {
    message: 'provide at least one field to change besides id',
  });

const updateFolderTool: ToolDef<typeof UpdateFolderArgs> = {
  write: true,
  argsSchema: UpdateFolderArgs,
  tool: {
    name: 'update_folder',
    description:
      'Rename a folder, move it under a different parent, or change its ' +
      'favorite/hidden state, by id. Fields you do not pass keep their current ' +
      'value. Hiding a folder also hides everything inside it.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Id of the folder to update (required).' },
        label: { type: 'string' },
        parent: { type: 'string', description: 'New parent folder id.' },
        favorite: { type: 'boolean' },
        hidden: {
          type: 'boolean',
          description: 'Hide/unhide the folder. Hiding also hides its contents.',
        },
      },
      required: ['id'],
      additionalProperties: false,
    },
    annotations: {
      title: 'Update a folder',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  handler: async (args, ctx) => {
    const { id, ...changes } = args;
    return jsonResult(await updateFolder(ctx.client, id, changes));
  },
};

const DeleteFolderArgs = z.object({ id: z.string().min(1, 'id is required') }).strict();

const deleteFolderTool: ToolDef<typeof DeleteFolderArgs> = {
  write: true,
  argsSchema: DeleteFolderArgs,
  tool: {
    name: 'delete_folder',
    description:
      'Move a folder AND ITS CONTENTS to the trash (reversible, soft delete). ' +
      'Refuses if the folder is already trashed, so it can never permanently delete.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string', description: 'Id of the folder to trash.' } },
      required: ['id'],
      additionalProperties: false,
    },
    annotations: {
      title: 'Move a folder to the trash',
      readOnlyHint: false,
      // Reversible, but it takes every password inside the folder out of view
      // along with it — the most far-reaching write this server offers.
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  handler: async (args, ctx) => {
    await trashFolder(ctx.client, args.id);
    return textResult(`Moved folder ${args.id} and its contents to the trash (reversible).`);
  },
};

// -----------------------------------------------------------------------------
// Restore tools — the undo for the soft deletes above.
//
// Both restore FROM TRASH only. The API's restore action can also roll a record
// back to an arbitrary earlier revision, which would discard changes the user
// never asked to lose; that is deliberately not exposed here.
// -----------------------------------------------------------------------------

const RestorePasswordArgs = z.object({ id: z.string().min(1, 'id is required') }).strict();

const restorePasswordTool: ToolDef<typeof RestorePasswordArgs> = {
  write: true,
  argsSchema: RestorePasswordArgs,
  tool: {
    name: 'restore_password',
    description:
      'Restore a trashed password, undoing delete_password. Only takes the entry ' +
      'out of the trash — it never rolls the entry back to an older revision. ' +
      'Reports an error if the password is not in the trash.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string', description: 'Id of the trashed password.' } },
      required: ['id'],
      additionalProperties: false,
    },
    annotations: {
      title: 'Restore a password from the trash',
      readOnlyHint: false,
      destructiveHint: false,
      // Restoring an already-restored entry is refused rather than repeated, so
      // this is not idempotent in the "safe to replay" sense.
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  handler: async (args, ctx) => {
    const result = await restorePassword(ctx.client, args.id);
    return textResult(
      `Restored password ${args.id} from the trash (new revision ${result.revision ?? 'unknown'}).`,
    );
  },
};

const RestoreFolderArgs = z.object({ id: z.string().min(1, 'id is required') }).strict();

const restoreFolderTool: ToolDef<typeof RestoreFolderArgs> = {
  write: true,
  argsSchema: RestoreFolderArgs,
  tool: {
    name: 'restore_folder',
    description:
      'Restore a trashed folder, undoing delete_folder. Only takes the folder out ' +
      'of the trash — it never rolls it back to an older revision. Reports an ' +
      'error if the folder is not in the trash.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string', description: 'Id of the trashed folder.' } },
      required: ['id'],
      additionalProperties: false,
    },
    annotations: {
      title: 'Restore a folder from the trash',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  handler: async (args, ctx) => {
    const result = await restoreFolder(ctx.client, args.id);
    return textResult(
      `Restored folder ${args.id} from the trash (new revision ${result.revision ?? 'unknown'}).`,
    );
  },
};

// -----------------------------------------------------------------------------
// Registry + dispatch
// -----------------------------------------------------------------------------

/**
 * The tool table.
 *
 * A `Map` rather than an object literal because the lookup key comes from the
 * client: on a plain object, `REGISTRY['toString']` (or `constructor`, or
 * `__proto__`) resolves through `Object.prototype` to something truthy, so a
 * request for one of those names would sail past the unknown-tool check and
 * crash on a missing `argsSchema` instead of returning a tool error.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const REGISTRY: ReadonlyMap<string, ToolDef<any>> = new Map<string, ToolDef<any>>([
  ['ping', ping],
  ['list_passwords', listPasswordsTool],
  ['search_passwords', searchPasswordsTool],
  ['get_password', getPasswordTool],
  ['list_folders', listFoldersTool],
  ['get_folder', getFolderTool],
  ['create_password', createPasswordTool],
  ['update_password', updatePasswordTool],
  ['delete_password', deletePasswordTool],
  ['restore_password', restorePasswordTool],
  ['create_folder', createFolderTool],
  ['update_folder', updateFolderTool],
  ['delete_folder', deleteFolderTool],
  ['restore_folder', restoreFolderTool],
]);

/** The tools to advertise. Write tools are omitted entirely in read-only mode. */
export function listTools(readOnly: boolean): Tool[] {
  return [...REGISTRY.values()].filter((d) => !(readOnly && d.write)).map((d) => d.tool);
}

export async function dispatchTool(
  name: string,
  rawArgs: unknown,
  ctx: Context,
): Promise<CallToolResult> {
  const def = REGISTRY.get(name);
  if (!def) {
    return { isError: true, content: [{ type: 'text', text: `Unknown tool: ${name}` }] };
  }

  // Defence in depth: refuse writes in read-only mode even if a client somehow
  // calls a tool that was never advertised.
  if (ctx.readOnly && def.write) {
    return {
      isError: true,
      content: [
        { type: 'text', text: `Tool ${name} is disabled: server is in read-only mode (PASSWORDS_READONLY=true).` },
      ],
    };
  }

  const parsed = def.argsSchema.safeParse(rawArgs ?? {});
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i: z.ZodIssue) => `${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('; ');
    return { isError: true, content: [{ type: 'text', text: `Invalid arguments: ${issues}` }] };
  }

  try {
    return await def.handler(parsed.data, ctx);
  } catch (err) {
    // Every error class here is written to carry an explanation and no secret
    // material; `HttpError` in particular never includes a response body.
    const message =
      err instanceof AlreadyTrashedError ||
      err instanceof NotTrashedError ||
      err instanceof CustomFieldError ||
      err instanceof CseUnsupportedError ||
      err instanceof WriteOutcomeUnknownError ||
      err instanceof HttpError
        ? err.message
        : err instanceof Error
          ? err.message
          : String(err);
    return { isError: true, content: [{ type: 'text', text: message }] };
  }
}
