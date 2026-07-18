import { z, type ZodTypeAny } from 'zod';
import type { CallToolResult, Tool } from '@modelcontextprotocol/sdk/types.js';

import {
  AlreadyTrashedError,
  createFolder,
  createPassword,
  HttpError,
  listFolders,
  listPasswords,
  passwordMatches,
  showFolder,
  showPassword,
  trashFolder,
  trashPassword,
  updateFolder,
  updatePassword,
} from './api.js';
import { CseUnsupportedError, type PasswordsClient } from './http.js';
import { toPasswordMeta } from './types.js';

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

function jsonResult(data: unknown): CallToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
}

function textResult(text: string): CallToolResult {
  return { content: [{ type: 'text', text }] };
}

// -----------------------------------------------------------------------------
// Read tools
// -----------------------------------------------------------------------------

const ping: ToolDef<typeof Empty> = {
  argsSchema: Empty,
  tool: {
    name: 'ping',
    description:
      'Verify connectivity to the configured Nextcloud Passwords instance, ' +
      'confirm client-side encryption is disabled, and report how many ' +
      'passwords and folders are visible.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  handler: async (_args, ctx) => {
    const [passwords, folders] = await Promise.all([
      listPasswords(ctx.client),
      listFolders(ctx.client),
    ]);
    return textResult(
      `OK — connected to ${ctx.configSummary} (${ctx.readOnly ? 'read-only' : 'read/write'}); ` +
        `${passwords.length} password(s), ${folders.length} folder(s) visible.`,
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
  },
  handler: async (_args, ctx) => jsonResult(await listFolders(ctx.client)),
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
  },
  handler: async (args, ctx) => jsonResult(await showFolder(ctx.client, args.id)),
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
      },
      required: ['label', 'password'],
      additionalProperties: false,
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
  })
  .strict()
  .refine(
    (a) =>
      a.label !== undefined ||
      a.password !== undefined ||
      a.username !== undefined ||
      a.url !== undefined ||
      a.notes !== undefined ||
      a.folder !== undefined ||
      a.favorite !== undefined,
    { message: 'provide at least one field to change besides id' },
  );

const updatePasswordTool: ToolDef<typeof UpdatePasswordArgs> = {
  write: true,
  argsSchema: UpdatePasswordArgs,
  tool: {
    name: 'update_password',
    description:
      'Update fields of an existing password by id. Only the fields you pass are ' +
      'changed; all others are preserved (the server rejects the write if the ' +
      'entry changed underneath us). Provide at least one field besides id.',
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
      },
      required: ['id'],
      additionalProperties: false,
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
      },
      required: ['label'],
      additionalProperties: false,
    },
  },
  handler: async (args, ctx) => jsonResult(await createFolder(ctx.client, args.label, args.parent)),
};

const UpdateFolderArgs = z
  .object({
    id: z.string().min(1, 'id is required'),
    label: z.string().optional(),
    parent: z.string().optional(),
  })
  .strict()
  .refine((a) => a.label !== undefined || a.parent !== undefined, {
    message: 'provide a label and/or parent to change',
  });

const updateFolderTool: ToolDef<typeof UpdateFolderArgs> = {
  write: true,
  argsSchema: UpdateFolderArgs,
  tool: {
    name: 'update_folder',
    description: 'Rename a folder and/or move it under a different parent, by id.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Id of the folder to update (required).' },
        label: { type: 'string' },
        parent: { type: 'string', description: 'New parent folder id.' },
      },
      required: ['id'],
      additionalProperties: false,
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
  },
  handler: async (args, ctx) => {
    await trashFolder(ctx.client, args.id);
    return textResult(`Moved folder ${args.id} and its contents to the trash (reversible).`);
  },
};

// -----------------------------------------------------------------------------
// Registry + dispatch
// -----------------------------------------------------------------------------

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const REGISTRY: Record<string, ToolDef<any>> = {
  ping,
  list_passwords: listPasswordsTool,
  search_passwords: searchPasswordsTool,
  get_password: getPasswordTool,
  list_folders: listFoldersTool,
  get_folder: getFolderTool,
  create_password: createPasswordTool,
  update_password: updatePasswordTool,
  delete_password: deletePasswordTool,
  create_folder: createFolderTool,
  update_folder: updateFolderTool,
  delete_folder: deleteFolderTool,
};

/** The tools to advertise. Write tools are omitted entirely in read-only mode. */
export function listTools(readOnly: boolean): Tool[] {
  return Object.values(REGISTRY)
    .filter((d) => !(readOnly && d.write))
    .map((d) => d.tool);
}

export async function dispatchTool(
  name: string,
  rawArgs: unknown,
  ctx: Context,
): Promise<CallToolResult> {
  const def = REGISTRY[name];
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
    const message =
      err instanceof AlreadyTrashedError ||
      err instanceof CseUnsupportedError ||
      err instanceof HttpError
        ? err.message
        : err instanceof Error
          ? err.message
          : String(err);
    return { isError: true, content: [{ type: 'text', text: message }] };
  }
}
