import { z, type ZodTypeAny } from 'zod';
import type { CallToolResult, Tool } from '@modelcontextprotocol/sdk/types.js';

import {
  listFolders,
  listPasswords,
  passwordMatches,
  showFolder,
  showPassword,
} from './api.js';
import { CseUnsupportedError, HttpError, type PasswordsClient } from './http.js';
import { toPasswordMeta } from './types.js';

export interface Context {
  client: PasswordsClient;
  configSummary: string;
}

interface ToolDef<S extends ZodTypeAny> {
  tool: Tool;
  argsSchema: S;
  handler: (args: z.infer<S>, ctx: Context) => Promise<CallToolResult>;
}

const Empty = z.object({}).strict();

function jsonResult(data: unknown): CallToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
}

function textResult(text: string): CallToolResult {
  return { content: [{ type: 'text', text }] };
}

// -----------------------------------------------------------------------------
// ping
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
      `OK — connected to ${ctx.configSummary}; ` +
        `${passwords.length} password(s), ${folders.length} folder(s) visible.`,
    );
  },
};

// -----------------------------------------------------------------------------
// list_passwords  (metadata only — never returns secrets)
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// search_passwords  (metadata only — never returns secrets)
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// get_password  (the ONLY tool that reveals a secret — single item, explicit)
// -----------------------------------------------------------------------------

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
    // Return the full record for this explicitly-requested single item.
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

// -----------------------------------------------------------------------------
// list_folders / get_folder
// -----------------------------------------------------------------------------

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

const GetFolderArgs = z
  .object({
    id: z.string().min(1, 'id is required'),
  })
  .strict();

const getFolderTool: ToolDef<typeof GetFolderArgs> = {
  argsSchema: GetFolderArgs,
  tool: {
    name: 'get_folder',
    description: 'Fetch a single folder by its id.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'The folder id.' },
      },
      required: ['id'],
      additionalProperties: false,
    },
  },
  handler: async (args, ctx) => jsonResult(await showFolder(ctx.client, args.id)),
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
};

export const TOOLS: Tool[] = Object.values(REGISTRY).map((d) => d.tool);

export async function dispatchTool(
  name: string,
  rawArgs: unknown,
  ctx: Context,
): Promise<CallToolResult> {
  const def = REGISTRY[name];
  if (!def) {
    return { isError: true, content: [{ type: 'text', text: `Unknown tool: ${name}` }] };
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
      err instanceof CseUnsupportedError || err instanceof HttpError
        ? err.message
        : err instanceof Error
          ? err.message
          : String(err);
    return { isError: true, content: [{ type: 'text', text: message }] };
  }
}
