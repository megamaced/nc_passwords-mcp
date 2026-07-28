import { z, type ZodTypeAny } from 'zod';
import type { CallToolResult, Tool } from '@modelcontextprotocol/sdk/types.js';

import {
  listFolders,
  listPasswords,
  passwordMatches,
  showFolder,
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

const ping: ToolDef<typeof Empty> = {
  argsSchema: Empty,
  tool: {
    name: 'ping',
    description:
      'Verify connectivity to the configured Nextcloud Passwords instance and report metadata counts.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  handler: async (_args, ctx) => {
    const [passwords, folders] = await Promise.all([
      listPasswords(ctx.client),
      listFolders(ctx.client),
    ]);
    return textResult(
      `OK — connected to ${ctx.configSummary} (metadata-only); ` +
        `${passwords.length} password(s), ${folders.length} folder(s) visible.`,
    );
  },
};

const ListPasswordsArgs = z
  .object({
    folder: z.string().optional(),
  })
  .strict();

const listPasswordsTool: ToolDef<typeof ListPasswordsArgs> = {
  argsSchema: ListPasswordsArgs,
  tool: {
    name: 'list_passwords',
    description:
      'List password metadata only: id, label, username, URL, folder, status, and timestamps.',
    inputSchema: {
      type: 'object',
      properties: {
        folder: { type: 'string', description: 'Optional exact folder id.' },
      },
      additionalProperties: false,
    },
  },
  handler: async (args, ctx) => {
    let all = await listPasswords(ctx.client);
    if (args.folder) all = all.filter((password) => password.folder === args.folder);
    return jsonResult(all.map(toPasswordMeta));
  },
};

const SearchPasswordsArgs = z.object({ query: z.string().min(1) }).strict();

const searchPasswordsTool: ToolDef<typeof SearchPasswordsArgs> = {
  argsSchema: SearchPasswordsArgs,
  tool: {
    name: 'search_passwords',
    description:
      'Search label, username, and URL. Returns metadata only and never searches secret-bearing fields.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Substring to match on label, username, or URL.' },
      },
      required: ['query'],
      additionalProperties: false,
    },
  },
  handler: async (args, ctx) => {
    const hits = (await listPasswords(ctx.client)).filter((password) =>
      passwordMatches(password, args.query),
    );
    return jsonResult(hits.map(toPasswordMeta));
  },
};

const listFoldersTool: ToolDef<typeof Empty> = {
  argsSchema: Empty,
  tool: {
    name: 'list_folders',
    description: 'List folder metadata. Folders contain no secret values.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  handler: async (_args, ctx) => jsonResult(await listFolders(ctx.client)),
};

const GetFolderArgs = z.object({ id: z.string().min(1) }).strict();

const getFolderTool: ToolDef<typeof GetFolderArgs> = {
  argsSchema: GetFolderArgs,
  tool: {
    name: 'get_folder',
    description: 'Fetch one folder metadata record by exact id.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string', description: 'Exact folder id.' } },
      required: ['id'],
      additionalProperties: false,
    },
  },
  handler: async (args, ctx) => jsonResult(await showFolder(ctx.client, args.id)),
};

// Tool definitions intentionally have different Zod input shapes.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const REGISTRY: Record<string, ToolDef<any>> = {
  ping,
  list_passwords: listPasswordsTool,
  search_passwords: searchPasswordsTool,
  list_folders: listFoldersTool,
  get_folder: getFolderTool,
};

export function listTools(): Tool[] {
  return Object.values(REGISTRY).map((definition) => definition.tool);
}

function safeError(err: unknown): string {
  if (err instanceof CseUnsupportedError) {
    return JSON.stringify({ ok: false, code: 'CSE_UNSUPPORTED' });
  }
  if (err instanceof HttpError) {
    return JSON.stringify({ ok: false, code: 'NEXTCLOUD_REQUEST_FAILED', status: err.status });
  }
  return JSON.stringify({ ok: false, code: 'OPERATION_FAILED' });
}

export async function dispatchTool(
  name: string,
  rawArgs: unknown,
  ctx: Context,
): Promise<CallToolResult> {
  const definition = REGISTRY[name];
  if (!definition) {
    return {
      isError: true,
      content: [{ type: 'text', text: JSON.stringify({ ok: false, code: 'UNKNOWN_TOOL' }) }],
    };
  }

  const parsed = definition.argsSchema.safeParse(rawArgs ?? {});
  if (!parsed.success) {
    return {
      isError: true,
      content: [{ type: 'text', text: JSON.stringify({ ok: false, code: 'INVALID_ARGUMENTS' }) }],
    };
  }

  try {
    return await definition.handler(parsed.data, ctx);
  } catch (err) {
    return { isError: true, content: [{ type: 'text', text: safeError(err) }] };
  }
}
