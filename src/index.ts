#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import { loadConfig } from './config.js';
import { PasswordsClient } from './http.js';
import { readSecret } from './secret-store.js';
import { dispatchTool, listTools, type Context } from './tools.js';

const config = loadConfig();
const appPassword = await readSecret(config.credential);
const client = new PasswordsClient(config, appPassword);
const ctx: Context = {
  client,
  configSummary: `${new URL(config.url).origin} as ${config.user}`,
};

const server = new Server(
  { name: 'passwords-mcp', version: '0.3.0' },
  { capabilities: { tools: {} } },
);

const tools = listTools();
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));

server.setRequestHandler(CallToolRequestSchema, async (req) =>
  dispatchTool(req.params.name, req.params.arguments, ctx),
);

// Best-effort session teardown on shutdown.
async function shutdown(): Promise<void> {
  await client.close();
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

const transport = new StdioServerTransport();
await server.connect(transport);
