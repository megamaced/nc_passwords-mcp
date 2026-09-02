#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import { loadConfig } from './config.js';
import { PasswordsClient } from './http.js';
import { dispatchTool, listTools, type Context } from './tools.js';

const config = loadConfig();
const client = new PasswordsClient(config);
const ctx: Context = {
  client,
  configSummary: `${config.url} as ${config.user}`,
  readOnly: config.readOnly,
};

const server = new Server(
  { name: 'passwords-mcp', version: '0.3.0' },
  { capabilities: { tools: {} } },
);

const tools = listTools(config.readOnly);
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
