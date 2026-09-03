#!/usr/bin/env node
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { getAppPaths } from './config.js';
import { ProfileStore } from './profile-store.js';
import { createMcpServer } from './server.js';
import { SessionManager } from './ssh/session-manager.js';

const paths = getAppPaths();
const profiles = new ProfileStore(paths);
const sessions = new SessionManager(paths, profiles);
const dependencies = { profiles, sessions };
const handle = serveStdio(() => createMcpServer(dependencies), {
  onerror: (error) => console.error(error.message),
});
let shuttingDown = false;

async function shutdown(): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  await sessions.closeAll();
  await handle.close();
}

process.once('SIGINT', () => void shutdown());
process.once('SIGTERM', () => void shutdown());
