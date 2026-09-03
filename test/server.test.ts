import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { Client, InMemoryTransport } from '@modelcontextprotocol/client';
import { ProfileStore } from '../src/profile-store.js';
import { createMcpServer } from '../src/server.js';
import { SessionManager } from '../src/ssh/session-manager.js';
import { testPaths } from './helpers.js';

test('publishes the complete native OpenSSH tool set through MCP', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'mcp-ssh-ops-server-'));
  const paths = testPaths(directory);
  const profiles = new ProfileStore(paths);
  const sessions = new SessionManager(paths, profiles, async () => 'unused');
  const server = createMcpServer({ profiles, sessions });
  const client = new Client({ name: 'mcp-ssh-ops-test', version: '1.0.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  try {
    await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((tool) => tool.name).sort(), [
      'ssh_apply_patch',
      'ssh_clone_session',
      'ssh_close_session',
      'ssh_create_session',
      'ssh_download_file',
      'ssh_exec',
      'ssh_list_directory',
      'ssh_list_profiles',
      'ssh_list_sessions',
      'ssh_read_file',
      'ssh_save_profile',
      'ssh_session_info',
      'ssh_stat',
      'ssh_trust_host',
      'ssh_upload_file',
    ]);
    const result = await client.callTool({ name: 'ssh_list_profiles', arguments: {} });
    assert.equal(result.isError, undefined);
    assert.match(JSON.stringify(result.content), /profiles/);
    const missingProfile = await client.callTool({ name: 'ssh_create_session', arguments: { profile_name: 'missing' } });
    assert.equal(missingProfile.isError, true);
    assert.match(JSON.stringify(missingProfile.content), /PROFILE_NOT_FOUND/);
    assert.doesNotMatch(JSON.stringify(missingProfile.content), /AMBIGUOUS_SESSION_CONFIG/);
    const missingHost = await client.callTool({ name: 'ssh_create_session', arguments: { host: 'missing' } });
    assert.equal(missingHost.isError, true);
    assert.match(JSON.stringify(missingHost.content), /PROFILE_NOT_FOUND/);
  } finally {
    await client.close();
    await server.close();
    await sessions.closeAll();
    await rm(directory, { recursive: true, force: true });
  }
});
