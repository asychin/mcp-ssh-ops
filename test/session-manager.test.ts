import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createConnection } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import ssh2 from 'ssh2';
import type { AppPaths } from '../src/config.js';
import type { SshProfile } from '../src/types.js';
import { sshFingerprint } from '../src/ssh/fingerprint.js';
import { ProfileStore } from '../src/profile-store.js';
import { SessionManager } from '../src/ssh/session-manager.js';
import { testKeyPair, testPaths } from './helpers.js';

const { Server, utils } = ssh2;

test('uses native ControlMaster, explicit host trust, RAM password reuse, and clone isolation', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'mcp-ssh-ops-openssh-'));
  const hostPair = testKeyPair();
  const hostParsed = utils.parseKey(hostPair.private);
  assert.ok(!(hostParsed instanceof Error));
  const fingerprint = sshFingerprint(hostParsed.getPublicSSH());
  let authenticatedConnections = 0;
  const commands: string[] = [];
  const server = new Server({ hostKeys: [hostPair.private] }, (connection) => {
    connection.on('error', () => undefined);
    connection.on('authentication', (context) => {
      if (context.method === 'password' && context.username === 'test-user' && context.password === 'test-secret') context.accept();
      else context.reject(['password']);
    });
    connection.on('ready', () => {
      authenticatedConnections += 1;
      connection.on('session', (accept) => {
        const session = accept();
        session.on('exec', (acceptExec, _rejectExec, info) => {
          commands.push(info.command);
          const stream = acceptExec();
          stream.write(`ran:${info.command}`);
          stream.exit(0);
          stream.end();
        });
      });
    });
  });
  let manager: SessionManager | undefined;
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address();
    assert.ok(address && typeof address !== 'string');
    const paths = testPaths(directory);
    const profiles = new ProfileStore(paths);
    await isolateTestKnownHosts(profiles, paths);
    let promptCount = 0;
    manager = new SessionManager(paths, profiles, async () => {
      promptCount += 1;
      await new Promise((resolve) => setTimeout(resolve, 25));
      return 'test-secret';
    });
    const profile: SshProfile = {
      host: '127.0.0.1',
      port: address.port,
      username: 'test-user',
      auth_method: 'password',
      connect_timeout_ms: 5_000,
    };

    await assert.rejects(manager.createSession(profile, 'first'), new RegExp(`HOST_KEY_UNKNOWN.*${fingerprint.replace(/[+]/g, '\\+')}`));
    const approved = await manager.trustHost('127.0.0.1', address.port, fingerprint);
    assert.equal(approved.status, 'approved');
    const first = await manager.createSession(profile, 'first');
    assert.match(first.session_id, /^first \| test-user@127\.0\.0\.1:\d+ \| [0-9a-f]{8}$/);
    assert.equal(promptCount, 1);
    assert.equal(authenticatedConnections, 1);
    const firstResult = await manager.exec(first.session_id, {
      command: 'first-command',
      timeout_ms: 5_000,
      max_output_bytes: 16_384,
    });
    const secondResult = await manager.exec(first.session_id, {
      command: 'second-command',
      timeout_ms: 5_000,
      max_output_bytes: 16_384,
    });
    assert.equal(firstResult.stdout, 'ran:first-command');
    assert.equal(firstResult.session.name, 'first');
    assert.match(firstResult.session.target, /^test-user@127\.0\.0\.1:\d+$/);
    assert.equal(secondResult.stdout, 'ran:second-command');
    assert.equal(authenticatedConnections, 1);
    const clone = await manager.cloneSession(first.session_id, 'second');
    const independent = await manager.createSession(profile, 'third');
    assert.equal(promptCount, 1);
    assert.equal(authenticatedConnections, 3);
    assert.equal(manager.listSessions().length, 3);
    assert.deepEqual(commands, ['true', 'first-command', 'second-command', 'true', 'true']);
    assert.ok((await readFile(paths.knownHostsFile, 'utf8')).includes(hostParsed.type));
    await manager.closeSession(first.session_id);
    await manager.closeSession(clone.session_id);
    await manager.closeSession(independent.session_id);
  } finally {
    await manager?.closeAll();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(directory, { recursive: true, force: true });
  }
});

test('honors native ProxyJump and verifies jump and target host keys independently', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'mcp-ssh-ops-jump-'));
  const jumpPair = testKeyPair();
  const targetPair = testKeyPair();
  const jumpParsed = utils.parseKey(jumpPair.private);
  const targetParsed = utils.parseKey(targetPair.private);
  assert.ok(!(jumpParsed instanceof Error));
  assert.ok(!(targetParsed instanceof Error));
  const jumpFingerprint = sshFingerprint(jumpParsed.getPublicSSH());
  const targetFingerprint = sshFingerprint(targetParsed.getPublicSSH());
  let targetConnections = 0;

  const targetServer = new Server({ hostKeys: [targetPair.private] }, (connection) => {
    connection.on('error', () => undefined);
    connection.on('authentication', (context) => {
      if (context.method === 'password' && context.username === 'target-user' && context.password === 'test-secret') context.accept();
      else context.reject(['password']);
    });
    connection.on('ready', () => {
      targetConnections += 1;
      connection.on('session', (accept) => {
        const session = accept();
        session.on('exec', (acceptExec, _rejectExec, info) => {
          const stream = acceptExec();
          stream.write(`target:${info.command}`);
          stream.exit(0);
          stream.end();
        });
      });
    });
  });
  const jumpServer = new Server({ hostKeys: [jumpPair.private] }, (connection) => {
    connection.on('error', () => undefined);
    connection.on('authentication', (context) => {
      if (context.method === 'password' && context.username === 'jump-user' && context.password === 'test-secret') context.accept();
      else context.reject(['password']);
    });
    connection.on('tcpip', (accept, reject, info) => {
      const upstream = createConnection({ host: info.destIP, port: info.destPort });
      upstream.once('connect', () => {
        const channel = accept();
        channel.pipe(upstream).pipe(channel);
      });
      upstream.once('error', () => reject());
    });
  });
  let manager: SessionManager | undefined;
  try {
    await Promise.all([
      new Promise<void>((resolve, reject) => {
        targetServer.once('error', reject);
        targetServer.listen(0, '127.0.0.1', resolve);
      }),
      new Promise<void>((resolve, reject) => {
        jumpServer.once('error', reject);
        jumpServer.listen(0, '127.0.0.1', resolve);
      }),
    ]);
    const targetAddress = targetServer.address();
    const jumpAddress = jumpServer.address();
    assert.ok(targetAddress && typeof targetAddress !== 'string');
    assert.ok(jumpAddress && typeof jumpAddress !== 'string');
    const paths = testPaths(directory);
    const profiles = new ProfileStore(paths);
    await isolateTestKnownHosts(profiles, paths);
    await profiles.save('jump', {
      host: '127.0.0.1',
      port: jumpAddress.port,
      username: 'jump-user',
      auth_method: 'password',
    });
    await profiles.save('target', {
      host: '127.0.0.1',
      port: targetAddress.port,
      username: 'target-user',
      auth_method: 'password',
      proxy_jump: 'jump',
    });
    let promptCount = 0;
    manager = new SessionManager(paths, profiles, async () => {
      promptCount += 1;
      await new Promise((resolve) => setTimeout(resolve, 25));
      return 'test-secret';
    });
    const profile = await profiles.get('target');

    await assert.rejects(manager.createSession(profile), new RegExp(`HOST_KEY_UNKNOWN.*${jumpFingerprint.replace(/[+]/g, '\\+')}`));
    await manager.trustHost('127.0.0.1', jumpAddress.port, jumpFingerprint);
    await assert.rejects(manager.createSession(profile), new RegExp(`HOST_KEY_UNKNOWN.*${targetFingerprint.replace(/[+]/g, '\\+')}`));
    await manager.trustHost('127.0.0.1', targetAddress.port, targetFingerprint);
    const session = await manager.createSession(profile, 'via-jump');
    const promptsAfterConnect = promptCount;
    const execution = await manager.exec(session.session_id, {
      command: 'hostname',
      timeout_ms: 5_000,
      max_output_bytes: 16_384,
    });
    assert.equal(execution.stdout, 'target:hostname');
    assert.equal(targetConnections, 1);
    const clone = await manager.cloneSession(session.session_id, 'via-jump-clone');
    assert.equal(targetConnections, 2);
    assert.equal(promptCount, promptsAfterConnect);
    await manager.closeSession(session.session_id);
    await manager.closeSession(clone.session_id);
  } finally {
    await manager?.closeAll();
    await Promise.all([
      new Promise<void>((resolve) => targetServer.close(() => resolve())),
      new Promise<void>((resolve) => jumpServer.close(() => resolve())),
    ]);
    await rm(directory, { recursive: true, force: true });
  }
});

test('passes production native askpass output directly to OpenSSH', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'mcp-ssh-ops-native-askpass-'));
  const hostPair = testKeyPair();
  const hostParsed = utils.parseKey(hostPair.private);
  assert.ok(!(hostParsed instanceof Error));
  const fingerprint = sshFingerprint(hostParsed.getPublicSSH());
  const server = new Server({ hostKeys: [hostPair.private] }, (connection) => {
    connection.on('error', () => undefined);
    connection.on('authentication', (context) => {
      if (context.method === 'password' && context.password === 'test-secret') context.accept();
      else context.reject(['password']);
    });
    connection.on('ready', () => {
      connection.on('session', (accept) => {
        const session = accept();
        session.on('exec', (acceptExec) => {
          const stream = acceptExec();
          stream.exit(0);
          stream.end();
        });
      });
    });
  });
  let manager: SessionManager | undefined;
  const originalPath = process.env.PATH;
  const originalPrompt = { SSH_ASKPASS: process.env.SSH_ASKPASS, DISPLAY: process.env.DISPLAY };
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address();
    assert.ok(address && typeof address !== 'string');
    const fakeBin = join(directory, 'bin');
    await mkdir(fakeBin, { recursive: true });
    for (const command of ['ksshaskpass', 'kdialog', 'zenity']) {
      const fakeAskpass = join(fakeBin, command);
      await writeFile(fakeAskpass, "#!/bin/sh\nprintf 'test-secret\\n'\n", { mode: 0o700 });
      await chmod(fakeAskpass, 0o700);
    }
    process.env.PATH = `${fakeBin}:${originalPath ?? ''}`;
    process.env.SSH_ASKPASS = join(fakeBin, 'ksshaskpass');
    process.env.DISPLAY = ':test';
    const paths = testPaths(directory);
    const profiles = new ProfileStore(paths);
    await isolateTestKnownHosts(profiles, paths);
    manager = new SessionManager(paths, profiles);
    const profile: SshProfile = {
      host: '127.0.0.1',
      port: address.port,
      username: 'test-user',
      auth_method: 'password',
      connect_timeout_ms: 5_000,
    };
    await assert.rejects(manager.createSession(profile), /HOST_KEY_UNKNOWN/);
    await manager.trustHost('127.0.0.1', address.port, fingerprint);
    const session = await manager.createSession(profile, 'native-askpass');
    assert.equal(session.status, 'connected');
    await manager.closeSession(session.session_id);
  } finally {
    process.env.PATH = originalPath;
    for (const [key, value] of Object.entries(originalPrompt)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    await manager?.closeAll();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(directory, { recursive: true, force: true });
  }
});

async function isolateTestKnownHosts(profiles: ProfileStore, paths: AppPaths): Promise<void> {
  await profiles.ensure();
  await writeFile(paths.sshConfigFile, [
    'Host *',
    `    UserKnownHostsFile ${paths.knownHostsFile}`,
    '    GlobalKnownHostsFile /dev/null',
    '    StrictHostKeyChecking ask',
    '',
  ].join('\n'));
}
