import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createConnection } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { createPatch } from 'diff';
import ssh2 from 'ssh2';
import type { ConnectConfig, Server as SshServer, SFTPWrapper } from 'ssh2';
import { ProfileStore } from '../src/profile-store.js';
import { SessionManager } from '../src/ssh/session-manager.js';
import { sshFingerprint } from '../src/ssh/fingerprint.js';
import { testKeyPair, testPaths } from './helpers.js';

async function fixture(authentication: 'password' | 'keyboard-interactive' = 'password') {
  const directory = await mkdtemp(join(tmpdir(), 'mcp-ssh2-'));
  const paths = testPaths(directory);
  const profiles = new ProfileStore(paths);
  await profiles.ensure();
  await writeFile(paths.sshConfigFile, `Host *\n UserKnownHostsFile "${paths.knownHostsFile.replaceAll('\\', '/')}"\n GlobalKnownHostsFile ${process.platform === 'win32' ? 'NUL' : '/dev/null'}\n StrictHostKeyChecking ask\n`);
  const pair = testKeyPair();
  const key = ssh2.utils.parseKey(pair.private);
  assert.ok(!(key instanceof Error));
  const state = { password: 'synthetic-password', connections: 0, sftpChannels: 0 };
  const files = new Map<string, Buffer>();
  const clients = new Set<ssh2.Connection>();
  const server = new ssh2.Server({ hostKeys: [pair.private] }, (connection) => {
    clients.add(connection);
    connection.once('close', () => clients.delete(connection));
    connection.on('error', () => undefined);
    connection.on('authentication', (context) => {
      if (authentication === 'password' && context.method === 'password' && context.password === state.password) context.accept();
      else if (authentication === 'keyboard-interactive' && context.method === 'keyboard-interactive') {
        context.prompt([{ prompt: 'Password:', echo: false }, { prompt: 'Verification code:', echo: false }], (answers) => {
          if (answers[0] === state.password && answers[1] === '123456') context.accept();
          else context.reject(['keyboard-interactive']);
        });
      } else context.reject(authentication === 'password' ? ['publickey', 'password'] : [authentication]);
    });
    connection.on('ready', () => {
      state.connections += 1;
      connection.on('tcpip', (accept, reject, info) => {
        const socket = createConnection({ host: info.destIP, port: info.destPort });
        socket.once('connect', () => { const channel = accept(); channel.pipe(socket).pipe(channel); });
        socket.once('error', () => reject());
      });
      connection.on('session', (accept) => {
        const session = accept();
        session.on('exec', (acceptExec, _reject, info) => {
          const stream = acceptExec();
          if (info.command === 'hang') return;
          const output = remoteCommand(files, info.command);
          stream.exit(0);
          stream.end(output);
        });
        session.on('sftp', (acceptSftp) => {
          state.sftpChannels += 1;
          serveSftp(acceptSftp(), files);
        });
      });
    });
  });
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  await profiles.save('target', { host: '127.0.0.1', port: address.port, username: 'test-user', auth_method: 'password' });
  return {
    directory, paths, profiles, state, files, server, port: address.port,
    fingerprint: sshFingerprint(key.getPublicSSH()),
    async close() {
      for (const client of clients) client.end();
      await closeServer(server);
      await rm(directory, { recursive: true, force: true });
    },
  };
}

test('ssh2 preserves one transport for concurrent exec/SFTP, clones and scoped RAM credentials', async () => {
  const f = await fixture();
  let prompts = 0;
  const manager = new SessionManager(f.paths, f.profiles, async () => { prompts += 1; return f.state.password; }, 'ssh2');
  const other = new SessionManager(f.paths, f.profiles, async () => 'unused', 'ssh2');
  try {
    const profile = await f.profiles.get('target');
    await assert.rejects(manager.createSession(profile), /HOST_KEY_UNKNOWN/);
    assert.equal(prompts, 0);
    await assert.rejects(async () => { await manager.trustHost('127.0.0.1', f.port, 'SHA256:wrong'); }, /HOST_KEY_NOT_PENDING/);
    await manager.trustHost('127.0.0.1', f.port, f.fingerprint);
    const session = await manager.createSession(profile, 'primary');
    assert.equal(session.backend, 'ssh2');
    assert.match(session.session_id, /^primary \| target -> test-user@127\.0\.0\.1:\d+ \| [a-f0-9]{8}$/);
    const request = { timeout_ms: 5_000, max_output_bytes: 4096 };
    const results = await Promise.all(['one', 'two'].map((command) => manager.exec(session.session_id, { ...request, command })));
    assert.deepEqual(results.map((result) => result.stdout), ['ran:one', 'ran:two']);
    assert.equal(results[0]!.session.name, 'primary');
    const source = join(f.directory, 'upload.txt');
    const destination = join(f.directory, 'download.txt');
    await writeFile(source, 'hello\n');
    const uploaded = await manager.uploadFile(session.session_id, source, '/remote.txt', false, false);
    assert.equal(uploaded.session.name, 'primary');
    assert.equal(f.files.get('/remote.txt')?.toString(), 'hello\n');
    await assert.rejects(manager.uploadFile(session.session_id, source, '/remote.txt', false, false), /REMOTE_FILE_EXISTS/);
    await manager.downloadFile(session.session_id, '/remote.txt', destination, false, false);
    assert.equal(await readFile(destination, 'utf8'), 'hello\n');
    await assert.rejects(manager.downloadFile(session.session_id, '/remote.txt', destination, false, false), /LOCAL_FILE_EXISTS/);
    const patched = await manager.applyPatch(session.session_id, '/remote.txt', createPatch('remote.txt', 'hello\n', 'updated\n'), hash(Buffer.from('hello\n')), true);
    assert.equal(patched.session.name, 'primary');
    assert.equal(f.files.get('/remote.txt')?.toString(), 'updated\n');
    assert.ok(f.state.sftpChannels > 3);
    assert.equal(f.state.connections, 1);
    const limited = await manager.exec(session.session_id, { ...request, command: 'flood', max_output_bytes: 5 });
    assert.equal(limited.stdout.length, 5);
    assert.equal(limited.output_truncated, true);
    assert.equal((await manager.exec(session.session_id, { ...request, command: 'hang', timeout_ms: 40 })).timed_out, true);
    assert.equal((await manager.exec(session.session_id, { ...request, command: 'after-timeout' })).stdout, 'ran:after-timeout');
    const clone = await manager.cloneSession(session.session_id, 'clone');
    assert.equal(prompts, 1);
    assert.equal(f.state.connections, 2);
    assert.deepEqual(other.listSessions(), []);
    await assert.rejects(other.exec(session.session_id, { ...request, command: 'wrong-process' }), /SESSION_NOT_FOUND/);
    f.state.password = 'replacement-password';
    await assert.rejects(manager.createSession(profile), /authentication/i);
    const fresh = await manager.createSession(profile);
    assert.equal(prompts, 2);
    await manager.closeSession(session.session_id);
    await manager.closeSession(clone.session_id);
    await manager.closeSession(fresh.session_id);
    const reopened = await manager.createSession(profile);
    assert.equal(prompts, 3);
    await manager.closeSession(reopened.session_id);
    await writeFile(f.paths.knownHostsFile, `[127.0.0.1]:${f.port} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n`);
    await assert.rejects(manager.createSession(profile), /HOST_KEY_CHANGED/);
    assert.equal(prompts, 3);
  } finally {
    await manager.closeAll();
    await other.closeAll();
    await f.close();
  }
});

test('ssh2 applies ProxyJump config and verifies each hop independently', async (t) => {
  const protocolLog: string[] = [];
  const connect = ssh2.Client.prototype.connect;
  t.mock.method(ssh2.Client.prototype, 'connect', function (this: ssh2.Client, config: ConnectConfig) {
    return connect.call(this, { ...config, debug: (message) => protocolLog.push(`${config.username}: ${message}`) });
  });
  const target = await fixture();
  const jump = await fixture();
  const secondJump = await fixture();
  const manager = new SessionManager(target.paths, target.profiles, async () => 'synthetic-password', 'ssh2');
  try {
    await target.profiles.save('bastion', { host: '127.0.0.1', port: jump.port, username: 'jump-user', auth_method: 'password' });
    await target.profiles.save('second', { host: '127.0.0.1', port: secondJump.port, username: 'second-user', auth_method: 'password' });
    await target.profiles.save('target', { host: '127.0.0.1', port: target.port, username: 'target-user', auth_method: 'password', proxy_jump: 'bastion,second' });
    const profile = await target.profiles.get('target');
    await assert.rejects(manager.createSession(profile), /HOST_KEY_UNKNOWN/);
    await manager.trustHost('127.0.0.1', jump.port, jump.fingerprint);
    await assert.rejects(manager.createSession(profile), /HOST_KEY_UNKNOWN/);
    await manager.trustHost('127.0.0.1', secondJump.port, secondJump.fingerprint);
    await assert.rejects(manager.createSession(profile), /HOST_KEY_UNKNOWN/);
    await manager.trustHost('127.0.0.1', target.port, target.fingerprint);
    const session = await manager.createSession(profile);
    const result = await manager.exec(session.session_id, { command: 'jumped', timeout_ms: 5_000, max_output_bytes: 4096 });
    assert.equal(result.stdout, 'ran:jumped');
    assert.equal(result.session.username, 'target-user');
    assert.equal(result.session.proxy_jump, 'bastion,second');
    assert.equal(target.state.connections, 1);
  } catch (error) {
    throw new Error(`${String(error)}\n${protocolLog.slice(-250).join('\n')}`, { cause: error });
  } finally {
    await manager.closeAll();
    await target.close();
    await jump.close();
    await secondJump.close();
  }
});

test('ssh2 caches only the password in keyboard-interactive authentication and honors BatchMode', async () => {
  const f = await fixture('keyboard-interactive');
  let passwords = 0;
  let challenges = 0;
  const manager = new SessionManager(f.paths, f.profiles, async (_title, message) => {
    if (message.includes('Password:')) { passwords += 1; return f.state.password; }
    challenges += 1;
    return '123456';
  }, 'ssh2');
  try {
    const config = (await readFile(f.paths.sshConfigFile, 'utf8')).replace(/PreferredAuthentications password/gi, 'PreferredAuthentications keyboard-interactive');
    await writeFile(f.paths.sshConfigFile, config);
    const profile = await f.profiles.get('target');
    await assert.rejects(manager.createSession(profile), /HOST_KEY_UNKNOWN/);
    await manager.trustHost('127.0.0.1', f.port, f.fingerprint);
    const session = await manager.createSession(profile);
    await manager.cloneSession(session.session_id);
    assert.equal(passwords, 1);
    assert.equal(challenges, 2);
    await writeFile(f.paths.sshConfigFile, `Host target\n BatchMode yes\n${config}`);
    await assert.rejects(manager.createSession(profile), /authentication/i);
    assert.equal(passwords, 1);
    assert.equal(challenges, 2);
  } finally { await manager.closeAll(); await f.close(); }
});

test('ssh2 cancellation and unsupported config do not leave live sessions', async () => {
  const f = await fixture();
  const manager = new SessionManager(f.paths, f.profiles, async () => 'unused', 'ssh2');
  try {
    const profile = await f.profiles.get('target');
    await assert.rejects(manager.createSession(profile, undefined, undefined, AbortSignal.abort()), /REQUEST_CANCELLED/);
    const config = await readFile(f.paths.sshConfigFile, 'utf8');
    await writeFile(f.paths.sshConfigFile, `Host target\n ForwardAgent yes\n${config}`);
    await assert.rejects(manager.createSession(profile), /SSH_CONFIG_UNSUPPORTED.*forwardagent/);
    assert.deepEqual(manager.listSessions(), []);
    assert.equal(f.state.connections, 0);
  } finally { await manager.closeAll(); await f.close(); }
});

test('ssh2 honors the false emitted by ssh -G for PubkeyAuthentication no', async () => {
  const f = await fixture();
  let prompts = 0;
  const manager = new SessionManager(f.paths, f.profiles, async () => { prompts += 1; return f.state.password; }, 'ssh2');
  try {
    const config = (await readFile(f.paths.sshConfigFile, 'utf8')).replace(/PreferredAuthentications password/gi, 'PreferredAuthentications publickey,password');
    await writeFile(f.paths.sshConfigFile, `Host target\n PubkeyAuthentication no\n IdentityAgent "${join(f.directory, 'missing-agent').replaceAll('\\', '/')}"\n${config}`);
    const profile = await f.profiles.get('target');
    assert.equal((await f.profiles.resolveOptions('target')).get('pubkeyauthentication')?.[0], 'false');
    await assert.rejects(manager.createSession(profile), /HOST_KEY_UNKNOWN/);
    await manager.trustHost('127.0.0.1', f.port, f.fingerprint);
    const session = await manager.createSession(profile);
    assert.equal(session.status, 'connected');
    assert.equal(prompts, 1);
  } finally { await manager.closeAll(); await f.close(); }
});

test('ssh2 falls back from an unavailable agent and still reports terminal auth failures', async () => {
  const f = await fixture();
  let prompts = 0;
  const manager = new SessionManager(f.paths, f.profiles, async () => { prompts += 1; return f.state.password; }, 'ssh2');
  try {
    const config = (await readFile(f.paths.sshConfigFile, 'utf8')).replace(/PreferredAuthentications password/gi, 'PreferredAuthentications publickey,password');
    await writeFile(f.paths.sshConfigFile, `Host target\n PubkeyAuthentication yes\n IdentityAgent "${join(f.directory, 'missing-agent').replaceAll('\\', '/')}"\n${config}`);
    const profile = await f.profiles.get('target');
    await assert.rejects(manager.createSession(profile), /HOST_KEY_UNKNOWN/);
    await manager.trustHost('127.0.0.1', f.port, f.fingerprint);
    const session = await manager.createSession(profile);
    assert.equal(session.status, 'connected');
    assert.equal(prompts, 1);
    f.state.password = 'new-synthetic-password';
    await assert.rejects(manager.createSession(profile), /authentication/i);
    assert.equal(prompts, 1);
  } finally { await manager.closeAll(); await f.close(); }
});

function remoteCommand(files: Map<string, Buffer>, command: string): Buffer {
  const paths = [...command.matchAll(/'([^']*)'/g)].map((match) => match[1]!);
  const path = paths.at(-1)!;
  if (command.includes(' stat ')) {
    const data = files.get(path)!;
    return Buffer.from(`regular file\t${data.length}\t644\t1000\t1000\t1\t2\n`);
  }
  if (command.startsWith('if [ -e')) return Buffer.from(files.has(paths[0]!) ? '1' : '0');
  if (command.startsWith('sha256sum')) return Buffer.from(`${hash(files.get(paths[0]!)!)}  ${paths[0]}\n`);
  if (command.startsWith('cp -p')) { files.set(paths[1]!, Buffer.from(files.get(paths[0]!)!)); return Buffer.alloc(0); }
  if (command === 'flood') return Buffer.alloc(20_000, 'x');
  return Buffer.from(`ran:${command}`);
}

function serveSftp(sftp: SFTPWrapper, files: Map<string, Buffer>) {
  const handles = new Map<number, string>();
  let sequence = 0;
  sftp.on('OPEN', (request, path, flags) => {
    if (files.has(path) && (flags & 32)) return sftp.status(request, 4);
    if (!files.has(path) && !(flags & 8)) return sftp.status(request, 2);
    if (!files.has(path) || flags & 16) files.set(path, Buffer.alloc(0));
    const handle = Buffer.alloc(4);
    handle.writeUInt32BE(++sequence);
    handles.set(sequence, path);
    sftp.handle(request, handle);
  });
  sftp.on('READ', (request, handle, offset, length) => {
    const data = files.get(handles.get(handle.readUInt32BE())!)!;
    if (offset >= data.length) sftp.status(request, 1);
    else sftp.data(request, data.subarray(offset, offset + length));
  });
  sftp.on('WRITE', (request, handle, offset, data) => {
    const path = handles.get(handle.readUInt32BE())!;
    const old = files.get(path)!;
    const updated = Buffer.alloc(Math.max(old.length, offset + data.length));
    old.copy(updated);
    data.copy(updated, offset);
    files.set(path, updated);
    sftp.status(request, 0);
  });
  sftp.on('CLOSE', (request, handle) => { handles.delete(handle.readUInt32BE()); sftp.status(request, 0); });
  sftp.on('SETSTAT', (request) => sftp.status(request, 0));
  sftp.on('FSTAT', (request, handle) => sftp.attrs(request, { size: files.get(handles.get(handle.readUInt32BE())!)!.length, mode: 0o100644, uid: 1000, gid: 1000, atime: 0, mtime: 0 }));
  sftp.on('RENAME', (request, source, destination) => { files.set(destination, files.get(source)!); files.delete(source); sftp.status(request, 0); });
  sftp.on('REMOVE', (request, path) => { files.delete(path); sftp.status(request, 0); });
  sftp.on('EXTENDED', (request) => sftp.status(request, 8));
}

function hash(data: Buffer): string { return createHash('sha256').update(data).digest('hex'); }
function closeServer(server: SshServer): Promise<void> { return new Promise((resolve) => server.close(() => resolve())); }
