import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { createPatch } from 'diff';
import { LocalPathPolicy } from '../src/local-path-policy.js';
import type { ProcessResult } from '../src/process-runner.js';
import type { OpenSshChannel } from '../src/ssh/openssh-file-operations.js';
import { OpenSshFileOperations } from '../src/ssh/openssh-file-operations.js';

class FakeOpenSshChannel implements OpenSshChannel {
  readonly files = new Map<string, Buffer>();
  readonly directories = new Set<string>(['/etc']);

  async execRaw(command: string): Promise<ProcessResult> {
    if (command.includes(' stat ')) {
      const path = command.match(/-- '([^']+)'$/)?.[1] ?? '';
      if (this.directories.has(path)) return result(Buffer.from('directory\t4096\t755\t0\t0\t1\t2\n'));
      const data = this.files.get(path);
      if (!data) return result(Buffer.alloc(0), Buffer.from('not found'), 1);
      return result(Buffer.from(`regular file\t${data.length}\t640\t1000\t1000\t1\t2\n`));
    }
    if (command.includes(' find ')) {
      const fields: string[] = [];
      for (const [path, data] of this.files) {
        if (!path.startsWith('/etc/') || path.slice('/etc/'.length).includes('/')) continue;
        fields.push(path.slice('/etc/'.length), 'f', String(data.length), '640', '1000', '1000', '2.0');
      }
      return result(Buffer.from(`${fields.join('\0')}\0`));
    }
    if (command.startsWith('dd ')) {
      const path = command.match(/if='([^']+)'/)?.[1] ?? '';
      const offset = Number(command.match(/skip=(\d+)/)?.[1] ?? 0);
      const length = Number(command.match(/count=(\d+)/)?.[1] ?? 0);
      const data = this.files.get(path);
      if (!data) return result(Buffer.alloc(0), Buffer.from('not found'), 1);
      return result(data.subarray(offset, offset + length));
    }
    if (command.startsWith('if [ -e ')) {
      return result(Buffer.from(this.files.has(singleQuotedPaths(command)[0]!) ? '1' : '0'));
    }
    if (command.startsWith('sha256sum ')) {
      const path = singleQuotedPaths(command)[0]!;
      const data = this.files.get(path);
      if (!data) return result(Buffer.alloc(0), Buffer.from('not found'), 1);
      return result(Buffer.from(`${sha256(data)}  ${path}\n`));
    }
    if (command.startsWith('cp -p -- ')) {
      const [source, destination] = singleQuotedPaths(command);
      const data = this.files.get(source!);
      if (!data) return result(Buffer.alloc(0), Buffer.from('not found'), 1);
      this.files.set(destination!, Buffer.from(data));
      return result(Buffer.alloc(0));
    }
    if (command === `printf ''`) return result(Buffer.alloc(0));
    return result(Buffer.alloc(0), Buffer.from(`unsupported command: ${command}`), 1);
  }

  async sftp(batch: string): Promise<ProcessResult> {
    for (const line of batch.trim().split('\n')) {
      const paths = quotedPaths(line);
      if (line.startsWith('get ')) {
        const data = this.files.get(paths[0]!);
        if (!data) return result(Buffer.alloc(0), Buffer.from('not found'), 1);
        await writeFile(paths[1]!, data);
      } else if (line.startsWith('put ')) {
        this.files.set(paths[1]!, await readFile(paths[0]!));
      } else if (line.startsWith('rename ')) {
        const data = this.files.get(paths[0]!);
        if (!data) return result(Buffer.alloc(0), Buffer.from('not found'), 1);
        this.files.set(paths[1]!, data);
        this.files.delete(paths[0]!);
      } else if (line.startsWith('-rm ')) {
        this.files.delete(paths[0]!);
      }
    }
    return result(Buffer.alloc(0));
  }
}

test('reads native remote metadata, bounded directory entries, and byte ranges', async () => {
  const channel = new FakeOpenSshChannel();
  channel.files.set('/etc/alpha.conf', Buffer.from('abcdef'));
  channel.files.set('/etc/beta.conf', Buffer.from('1234'));
  const files = new OpenSshFileOperations(channel);
  assert.equal((await files.stat('/etc/alpha.conf')).size, 6);
  const listing = await files.listDirectory('/etc', 1);
  assert.equal(listing.entries.length, 1);
  assert.equal(listing.truncated, true);
  const read = await files.readFile('/etc/alpha.conf', 2, 3, 10, 'utf8');
  assert.equal(read.content, 'cde');
  assert.equal(read.next_offset, 5);
});

test('applies a native hash-guarded patch through SFTP channels', async () => {
  const channel = new FakeOpenSshChannel();
  const path = '/etc/example.conf';
  const before = 'enabled=false\nport=80\n';
  const after = 'enabled=true\nport=8080\n';
  channel.files.set(path, Buffer.from(before));
  const files = new OpenSshFileOperations(channel);
  const patched = await files.applyPatch(path, createPatch(path, before, after), sha256(before), true);
  assert.equal(channel.files.get(path)?.toString(), after);
  assert.equal(patched.sha256, sha256(after));
  assert.equal(channel.files.get(patched.backup_path!)?.toString(), before);
});

test('uploads and downloads files with hashes, overwrite guards, and backups', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'mcp-ssh-ops-transfer-'));
  try {
    const channel = new FakeOpenSshChannel();
    const files = new OpenSshFileOperations(channel, new LocalPathPolicy([directory]), 104_857_600);
    const source = join(directory, 'source.txt');
    const destination = join(directory, 'download.txt');
    await writeFile(source, 'version-one\n');

    const uploaded = await files.uploadFile(source, '/etc/upload.txt', false, true, sha256('version-one\n'));
    assert.equal(uploaded.sha256, sha256('version-one\n'));
    assert.equal(channel.files.get('/etc/upload.txt')?.toString(), 'version-one\n');
    await assert.rejects(
      files.uploadFile(source, '/etc/upload.txt', false, true),
      /REMOTE_FILE_EXISTS/,
    );

    await writeFile(source, 'version-two\n');
    const replaced = await files.uploadFile(
      source,
      '/etc/upload.txt',
      true,
      true,
      sha256('version-two\n'),
      sha256('version-one\n'),
    );
    assert.equal(channel.files.get('/etc/upload.txt')?.toString(), 'version-two\n');
    assert.equal(channel.files.get(replaced.backup_path!)?.toString(), 'version-one\n');

    const downloaded = await files.downloadFile('/etc/upload.txt', destination, false, true, sha256('version-two\n'));
    assert.equal(await readFile(destination, 'utf8'), 'version-two\n');
    assert.equal(downloaded.sha256, sha256('version-two\n'));
    channel.files.set('/etc/upload.txt', Buffer.from('version-three\n'));
    const overwritten = await files.downloadFile('/etc/upload.txt', destination, true, true, sha256('version-three\n'));
    assert.equal(await readFile(destination, 'utf8'), 'version-three\n');
    assert.equal(await readFile(overwritten.backup_path!, 'utf8'), 'version-two\n');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

function quotedPaths(line: string): string[] {
  return [...line.matchAll(/"((?:\\.|[^"])*)"/g)].map((match) => match[1]!.replace(/\\(.)/g, '$1'));
}

function singleQuotedPaths(line: string): string[] {
  return [...line.matchAll(/'([^']*)'/g)].map((match) => match[1]!);
}

function result(stdout: Buffer, stderr = Buffer.alloc(0), exitCode = 0): ProcessResult {
  return {
    exit_code: exitCode,
    signal: null,
    stdout,
    stderr,
    timed_out: false,
    output_truncated: false,
    duration_ms: 1,
  };
}

function sha256(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}
