import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { createPatch } from 'diff';
import type { Callback, SFTPWrapper, Stats } from 'ssh2';
import { SftpOperations } from '../src/ssh/sftp-operations.js';

class FakeSftp {
  readonly files = new Map<string, Buffer>();

  stat(path: string, callback: (error: Error | undefined, stats: Stats) => void) {
    this.returnStats(path, callback);
  }

  lstat(path: string, callback: (error: Error | undefined, stats: Stats) => void) {
    this.returnStats(path, callback);
  }

  readFile(path: string, callback: (error: Error | undefined, data: Buffer) => void) {
    const data = this.files.get(path);
    if (!data) callback(new Error('not found'), Buffer.alloc(0));
    else callback(undefined, Buffer.from(data));
  }

  writeFile(path: string, data: Buffer, options: { flag?: string }, callback: Callback) {
    if (options.flag === 'wx' && this.files.has(path)) callback(new Error('exists'));
    else {
      this.files.set(path, Buffer.from(data));
      callback(undefined);
    }
  }

  ext_openssh_rename(source: string, destination: string, callback: Callback) {
    this.move(source, destination, callback);
  }

  rename(source: string, destination: string, callback: Callback) {
    this.move(source, destination, callback);
  }

  unlink(path: string, callback: Callback) {
    this.files.delete(path);
    callback(undefined);
  }

  private move(source: string, destination: string, callback: Callback) {
    const data = this.files.get(source);
    if (!data) {
      callback(new Error('not found'));
      return;
    }
    this.files.set(destination, data);
    this.files.delete(source);
    callback(undefined);
  }

  private returnStats(path: string, callback: (error: Error | undefined, stats: Stats) => void) {
    const data = this.files.get(path);
    if (!data) {
      callback(new Error('not found'), undefined as never);
      return;
    }
    callback(undefined, {
      mode: 0o100640,
      uid: 1000,
      gid: 1000,
      size: data.length,
      atime: 0,
      mtime: 0,
      isFile: () => true,
      isDirectory: () => false,
      isBlockDevice: () => false,
      isCharacterDevice: () => false,
      isSymbolicLink: () => false,
      isFIFO: () => false,
      isSocket: () => false,
    });
  }
}

test('applies a hash-guarded patch and creates a backup', async () => {
  const fake = new FakeSftp();
  const path = '/etc/example.conf';
  const before = 'enabled=false\nport=80\n';
  const after = 'enabled=true\nport=8080\n';
  fake.files.set(path, Buffer.from(before));
  const operations = new SftpOperations(fake as unknown as SFTPWrapper);
  const result = await operations.applyPatch(path, createPatch(path, before, after), sha256(before), true);
  assert.equal(fake.files.get(path)?.toString(), after);
  assert.equal(result.sha256, sha256(after));
  assert.equal(fake.files.get(result.backup_path!)?.toString(), before);
});

test('rejects a patch when the expected hash is stale', async () => {
  const fake = new FakeSftp();
  const path = '/etc/example.conf';
  fake.files.set(path, Buffer.from('current\n'));
  const operations = new SftpOperations(fake as unknown as SFTPWrapper);
  await assert.rejects(
    operations.applyPatch(path, createPatch(path, 'old\n', 'new\n'), sha256('old\n'), false),
    /FILE_CHANGED/,
  );
  assert.equal(fake.files.get(path)?.toString(), 'current\n');
});

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}
