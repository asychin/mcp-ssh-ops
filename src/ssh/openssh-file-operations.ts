import { isUtf8 } from 'node:buffer';
import { createHash, randomUUID } from 'node:crypto';
import { constants, createReadStream } from 'node:fs';
import { chmod, copyFile, mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { applyPatch } from 'diff';
import { DEFAULT_TRANSFER_LIMIT_BYTES, MAX_EDIT_FILE_BYTES, MAX_READ_LIMIT_BYTES } from '../config.js';
import { McpOpsError } from '../errors.js';
import { LocalPathPolicy } from '../local-path-policy.js';
import type { ProcessResult } from '../process-runner.js';
import { shellQuote } from './shell.js';

export interface OpenSshChannel {
  execRaw(command: string, timeoutMs: number, maxOutputBytes: number): Promise<ProcessResult>;
  sftp(batch: string, timeoutMs: number, maxOutputBytes: number): Promise<ProcessResult>;
}

export interface RemoteStats {
  path: string;
  type: string;
  size: number;
  mode: string;
  uid: number;
  gid: number;
  atime: number;
  mtime: number;
}

export class OpenSshFileOperations {
  constructor(
    private readonly channel: OpenSshChannel,
    private readonly localPaths = new LocalPathPolicy([process.cwd(), tmpdir()]),
    private readonly maxTransferBytes = DEFAULT_TRANSFER_LIMIT_BYTES,
  ) {}

  async stat(path: string, followSymlinks = false): Promise<RemoteStats> {
    validateRemotePath(path);
    const command = `LC_ALL=C stat ${followSymlinks ? '-L ' : ''}-c '%F\t%s\t%a\t%u\t%g\t%X\t%Y' -- ${shellQuote(path)}`;
    const result = await this.channel.execRaw(command, 30_000, 65_536);
    if (result.exit_code !== 0 || result.timed_out) throw operationError('REMOTE_STAT_FAILED', path, result);
    const fields = result.stdout.toString('utf8').replace(/\r?\n$/, '').split('\t');
    if (fields.length !== 7) throw new McpOpsError('REMOTE_STAT_INVALID', `Unexpected stat output for ${path}. The target must provide GNU stat.`);
    return {
      path,
      type: normalizeFileType(fields[0]!),
      size: parseInteger(fields[1]!, 'size'),
      mode: `0${fields[2]}`,
      uid: parseInteger(fields[3]!, 'uid'),
      gid: parseInteger(fields[4]!, 'gid'),
      atime: parseInteger(fields[5]!, 'atime'),
      mtime: parseInteger(fields[6]!, 'mtime'),
    };
  }

  async listDirectory(path: string, maxEntries: number) {
    const stats = await this.stat(path, true);
    if (stats.type !== 'directory') throw new McpOpsError('NOT_A_DIRECTORY', `${path} is not a directory.`);
    const fieldLimit = (maxEntries + 1) * 7;
    const command = `LC_ALL=C find ${shellQuote(path)} -mindepth 1 -maxdepth 1 -printf '%f\\0%y\\0%s\\0%m\\0%U\\0%G\\0%T@\\0' | head -z -n ${fieldLimit}`;
    const result = await this.channel.execRaw(command, 30_000, 5_242_880);
    if (result.exit_code !== 0 || result.timed_out) throw operationError('REMOTE_LIST_FAILED', path, result);
    const fields = result.stdout.toString('utf8').split('\0');
    if (fields.at(-1) === '') fields.pop();
    const entries = [];
    for (let index = 0; index + 6 < fields.length && entries.length <= maxEntries; index += 7) {
      entries.push({
        name: fields[index]!,
        type: findType(fields[index + 1]!),
        size: parseInteger(fields[index + 2]!, 'size'),
        mode: `0${fields[index + 3]}`,
        uid: parseInteger(fields[index + 4]!, 'uid'),
        gid: parseInteger(fields[index + 5]!, 'gid'),
        mtime: Math.floor(Number(fields[index + 6])),
      });
    }
    const truncated = entries.length > maxEntries;
    if (truncated) entries.pop();
    return { path, entries, truncated };
  }

  async readFile(
    path: string,
    offset: number,
    requestedLength: number | undefined,
    maxBytes: number,
    encoding: 'utf8' | 'base64',
  ) {
    if (maxBytes > MAX_READ_LIMIT_BYTES) throw new McpOpsError('READ_LIMIT_TOO_LARGE', `max_bytes cannot exceed ${MAX_READ_LIMIT_BYTES}.`);
    const stats = await this.stat(path, true);
    if (stats.type !== 'file') throw new McpOpsError('NOT_A_FILE', `${path} is not a regular file.`);
    if (offset > stats.size) throw new McpOpsError('OFFSET_OUT_OF_RANGE', `Offset ${offset} exceeds file size ${stats.size}.`);
    const available = stats.size - offset;
    const length = Math.min(requestedLength ?? available, available, maxBytes);
    const command = length === 0
      ? `printf ''`
      : `dd if=${shellQuote(path)} iflag=skip_bytes,count_bytes skip=${offset} count=${length} status=none`;
    const result = await this.channel.execRaw(command, 30_000, Math.max(length + 1_024, 4_096));
    if (result.exit_code !== 0 || result.timed_out || result.output_truncated) throw operationError('REMOTE_READ_FAILED', path, result);
    const data = result.stdout;
    const complete = offset === 0 && data.length === stats.size;
    return {
      path,
      size: stats.size,
      offset,
      bytes_read: data.length,
      next_offset: offset + data.length < stats.size ? offset + data.length : null,
      truncated: !complete,
      encoding,
      content: encoding === 'base64' ? data.toString('base64') : data.toString('utf8'),
      sha256: complete ? sha256(data) : null,
      range_sha256: sha256(data),
    };
  }

  async uploadFile(
    localPath: string,
    remotePath: string,
    overwrite: boolean,
    preserveMode: boolean,
    expectedLocalSha256?: string,
    expectedDestinationSha256?: string,
  ) {
    validateRemotePath(remotePath);
    const source = await this.localPaths.sourceFile(localPath);
    if (source.stats.size > this.maxTransferBytes) {
      throw new McpOpsError('TRANSFER_TOO_LARGE', `${source.path} is ${source.stats.size} bytes; the transfer limit is ${this.maxTransferBytes} bytes.`);
    }
    const localSha256 = await hashLocalFile(source.path);
    if (expectedLocalSha256 && normalizeHash(expectedLocalSha256) !== localSha256) {
      throw new McpOpsError('LOCAL_FILE_CHANGED', `Expected local SHA-256 ${normalizeHash(expectedLocalSha256)}, but ${source.path} is ${localSha256}.`);
    }

    const destinationExists = await this.remoteExists(remotePath);
    let previousSha256: string | null = null;
    let backupPath: string | null = null;
    if (destinationExists) {
      const destination = await this.stat(remotePath, false);
      if (destination.type !== 'file') throw new McpOpsError('REMOTE_DESTINATION_INVALID', `${remotePath} exists and is not a regular file.`);
      if (!overwrite) throw new McpOpsError('REMOTE_FILE_EXISTS', `${remotePath} already exists. Retry with overwrite=true to create a backup and replace it.`);
      previousSha256 = await this.remoteHash(remotePath);
      if (expectedDestinationSha256 && normalizeHash(expectedDestinationSha256) !== previousSha256) {
        throw new McpOpsError('REMOTE_FILE_CHANGED', `Expected destination SHA-256 ${normalizeHash(expectedDestinationSha256)}, but ${remotePath} is ${previousSha256}.`);
      }
      backupPath = `${remotePath}.mcp-ssh-ops-backup-${randomUUID()}`;
      const backup = await this.channel.execRaw(`cp -p -- ${shellQuote(remotePath)} ${shellQuote(backupPath)}`, transferTimeout(destination.size), 65_536);
      if (backup.exit_code !== 0 || backup.timed_out) throw operationError('REMOTE_BACKUP_FAILED', remotePath, backup);
    } else if (expectedDestinationSha256) {
      throw new McpOpsError('REMOTE_FILE_MISSING', `${remotePath} does not exist, so expected_destination_sha256 cannot be verified.`);
    }

    const temporaryPath = `${remotePath}.mcp-ssh-ops-${randomUUID()}.tmp`;
    const mode = preserveMode ? `0${(source.stats.mode & 0o7777).toString(8)}` : '0644';
    let temporaryCreated = false;
    try {
      await this.put(source.path, temporaryPath, mode, transferTimeout(source.stats.size));
      temporaryCreated = true;
      const uploadedSha256 = await this.remoteHash(temporaryPath);
      if (uploadedSha256 !== localSha256) {
        throw new McpOpsError('UPLOAD_HASH_MISMATCH', `Uploaded temporary file hash ${uploadedSha256} differs from local hash ${localSha256}.`);
      }
      if (destinationExists && previousSha256 !== await this.remoteHash(remotePath)) {
        throw new McpOpsError('REMOTE_FILE_CHANGED', `${remotePath} changed during upload. The replacement was not applied. Backup: ${backupPath}.`);
      }
      if (!destinationExists && await this.remoteExists(remotePath)) {
        throw new McpOpsError('REMOTE_FILE_APPEARED', `${remotePath} was created by another process during upload. The replacement was not applied.`);
      }
      await this.runSftp(`rename ${quoteSftpPath(temporaryPath)} ${quoteSftpPath(remotePath)}\n`, transferTimeout(source.stats.size));
      temporaryCreated = false;
      const finalSha256 = await this.remoteHash(remotePath);
      if (finalSha256 !== localSha256) throw new McpOpsError('UPLOAD_VERIFICATION_FAILED', `Final remote hash ${finalSha256} differs from local hash ${localSha256}.`);
      return {
        local_path: source.path,
        remote_path: remotePath,
        bytes_transferred: source.stats.size,
        sha256: finalSha256,
        overwritten: destinationExists,
        backup_path: backupPath,
        mode,
      };
    } finally {
      if (temporaryCreated) await this.runSftp(`-rm ${quoteSftpPath(temporaryPath)}\n`).catch(() => undefined);
    }
  }

  async downloadFile(
    remotePath: string,
    localPath: string,
    overwrite: boolean,
    preserveMode: boolean,
    expectedRemoteSha256?: string,
  ) {
    validateRemotePath(remotePath);
    const remote = await this.stat(remotePath, false);
    if (remote.type !== 'file') throw new McpOpsError('REMOTE_NOT_A_FILE', `${remotePath} is not a regular file.`);
    if (remote.size > this.maxTransferBytes) {
      throw new McpOpsError('TRANSFER_TOO_LARGE', `${remotePath} is ${remote.size} bytes; the transfer limit is ${this.maxTransferBytes} bytes.`);
    }
    const remoteSha256 = await this.remoteHash(remotePath);
    if (expectedRemoteSha256 && normalizeHash(expectedRemoteSha256) !== remoteSha256) {
      throw new McpOpsError('REMOTE_FILE_CHANGED', `Expected remote SHA-256 ${normalizeHash(expectedRemoteSha256)}, but ${remotePath} is ${remoteSha256}.`);
    }

    const destination = await this.localPaths.destinationFile(localPath);
    if (destination.stats && !overwrite) {
      throw new McpOpsError('LOCAL_FILE_EXISTS', `${destination.path} already exists. Retry with overwrite=true to create a backup and replace it.`);
    }
    const suffix = randomUUID();
    const temporaryPath = `${destination.path}.mcp-ssh-ops-${suffix}.tmp`;
    const backupPath = destination.stats ? `${destination.path}.mcp-ssh-ops-backup-${suffix}` : null;
    let temporaryCreated = false;
    try {
      await this.get(remotePath, temporaryPath, preserveMode, transferTimeout(remote.size));
      temporaryCreated = true;
      const downloadedSha256 = await hashLocalFile(temporaryPath);
      if (downloadedSha256 !== remoteSha256) {
        throw new McpOpsError('DOWNLOAD_HASH_MISMATCH', `Downloaded hash ${downloadedSha256} differs from remote hash ${remoteSha256}.`);
      }
      if (await this.remoteHash(remotePath) !== remoteSha256) {
        throw new McpOpsError('REMOTE_FILE_CHANGED', `${remotePath} changed during download. The local destination was not replaced.`);
      }
      if (preserveMode) await chmod(temporaryPath, Number.parseInt(remote.mode, 8) & 0o7777);
      else await chmod(temporaryPath, 0o644);
      if (destination.stats && backupPath) {
        await copyFile(destination.path, backupPath, constants.COPYFILE_EXCL);
        await chmod(backupPath, destination.stats.mode & 0o7777);
      }
      await rename(temporaryPath, destination.path);
      temporaryCreated = false;
      const finalSha256 = await hashLocalFile(destination.path);
      if (finalSha256 !== remoteSha256) throw new McpOpsError('DOWNLOAD_VERIFICATION_FAILED', `Final local hash ${finalSha256} differs from remote hash ${remoteSha256}.`);
      return {
        remote_path: remotePath,
        local_path: destination.path,
        bytes_transferred: remote.size,
        sha256: finalSha256,
        overwritten: Boolean(destination.stats),
        backup_path: backupPath,
        mode: preserveMode ? remote.mode : '0644',
      };
    } finally {
      if (temporaryCreated) await rm(temporaryPath, { force: true });
    }
  }

  async applyPatch(path: string, patch: string, expectedSha256: string, createBackup: boolean) {
    const stats = await this.stat(path, false);
    if (stats.type !== 'file') throw new McpOpsError('NOT_A_REGULAR_FILE', `${path} must be a regular file and not a symlink.`);
    if (stats.size > MAX_EDIT_FILE_BYTES) throw new McpOpsError('EDIT_FILE_TOO_LARGE', `${path} is ${stats.size} bytes; the edit limit is ${MAX_EDIT_FILE_BYTES} bytes.`);
    const localDirectory = await mkdtemp(join(tmpdir(), 'mcp-ssh-ops-edit-'));
    const originalPath = join(localDirectory, 'original');
    const latestPath = join(localDirectory, 'latest');
    const updatedPath = join(localDirectory, 'updated');
    const verifiedPath = join(localDirectory, 'verified');
    const suffix = randomUUID();
    const temporaryPath = `${path}.mcp-ssh-ops-${suffix}.tmp`;
    const backupPath = createBackup ? `${path}.mcp-ssh-ops-backup-${suffix}` : null;
    let temporaryCreated = false;
    try {
      await this.get(path, originalPath);
      const current = await readFile(originalPath);
      if (current.length > MAX_EDIT_FILE_BYTES) throw new McpOpsError('EDIT_FILE_TOO_LARGE', `${path} grew beyond the edit limit.`);
      if (!isUtf8(current) || current.includes(0)) throw new McpOpsError('BINARY_FILE_UNSUPPORTED', 'ssh_apply_patch accepts UTF-8 text files without NUL bytes only.');
      const currentHash = sha256(current);
      if (normalizeHash(expectedSha256) !== currentHash) {
        throw new McpOpsError('FILE_CHANGED', `Expected SHA-256 ${normalizeHash(expectedSha256)}, but the current file hash is ${currentHash}. Read the file again and regenerate the patch.`);
      }
      const updatedText = applyPatch(current.toString('utf8'), patch, { fuzzFactor: 0 });
      if (updatedText === false) throw new McpOpsError('PATCH_REJECTED', 'The unified diff does not apply cleanly to the current file.');
      const updated = Buffer.from(updatedText, 'utf8');
      if (updated.length > MAX_EDIT_FILE_BYTES) throw new McpOpsError('EDIT_RESULT_TOO_LARGE', `The patched file would exceed ${MAX_EDIT_FILE_BYTES} bytes.`);
      await writeFile(updatedPath, updated, { mode: Number.parseInt(stats.mode, 8) & 0o7777 });
      await chmod(updatedPath, Number.parseInt(stats.mode, 8) & 0o7777);
      await this.put(updatedPath, temporaryPath, stats.mode);
      temporaryCreated = true;
      await this.get(path, latestPath);
      if (sha256(await readFile(latestPath)) !== currentHash) throw new McpOpsError('FILE_CHANGED', 'The file changed while the patch was being prepared. Read it again and retry.');
      if (backupPath) await this.put(originalPath, backupPath, stats.mode);
      await this.runSftp(`rename ${quoteSftpPath(temporaryPath)} ${quoteSftpPath(path)}\n`);
      temporaryCreated = false;
      await this.get(path, verifiedPath);
      const finalHash = sha256(await readFile(verifiedPath));
      const expectedFinalHash = sha256(updated);
      if (finalHash !== expectedFinalHash) {
        throw new McpOpsError('EDIT_VERIFICATION_FAILED', `The remote file hash ${finalHash} differs from ${expectedFinalHash}. Backup: ${backupPath ?? 'disabled'}.`);
      }
      return {
        path,
        previous_sha256: currentHash,
        sha256: finalHash,
        bytes_written: updated.length,
        backup_path: backupPath,
      };
    } finally {
      if (temporaryCreated) await this.runSftp(`-rm ${quoteSftpPath(temporaryPath)}\n`).catch(() => undefined);
      await rm(localDirectory, { recursive: true, force: true });
    }
  }

  private async get(remotePath: string, localPath: string, preserveMode = true, timeoutMs = 60_000): Promise<void> {
    await this.runSftp(`get ${preserveMode ? '-p ' : ''}${quoteSftpPath(remotePath)} ${quoteSftpPath(localPath)}\n`, timeoutMs);
  }

  private async put(localPath: string, remotePath: string, mode: string, timeoutMs = 60_000): Promise<void> {
    await this.runSftp(`put ${quoteSftpPath(localPath)} ${quoteSftpPath(remotePath)}\nchmod ${mode} ${quoteSftpPath(remotePath)}\n`, timeoutMs);
  }

  private async remoteExists(path: string): Promise<boolean> {
    const result = await this.channel.execRaw(`if [ -e ${shellQuote(path)} ] || [ -L ${shellQuote(path)} ]; then printf 1; else printf 0; fi`, 30_000, 4_096);
    if (result.exit_code !== 0 || result.timed_out) throw operationError('REMOTE_EXISTS_FAILED', path, result);
    return result.stdout.toString('utf8') === '1';
  }

  private async remoteHash(path: string): Promise<string> {
    const result = await this.channel.execRaw(`sha256sum -- ${shellQuote(path)}`, 60_000, 65_536);
    if (result.exit_code !== 0 || result.timed_out) throw operationError('REMOTE_HASH_FAILED', path, result);
    const hash = result.stdout.toString('utf8').match(/^[a-fA-F0-9]{64}/)?.[0];
    if (!hash) throw new McpOpsError('REMOTE_HASH_INVALID', `Unexpected sha256sum output for ${path}.`);
    return hash.toLowerCase();
  }

  private async runSftp(batch: string, timeoutMs = 60_000): Promise<ProcessResult> {
    const result = await this.channel.sftp(batch, timeoutMs, 1_048_576);
    if (result.exit_code !== 0 || result.timed_out) throw operationError('SFTP_OPERATION_FAILED', 'remote path', result);
    return result;
  }
}

export function quoteSftpPath(path: string): string {
  validateRemotePath(path);
  return `"${path.replace(/([\\"*?\[\]])/g, '\\$1')}"`;
}

function validateRemotePath(path: string): void {
  if (!path || /[\r\n\0]/.test(path)) throw new McpOpsError('REMOTE_PATH_INVALID', 'Remote paths cannot be empty or contain NUL/newline characters.');
}

function operationError(code: string, target: string, result: ProcessResult): McpOpsError {
  const details = result.stderr.toString('utf8').trim() || `exit ${result.exit_code}`;
  return new McpOpsError(code, `${target}: ${result.timed_out ? 'operation timed out' : details}`);
}

function normalizeFileType(value: string): string {
  if (value === 'regular file' || value === 'regular empty file') return 'file';
  if (value === 'directory') return 'directory';
  if (value === 'symbolic link') return 'symlink';
  return 'other';
}

function findType(value: string): string {
  if (value === 'f') return 'file';
  if (value === 'd') return 'directory';
  if (value === 'l') return 'symlink';
  return 'other';
}

function parseInteger(value: string, field: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new McpOpsError('REMOTE_METADATA_INVALID', `Invalid ${field}: ${value}`);
  return parsed;
}

async function hashLocalFile(path: string): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest('hex');
}

function transferTimeout(size: number): number {
  return Math.min(600_000, Math.max(60_000, 30_000 + Math.ceil(size / 262_144) * 1_000));
}

function sha256(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

function normalizeHash(hash: string): string {
  return hash.replace(/^sha256:/i, '').toLowerCase();
}
