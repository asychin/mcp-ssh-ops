import { isUtf8 } from 'node:buffer';
import { createHash, randomUUID } from 'node:crypto';
import { applyPatch } from 'diff';
import type { SFTPWrapper, Stats } from 'ssh2';
import { MAX_EDIT_FILE_BYTES, MAX_READ_LIMIT_BYTES } from '../config.js';
import { McpOpsError, errorMessage } from '../errors.js';
import {
  fileType,
  sftpClose,
  sftpOpen,
  sftpOpenDirectory,
  sftpRead,
  sftpReadDirectoryChunk,
  sftpReadFile,
  sftpRename,
  sftpStat,
  sftpUnlink,
  sftpWriteFile,
} from './callbacks.js';

export class SftpOperations {
  constructor(private readonly sftp: SFTPWrapper) {}

  async stat(path: string, followSymlinks = true) {
    const stats = await sftpStat(this.sftp, path, !followSymlinks);
    return serializeStats(path, stats);
  }

  async listDirectory(path: string, maxEntries: number) {
    const handle = await sftpOpenDirectory(this.sftp, path);
    const entries: ReturnType<typeof serializeDirectoryEntry>[] = [];
    let truncated = false;
    try {
      while (entries.length <= maxEntries) {
        let chunk;
        try {
          chunk = await sftpReadDirectoryChunk(this.sftp, handle);
        } catch (error) {
          if ((error as { code?: number }).code === 1) break;
          throw error;
        }
        for (const entry of chunk) {
          if (entry.filename === '.' || entry.filename === '..') continue;
          entries.push(serializeDirectoryEntry(entry));
          if (entries.length > maxEntries) {
            entries.pop();
            truncated = true;
            break;
          }
        }
        if (truncated) break;
      }
    } finally {
      await sftpClose(this.sftp, handle);
    }
    return { path, entries, truncated };
  }

  async readFile(
    path: string,
    offset: number,
    requestedLength: number | undefined,
    maxBytes: number,
    encoding: 'utf8' | 'base64',
  ) {
    if (maxBytes > MAX_READ_LIMIT_BYTES) {
      throw new McpOpsError('READ_LIMIT_TOO_LARGE', `max_bytes cannot exceed ${MAX_READ_LIMIT_BYTES}.`);
    }
    const stats = await sftpStat(this.sftp, path);
    if (!stats.isFile()) throw new McpOpsError('NOT_A_FILE', `${path} is not a regular file.`);
    if (offset > stats.size) throw new McpOpsError('OFFSET_OUT_OF_RANGE', `Offset ${offset} exceeds file size ${stats.size}.`);
    const available = stats.size - offset;
    const length = Math.min(requestedLength ?? available, available, maxBytes);
    const data = await this.readRange(path, offset, length);
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

  async applyPatch(path: string, patch: string, expectedSha256: string, createBackup: boolean) {
    const stats = await sftpStat(this.sftp, path, true);
    if (stats.isSymbolicLink() || !stats.isFile()) throw new McpOpsError('NOT_A_REGULAR_FILE', `${path} must be a regular file and not a symlink.`);
    if (stats.size > MAX_EDIT_FILE_BYTES) {
      throw new McpOpsError('EDIT_FILE_TOO_LARGE', `${path} is ${stats.size} bytes; the edit limit is ${MAX_EDIT_FILE_BYTES} bytes.`);
    }
    const current = await sftpReadFile(this.sftp, path);
    if (current.length > MAX_EDIT_FILE_BYTES) {
      throw new McpOpsError('EDIT_FILE_TOO_LARGE', `${path} grew beyond the ${MAX_EDIT_FILE_BYTES}-byte edit limit.`);
    }
    if (!isUtf8(current) || current.includes(0)) {
      throw new McpOpsError('BINARY_FILE_UNSUPPORTED', 'ssh_apply_patch accepts UTF-8 text files without NUL bytes only.');
    }
    const currentHash = sha256(current);
    if (normalizeHash(expectedSha256) !== currentHash) {
      throw new McpOpsError('FILE_CHANGED', `Expected SHA-256 ${normalizeHash(expectedSha256)}, but the current file hash is ${currentHash}. Read the file again and regenerate the patch.`);
    }
    const updatedText = applyPatch(current.toString('utf8'), patch, { fuzzFactor: 0 });
    if (updatedText === false) {
      throw new McpOpsError('PATCH_REJECTED', 'The unified diff does not apply cleanly to the current file.');
    }
    const updated = Buffer.from(updatedText, 'utf8');
    if (updated.length > MAX_EDIT_FILE_BYTES) {
      throw new McpOpsError('EDIT_RESULT_TOO_LARGE', `The patched file would exceed ${MAX_EDIT_FILE_BYTES} bytes.`);
    }

    const mode = stats.mode & 0o7777;
    const suffix = randomUUID();
    const temporaryPath = `${path}.mcp-ssh-ops-${suffix}.tmp`;
    const backupPath = createBackup ? `${path}.mcp-ssh-ops-backup-${suffix}` : null;
    let temporaryCreated = false;
    try {
      await sftpWriteFile(this.sftp, temporaryPath, updated, { mode, flag: 'wx' });
      temporaryCreated = true;
      const latest = await sftpReadFile(this.sftp, path);
      if (sha256(latest) !== currentHash) {
        throw new McpOpsError('FILE_CHANGED', 'The file changed while the patch was being prepared. Read it again and retry.');
      }
      if (backupPath) await sftpWriteFile(this.sftp, backupPath, current, { mode, flag: 'wx' });
      try {
        await sftpRename(this.sftp, temporaryPath, path, true);
      } catch (posixError) {
        try {
          await sftpRename(this.sftp, temporaryPath, path);
        } catch (renameError) {
          throw new McpOpsError('ATOMIC_RENAME_FAILED', `The server does not support replacing the file atomically. POSIX rename: ${errorMessage(posixError)}; regular rename: ${errorMessage(renameError)}`);
        }
      }
      temporaryCreated = false;
      const finalContent = await sftpReadFile(this.sftp, path);
      const finalHash = sha256(finalContent);
      const expectedFinalHash = sha256(updated);
      if (finalHash !== expectedFinalHash) {
        throw new McpOpsError('EDIT_VERIFICATION_FAILED', `The remote file hash ${finalHash} differs from the expected hash ${expectedFinalHash}. Backup: ${backupPath ?? 'disabled'}.`);
      }
      return {
        path,
        previous_sha256: currentHash,
        sha256: finalHash,
        bytes_written: updated.length,
        backup_path: backupPath,
      };
    } finally {
      if (temporaryCreated) await ignoreError(() => sftpUnlink(this.sftp, temporaryPath));
    }
  }

  private async readRange(path: string, position: number, length: number): Promise<Buffer> {
    if (length === 0) return Buffer.alloc(0);
    const handle = await sftpOpen(this.sftp, path, 'r');
    const output = Buffer.alloc(length);
    let offset = 0;
    try {
      while (offset < length) {
        const bytesRead = await sftpRead(this.sftp, handle, output, offset, length - offset, position + offset);
        if (bytesRead === 0) break;
        offset += bytesRead;
      }
    } finally {
      await sftpClose(this.sftp, handle);
    }
    return output.subarray(0, offset);
  }
}

function serializeStats(path: string, stats: Stats) {
  return {
    path,
    type: fileType(stats),
    size: stats.size,
    mode: `0${(stats.mode & 0o7777).toString(8)}`,
    uid: stats.uid,
    gid: stats.gid,
    atime: stats.atime,
    mtime: stats.mtime,
  };
}

function serializeDirectoryEntry(entry: { filename: string; longname: string; attrs: Stats }) {
  return {
    name: entry.filename,
    longname: entry.longname,
    type: fileType(entry.attrs),
    size: entry.attrs.size,
    mode: `0${(entry.attrs.mode & 0o7777).toString(8)}`,
    uid: entry.attrs.uid,
    gid: entry.attrs.gid,
    mtime: entry.attrs.mtime,
  };
}

function sha256(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

function normalizeHash(hash: string): string {
  return hash.replace(/^sha256:/i, '').toLowerCase();
}

async function ignoreError(operation: () => Promise<void>): Promise<void> {
  try {
    await operation();
  } catch {
    return;
  }
}
