import { createReadStream, createWriteStream } from 'node:fs';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import ssh2 from 'ssh2';
import type { ClientChannel, SFTPWrapper } from 'ssh2';
import { McpOpsError } from '../errors.js';
import type { ProcessResult } from '../process-runner.js';
import type { FileChannel } from './openssh-file-operations.js';
import { sftpRename, sftpUnlink } from './callbacks.js';

export class Ssh2Transport implements FileChannel {
  connected = false;
  private closed = false;
  readonly client = new ssh2.Client();

  get isClosed(): boolean { return this.closed; }

  constructor(private readonly maxTransferBytes: number, private readonly release: () => void, private readonly parent?: Ssh2Transport) {
    this.client.once('close', () => this.close());
    this.client.on('error', () => undefined);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.connected = false;
    this.client.destroy();
    this.release();
    this.parent?.close();
  }

  execRaw(command: string, timeoutMs: number, maxOutputBytes: number): Promise<ProcessResult> {
    this.assertConnected();
    return new Promise((resolve, reject) => {
      const started = Date.now();
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let channel: ClientChannel | undefined;
      let bytes = 0;
      let truncated = false;
      let settled = false;
      let exitCode: number | null = null;
      let signal: NodeJS.Signals | null = null;
      const finish = (error?: Error, timedOut = false) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) reject(error);
        else resolve({ exit_code: exitCode, signal, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr),
          timed_out: timedOut, output_truncated: truncated, duration_ms: Date.now() - started });
      };
      const timer = setTimeout(() => {
        finish(undefined, true);
        channel?.signal('TERM');
        channel?.close();
        channel?.destroy();
      }, timeoutMs);
      const append = (target: Buffer[], data: Buffer) => {
        if (settled) return;
        const remaining = Math.max(0, maxOutputBytes - bytes);
        const accepted = data.subarray(0, remaining);
        if (accepted.length) target.push(Buffer.from(accepted));
        bytes += accepted.length;
        if (accepted.length < data.length) truncated = true;
      };
      this.client.exec(command, { pty: false }, (error, stream) => {
        if (error) return finish(error);
        if (settled) { stream.close(); stream.destroy(); return; }
        channel = stream;
        stream.on('data', (data: Buffer) => append(stdout, data));
        stream.stderr.on('data', (data: Buffer) => append(stderr, data));
        stream.once('exit', (code: number | null, name?: string) => { exitCode = code; signal = name ? name as NodeJS.Signals : null; });
        stream.once('error', finish);
        stream.once('close', () => finish());
        stream.end();
      });
    });
  }

  async getFile(remotePath: string, localPath: string, _preserveMode: boolean, timeoutMs: number): Promise<void> {
    await this.withSftp(timeoutMs, (sftp, signal) => pipeline(
      sftp.createReadStream(remotePath), this.transferLimit(), createWriteStream(localPath, { flags: 'wx', mode: 0o600 }),
      { signal },
    ));
  }

  async putFile(localPath: string, remotePath: string, mode: string, timeoutMs: number): Promise<void> {
    await this.withSftp(timeoutMs, async (sftp, signal) => {
      await pipeline(createReadStream(localPath), this.transferLimit(), sftp.createWriteStream(remotePath, { flags: 'wx', mode: parseInt(mode, 8) }), { signal });
      await new Promise<void>((resolve, reject) => sftp.chmod(remotePath, parseInt(mode, 8), (error) => error ? reject(error) : resolve()));
    });
  }

  async renameFile(source: string, destination: string, timeoutMs: number): Promise<void> {
    await this.withSftp(timeoutMs, async (sftp) => {
      try { await sftpRename(sftp, source, destination, true); }
      catch (error) {
        if ((error as { code?: number }).code !== 8 && (error as Error).message !== 'Server does not support this extended request') throw error;
        await sftpRename(sftp, source, destination);
      }
    });
  }

  async removeFile(path: string): Promise<void> {
    await this.withSftp(30_000, (sftp) => sftpUnlink(sftp, path));
  }

  private assertConnected(): void {
    if (!this.connected) throw new McpOpsError('SESSION_DISCONNECTED', 'The SSH transport has disconnected. Create a new session.');
  }

  private transferLimit(): Transform {
    let bytes = 0;
    const maximum = this.maxTransferBytes;
    return new Transform({ transform(chunk: Buffer, _encoding, callback) {
      bytes += chunk.length;
      callback(bytes > maximum ? new McpOpsError('TRANSFER_TOO_LARGE', `Transfer exceeded ${maximum} bytes.`) : null, chunk);
    } });
  }

  private withSftp<T>(timeoutMs: number, operation: (sftp: SFTPWrapper, signal: AbortSignal) => Promise<T>): Promise<T> {
    this.assertConnected();
    return new Promise((resolve, reject) => {
      let settled = false;
      const controller = new AbortController();
      let channel: SFTPWrapper | undefined;
      const finish = (error?: unknown, value?: T) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) { controller.abort(); channel?.destroy(); }
        else channel?.end();
        if (error) reject(error);
        else resolve(value as T);
      };
      const timer = setTimeout(() => finish(new McpOpsError('SFTP_TIMEOUT', 'The SFTP operation timed out.')), timeoutMs);
      this.client.sftp((error, sftp) => {
        if (error) return finish(error);
        if (settled) { sftp.destroy(); return; }
        channel = sftp;
        sftp.once('error', finish);
        sftp.once('close', () => finish(new McpOpsError('SFTP_DISCONNECTED', 'The SFTP channel closed before completion.')));
        operation(sftp, controller.signal).then((value) => finish(undefined, value), finish);
      });
    });
  }
}
