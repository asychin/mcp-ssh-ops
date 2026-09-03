import type { Attributes, FileEntryWithStats, SFTPWrapper, Stats } from 'ssh2';

export function sftpStat(sftp: SFTPWrapper, path: string, lstat = false): Promise<Stats> {
  return new Promise((resolve, reject) => {
    const callback = (error: Error | undefined, stats: Stats) => error ? reject(error) : resolve(stats);
    if (lstat) sftp.lstat(path, callback);
    else sftp.stat(path, callback);
  });
}

export function sftpReadFile(sftp: SFTPWrapper, path: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    sftp.readFile(path, (error, data) => error ? reject(error) : resolve(data));
  });
}

export function sftpWriteFile(sftp: SFTPWrapper, path: string, data: Buffer, options: { mode: number; flag: string }): Promise<void> {
  return new Promise((resolve, reject) => {
    sftp.writeFile(path, data, options, (error) => error ? reject(error) : resolve());
  });
}

export function sftpRename(sftp: SFTPWrapper, source: string, destination: string, posix = false): Promise<void> {
  return new Promise((resolve, reject) => {
    const callback = (error?: Error | null) => error ? reject(error) : resolve();
    if (posix) sftp.ext_openssh_rename(source, destination, callback);
    else sftp.rename(source, destination, callback);
  });
}

export function sftpUnlink(sftp: SFTPWrapper, path: string): Promise<void> {
  return new Promise((resolve, reject) => {
    sftp.unlink(path, (error) => error ? reject(error) : resolve());
  });
}

export function sftpOpen(sftp: SFTPWrapper, path: string, mode: 'r'): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    sftp.open(path, mode, (error, handle) => error ? reject(error) : resolve(handle));
  });
}

export function sftpClose(sftp: SFTPWrapper, handle: Buffer): Promise<void> {
  return new Promise((resolve, reject) => {
    sftp.close(handle, (error) => error ? reject(error) : resolve());
  });
}

export function sftpRead(sftp: SFTPWrapper, handle: Buffer, buffer: Buffer, offset: number, length: number, position: number): Promise<number> {
  return new Promise((resolve, reject) => {
    sftp.read(handle, buffer, offset, length, position, (error, bytesRead) => error ? reject(error) : resolve(bytesRead));
  });
}

export function sftpOpenDirectory(sftp: SFTPWrapper, path: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    sftp.opendir(path, (error, handle) => error ? reject(error) : resolve(handle));
  });
}

export function sftpReadDirectoryChunk(sftp: SFTPWrapper, handle: Buffer): Promise<FileEntryWithStats[]> {
  return new Promise((resolve, reject) => {
    sftp.readdir(handle, (error, list) => error ? reject(error) : resolve(list));
  });
}

export function fileType(stats: Stats | Attributes): string {
  if ('isFile' in stats && stats.isFile()) return 'file';
  if ('isDirectory' in stats && stats.isDirectory()) return 'directory';
  if ('isSymbolicLink' in stats && stats.isSymbolicLink()) return 'symlink';
  return 'other';
}
