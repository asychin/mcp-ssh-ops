import { createHash } from 'node:crypto';
import { McpOpsError } from '../errors.js';

export function sshKeyType(key: Buffer): string {
  if (key.length < 4) throw new McpOpsError('HOST_KEY_INVALID', 'The server supplied an invalid SSH host key.');
  const length = key.readUInt32BE(0);
  if (length < 1 || length > key.length - 4 || length > 255) {
    throw new McpOpsError('HOST_KEY_INVALID', 'The server supplied an invalid SSH host key.');
  }
  return key.subarray(4, 4 + length).toString('ascii');
}

export function sshFingerprint(key: Buffer): string {
  return `SHA256:${createHash('sha256').update(key).digest('base64').replace(/=+$/, '')}`;
}
