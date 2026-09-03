import { appendFile, chmod, mkdir, readFile } from 'node:fs/promises';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { dirname } from 'node:path';
import { McpOpsError, errorMessage } from '../errors.js';
import { sshFingerprint, sshKeyType } from './fingerprint.js';

interface KnownHostEntry {
  marker?: string;
  patterns: string[];
  keyType: string;
  key: Buffer;
  source: string;
}

export interface HostKeyVerification {
  status: 'trusted' | 'unknown' | 'changed' | 'revoked';
  fingerprint: string;
  key_type: string;
  sources: string[];
}

interface PendingHostKey {
  host: string;
  port: number;
  key: Buffer;
  fingerprint: string;
}

export class HostKeyStore {
  private entries: KnownHostEntry[] = [];
  private readonly pending = new Map<string, PendingHostKey>();
  private readonly knownHostsFiles: string[];

  constructor(
    private readonly trustedHostsFile: string,
    knownHostsFiles: string[],
  ) {
    this.knownHostsFiles = [...new Set(knownHostsFiles)];
  }

  async refresh(): Promise<void> {
    const loaded = await Promise.all(this.knownHostsFiles.map((file) => this.readFile(file)));
    this.entries = loaded.flat();
  }

  verify(host: string, port: number, key: Buffer): HostKeyVerification {
    const canonical = canonicalHost(host, port);
    const fingerprint = sshFingerprint(key);
    const keyType = sshKeyType(key);
    const hostEntries = this.entries.filter((entry) => entryMatchesHost(entry, canonical));
    const revoked = hostEntries.find((entry) => entry.marker === '@revoked' && entry.key.equals(key));
    if (revoked) {
      return { status: 'revoked', fingerprint, key_type: keyType, sources: [revoked.source] };
    }
    const usableEntries = hostEntries.filter((entry) => !entry.marker);
    const exact = usableEntries.find((entry) => entry.keyType === keyType && entry.key.equals(key));
    if (exact) {
      return { status: 'trusted', fingerprint, key_type: keyType, sources: [exact.source] };
    }
    const sameType = usableEntries.filter((entry) => entry.keyType === keyType);
    if (sameType.length > 0) {
      return {
        status: 'changed',
        fingerprint,
        key_type: keyType,
        sources: [...new Set(sameType.map((entry) => entry.source))],
      };
    }
    return { status: 'unknown', fingerprint, key_type: keyType, sources: [] };
  }

  rememberUnknown(host: string, port: number, key: Buffer): HostKeyVerification {
    const verification = this.verify(host, port, key);
    if (verification.status === 'unknown') {
      const pending = { host, port, key: Buffer.from(key), fingerprint: verification.fingerprint };
      this.pending.set(pendingKey(host, port, verification.fingerprint), pending);
    }
    return verification;
  }

  async trustPending(host: string, port: number, fingerprint: string): Promise<HostKeyVerification> {
    const pending = this.pending.get(pendingKey(host, port, fingerprint));
    if (!pending) {
      throw new McpOpsError('HOST_KEY_NOT_PENDING', 'No matching pending host key exists. Call ssh_create_session first and copy the exact fingerprint it returns.');
    }
    await this.refresh();
    const current = this.verify(host, port, pending.key);
    if (current.status === 'trusted') {
      this.pending.delete(pendingKey(host, port, fingerprint));
      return current;
    }
    if (current.status !== 'unknown') {
      throw new McpOpsError('HOST_KEY_CONFLICT', `Cannot trust the key because its current status is ${current.status}. Inspect the known_hosts files manually.`);
    }

    const line = `${canonicalHost(host, port)} ${current.key_type} ${pending.key.toString('base64')}\n`;
    await mkdir(dirname(this.trustedHostsFile), { recursive: true, mode: 0o700 });
    try {
      let prefix = '';
      try {
        const existing = await readFile(this.trustedHostsFile);
        if (existing.length > 0 && existing[existing.length - 1] !== 0x0a) prefix = '\n';
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
      await appendFile(this.trustedHostsFile, `${prefix}${line}`, { mode: 0o600 });
      await chmod(this.trustedHostsFile, 0o600);
    } catch (error) {
      throw new McpOpsError('HOST_KEY_SAVE_FAILED', `Cannot update ${this.trustedHostsFile}: ${errorMessage(error)}`);
    }
    this.pending.delete(pendingKey(host, port, fingerprint));
    await this.refresh();
    return this.verify(host, port, pending.key);
  }

  private async readFile(file: string): Promise<KnownHostEntry[]> {
    let content: string;
    try {
      content = await readFile(file, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw new McpOpsError('KNOWN_HOSTS_READ_FAILED', `Cannot read ${file}: ${errorMessage(error)}`);
    }
    return content.split(/\r?\n/).flatMap((line) => parseKnownHostLine(line, file));
  }
}

export function canonicalHost(host: string, port: number): string {
  return port === 22 ? host : `[${host}]:${port}`;
}

function pendingKey(host: string, port: number, fingerprint: string): string {
  return `${canonicalHost(host, port)}\0${fingerprint}`;
}

function parseKnownHostLine(line: string, source: string): KnownHostEntry[] {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('#')) return [];
  const fields = trimmed.split(/\s+/);
  let marker: string | undefined;
  if (fields[0]?.startsWith('@')) marker = fields.shift();
  const hosts = fields[0];
  const keyType = fields[1];
  const encodedKey = fields[2];
  if (!hosts || !keyType || !encodedKey) return [];
  let key: Buffer;
  try {
    key = Buffer.from(encodedKey, 'base64');
    if (key.length === 0) return [];
  } catch {
    return [];
  }
  return [{ marker, patterns: hosts.split(','), keyType, key, source }];
}

function entryMatchesHost(entry: KnownHostEntry, host: string): boolean {
  let matched = false;
  for (const rawPattern of entry.patterns) {
    const negative = rawPattern.startsWith('!');
    const pattern = negative ? rawPattern.slice(1) : rawPattern;
    if (!hostPatternMatches(pattern, host)) continue;
    if (negative) return false;
    matched = true;
  }
  return matched;
}

function hostPatternMatches(pattern: string, host: string): boolean {
  if (pattern.startsWith('|1|')) {
    const fields = pattern.split('|');
    if (fields.length !== 4 || !fields[2] || !fields[3]) return false;
    const salt = Buffer.from(fields[2], 'base64');
    const expected = Buffer.from(fields[3], 'base64');
    const actual = createHmac('sha1', salt).update(host).digest();
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  }
  const expression = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replaceAll('*', '.*')
    .replaceAll('?', '.');
  return new RegExp(`^${expression}$`, 'i').test(host);
}
