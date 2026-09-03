import { randomUUID } from 'node:crypto';
import { chmod, mkdir, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import type { Server, Socket } from 'node:net';
import { dirname } from 'node:path';
import { ASKPASS_TIMEOUT_MS } from '../config.js';
import { McpOpsError, errorMessage } from '../errors.js';
import { promptSecret } from '../password-prompt.js';

interface AskpassContext {
  id: string;
  credentialGroup: string;
  fallbackHost: string;
  fallbackPort: number;
}

export interface PendingHostKey {
  host: string;
  port: number;
  fingerprint: string;
  key_type: string;
}

interface AskpassRequest {
  context_id: string;
  prompt: string;
}

export class AskpassBroker {
  private server?: Server;
  private readonly contexts = new Map<string, AskpassContext>();
  private readonly pending = new Map<string, PendingHostKey>();
  private readonly pendingByContext = new Map<string, PendingHostKey>();
  private readonly errorsByContext = new Map<string, unknown>();
  private readonly approved = new Set<string>();
  private readonly secrets = new Map<string, Map<string, string>>();
  private readonly credentialReferences = new Map<string, number>();

  constructor(
    readonly socketPath: string,
    private readonly secretPrompt: typeof promptSecret = promptSecret,
  ) {}

  async start(): Promise<void> {
    if (this.server) return;
    await mkdir(dirname(this.socketPath), { recursive: true, mode: 0o700 });
    await rm(this.socketPath, { force: true });
    const server = createServer((socket) => this.handleSocket(socket));
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(this.socketPath, resolve);
    });
    await chmod(this.socketPath, 0o600);
    this.server = server;
  }

  async close(): Promise<void> {
    const server = this.server;
    this.server = undefined;
    if (server) await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(this.socketPath, { force: true });
    this.contexts.clear();
    this.pending.clear();
    this.pendingByContext.clear();
    this.errorsByContext.clear();
    this.approved.clear();
    this.clearSecrets();
  }

  createContext(credentialGroup: string, fallbackHost: string, fallbackPort: number): string {
    const id = randomUUID();
    this.contexts.set(id, { id, credentialGroup, fallbackHost, fallbackPort });
    return id;
  }

  releaseContext(id: string): void {
    this.contexts.delete(id);
  }

  takePendingForContext(id: string): PendingHostKey | undefined {
    const pending = this.pendingByContext.get(id);
    this.pendingByContext.delete(id);
    return pending;
  }

  takeErrorForContext(id: string): unknown {
    const error = this.errorsByContext.get(id);
    this.errorsByContext.delete(id);
    return error;
  }

  hasCredentialReferences(group: string): boolean {
    return (this.credentialReferences.get(group) ?? 0) > 0;
  }

  retainCredential(group: string): void {
    this.credentialReferences.set(group, (this.credentialReferences.get(group) ?? 0) + 1);
  }

  invalidateCredential(group: string): void {
    clearSecretMap(this.secrets.get(group));
    this.secrets.delete(group);
  }

  releaseCredential(group: string): void {
    const remaining = (this.credentialReferences.get(group) ?? 1) - 1;
    if (remaining > 0) {
      this.credentialReferences.set(group, remaining);
      return;
    }
    this.credentialReferences.delete(group);
    this.invalidateCredential(group);
  }

  trustPending(host: string, port: number, fingerprint: string) {
    const key = hostKeyId(host, port, fingerprint);
    const pending = this.pending.get(key);
    if (!pending) {
      throw new McpOpsError('HOST_KEY_NOT_PENDING', 'No matching OpenSSH host-key prompt is pending. Call ssh_create_session first and use the exact host, port, and fingerprint it returns.');
    }
    this.approved.add(key);
    return { status: 'approved', ...pending };
  }

  private handleSocket(socket: Socket): void {
    socket.setEncoding('utf8');
    socket.setTimeout(ASKPASS_TIMEOUT_MS + 5_000, () => socket.destroy());
    let content = '';
    let handled = false;
    socket.on('data', (chunk: string) => {
      if (handled) return;
      content += chunk;
      if (content.length > 65_536) {
        handled = true;
        socket.end(JSON.stringify({ ok: false }));
        return;
      }
      const newline = content.indexOf('\n');
      if (newline < 0) return;
      handled = true;
      void this.respond(socket, content.slice(0, newline));
    });
    socket.once('error', () => undefined);
  }

  private async respond(socket: Socket, rawRequest: string): Promise<void> {
    let contextId: string | undefined;
    try {
      const request = JSON.parse(rawRequest) as AskpassRequest;
      if (typeof request.context_id !== 'string' || typeof request.prompt !== 'string') throw new Error('Invalid request');
      contextId = request.context_id;
      const context = this.contexts.get(contextId);
      if (!context) throw new Error('Expired askpass context');
      const value = await this.answerPrompt(context, request.prompt);
      socket.end(`${JSON.stringify({ ok: true, value })}\n`);
    } catch (error) {
      if (contextId) this.errorsByContext.set(contextId, error);
      socket.end(`${JSON.stringify({ ok: false, error: errorMessage(error) })}\n`);
    }
  }

  private async answerPrompt(context: AskpassContext, prompt: string): Promise<string> {
    const hostKey = parseHostKeyPrompt(prompt, context);
    if (hostKey) {
      const key = hostKeyId(hostKey.host, hostKey.port, hostKey.fingerprint);
      if (this.approved.delete(key)) {
        this.pending.delete(key);
        return 'yes';
      }
      this.pending.set(key, hostKey);
      this.pendingByContext.set(context.id, hostKey);
      return 'no';
    }

    const cacheable = /password|passphrase/i.test(prompt);
    const promptKey = /password/i.test(prompt) && !/passphrase/i.test(prompt)
      ? passwordPromptKey(prompt)
      : normalizeSecretPrompt(prompt);
    const groupSecrets = this.secrets.get(context.credentialGroup) ?? new Map<string, string>();
    this.secrets.set(context.credentialGroup, groupSecrets);
    if (cacheable) {
      const cached = groupSecrets.get(promptKey);
      if (cached !== undefined) return cached;
    }
    const secret = await this.secretPrompt('MCP Ops OpenSSH authentication', prompt);
    if (cacheable) groupSecrets.set(promptKey, secret);
    return secret;
  }

  private clearSecrets(): void {
    for (const groupSecrets of this.secrets.values()) clearSecretMap(groupSecrets);
    this.secrets.clear();
    this.credentialReferences.clear();
  }
}

function parseHostKeyPrompt(prompt: string, context: AskpassContext): PendingHostKey | null {
  const fingerprint = prompt.match(/SHA256:[A-Za-z0-9+/]+/)?.[0];
  if (!fingerprint || !/authenticity of host/i.test(prompt)) return null;
  const endpoint = prompt.match(/authenticity of host ['"]([^'"]+)['"]/i)?.[1];
  const parsed = endpoint ? parseEndpoint(endpoint) : null;
  const keyType = prompt.match(/\b([A-Z0-9][A-Z0-9-]+) key fingerprint/i)?.[1]?.toLowerCase() ?? 'unknown';
  return {
    host: parsed?.host ?? context.fallbackHost,
    port: parsed?.port ?? context.fallbackPort,
    fingerprint,
    key_type: keyType,
  };
}

function parseEndpoint(endpoint: string): { host: string; port?: number } {
  const withoutAddress = endpoint.replace(/\s+\([^)]*\)$/, '');
  const bracketed = withoutAddress.match(/^\[([^\]]+)]:(\d+)$/);
  if (bracketed?.[1] && bracketed[2]) return { host: bracketed[1], port: Number(bracketed[2]) };
  return { host: withoutAddress };
}

function hostKeyId(host: string, port: number, fingerprint: string): string {
  return `${host.toLowerCase()}\0${port}\0${fingerprint}`;
}

function normalizeSecretPrompt(prompt: string): string {
  return prompt.replace(/\s+/g, ' ').trim().toLowerCase();
}

function passwordPromptKey(prompt: string): string {
  const username = prompt.match(/(?:^|\s|\()([^@\s()]+)@[^\s:')]+/i)?.[1];
  return `password:${username?.toLowerCase() ?? 'default'}`;
}

function clearSecretMap(secrets: Map<string, string> | undefined): void {
  if (!secrets) return;
  for (const secret of secrets.values()) overwriteString(secret);
  secrets.clear();
}

function overwriteString(value: string): void {
  value = '\0'.repeat(value.length);
}
