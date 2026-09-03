import { randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { access, chmod, glob, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import * as z from 'zod/v4';
import type { AppPaths } from './config.js';
import { DEFAULT_CONNECT_TIMEOUT_MS } from './config.js';
import { McpOpsError, errorMessage } from './errors.js';
import { runProcess } from './process-runner.js';
import type { NamedSshProfile, SshProfile } from './types.js';

const profileNameSchema = z.string().min(1).max(64).regex(/^[A-Za-z0-9._-]+$/);
const profileSchema = z.object({
  host: z.string().min(1).max(255).regex(/^\S+$/),
  port: z.number().int().min(1).max(65_535).default(22),
  username: z.string().min(1).max(128).regex(/^\S+$/),
  auth_method: z.enum(['agent', 'key', 'password']).default('agent'),
  private_key_path: z.string().min(1).max(4096).optional(),
  proxy_jump: z.string().min(1).max(4096).regex(/^\S+$/).optional(),
  connect_timeout_ms: z.number().int().min(1_000).max(120_000).default(DEFAULT_CONNECT_TIMEOUT_MS),
}).superRefine((profile, context) => {
  if (profile.auth_method === 'key' && !profile.private_key_path) {
    context.addIssue({ code: 'custom', path: ['private_key_path'], message: 'Required for key authentication' });
  }
});
const legacyFileSchema = z.object({
  version: z.literal(1),
  profiles: z.record(z.string(), profileSchema),
});

export type ProfileInput = z.input<typeof profileSchema>;

export class ProfileStore {
  private ensurePromise?: Promise<void>;

  constructor(private readonly paths: AppPaths) {}

  validateName(name: string): string {
    const result = profileNameSchema.safeParse(name);
    if (!result.success) {
      throw new McpOpsError('INVALID_PROFILE_NAME', 'Profile names may contain only letters, digits, dot, underscore, and hyphen.');
    }
    return result.data;
  }

  validateProfile(profile: ProfileInput): SshProfile {
    const result = profileSchema.safeParse(profile);
    if (!result.success) throw new McpOpsError('INVALID_PROFILE', z.prettifyError(result.error));
    return result.data;
  }

  async ensure(): Promise<void> {
    this.ensurePromise ??= this.initialize();
    return this.ensurePromise;
  }

  async has(name: string): Promise<boolean> {
    const alias = this.validateName(name);
    await this.ensure();
    return (await this.collectAliases()).has(alias);
  }

  async get(name: string): Promise<SshProfile> {
    const alias = this.validateName(name);
    if (!await this.has(alias)) {
      throw new McpOpsError('PROFILE_NOT_FOUND', `OpenSSH Host alias "${alias}" does not exist in ${this.paths.sshConfigFile} or its Include files.`);
    }
    return this.resolve(alias);
  }

  async list(): Promise<NamedSshProfile[]> {
    await this.ensure();
    const aliases = [...await this.collectAliases()].sort((left, right) => left.localeCompare(right));
    return Promise.all(aliases.map(async (name) => ({ name, ...await this.resolve(name) })));
  }

  async save(name: string, input: ProfileInput): Promise<NamedSshProfile> {
    const alias = this.validateName(name);
    const profile = this.validateProfile(input);
    await this.ensure();
    const content = await readFile(this.paths.sshConfigFile, 'utf8');
    const updated = replaceHostBlock(content, alias, renderProfile(alias, profile));
    await this.writeConfig(updated);
    return { name: alias, ...await this.resolve(alias) };
  }

  async resolve(alias: string): Promise<SshProfile> {
    await this.ensure();
    const result = await runProcess('ssh', ['-G', '-F', this.paths.sshConfigFile, alias], {
      timeout_ms: 10_000,
      max_output_bytes: 1_048_576,
    });
    if (result.exit_code !== 0 || result.timed_out) {
      throw new McpOpsError('SSH_CONFIG_INVALID', `Cannot resolve Host ${alias} from ${this.paths.sshConfigFile}: ${result.stderr.toString('utf8').trim()}`);
    }
    const values = parseSshG(result.stdout.toString('utf8'));
    const preferred = values.get('preferredauthentications')?.[0]?.split(',') ?? [];
    const identityFile = values.get('identityfile')?.[0];
    const identitiesOnly = values.get('identitiesonly')?.[0] === 'yes';
    const firstAuth = preferred[0];
    const authMethod = firstAuth === 'password' || firstAuth === 'keyboard-interactive'
      ? 'password'
      : identitiesOnly && identityFile
        ? 'key'
        : 'agent';
    const proxyJump = values.get('proxyjump')?.[0];
    const connectTimeoutSeconds = Number(values.get('connecttimeout')?.[0]);
    return {
      host: requiredValue(values, 'hostname', alias),
      port: Number(requiredValue(values, 'port', alias)),
      username: requiredValue(values, 'user', alias),
      auth_method: authMethod,
      private_key_path: authMethod === 'key' ? identityFile : undefined,
      proxy_jump: proxyJump && proxyJump !== 'none' ? proxyJump : undefined,
      connect_timeout_ms: Number.isFinite(connectTimeoutSeconds) && connectTimeoutSeconds > 0
        ? connectTimeoutSeconds * 1_000
        : DEFAULT_CONNECT_TIMEOUT_MS,
      ssh_alias: alias,
    };
  }

  private async initialize(): Promise<void> {
    await mkdir(this.paths.sshDir, { recursive: true, mode: 0o700 });
    await mkdir(this.paths.runtimeDir, { recursive: true, mode: 0o700 });
    await chmod(this.paths.runtimeDir, 0o700);

    if (!await exists(this.paths.sshConfigFile)) await this.writeConfig('');
    else await chmod(this.paths.sshConfigFile, 0o600);

    if (!await exists(this.paths.knownHostsFile)) {
      await writeFile(this.paths.knownHostsFile, '', { mode: 0o600, flag: 'wx' });
    } else {
      await chmod(this.paths.knownHostsFile, 0o600);
    }
  }

  private async readLegacyProfiles(): Promise<Record<string, SshProfile>> {
    try {
      const parsed: unknown = JSON.parse(await readFile(this.paths.legacyProfilesFile, 'utf8'));
      const result = legacyFileSchema.safeParse(parsed);
      return result.success ? result.data.profiles : {};
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return {};
      if (error instanceof SyntaxError) return {};
      throw error;
    }
  }

  private async collectAliases(): Promise<Set<string>> {
    const aliases = new Set<string>();
    const visited = new Set<string>();
    await collectAliasesFromFile(this.paths.sshConfigFile, aliases, visited);
    return aliases;
  }

  private async writeConfig(content: string): Promise<void> {
    const temporaryPath = `${this.paths.sshConfigFile}.${randomUUID()}.tmp`;
    try {
      await writeFile(temporaryPath, content.endsWith('\n') ? content : `${content}\n`, { mode: 0o600, flag: 'wx' });
      await chmod(temporaryPath, 0o600);
      await rename(temporaryPath, this.paths.sshConfigFile);
    } catch (error) {
      await rm(temporaryPath, { force: true }).catch(() => undefined);
      throw new McpOpsError('SSH_CONFIG_WRITE_FAILED', `Cannot write ${this.paths.sshConfigFile}: ${errorMessage(error)}`);
    }
  }
}

function renderGlobalConfig(knownHostsFile: string): string {
  return [
    'Host *',
    `    UserKnownHostsFile ${quoteConfigValue(knownHostsFile)}`,
    '    GlobalKnownHostsFile /dev/null',
    '    StrictHostKeyChecking ask',
    '    UpdateHostKeys no',
    '    ForwardAgent no',
    '    RequestTTY no',
    '    ServerAliveInterval 30',
    '    ServerAliveCountMax 3',
    '',
  ].join('\n');
}

function renderProfile(name: string, profile: SshProfile): string {
  const authentications = profile.auth_method === 'password'
    ? 'password'
    : 'publickey';
  const lines = [
    `Host ${name}`,
    `    HostName ${quoteConfigValue(profile.host)}`,
    `    User ${quoteConfigValue(profile.username)}`,
    `    Port ${profile.port}`,
    `    ConnectTimeout ${Math.max(1, Math.ceil(profile.connect_timeout_ms / 1_000))}`,
    `    PreferredAuthentications ${authentications}`,
  ];
  if (profile.auth_method === 'key') {
    lines.push(`    IdentityFile ${quoteConfigValue(profile.private_key_path!)}`, '    IdentitiesOnly yes');
  }
  if (profile.proxy_jump) lines.push(`    ProxyJump ${quoteConfigValue(profile.proxy_jump)}`);
  return `${lines.join('\n')}\n`;
}

function replaceHostBlock(content: string, name: string, block: string): string {
  const lines = content.replace(/\r\n/g, '\n').split('\n');
  let start = -1;
  let end = -1;
  for (let index = 0; index < lines.length; index += 1) {
    const words = parseConfigWords(lines[index] ?? '');
    if (words[0]?.toLowerCase() !== 'host') continue;
    const hosts = words.slice(1);
    if (hosts.includes(name) && !(hosts.length === 1 && hosts[0] === name)) {
      throw new McpOpsError('PROFILE_AMBIGUOUS', `Host ${name} is part of a multi-pattern Host block. Edit ${name} manually in the OpenSSH config.`);
    }
    if (hosts.length === 1 && hosts[0] === name) {
      if (start !== -1) throw new McpOpsError('PROFILE_DUPLICATE', `Host ${name} is defined more than once.`);
      start = index;
      end = lines.length;
      for (let next = index + 1; next < lines.length; next += 1) {
        const directive = parseConfigWords(lines[next] ?? '')[0]?.toLowerCase();
        if (directive === 'host' || directive === 'match') {
          end = next;
          break;
        }
      }
    }
  }
  const blockLines = block.trimEnd().split('\n');
  if (start === -1) return `${content.trimEnd()}\n\n${blockLines.join('\n')}\n`;
  lines.splice(start, end - start, ...blockLines);
  return `${lines.join('\n').trimEnd()}\n`;
}

async function collectAliasesFromFile(file: string, aliases: Set<string>, visited: Set<string>): Promise<void> {
  const absolute = resolve(file);
  if (visited.has(absolute)) return;
  visited.add(absolute);
  let content: string;
  try {
    content = await readFile(absolute, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
    throw error;
  }
  for (const line of content.split(/\r?\n/)) {
    const words = parseConfigWords(line);
    const directive = words[0]?.toLowerCase();
    if (directive === 'host') {
      for (const host of words.slice(1)) {
        if (!host.startsWith('!') && !/[*?\[]/.test(host) && profileNameSchema.safeParse(host).success) aliases.add(host);
      }
    } else if (directive === 'include') {
      for (const pattern of words.slice(1)) {
        const expanded = expandConfigPath(pattern, dirname(absolute));
        for await (const included of glob(expanded)) await collectAliasesFromFile(included, aliases, visited);
      }
    }
  }
}

function parseConfigWords(line: string): string[] {
  const words: string[] = [];
  let current = '';
  let quote: '"' | "'" | null = null;
  let escaped = false;
  for (const character of line.trim()) {
    if (escaped) {
      current += character;
      escaped = false;
    } else if (character === '\\') {
      escaped = true;
    } else if (quote) {
      if (character === quote) quote = null;
      else current += character;
    } else if (character === '"' || character === "'") {
      quote = character;
    } else if (character === '#') {
      break;
    } else if (/\s/.test(character)) {
      if (current) {
        words.push(current);
        current = '';
      }
    } else {
      current += character;
    }
  }
  if (current) words.push(current);
  return words;
}

function parseSshG(output: string): Map<string, string[]> {
  const values = new Map<string, string[]>();
  for (const line of output.split(/\r?\n/)) {
    const separator = line.indexOf(' ');
    if (separator < 1) continue;
    const key = line.slice(0, separator).toLowerCase();
    const value = line.slice(separator + 1);
    const existing = values.get(key) ?? [];
    existing.push(value);
    values.set(key, existing);
  }
  return values;
}

function requiredValue(values: Map<string, string[]>, key: string, alias: string): string {
  const value = values.get(key)?.[0];
  if (!value) throw new McpOpsError('SSH_CONFIG_INCOMPLETE', `Host ${alias} has no resolved ${key}.`);
  return value;
}

function quoteConfigValue(value: string): string {
  if (/[\r\n\0]/.test(value)) throw new McpOpsError('SSH_CONFIG_VALUE_INVALID', 'OpenSSH config values cannot contain NUL or newlines.');
  if (/^[A-Za-z0-9_@%+=:,./~-]+$/.test(value)) return value;
  return `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
}

function expandConfigPath(path: string, baseDirectory: string): string {
  if (path === '~') return resolve(process.env.HOME ?? baseDirectory);
  if (path.startsWith('~/')) return join(process.env.HOME ?? baseDirectory, path.slice(2));
  return isAbsolute(path) ? path : resolve(baseDirectory, path);
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}
