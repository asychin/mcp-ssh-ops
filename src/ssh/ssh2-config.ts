import { homedir } from 'node:os';
import { resolve } from 'node:path';
import type { Algorithms } from 'ssh2';
import { McpOpsError } from '../errors.js';

export type SshOptions = Map<string, string[]>;

const supportedOptions = new Set(`host hostname user port proxyjump identityagent identitiesonly
preferredauthentications passwordauthentication kbdinteractiveauthentication pubkeyauthentication
connecttimeout serveraliveinterval serveralivecountmax hostkeyalias
userknownhostsfile globalknownhostsfile stricthostkeychecking
hostkeyalgorithms ciphers macs kexalgorithms compression batchmode numberofpasswordprompts
controlmaster controlpath controlpersist loglevel logverbose canonicalizehostname
canonicaldomains canonicalizefallbacklocal canonicalizemaxdots canonicalizepermittedcnames`.split(/\s+/));

export function validateSsh2Options(values: SshOptions, defaults: SshOptions): void {
  for (const [key, value] of values) {
    if ((key === 'updatehostkeys' || key === 'hashknownhosts') && ['no', 'false'].includes(value[0] ?? '')) continue;
    if (!supportedOptions.has(key) && JSON.stringify(value) !== JSON.stringify(defaults.get(key))) {
      throw new McpOpsError('SSH_CONFIG_UNSUPPORTED', `The Windows ssh2 backend cannot preserve OpenSSH ${key}. Use OpenSSH under WSL or remove this setting for this Host.`);
    }
  }
  if (option(values, 'identitiesonly') === 'yes') {
    throw new McpOpsError('SSH_CONFIG_UNSUPPORTED', 'Windows ssh2 does not yet support IdentitiesOnly. Load the intended key in ssh-agent and use agent authentication, or use OpenSSH under WSL.');
  }
}

export function option(values: SshOptions, name: string): string | undefined {
  return values.get(name)?.[0];
}

export function configPaths(values: SshOptions, name: string, host: string, port: number, username: string): string[] {
  return (values.get(name) ?? []).flatMap(splitConfigPaths)
    .filter((path) => path !== 'none' && path !== '/dev/null' && path.toUpperCase() !== 'NUL')
    .map((path) => expandPath(path, host, port, username));
}

export function expandPath(path: string, host: string, port: number, username: string): string {
  const home = homedir();
  const tokens: Record<string, string> = { '%': '%', d: home, h: host, p: String(port), r: username };
  const expanded = path.replace(/\$\{([^}]+)\}/g, (_match, name: string) => {
    const value = process.env[name];
    if (value === undefined) throw new McpOpsError('SSH_CONFIG_UNSUPPORTED', `Missing environment variable in SSH path: ${name}.`);
    return value;
  }).replace(/%(.)/g, (_match, token: string) => {
    if (!(token in tokens)) throw new McpOpsError('SSH_CONFIG_UNSUPPORTED', `Unsupported SSH path token %${token}.`);
    return tokens[token]!;
  }).replace(/^~(?=$|[\\/])/, home);
  return resolve(expanded);
}

export function splitConfigPaths(value: string): string[] {
  const paths: string[] = [];
  let path = '';
  let quoted = false;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index]!;
    if (character === '"') quoted = !quoted;
    else if (character === '\\' && /[\s"]/.test(value[index + 1] ?? '')) path += value[++index];
    else if (/\s/.test(character) && !quoted) {
      if (path) paths.push(path);
      path = '';
    } else path += character;
  }
  if (quoted) throw new McpOpsError('SSH_CONFIG_UNSUPPORTED', 'Unterminated quoted SSH path.');
  if (path) paths.push(path);
  return paths;
}

export function ssh2Algorithms(values: SshOptions): Algorithms {
  const supported = {
    serverHostKey: ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa', 'ssh-dss'],
    cipher: ['chacha20-poly1305@openssh.com', 'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com', 'aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes256-cbc', 'aes192-cbc', 'aes128-cbc', 'blowfish-cbc', '3des-cbc'],
    kex: ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521', 'diffie-hellman-group-exchange-sha256', 'diffie-hellman-group14-sha256', 'diffie-hellman-group15-sha512', 'diffie-hellman-group16-sha512', 'diffie-hellman-group17-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group-exchange-sha1', 'diffie-hellman-group14-sha1', 'diffie-hellman-group1-sha1'],
    hmac: ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'hmac-sha1-etm@openssh.com', 'hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1', 'hmac-md5', 'hmac-sha2-256-96', 'hmac-sha2-512-96', 'hmac-ripemd160', 'hmac-sha1-96', 'hmac-md5-96'],
  };
  const result: Algorithms = {};
  for (const [key, sshKey] of [['serverHostKey', 'hostkeyalgorithms'], ['cipher', 'ciphers'], ['kex', 'kexalgorithms'], ['hmac', 'macs']] as const) {
    const configured = option(values, sshKey);
    if (!configured) continue;
    const allowed = configured.split(',').filter((algorithm) => supported[key].includes(algorithm));
    if (!allowed.length) throw new McpOpsError('SSH_CONFIG_UNSUPPORTED', `No ssh2-compatible algorithms allowed by ${sshKey}.`);
    Object.assign(result, { [key]: allowed });
  }
  result.compress = option(values, 'compression') === 'yes' ? ['zlib@openssh.com', 'zlib', 'none'] : ['none'];
  return result;
}
