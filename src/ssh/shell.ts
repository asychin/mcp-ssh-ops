import { McpOpsError } from '../errors.js';

export function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

export function buildRemoteCommand(command: string, cwd?: string, env?: Record<string, string>): string {
  if (!cwd && (!env || Object.keys(env).length === 0)) return command;
  const environment = Object.entries(env ?? {}).map(([name, value]) => {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
      throw new McpOpsError('INVALID_ENV_NAME', `Invalid environment variable name: ${name}`);
    }
    return `${name}=${shellQuote(value)}`;
  });
  const prefix = cwd ? `cd -- ${shellQuote(cwd)} && ` : '';
  const envCommand = environment.length > 0 ? `env ${environment.join(' ')} ` : '';
  return `${prefix}exec ${envCommand}sh -c ${shellQuote(command)}`;
}
