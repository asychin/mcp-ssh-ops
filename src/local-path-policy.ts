import { lstat, realpath } from 'node:fs/promises';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import type { Stats } from 'node:fs';
import { McpOpsError, errorMessage } from './errors.js';

export interface LocalFileTarget {
  path: string;
  stats?: Stats;
}

export class LocalPathPolicy {
  private rootsPromise?: Promise<string[]>;

  constructor(private readonly configuredRoots: string[]) {}

  async sourceFile(path: string): Promise<Required<LocalFileTarget>> {
    const absolute = resolveInput(path);
    this.rejectSensitive(absolute);
    let stats: Stats;
    try {
      stats = await lstat(absolute);
    } catch (error) {
      throw new McpOpsError('LOCAL_FILE_READ_FAILED', `${absolute}: ${errorMessage(error)}`);
    }
    if (stats.isSymbolicLink()) throw new McpOpsError('LOCAL_SYMLINK_REJECTED', `${absolute} is a symbolic link.`);
    if (!stats.isFile()) throw new McpOpsError('LOCAL_NOT_A_FILE', `${absolute} is not a regular file.`);
    const canonical = await realpath(absolute);
    await this.assertAllowed(canonical);
    return { path: canonical, stats };
  }

  async destinationFile(path: string): Promise<LocalFileTarget> {
    const absolute = resolveInput(path);
    this.rejectSensitive(absolute);
    const parent = dirname(absolute);
    let canonicalParent: string;
    try {
      canonicalParent = await realpath(parent);
    } catch (error) {
      throw new McpOpsError('LOCAL_PARENT_INVALID', `${parent}: ${errorMessage(error)}. Create the destination directory first.`);
    }
    await this.assertAllowed(canonicalParent);
    const target = join(canonicalParent, basename(absolute));
    this.rejectSensitive(target);
    try {
      const stats = await lstat(target);
      if (stats.isSymbolicLink()) throw new McpOpsError('LOCAL_SYMLINK_REJECTED', `${target} is a symbolic link.`);
      if (!stats.isFile()) throw new McpOpsError('LOCAL_NOT_A_FILE', `${target} is not a regular file.`);
      return { path: target, stats };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { path: target };
      throw error;
    }
  }

  async roots(): Promise<string[]> {
    this.rootsPromise ??= Promise.all(this.configuredRoots.map(async (root) => {
      try {
        return await realpath(resolve(root));
      } catch (error) {
        throw new McpOpsError('LOCAL_ROOT_INVALID', `${root}: ${errorMessage(error)}`);
      }
    }));
    return this.rootsPromise;
  }

  private async assertAllowed(path: string): Promise<void> {
    const roots = await this.roots();
    if (roots.some((root) => isWithin(path, root))) return;
    throw new McpOpsError('LOCAL_PATH_DENIED', `${path} is outside allowed local roots: ${roots.join(', ')}`);
  }

  private rejectSensitive(path: string): void {
    const home = homedir();
    const sensitive = [
      join(home, '.ssh'),
      join(home, '.gnupg'),
      join(home, '.password-store'),
      join(home, '.local', 'share', 'keyrings'),
      join(home, '.local', 'share', 'kwalletd'),
      join(home, '.config', 'kwalletd'),
    ];
    if (sensitive.some((root) => isWithin(path, root))) {
      throw new McpOpsError('SENSITIVE_LOCAL_PATH', `${path} is inside a protected credential directory.`);
    }
  }
}

function resolveInput(path: string): string {
  if (!path || /[\r\n\0]/.test(path)) throw new McpOpsError('LOCAL_PATH_INVALID', 'Local paths cannot be empty or contain NUL/newline characters.');
  return isAbsolute(path) ? resolve(path) : resolve(process.cwd(), path);
}

function isWithin(path: string, root: string): boolean {
  const candidate = relative(root, path);
  return candidate === '' || (!candidate.startsWith('..') && !isAbsolute(candidate));
}
