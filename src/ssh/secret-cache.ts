import { promptSecret } from '../password-prompt.js';

export class SecretCache {
  private readonly groups = new Map<string, { references: number; values: Map<string, string>; pending: Map<string, Promise<string>> }>();

  constructor(private readonly prompt: typeof promptSecret) {}

  retain(group: string): void {
    const entry = this.groups.get(group) ?? { references: 0, values: new Map(), pending: new Map() };
    entry.references += 1;
    this.groups.set(group, entry);
  }

  release(group: string): void {
    const entry = this.groups.get(group);
    if (!entry || --entry.references > 0) return;
    entry.values.clear();
    this.groups.delete(group);
  }

  invalidate(group: string): void {
    const entry = this.groups.get(group);
    if (!entry) return;
    entry.values.clear();
    entry.pending.clear();
  }

  async get(group: string, key: string, message: string, cacheable = true): Promise<string> {
    const entry = this.groups.get(group);
    const cached = entry?.values.get(key);
    if (cached !== undefined) return cached;
    if (!cacheable || !entry) return this.prompt('MCP SSH Ops authentication', message);
    let pending = entry.pending.get(key);
    if (!pending) {
      pending = this.prompt('MCP SSH Ops authentication', message);
      entry.pending.set(key, pending);
    }
    try {
      const value = await pending;
      if (this.groups.get(group) === entry && entry.pending.get(key) === pending) entry.values.set(key, value);
      return value;
    } finally {
      if (entry.pending.get(key) === pending) entry.pending.delete(key);
    }
  }
}
