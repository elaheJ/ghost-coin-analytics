const RETAIN_MS = 2 * 24 * 60 * 60 * 1000;
const MAX_PENDING = 3000;
const BATCH_SIZE = 16;

export class Outbox {
  constructor(namespace, storage, onStorageError) {
    this.prefix = `gca-v1:queue:${namespace}:`;
    this.storage = storage;
    this.onStorageError = onStorageError;
    this.memory = new Map();
    this.inFlight = null;
    this.prune();
  }

  prune() {
    const cutoff = Date.now() - RETAIN_MS;
    for (const [key, item] of this.entries()) {
      if (item.savedAt < cutoff) this.remove(key);
    }
  }

  entries() {
    const found = new Map(this.memory);
    try {
      for (let index = 0; this.storage && index < this.storage.length; index++) {
        const key = this.storage.key(index);
        if (!key?.startsWith(this.prefix) || found.has(key)) continue;
        try {
          const item = JSON.parse(this.storage.getItem(key));
          if (item?.event?.event_id && item.sessionId && item.identityId && item.savedAt) found.set(key, item);
        } catch {
          // Ignore storage entries from a corrupted or older client.
        }
      }
    } catch { this.onStorageError(); }
    return found;
  }

  enqueue(sessionId, identityId, event) {
    const key = this.prefix + event.event_id;
    const item = { sessionId, identityId, event, savedAt: Date.now() };
    if (this.entries().size >= MAX_PENDING) {
      this.onStorageError();
      return false;
    }
    try {
      if (!this.storage) throw new Error('Browser storage unavailable');
      this.storage.setItem(key, JSON.stringify(item));
    } catch {
      this.memory.set(key, item);
      this.onStorageError();
    }
    return true;
  }

  remove(key) {
    this.memory.delete(key);
    try { this.storage?.removeItem(key); } catch { this.onStorageError(); }
  }

  pendingFor(sessionId) {
    return [...this.entries().values()].some(item => item.sessionId === sessionId);
  }

  flush(client, identityId, onAck, keepalive = false) {
    if (this.inFlight) return this.inFlight;
    this.inFlight = this.send(client, identityId, onAck, keepalive).finally(() => { this.inFlight = null; });
    return this.inFlight;
  }

  async send(client, identityId, onAck, keepalive) {
    this.prune();
    const sessions = new Map();
    for (const entry of this.entries()) {
      const item = entry[1];
      if (item.identityId !== identityId) continue;
      if (!sessions.has(item.sessionId)) sessions.set(item.sessionId, []);
      sessions.get(item.sessionId).push(entry);
    }
    let firstError;
    for (const [sessionId, items] of sessions) {
      items.sort((a, b) => a[1].event.seq - b[1].event.seq);
      for (let start = 0; start < items.length; start += BATCH_SIZE) {
        const batch = items.slice(start, start + BATCH_SIZE);
        try {
          const result = await client.rpc('gca_ingest', {
            p_session: sessionId,
            p_events: batch.map(([, item]) => item.event),
          }, { keepalive, identityId });
          const acknowledged = new Set(result?.acknowledged || []);
          for (const [key, item] of batch) {
            if (acknowledged.has(item.event.event_id)) this.remove(key);
          }
          if (batch.some(([, item]) => !acknowledged.has(item.event.event_id))) throw new Error('Save not acknowledged');
          onAck(sessionId, result);
        } catch (error) {
          firstError ||= error;
          break;
        }
        if (keepalive) return;
      }
      if (keepalive) break;
    }
    if (firstError) throw firstError;
  }
}
