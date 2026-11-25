import { config } from './config.mjs';

export class SupabaseError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

export function project() {
  let url;
  try { url = new URL(config.url); } catch { return null; }
  const hosted = url.protocol === 'https:' && /^[\w-]+\.supabase\.co$/.test(url.hostname);
  const local = url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname) && url.port === '54321';
  const publicKey = /^sb_publishable_[\w-]+$/.test(config.publishableKey);
  const localKey = local && /^eyJ[\w-]+\.[\w-]+\.[\w-]+$/.test(config.publishableKey);
  if ((!hosted && !local) || (!publicKey && !localKey)) return null;
  return { origin: url.origin, key: config.publishableKey };
}

export function createSupabase(scope) {
  const settings = project();
  if (!settings) throw new Error('Classroom analytics has not been configured.');
  const storageKey = `gca-v1:auth:${settings.origin}:${scope}`;
  let storage;
  try {
    storage = scope === 'instructor' ? sessionStorage : localStorage;
    storage.getItem(storageKey);
    storage.setItem(`${storageKey}:probe`, '1');
    storage.removeItem(`${storageKey}:probe`);
  } catch { storage = null; }
  let memory = null;
  let identityRequest;

  function read() {
    if (!storage) return memory;
    try { return JSON.parse(storage.getItem(storageKey)); } catch { return memory; }
  }

  function save(session) {
    memory = session;
    if (!storage) return;
    try {
      if (session) storage.setItem(storageKey, JSON.stringify(session));
      else storage.removeItem(storageKey);
    } catch { storage = null; }
  }

  async function request(path, { body, token, keepalive = false } = {}) {
    const headers = { apikey: settings.key };
    if (token) headers.Authorization = `Bearer ${token}`;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const response = await fetch(settings.origin + path, {
      method: body === undefined ? 'GET' : 'POST',
      credentials: 'omit',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      keepalive,
      signal: keepalive ? undefined : AbortSignal.timeout(15000),
    });
    const text = await response.text();
    let result;
    try { result = text ? JSON.parse(text) : null; } catch { result = null; }
    if (!response.ok) {
      throw new SupabaseError(result?.message || result?.msg || result?.error_description || 'The server could not complete the request.', response.status);
    }
    return result;
  }

  function accept(result) {
    if (!result?.access_token || !result?.refresh_token || !result?.user?.id) {
      throw new Error('Supabase did not return a signed-in account.');
    }
    const session = {
      id: result.user.id,
      expires: result.expires_at ?? Math.floor(Date.now() / 1000) + result.expires_in,
      access: result.access_token,
      refresh: result.refresh_token,
    };
    save(session);
    return session;
  }

  function identity(createStudent = false) {
    if (identityRequest) return identityRequest;
    const renew = async () => {
      const old = read();
      if (old && old.expires > Date.now() / 1000 + 45) return old;
      if (old) {
        try {
          return accept(await request('/auth/v1/token?grant_type=refresh_token', {
            body: { refresh_token: old.refresh },
          }));
        } catch (error) {
          if (![400, 401, 403].includes(error.status)) throw error;
          save(null);
          if (scope === 'student') throw new Error('Student sign-in expired. Reload to enroll again.');
        }
      }
      if (!createStudent) throw new SupabaseError('Sign in to continue.', 401);
      return accept(await request('/auth/v1/signup', { body: {} }));
    };
    identityRequest = (scope === 'student' && navigator.locks
      ? navigator.locks.request(storageKey, renew)
      : renew()).finally(() => { identityRequest = null; });
    return identityRequest;
  }

  return {
    identity,
    cachedIdentity: read,
    async signInPassword(email, password) {
      return accept(await request('/auth/v1/token?grant_type=password', { body: { email, password } }));
    },
    async sendSignInLink(email, redirect) {
      return request('/auth/v1/otp?redirect_to=' + encodeURIComponent(redirect), {
        body: { email, create_user: false },
      });
    },
    async acceptSignInLink(access, refresh, expires) {
      const user = await request('/auth/v1/user', { token: access });
      return accept({ user, access_token: access, refresh_token: refresh, expires_at: expires });
    },
    async signOut() {
      const session = read();
      save(null);
      if (session) await request('/auth/v1/logout?scope=local', { body: {}, token: session.access });
    },
    async rpc(name, body = {}, { keepalive = false, identityId } = {}) {
      const session = keepalive ? read() : await identity();
      if (!session || (identityId && session.id !== identityId)) {
        throw new SupabaseError('This saved activity belongs to a different sign-in.', 401);
      }
      const result = await request(`/rest/v1/rpc/${name}`, { body, token: session.access, keepalive });
      if (result?.error) throw new SupabaseError(result.error, 429);
      return result;
    },
  };
}
