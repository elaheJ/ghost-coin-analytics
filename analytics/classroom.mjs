import { createSupabase, project } from './supabase.mjs';
import { ActivityClock } from './timing.mjs';
import { Outbox } from './outbox.mjs';

const SNAPSHOT_MS = 15_000;
const GAME_VERSION = 'level2-pilot-1';
const BACKOFF_MAX_MS = 60_000;

export function setupClassroom(game) {
  const form = document.querySelector('#gca-enrollment');
  const notice = document.querySelector('#gca-classroom');
  const status = document.querySelector('#gca-save');
  const credit = document.querySelector('#gca-credit');
  const sessionId = crypto.randomUUID();
  const submit = form.querySelector('button[type="submit"]');
  let client;
  let student;
  let clock;
  let seq = 0;
  let roundKey;
  let roundId;
  let paused = false;
  let retryDelay = 2000;
  let retryTimer;
  let localRounds = 0;
  let knownRounds = 0;
  let requiredRounds = 1;
  let completedAt;
  let storageWarning = false;
  let lastStatus = '';
  let expiryWarning = false;
  let idleTimer;
  const settings = project();

  function setStatus(text) {
    lastStatus = text;
    const warning = storageWarning ? ' Some unsaved activity may be lost if you close this tab.' : '';
    status.textContent = text + warning;
  }

  let storage;
  try { storage = localStorage; } catch { /* The outbox can still hold data in memory. */ }
  const outbox = new Outbox(settings?.origin ?? 'unconfigured', storage, () => {
    storageWarning = true;
    setStatus(lastStatus);
  });

  function showCredit() {
    if (completedAt) {
      credit.textContent = 'Completion credit saved.';
    } else if (knownRounds + localRounds >= requiredRounds) {
      credit.textContent = 'Activity complete. Waiting to save credit.';
    } else {
      credit.textContent = `${knownRounds} of ${requiredRounds} completed rounds saved.`;
    }
  }

  function onAck(id, result) {
    if (id !== sessionId || !clock) return;
    const firstSaved = !completedAt && result.completed_at;
    const newlySaved = Math.max(0, result.resolved_rounds - knownRounds);
    knownRounds = result.resolved_rounds;
    localRounds = Math.max(0, localRounds - newlySaved);
    requiredRounds = result.rounds_required;
    completedAt = result.completed_at;
    showCredit();
    if (firstSaved) record('completion_reached', { confirmed: true });
  }

  async function flush(keepalive = false) {
    if (!client || !student) return;
    if (keepalive && !client.cachedIdentity()) return;
    try {
      await outbox.flush(client, student.id, onAck, keepalive);
      if (keepalive) return;
      clearTimeout(retryTimer);
      retryTimer = undefined;
      retryDelay = 2000;
      if (clock && !expiryWarning) {
        if (outbox.pendingFor(sessionId)) {
          setStatus('Activity waiting to save.');
          retryTimer = setTimeout(() => { retryTimer = undefined; void flush(); }, 250);
        } else {
          setStatus('Activity saved.');
        }
      }
    } catch (error) {
      if (keepalive) return;
      if (clock) setStatus('Save interrupted. You can keep playing while we retry.');
      if (error.status === 401 || error.status === 403) {
        if (clock) setStatus('This session can no longer save. Reload and rejoin if your class is still open.');
        return;
      }
      if (!retryTimer) {
        retryTimer = setTimeout(() => { retryTimer = undefined; void flush(); }, retryDelay);
        retryDelay = Math.min(retryDelay * 2, BACKOFF_MAX_MS);
      }
    }
  }

  function emit(type, payload, sample, eventRound = null) {
    if (seq >= 20000 || sample.elapsed > 86400000) {
      expiryWarning = true;
      setStatus('This recording session has reached its limit. Reload to keep recording.');
      return;
    }
    const queued = outbox.enqueue(sessionId, student.id, {
      event_id: crypto.randomUUID(),
      seq: ++seq,
      type,
      round_id: eventRound,
      activity_id: 'ghost-coin',
      activity_version: GAME_VERSION,
      schema_version: 1,
      level: 2,
      client_at: new Date().toISOString(),
      elapsed_ms: sample.elapsed,
      payload: { ...payload, timing: sample.timing },
    });
    if (queued && !lastStatus.startsWith('Save interrupted')) setStatus('Activity waiting to save.');
  }

  function sample(changes) {
    const next = clock.sample(performance.now(), changes);
    if (next.idleChanged) {
      emit('idle_changed', { idle: next.idle }, next);
    }
    return next;
  }

  function scheduleIdle() {
    clearTimeout(idleTimer);
    if (!clock?.tracked || !clock.visible || clock.idle || paused) return;
    const wait = clock.input + clock.idleAfter - performance.now();
    idleTimer = setTimeout(() => { sample(); scheduleIdle(); }, Math.max(0, Math.ceil(wait)));
  }

  function record(type, payload = {}, options = {}) {
    if (!clock?.tracked || paused) return;
    if (options.human) sample();
    const reading = sample({ human: options.human });
    emit(type, payload, reading, options.round === false ? null : roundId);
    scheduleIdle();
    if (type === 'round_resolved') {
      if (payload.observed_all_cards) localRounds++;
      showCredit();
      void flush();
    }
  }

  const hooks = {
    context(tracked) {
      if (!clock || paused || clock.tracked === tracked) return;
      const reading = sample({ tracked, human: tracked, visible: !document.hidden });
      emit(tracked ? 'level_enter' : 'level_exit', {}, reading);
      scheduleIdle();
      if (!tracked) void flush();
    },
    startRound(key, payload) {
      if (!clock?.tracked || paused || roundKey === key) return;
      roundKey = key;
      roundId = crypto.randomUUID();
      record('round_start', payload);
    },
    record,
  };

  async function enroll(event) {
    event.preventDefault();
    const values = new FormData(form);
    const name = String(values.get('name') || '').trim();
    const partner = String(values.get('partner') || '').trim();
    const code = String(values.get('classCode') || '').trim().toUpperCase();
    if (!name || !/^[A-F0-9]{16}$/.test(code)) {
      setStatus('Enter your name and the 16-character class code.');
      return;
    }
    submit.disabled = true;
    try {
      setStatus('Joining your class…');
      student = await client.identity(true);
      const result = await client.rpc('gca_enroll', {
        p_session: sessionId, p_class_code: code, p_name: name, p_partner: partner,
      }, { identityId: student.id });
      if (result.session_id !== sessionId) throw new Error('The server did not confirm enrollment.');
      knownRounds = result.resolved_rounds;
      requiredRounds = result.rounds_required;
      completedAt = result.completed_at;
      form.reset();
      form.hidden = true;
      clock = new ActivityClock(performance.now());
      showCredit();
      game.begin(hooks);
      window.addEventListener('online', () => void flush());
      setInterval(() => {
        if (clock.tracked && !document.hidden && !paused) record('timing_snapshot', {}, { round: false });
        void flush();
      }, SNAPSHOT_MS);
      void flush();
    } catch (error) {
      if (clock) setStatus('Classroom activity could not start.');
      else setStatus(error.message || 'Could not join. Check your connection and try again.');
    } finally {
      submit.disabled = false;
    }
  }

  document.addEventListener('visibilitychange', () => {
    if (!clock || paused) return;
    const reading = sample({ visible: !document.hidden });
    if (clock.tracked) emit('visibility_changed', { visible: !document.hidden }, reading);
    scheduleIdle();
    if (document.hidden) void flush(true);
  });
  for (const type of ['focus', 'blur']) {
    window.addEventListener(type, () => record('focus_changed', { focused: type === 'focus' }, { round: false }));
  }
  window.addEventListener('pagehide', () => {
    if (!clock || paused) return;
    const snapshot = sample({ tracked: false, visible: false });
    emit('session_pause', {}, snapshot);
    paused = true;
    scheduleIdle();
    void flush(true);
  });
  window.addEventListener('pageshow', (event) => {
    if (!event.persisted || !paused) return;
    paused = false;
    emit('session_resume', {}, sample());
    game.resume();
    void flush();
  });
  notice.hidden = false;
  if (!settings) {
    form.hidden = true;
    game.preview();
    setStatus('Classroom saving is not configured. You can still play Level 2.');
    return;
  }
  client = createSupabase('student');
  form.addEventListener('submit', enroll);
  const previous = client.cachedIdentity();
  if (previous) {
    student = previous;
    void flush();
  }
}
