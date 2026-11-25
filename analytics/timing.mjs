export const IDLE_AFTER_MS = 60_000;

export class ActivityClock {
  constructor(time, idleAfter = IDLE_AFTER_MS) {
    this.started = this.updated = this.input = Math.floor(time);
    this.idleAfter = idleAfter;
    this.tracked = this.visible = this.idle = false;
    this.activeMs = this.idleMs = this.hiddenMs = 0;
  }

  sample(time, state = {}) {
    time = Math.max(Math.floor(time), this.updated);
    const delta = time - this.updated;
    if (this.tracked && this.visible) {
      const active = Math.max(0, Math.min(delta, this.input + this.idleAfter - this.updated));
      this.activeMs += active;
      this.idleMs += delta - active;
    } else if (this.tracked) {
      this.hiddenMs += delta;
    }
    const wasIdle = this.idle;
    this.tracked = state.tracked ?? this.tracked;
    this.visible = state.visible ?? this.visible;
    if (state.human) this.input = time;
    this.idle = this.tracked && this.visible && time >= this.input + this.idleAfter;
    this.updated = time;
    return {
      idleChanged: wasIdle !== this.idle,
      idle: this.idle,
      elapsed: time - this.started,
      timing: {
        visible_ms: this.activeMs + this.idleMs,
        active_ms: this.activeMs,
        idle_ms: this.idleMs,
        hidden_ms: this.hiddenMs,
      },
    };
  }
}
