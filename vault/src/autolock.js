// The vault locks itself after a time without use (docs/AUDIT.md §8.8): its keys leave the page's
// memory, as with the Lock button, until the passphrase opens it again. What counts as use: a key,
// a click, a touch, the pointer or the wheel over the page. What holds the lock off: an action under
// way (a proof, a wallet signature, a sync), or a DEPLOY waiting for its reveal, which the page sends
// once the commit is deep enough. The time without use counts from the end of whatever held it.
//
// The clock is read when a check runs: every `every` ms, and when the page is shown again (a hidden
// tab's timers are slowed down, so a tab left in the background locks the moment it comes back).

export const LOCK_AFTER_MS = 10 * 60 * 1000;
export const ACTIVITY_EVENTS = ['pointerdown', 'pointermove', 'keydown', 'wheel', 'touchstart', 'input', 'click'];

/**
 * `unlocked()`: whether a vault is open; `held()`: why it must stay open (a string), or null;
 * `lock()`: locks it. Returns { touch, check, remaining, stop }; check() returns true when it locked.
 */
export function autoLock({ unlocked, held, lock, after = LOCK_AFTER_MS, every = 15000, now = () => Date.now(), target = globalThis, doc = globalThis.document }) {
  let last = now();
  const touch = () => {
    last = now();
  };
  const check = () => {
    if (!unlocked() || held()) {
      last = now();
      return false;
    }
    if (now() - last < after) return false;
    lock();
    return true;
  };
  const visible = () => {
    if (doc?.visibilityState !== 'hidden') check();
  };
  for (const e of ACTIVITY_EVENTS) target.addEventListener(e, touch, { capture: true, passive: true });
  doc?.addEventListener('visibilitychange', visible);
  const timer = setInterval(check, every);
  return {
    touch,
    check,
    remaining: () => Math.max(0, after - (now() - last)),
    stop() {
      clearInterval(timer);
      for (const e of ACTIVITY_EVENTS) target.removeEventListener(e, touch, { capture: true });
      doc?.removeEventListener('visibilitychange', visible);
    },
  };
}
