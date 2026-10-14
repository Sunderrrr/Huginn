//! In-process task-completion and queue-availability notifier — a faithful
//! port of `hub/app/core/task_events.py` onto `tokio::sync::Notify`.
//!
//! Two wake channels:
//!
//! - Per-task completion: [`TaskEvents::notify`] fires on result submission and
//!   wakes waiters blocked in [`TaskEvents::wait_for_terminal`] (e.g. the
//!   future `GET /tasks/{id}/wait`).
//! - Queue availability: wherever a task becomes claimable (creation, timeout
//!   re-queue) the publisher fires [`TaskEvents::notify_queue`]. Workers parked
//!   in the `GET /api/worker/tasks/next` long-poll subscribe per VM
//!   ([`TaskEvents::subscribe_queue`]) and wake instantly instead of the hub
//!   re-polling the database; [`TaskEvents::broadcast_queue`] is the fallback
//!   for publishers that cannot target a VM and wakes every parked worker.
//!
//! # "Wake on commit" discipline
//!
//! The Python original registers a pending wake on the SQLAlchemy session and
//! an `after_commit` hook fires it, so a parked long-poll is never woken into
//! re-claiming before the task row is actually visible to other connections
//! (waking at flush time wastes the wake and stalls pickup until the poll
//! times out). Rust/SQLx has no session hook, so the same mechanism is
//! expressed two ways:
//!
//! - call [`TaskEvents::notify_queue_on_commit`] (or `notify_queue`) **after**
//!   the creating transaction's `COMMIT` succeeded — the function that creates
//!   a task fires the wake as its last step, once committed;
//! - or collect the wakes with [`TaskEvents::defer_queue_wakes`] while the
//!   transaction is open and fire them all with [`PendingQueueWakes::commit`]
//!   after the `COMMIT`. Dropping the guard without committing discards the
//!   wakes (the transaction rolled back, so the task never became claimable and
//!   its wake must not fire on some later, unrelated commit) — the exact
//!   semantics of the Python `after_rollback` listener.
//!
//! Single-process only. With multiple hub replicas a waiter on one replica
//! won't be woken by a result committed on another — the callers all re-check
//! the DB on a bounded timeout, so this degrades to polling rather than
//! breaking. For a multi-replica deployment, back this with PostgreSQL
//! LISTEN/NOTIFY or Redis pub/sub.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::Instant;

/// Queue waiters are filed under their VM id and, additionally, under this
/// broadcast key so broadcast wakes reach everyone; VM ids are UUIDs, so the
/// key cannot collide.
const QUEUE_BROADCAST_KEY: &str = "*";

/// `asyncio.Event` equivalent: a wake is *remembered* if it fires before the
/// waiter starts awaiting (at most one, coalesced) and is cleared explicitly
/// with [`Signal::clear`] — the same `set`/`clear`/`wait` protocol as the
/// Python original.
#[derive(Debug, Default)]
struct Signal {
    signalled: AtomicBool,
    notify: Notify,
}

impl Signal {
    fn set(&self) {
        self.signalled.store(true, Ordering::SeqCst);
        // Wakes every currently parked `wait`; a wake delivered before the
        // first `wait` is caught by the flag instead (see `wait`).
        self.notify.notify_waiters();
    }

    fn clear(&self) {
        self.signalled.store(false, Ordering::SeqCst);
    }

    /// Wait for one wake, up to `timeout`. Returns `false` on timeout.
    ///
    /// A wake consumes exactly one signal: `set` delivered before the call is
    /// remembered (at most one, coalesced) and several `set`s in a row still
    /// yield a single wake round — one wake, one re-claim.
    async fn wait(&self, timeout: Duration) -> bool {
        let notified = self.notify.notified();
        tokio::pin!(notified);
        // Register interest BEFORE re-checking the flag: `notify_waiters` only
        // wakes registered waiters, so without this a `set` landing between the
        // check and the first poll of `notified` would be lost.
        notified.as_mut().enable();
        if self.signalled.swap(false, Ordering::SeqCst) {
            return true;
        }
        if tokio::time::timeout(timeout, notified).await.is_err() {
            return false;
        }
        // Woken by `set`: consume that one wake (the `wake.clear()` of the
        // Python loop, folded into the wait).
        self.signalled.store(false, Ordering::SeqCst);
        true
    }
}

type WaiterMap = HashMap<String, Vec<Arc<Signal>>>;

/// The bus: per-task completion waiters and per-VM queue waiters.
#[derive(Debug, Default)]
pub struct TaskEvents {
    task_waiters: Mutex<WaiterMap>,
    queue_waiters: Mutex<WaiterMap>,
}

/// Registered interest in one VM's queue; unsubscribes on drop.
#[derive(Debug)]
pub struct QueueWaiter {
    events: Arc<TaskEvents>,
    vm_id: String,
    signal: Arc<Signal>,
}

/// Registered interest in one task's completion; unsubscribes on drop.
#[derive(Debug)]
pub struct TaskWaiter {
    events: Arc<TaskEvents>,
    task_id: String,
    signal: Arc<Signal>,
}

impl TaskEvents {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Register interest in tasks becoming claimable for `vm_id`.
    ///
    /// The waiter fires when [`TaskEvents::notify_queue`] targets this VM or
    /// when [`TaskEvents::broadcast_queue`] wakes every parked waiter.
    pub fn subscribe_queue(self: &Arc<Self>, vm_id: &str) -> QueueWaiter {
        let signal = Arc::new(Signal::default());
        insert(&self.queue_waiters, vm_id, &signal);
        insert(&self.queue_waiters, QUEUE_BROADCAST_KEY, &signal);
        QueueWaiter {
            events: Arc::clone(self),
            vm_id: vm_id.to_owned(),
            signal,
        }
    }

    /// Register interest in a task's completion.
    pub fn subscribe_task(self: &Arc<Self>, task_id: &str) -> TaskWaiter {
        let signal = Arc::new(Signal::default());
        insert(&self.task_waiters, task_id, &signal);
        TaskWaiter {
            events: Arc::clone(self),
            task_id: task_id.to_owned(),
            signal,
        }
    }

    /// Wake everyone waiting on this task. Call AFTER the result is committed.
    pub fn notify(&self, task_id: &str) {
        for signal in waiters(&self.task_waiters, task_id) {
            signal.set();
        }
    }

    /// Wake workers long-polling `vm_id`'s queue.
    pub fn notify_queue(&self, vm_id: &str) {
        for signal in waiters(&self.queue_waiters, vm_id) {
            signal.set();
        }
    }

    /// Fire a queue wake for `vm_id` *after* the creating transaction's
    /// `COMMIT` succeeded — see the module docs for why the ordering matters.
    ///
    /// In Rust there is no SQLAlchemy session to hook, so "wake on commit" is
    /// expressed by call-site ordering (or by [`TaskEvents::defer_queue_wakes`]
    /// when one transaction creates several tasks).
    pub fn notify_queue_on_commit(&self, vm_id: &str) {
        self.notify_queue(vm_id);
    }

    /// Fallback wake for publishers that cannot target a single VM.
    pub fn broadcast_queue(&self) {
        for signal in waiters(&self.queue_waiters, QUEUE_BROADCAST_KEY) {
            signal.set();
        }
    }

    /// Collect queue wakes while a transaction is open; fire them with
    /// [`PendingQueueWakes::commit`] once its `COMMIT` succeeded. Dropping the
    /// guard without committing discards them (mirrors the Python
    /// `after_rollback` listener).
    pub fn defer_queue_wakes(self: &Arc<Self>) -> PendingQueueWakes {
        PendingQueueWakes {
            events: Arc::clone(self),
            vm_ids: HashSet::new(),
        }
    }

    /// Wait for one completion wake of `task_id` or `timeout` elapsing.
    /// Returns `true` when woken by [`TaskEvents::notify`].
    ///
    /// The task's *row* is not re-read here (the bus has no DB access): callers
    /// that need the state after the wake re-read it themselves, or use
    /// [`TaskEvents::wait_for_terminal_checked`].
    pub async fn wait_for_terminal(self: &Arc<Self>, task_id: &str, timeout: Duration) -> bool {
        let waiter = self.subscribe_task(task_id);
        waiter.wait(timeout).await
    }

    /// Block until the task reaches a terminal state or `timeout` elapses —
    /// the event-driven `services/tasks.wait_for_terminal` loop, with `load`
    /// standing in for the DB re-read.
    ///
    /// Subscribes BEFORE the first read so a result that commits in the gap
    /// still wakes us. `load` returns `None` when the task does not exist;
    /// `is_terminal` answers whether the loaded row is final. Returns the last
    /// observed row (like the Python original: whatever state it is in when we
    /// stop waiting), or `None` when the task never existed.
    pub async fn wait_for_terminal_checked<T, F, Fut>(
        self: &Arc<Self>,
        task_id: &str,
        timeout: Duration,
        mut load: F,
        is_terminal: impl Fn(&T) -> bool,
    ) -> Option<T>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Option<T>>,
    {
        let waiter = self.subscribe_task(task_id);
        let mut task = load().await?;
        if is_terminal(&task) {
            return Some(task);
        }
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            if !waiter.wait(remaining).await {
                break;
            }
            // Re-read the worker's committed row.
            if let Some(latest) = load().await {
                task = latest;
            }
            if is_terminal(&task) {
                return Some(task);
            }
        }
        if let Some(latest) = load().await {
            task = latest;
        }
        Some(task)
    }

    /// Drop a waiter from the maps it registered under (called on drop).
    fn unsubscribe_task(&self, task_id: &str, signal: &Arc<Signal>) {
        remove(&self.task_waiters, task_id, signal);
    }

    fn unsubscribe_queue(&self, vm_id: &str, signal: &Arc<Signal>) {
        for key in [vm_id, QUEUE_BROADCAST_KEY] {
            remove(&self.queue_waiters, key, signal);
        }
    }

    /// Live waiter counts `(task_waiters, queue_waiters)` — tests and
    /// diagnostics only.
    pub fn waiter_counts(&self) -> (usize, usize) {
        (
            self.task_waiters
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .values()
                .map(Vec::len)
                .sum(),
            self.queue_waiters
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .values()
                .map(Vec::len)
                .sum(),
        )
    }
}

impl QueueWaiter {
    /// Wait for one queue wake, up to `timeout`. Returns `false` on timeout.
    pub async fn wait(&self, timeout: Duration) -> bool {
        self.signal.wait(timeout).await
    }

    /// Drop a wake that fired but has not been consumed (the long-poll's
    /// `wake.clear()` before re-claiming).
    pub fn clear(&self) {
        self.signal.clear();
    }
}

impl TaskWaiter {
    /// Wait for one completion wake, up to `timeout`. Returns `false` on timeout.
    pub async fn wait(&self, timeout: Duration) -> bool {
        self.signal.wait(timeout).await
    }

    /// Drop a wake that fired but has not been consumed.
    pub fn clear(&self) {
        self.signal.clear();
    }
}

impl Drop for QueueWaiter {
    fn drop(&mut self) {
        self.events.unsubscribe_queue(&self.vm_id, &self.signal);
    }
}

impl Drop for TaskWaiter {
    fn drop(&mut self) {
        self.events.unsubscribe_task(&self.task_id, &self.signal);
    }
}

/// Queue wakes held until the surrounding transaction commits (or discarded
/// when it rolls back) — the Rust stand-in for the Python session's
/// `after_commit` / `after_rollback` listeners.
#[derive(Debug)]
pub struct PendingQueueWakes {
    events: Arc<TaskEvents>,
    vm_ids: HashSet<String>,
}

impl PendingQueueWakes {
    /// Remember a wake for `vm_id`; it fires on [`PendingQueueWakes::commit`].
    pub fn add(&mut self, vm_id: impl Into<String>) {
        self.vm_ids.insert(vm_id.into());
    }

    pub fn len(&self) -> usize {
        self.vm_ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.vm_ids.is_empty()
    }

    /// Fire every remembered wake. Call ONLY after the transaction's `COMMIT`
    /// succeeded: that is what makes the wake coincide exactly with the task
    /// becoming claimable.
    pub fn commit(self) {
        for vm_id in &self.vm_ids {
            self.events.notify_queue(vm_id);
        }
    }

    /// The transaction rolled back: the task never became claimable, so its
    /// wake must not fire on some later, unrelated commit.
    pub fn rollback(self) {
        // Explicit discard; dropping the guard does the same (see Drop).
    }
}

impl Drop for PendingQueueWakes {
    fn drop(&mut self) {
        // Dropped without commit = rolled back: the remembered wakes are
        // discarded, exactly like the Python `after_rollback` listener.
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

fn insert(map: &Mutex<WaiterMap>, key: &str, signal: &Arc<Signal>) {
    lock(map)
        .entry(key.to_owned())
        .or_default()
        .push(Arc::clone(signal));
}

fn waiters(map: &Mutex<WaiterMap>, key: &str) -> Vec<Arc<Signal>> {
    lock(map).get(key).cloned().unwrap_or_default()
}

fn remove(map: &Mutex<WaiterMap>, key: &str, signal: &Arc<Signal>) {
    let mut guard = lock(map);
    if let Some(signals) = guard.get_mut(key) {
        signals.retain(|s| !Arc::ptr_eq(s, signal));
        if signals.is_empty() {
            guard.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const WAKE: Duration = Duration::from_millis(20);
    /// Generous bound for "this must NOT fire" checks (real time, no pause).
    const NO_WAKE: Duration = Duration::from_millis(60);

    #[tokio::test]
    async fn queue_wake_targets_a_single_vm() {
        let events = TaskEvents::new();
        let w1 = events.subscribe_queue("vm-1");
        let w2 = events.subscribe_queue("vm-2");

        events.notify_queue("vm-1");

        assert!(w1.wait(WAKE).await, "vm-1 waiter must wake");
        assert!(!w2.wait(NO_WAKE).await, "vm-2 waiter must not be woken");
    }

    #[tokio::test]
    async fn broadcast_wakes_every_parked_waiter() {
        let events = TaskEvents::new();
        let w1 = events.subscribe_queue("vm-1");
        let w2 = events.subscribe_queue("vm-2");

        events.broadcast_queue();

        assert!(w1.wait(WAKE).await);
        assert!(w2.wait(WAKE).await);
    }

    #[tokio::test]
    async fn wait_times_out_when_nothing_wakes_it() {
        let events = TaskEvents::new();
        let waiter = events.subscribe_queue("vm-1");

        let started = tokio::time::Instant::now();
        assert!(!waiter.wait(WAKE).await);
        assert!(started.elapsed() >= WAKE, "must wait the full timeout");
    }

    #[tokio::test]
    async fn wake_before_wait_is_not_lost() {
        // The long-poll subscribes BEFORE its first claim: a task committed in
        // that gap must still wake the waiter (no lost-wake stall).
        let events = TaskEvents::new();
        let waiter = events.subscribe_queue("vm-1");

        events.notify_queue("vm-1");

        assert!(
            waiter.wait(WAKE).await,
            "a wake before wait must be remembered"
        );
    }

    #[tokio::test]
    async fn coalesced_wakes_deliver_a_single_wake() {
        // "Pas de double distribution": several wakes for one waiter coalesce
        // into one wake round, so one wake = one re-claim.
        let events = TaskEvents::new();
        let waiter = events.subscribe_queue("vm-1");

        events.notify_queue("vm-1");
        events.notify_queue("vm-1");
        events.broadcast_queue();

        assert!(waiter.wait(WAKE).await);
        assert!(
            !waiter.wait(NO_WAKE).await,
            "only one wake must be delivered"
        );
    }

    #[tokio::test]
    async fn clear_drops_a_pending_wake() {
        let events = TaskEvents::new();
        let waiter = events.subscribe_task("task-1");

        events.notify("task-1");
        waiter.clear();

        assert!(!waiter.wait(NO_WAKE).await);
    }

    #[tokio::test]
    async fn task_wake_targets_a_single_task() {
        let events = TaskEvents::new();
        let w1 = events.subscribe_task("task-1");
        let w2 = events.subscribe_task("task-2");

        events.notify("task-1");

        assert!(w1.wait(WAKE).await);
        assert!(!w2.wait(NO_WAKE).await);
    }

    #[tokio::test]
    async fn two_waiters_on_one_vm_both_wake_and_the_claim_is_the_arbiter() {
        // Several workers of one VM may be parked; every wake re-claims and the
        // transactional claim decides who gets the task (see routes::worker).
        let events = TaskEvents::new();
        let w1 = events.subscribe_queue("vm-1");
        let w2 = events.subscribe_queue("vm-1");

        events.notify_queue("vm-1");

        assert!(w1.wait(WAKE).await);
        assert!(w2.wait(WAKE).await);
    }

    #[tokio::test]
    async fn pending_wakes_fire_only_after_commit() {
        let events = TaskEvents::new();
        let waiter = events.subscribe_queue("vm-1");

        let mut pending = events.defer_queue_wakes();
        pending.add("vm-1");
        assert_eq!(pending.len(), 1);
        assert!(!waiter.wait(NO_WAKE).await, "must not wake before commit");

        pending.commit();
        assert!(waiter.wait(WAKE).await, "must wake on commit");
    }

    #[tokio::test]
    async fn pending_wakes_are_discarded_on_rollback() {
        let events = TaskEvents::new();
        let waiter = events.subscribe_queue("vm-1");

        {
            let mut pending = events.defer_queue_wakes();
            pending.add("vm-1");
            // Transaction rolled back (or just dropped): the wake is lost and
            // must not fire on some later, unrelated commit.
        }
        assert!(!waiter.wait(NO_WAKE).await);

        events.notify_queue("vm-2"); // unrelated commit
        assert!(!waiter.wait(NO_WAKE).await);
    }

    #[tokio::test]
    async fn dropped_waiters_unsubscribe_themselves() {
        let events = TaskEvents::new();
        {
            let _w1 = events.subscribe_queue("vm-1");
            let _t1 = events.subscribe_task("task-1");
            assert_eq!(
                events.waiter_counts(),
                (1, 2),
                "queue waiter filed under vm + broadcast key"
            );
        }
        assert_eq!(events.waiter_counts(), (0, 0), "drop must clean every key");
    }

    #[tokio::test]
    async fn wait_for_terminal_returns_true_on_notify_and_false_on_timeout() {
        let events = TaskEvents::new();

        let notifier = {
            let events = Arc::clone(&events);
            tokio::spawn(async move {
                tokio::time::sleep(WAKE).await;
                events.notify("task-1");
            })
        };
        assert!(
            events
                .wait_for_terminal("task-1", Duration::from_secs(5))
                .await
        );
        notifier.await.unwrap();

        assert!(!events.wait_for_terminal("task-1", WAKE).await);
    }

    #[tokio::test]
    async fn wait_for_terminal_checked_re_reads_on_each_wake() {
        let events = TaskEvents::new();
        let state = Arc::new(Mutex::new(("running", 0usize)));
        let loads = Arc::new(AtomicUsize::new(0));

        let driver = {
            let state = Arc::clone(&state);
            let events = Arc::clone(&events);
            tokio::spawn(async move {
                tokio::time::sleep(WAKE).await;
                events.notify("task-1");
                tokio::time::sleep(WAKE).await;
                *state.lock().unwrap() = ("succeeded", 7);
                events.notify("task-1");
            })
        };

        let observed = events
            .wait_for_terminal_checked(
                "task-1",
                Duration::from_secs(5),
                {
                    let state = Arc::clone(&state);
                    let loads = Arc::clone(&loads);
                    move || {
                        let state = Arc::clone(&state);
                        let loads = Arc::clone(&loads);
                        async move {
                            loads.fetch_add(1, Ordering::SeqCst);
                            let (status, code) = *state.lock().unwrap();
                            Some((status.to_owned(), code))
                        }
                    }
                },
                |(status, _)| *status == "succeeded",
            )
            .await;

        driver.await.unwrap();
        let (status, code) = observed.expect("task row must be observed");
        assert_eq!(status, "succeeded");
        assert_eq!(code, 7);
        assert!(
            loads.load(Ordering::SeqCst) >= 2,
            "must re-read after each wake"
        );
    }

    #[tokio::test]
    async fn wait_for_terminal_checked_subscribes_before_the_first_read() {
        // A result that "commits" between subscribe and first read must not
        // make us miss the terminal state: the read itself sees it.
        let events = TaskEvents::new();
        events.notify("task-1"); // completed before we even started

        let observed = events
            .wait_for_terminal_checked(
                "task-1",
                WAKE,
                || async { Some("succeeded".to_owned()) },
                |s| s == "succeeded",
            )
            .await;

        assert_eq!(observed.as_deref(), Some("succeeded"));
    }

    #[tokio::test]
    async fn wait_for_terminal_checked_returns_none_for_unknown_tasks() {
        let events = TaskEvents::new();
        let observed: Option<String> = events
            .wait_for_terminal_checked("missing", WAKE, || async { None }, |_: &String| true)
            .await;
        assert!(observed.is_none());
    }

    #[tokio::test]
    async fn wait_for_terminal_checked_times_out_with_the_last_state() {
        // Parity with Python: on timeout the row is returned as-is, the caller
        // decides what to do with a still-running task.
        let events = TaskEvents::new();
        let observed = events
            .wait_for_terminal_checked(
                "task-1",
                WAKE,
                || async { Some("running".to_owned()) },
                |s| s == "succeeded",
            )
            .await;
        assert_eq!(observed.as_deref(), Some("running"));
    }
}
