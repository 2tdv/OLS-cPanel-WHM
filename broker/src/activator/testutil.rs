//! Test helpers: unique temporary trees and a scripted runtime (no root, no services, no network).

use super::runtime::Runtime;
use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

pub struct TempTree(PathBuf);

impl TempTree {
    pub fn new() -> TempTree {
        TempTree::new_in(&std::env::temp_dir())
    }

    /// Below `base` (the validator ignores log directories under /tmp, so its tests use /var/tmp).
    pub fn new_in(base: &Path) -> TempTree {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
        let path = base.join(format!(
            "ols-activator-test-{}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst),
            nanos
        ));
        std::fs::create_dir_all(&path).expect("temporary directory");
        TempTree(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A scripted OLS: what the marker serves, what a reload or start makes it serve, whether vhost
/// health answers, whether a stop works. Sleeping advances a fake monotonic clock.
pub struct Mock {
    pub active: Cell<bool>,
    pub process: Cell<bool>,
    pub serving: RefCell<Option<String>>,
    pub after_reload: RefCell<Option<String>>,
    pub healthy: Cell<bool>,
    pub stop_works: Cell<bool>,
    pub kill_works: Cell<bool>,
    pub calls: RefCell<Vec<String>>,
    pub clock: Cell<f64>,
    pub wall: Cell<f64>,
    /// Every health target attempt times out after its whole timeout.
    pub slow_health: Cell<bool>,
    /// The timeout of every health attempt, in order.
    pub health_timeouts: RefCell<Vec<f64>>,
}

impl Mock {
    pub fn new() -> Mock {
        Mock {
            active: Cell::new(false),
            process: Cell::new(false),
            serving: RefCell::new(None),
            after_reload: RefCell::new(None),
            healthy: Cell::new(true),
            stop_works: Cell::new(true),
            kill_works: Cell::new(true),
            calls: RefCell::new(Vec::new()),
            clock: Cell::new(0.0),
            wall: Cell::new(1000.0),
            slow_health: Cell::new(false),
            health_timeouts: RefCell::new(Vec::new()),
        }
    }

    /// OLS running and serving `gen`.
    pub fn running(gen: Option<&str>) -> Mock {
        let mock = Mock::new();
        mock.active.set(true);
        mock.process.set(true);
        *mock.serving.borrow_mut() = gen.map(str::to_string);
        mock
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }
}

impl Runtime for Mock {
    fn service_active(&self) -> bool {
        self.active.get()
    }

    fn systemctl(&self, action: &str, _timeout: Duration) -> i32 {
        self.calls.borrow_mut().push(action.to_string());
        match action {
            "reload" | "start" => {
                let next = self.after_reload.borrow().clone();
                if next.is_some() {
                    *self.serving.borrow_mut() = next;
                    self.active.set(true);
                    self.process.set(true);
                }
                0
            }
            "stop" => {
                if self.stop_works.get() {
                    self.active.set(false);
                    self.process.set(false);
                    *self.serving.borrow_mut() = None;
                }
                0
            }
            _ => 1,
        }
    }

    fn ols_process(&self) -> bool {
        self.process.get()
    }

    fn kill_ols(&self) {
        self.calls.borrow_mut().push("kill".into());
        if self.kill_works.get() {
            self.process.set(false);
            self.active.set(false);
            *self.serving.borrow_mut() = None;
        }
    }

    fn marker(&self, _url: &str, _timeout: Duration) -> Option<String> {
        self.serving.borrow().clone()
    }

    fn health(&self, _url: &str, host: &str, timeout: Duration) -> String {
        self.health_timeouts.borrow_mut().push(timeout.as_secs_f64());
        if self.slow_health.get() {
            // A target that never answers: the attempt takes its whole timeout.
            self.sleep(timeout);
            return "error: timeout".into();
        }
        match (self.serving.borrow().as_deref(), self.healthy.get()) {
            (Some(gen), true) => format!("{gen} {host}"),
            (Some(_), false) => "error: HTTP 404".into(),
            (None, _) => "error: URLError".into(),
        }
    }

    fn sleep(&self, duration: Duration) {
        // Both clocks advance: enforcement deadlines are wall-clock times, waits are monotonic.
        self.clock.set(self.clock.get() + duration.as_secs_f64());
        self.wall.set(self.wall.get() + duration.as_secs_f64());
    }

    fn now(&self) -> f64 {
        self.wall.get()
    }

    fn monotonic(&self) -> f64 {
        self.clock.get()
    }
}
