//! Library half of the OLS-cPanel privileged components (plan section 5.1): the generation activator
//! and staged validator used by the `ols-cpanel-activator` binary, the engine socket's operations,
//! which the broker (src/main.rs) runs with the activator in-process, and the plugin data and jobs of the
//! admin and tenant sockets (`panel`), and the tenant `.htaccess` watch (`watch`, CMP-02) that the broker binary runs as
//! its own service with `--htaccess-watch=DIR`.

pub mod activator;
pub mod engine;
pub mod panel;
pub mod watch;
