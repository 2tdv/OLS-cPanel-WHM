//! Generation activator (plan section 17, G0-G) and staged validator (G0-B), ported from the lab tools
//! build/vm-qualification/ols_generation.py and ols_stage_validate.py (with ols_config_lint.py).
//! The command line, JSON output and on-disk formats are those of the Python tools, so both
//! implementations can run against the same state directory.

pub mod cli;
pub mod generation;
pub mod lint;
pub mod pyjson;
pub mod pystr;
pub mod runtime;
pub mod validate;

#[cfg(test)]
pub(crate) mod testutil;
