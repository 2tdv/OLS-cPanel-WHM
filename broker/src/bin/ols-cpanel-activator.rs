//! ols-cpanel-activator: generation activation, restriction epoch, recovery and enforcement, plus the
//! staged validator and the structural lint. Same command line and JSON output as the lab tool
//! build/vm-qualification/ols_generation.py; run as root.

fn main() {
    let args: Vec<String> = std::env::args_os().skip(1).map(|a| a.to_string_lossy().into_owned()).collect();
    std::process::exit(ols_cpanel_broker::activator::cli::main(&args));
}
