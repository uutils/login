// This file is part of the uutils login package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

use clap::crate_version;
use clap::Command;
use uucore::{error::UResult, format_usage};

#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    let _matches = uu_app().try_get_matches_from(args)?;
    Ok(())
}

pub fn uu_app() -> Command {
    const USAGE: &str = "login [-p] [-h host] [username] [ENV=VAR...]
login [-p] [-h host] -f username
login [-p] -r host";

    Command::new(uucore::util_name())
        .version(crate_version!())
        .about("begin session on the system")
        .override_usage(format_usage(USAGE))
        .infer_long_args(true)
    // TODO
}
