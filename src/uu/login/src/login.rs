// This file is part of the uutils login package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

use clap::crate_version;
use clap::Command;
use uucore::{error::UResult, format_usage, help_about, help_usage};

const ABOUT: &str = help_about!("login.md");
const USAGE: &str = help_usage!("login.md");

#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    let _matches = uu_app().try_get_matches_from(args)?;
    Ok(())
}

pub fn uu_app() -> Command {
    Command::new(uucore::util_name())
        .version(crate_version!())
        .about(ABOUT)
        .override_usage(format_usage(USAGE))
        .infer_long_args(true)
    // TODO
}
