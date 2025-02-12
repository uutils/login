// This file is part of the uutils login package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

use clap::{crate_version, Arg, Command};
use std::{ffi::OsString, io::Write};
use uucore::{error::{set_exit_code, UResult}, format_usage, help_about, help_usage};

const ABOUT: &str = help_about!("nologin.md");
const USAGE: &str = help_usage!("nologin.md");

#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    let mut command = uu_app();

    // Mirror GNU options, always return `1`. In particular even the 'successful' cases of no-op,
    // and the interrupted display of help and version should return `1`. Also, we return Ok in all
    // paths to avoid the allocation of an error object, an operation that could, in theory, fail
    // and unwind through the standard library allocation handling machinery.
    set_exit_code(1);

    let args: Vec<OsString> = args.collect();
    if args.len() > 2 {
        return Ok(());
    }

    if let Err(e) = command.try_get_matches_from_mut(args) {
        let error = match e.kind() {
            clap::error::ErrorKind::DisplayHelp => command.print_help(),
            clap::error::ErrorKind::DisplayVersion => {
                writeln!(std::io::stdout(), "{}", command.render_version())
            }
            clap::error::ErrorKind::UnknownArgument => {
                if let Some((_, val)) = e.context().next() {
                    writeln!(std::io::stdout(), "nologin: unrecognized option: {val}")?;
                } else {
                    writeln!(std::io::stdout(), "nologin: unrecognized option")?;
                }
                writeln!(std::io::stdout(), "Try 'nologin --help' for more information.")
            }
            _ => Ok(()),
        };

        // Try to display this error.
        if let Err(print_fail) = error {
            // Completely ignore any error here, no more failover and we will fail in any case.
            let _ = writeln!(std::io::stderr(), "{}: {}", uucore::util_name(), print_fail);
        }
    } else {
        let _ = writeln!(std::io::stdout(), "This account is currently not available.");
    }

    Ok(())
}

pub fn uu_app() -> Command {
    Command::new(uucore::util_name())
        .version(crate_version!())
        .about(ABOUT)
        .override_usage(format_usage(USAGE))
        .infer_long_args(true)
        .args_override_self(true)
        .arg(
            Arg::new("command")
                .short('c')
                .long("command")
                .value_name("command")
                .help("does nothing (for compatibility with su -c)")
        )
}

