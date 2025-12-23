// Temporary during early development: command-line processing is implemented
// ahead of the working login functionality, so some items may be defined but
// unused for now.
#![allow(dead_code)]

// This file is part of the uutils login package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

use clap::{Arg, Command};
use clap::{ArgMatches, crate_version};
use std::ffi::OsString;
use uucore::error::USimpleError;
use uucore::process::geteuid;
use uucore::{error::UResult, format_usage, help_about, help_usage};

mod login_defs;

const HELP: &str = "help";
const PRESERVE_ENVIRONMENT: &str = "preserve-environment";
const SKIP_AUTHENTICATION: &str = "skip-authentication";
const HOST: &str = "host";
const SUPPRESS_HOSTNAME: &str = "suppress-hostname";
const ABOUT: &str = help_about!("login.md");
const USAGE: &str = help_usage!("login.md");

#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    let matches = uu_app().try_get_matches_from(args)?;
    perform_login(matches.into())
}

fn perform_login(_config: LoginConfiguration) -> UResult<()> {
    if geteuid() != 0 {
        return Err(USimpleError::new(1, "must be suid to work properly"));
    }

    Ok(())
}

pub fn uu_app() -> Command {
    Command::new(uucore::util_name())
        .version(crate_version!())
        .about(ABOUT)
        .override_usage(format_usage(USAGE))
        .infer_long_args(true)
        .disable_help_flag(true)
        .arg(
            Arg::new(HELP)
                .long(HELP)
                .help("Print help information")
                .action(clap::ArgAction::Help),
        )
        .arg(
            Arg::new(PRESERVE_ENVIRONMENT)
                .short('p')
                .help("preserve environmental variables")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new(SKIP_AUTHENTICATION)
                .short('f')
                .help("skip login authentication, e.g., for autologin")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new(HOST)
                .short('h')
                .help("hostname to be used for utmp logging")
                .value_name("host"),
        )
        .arg(
            Arg::new(SUPPRESS_HOSTNAME)
                .short('H')
                .help("suppress hostname in the login prompt")
                .action(clap::ArgAction::SetTrue),
        )
}

#[derive(Debug, Default)]
struct LoginConfiguration {
    preserve_environment: bool,
    skip_authentication: bool,
    host: Option<OsString>,
    suppress_hostname: bool,
}

impl From<ArgMatches> for LoginConfiguration {
    fn from(matches: ArgMatches) -> Self {
        LoginConfiguration {
            preserve_environment: matches
                .get_one::<bool>(PRESERVE_ENVIRONMENT)
                .copied()
                .unwrap_or(false),
            skip_authentication: matches
                .get_one::<bool>(SKIP_AUTHENTICATION)
                .copied()
                .unwrap_or(false),
            host: matches.get_one::<OsString>(HOST).cloned(),
            suppress_hostname: matches
                .get_one::<bool>(SUPPRESS_HOSTNAME)
                .copied()
                .unwrap_or(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uu_app() {
        let result = perform_login(Default::default());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), 1);
        assert!(err.to_string().contains("must be suid to work properly"));
    }
}
