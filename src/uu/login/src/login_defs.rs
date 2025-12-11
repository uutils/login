// Temporary during early development: configuration parsing is implemented
// ahead of the working login functionality, so some items may be defined but
// unused for now.
#![allow(dead_code)]

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::num::NonZeroU32;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::{io, str};
use thiserror::Error;

/// Maximum length of a line in login.defs (8kB).
/// Lines longer than this will be skipped with a warning.
const LOGIN_DEFS_MAX_LINE_LENGTH: usize = 8192;

/// Represents warnings that can occur during parsing of login.defs file.
#[derive(Debug, Error)]
pub enum LoginDefsWarning {
    /// The login.defs file was not found at the expected path.
    #[error("Configuration file not found: {0}")]
    FileNotFound(String),
    /// The login.defs file could not be opened due to an error.
    #[error("Failed to open configuration file '{path}': {error}")]
    FileOpenError { path: String, error: io::Error },
    /// A key in the login.defs file could not be parsed as valid UTF-8.
    #[error("Invalid key found: {0}")]
    InvalidKey(String),
    /// A value in the login.defs file could not be parsed as the expected type.
    #[error("Invalid value for key '{key}': expected {expected_type} (Value: {value:?})")]
    InvalidValue {
        key: String,
        value: Vec<u8>,
        expected_type: String,
    },
    /// An unknown key was encountered in the login.defs file.
    #[error("Unknown configuration key: {0}")]
    UnknownKey(String),
    /// An I/O error occurred while reading the login.defs file.
    #[error("I/O error while reading configuration: {0}")]
    IoErrorDuringRead(io::Error),
    /// A line in the configuration file exceeded the maximum allowed length.
    ///
    /// This limit is enforced to prevent unbounded memory usage in case it could be
    /// exploited as a denial of service vector.
    #[error("Line {line_number} exceeded maximum length of {max_length} bytes and was skipped")]
    LineTooLong {
        line_number: usize,
        max_length: usize,
    },
}

/// Contains both the parsed LoginDefs configuration and any warnings encountered during parsing.
#[derive(Debug)]
pub struct LoginDefsWithWarnings {
    /// The parsed configuration settings.
    pub defs: LoginDefs,
    /// Any warnings encountered during parsing.
    pub warnings: Vec<LoginDefsWarning>,
}

/// Defines the policy for handling login attempts for accounts without a password.
///
/// This enum corresponds to the `PREVENT_NO_AUTH` setting in `login.defs`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PreventNoAuthPolicy {
    /// Always prevent login if the account has no password. (Value: "yes")
    Yes,
    /// Prevent login only for the superuser (UID 0) if the account has no password. (Value: "superuser")
    /// This is often the default behavior if the setting is unspecified.
    SuperuserOnly,
    /// Allow login if the account has no password, subject to other system restrictions. (Value: "no")
    Disabled,
}

impl TryFrom<&[u8]> for PreventNoAuthPolicy {
    type Error = LoginDefsWarning;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        str::from_utf8(value)
            .ok()
            .map(|s| s.trim().to_ascii_lowercase())
            .and_then(|s| match s.as_str() {
                "yes" => Some(PreventNoAuthPolicy::Yes),
                "superuser" => Some(PreventNoAuthPolicy::SuperuserOnly),
                "no" => Some(PreventNoAuthPolicy::Disabled),
                _ => None,
            })
            .ok_or_else(|| LoginDefsWarning::InvalidValue {
                key: "PREVENT_NO_AUTH".to_string(),
                value: value.to_vec(),
                expected_type: "one of: yes, superuser, no".to_string(),
            })
    }
}

/// Configuration settings parsed from `/etc/login.defs` relevant to the `/bin/login` program.
///
/// This struct holds values read from the `login.defs` configuration file.
/// Default values are applied if a setting is not found in the file or
/// if the file itself is not present or unreadable. Fields are named to be more
/// descriptive than their `login.defs` counterparts (e.g., `LASTLOG_ENAB` is called
/// `lastlog_enabled`).
///
/// Values that are file paths or can contain arbitrary characters are stored as `OsString`.
/// Numeric values are parsed considering decimal, octal (0-prefix), and hexadecimal (0x-prefix) notations.
/// Boolean values are "yes" (true) or any other value including "no" (false) when the key is present.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LoginDefs {
    /// Default `PATH` environment variable for regular users.
    /// Configured by the `ENV_PATH` setting in `login.defs`.
    pub env_path: OsString,
    /// Default `PATH` environment variable for the superuser.
    /// Configured by the `ENV_SUPATH` setting in `login.defs`.
    pub env_supath: OsString,
    /// Delay in seconds before prompting for another login attempt after a failure.
    /// Configured by the `FAIL_DELAY` setting in `login.defs`.
    pub fail_delay_seconds: u32,
    /// Path to the hushlogin file. Treated as relative to the user's home directory
    /// if not absolute. Can be an empty string if not set.
    /// Configured by the `HUSHLOGIN_FILE` setting in `login.defs`.
    pub hushlogin_file: Option<OsString>,
    /// Whether to enable updating of last login records.
    /// Configured by the `LASTLOG_ENAB` setting in `login.defs`.
    pub lastlog_enabled: bool,
    /// Maximum UID for which lastlog entries should be updated.
    /// Configured by the `LASTLOG_UID_MAX` setting in `login.defs`.
    pub lastlog_uid_max: Option<u32>,
    /// Whether to log the username if a login attempt for a non-existent user fails.
    /// Configured by the `LOG_UNKFAIL_ENAB` setting in `login.defs`.
    pub log_unknown_username_failures_enabled: bool,
    /// Maximum number of login retries before the connection is terminated.
    /// Configured by the `LOGIN_RETRIES` setting in `login.defs`.
    pub login_retries_max: u32,
    /// Maximum time in seconds allowed for a user to complete the login process.
    /// Configured by the `LOGIN_TIMEOUT` setting in `login.defs`.
    pub login_timeout_seconds: u32,
    /// Path to the "message of the day" file.
    /// Configured by the `MOTD_FILE` setting in `login.defs`.
    pub motd_file_path: OsString,
    /// Path to the file that, if present, disallows non-root logins.
    /// Its contents are displayed to the user.
    /// Configured by the `NOLOGINS_FILE` setting in `login.defs`.
    pub nologins_file_path: OsString,
    /// Maximum number of days a password may be used.
    ///
    /// `None` indicates that there is no maximum age for passwords (this check is disabled).
    /// Configured by the `PASS_MAX_DAYS` setting in `login.defs`.
    pub password_max_days: Option<u32>,
    /// Minimum number of days allowed between password changes.
    ///
    /// `None` indicates that there are no restrictions on how often the password can be changed.
    /// Configured by the `PASS_MIN_DAYS` setting in `login.defs`.
    pub password_min_days: Option<NonZeroU32>,
    /// Number of days before password expiration to warn the user. `None` means no warning is given.
    /// Configured by the `PASS_WARN_AGE` setting in `login.defs`.
    pub password_warn_age_days: Option<u32>,
    /// Default file mode creation mask. Often specified in octal (e.g., 022).
    /// Configured by the `UMASK` setting in `login.defs`.
    pub default_umask: u32,
    /// Whether to allow login if the user's home directory cannot be accessed.
    /// If true, the user may be logged into the root ("/") directory.
    /// Configured by the `DEFAULT_HOME` setting in `login.defs`.
    pub allow_login_if_no_home: bool,
    /// Whether to enable failure logging (e.g., to a system faillog database).
    /// Configured by the `FAILLOG_ENAB` setting in `login.defs`.
    pub faillog_enabled: bool,
    /// Whether to log successful login attempts to system logs.
    /// Configured by the `LOG_OK_LOGINS` setting in `login.defs`.
    pub log_successful_logins_enabled: bool,
    /// Policy for handling accounts with no password upon login attempts.
    /// Configured by the `PREVENT_NO_AUTH` setting in `login.defs`.
    pub prevent_no_auth_policy: PreventNoAuthPolicy,
    /// Path to the file listing TTYs on which root login is permitted (e.g., /etc/securetty).
    /// Configured by the `CONSOLE` setting in `login.defs`.
    pub secure_tty_file_path: OsString,
    /// Default `TZ` (timezone) environment variable. `None` indicates that
    /// `login.defs` does not specify a default.
    /// Configured by the `ENV_TZ` setting in `login.defs`.
    pub environment_timezone: Option<OsString>,
    /// Group to own the TTY. This can be a group name or a numeric GID.
    /// `None` signifies that the login program should use the user's primary group.
    /// Configured by the `TTYGROUP` setting in `login.defs`.
    pub tty_group_name_or_id: Option<OsString>,
    /// Permissions for the login TTY (e.g., 0o600 or 0o620). Often specified in octal.
    /// Configured by the `TTYPERM` setting in `login.defs`.
    pub tty_permissions: u32,
}

impl Default for LoginDefs {
    fn default() -> Self {
        LoginDefs {
            env_path: OsString::from("PATH=/bin:/usr/bin"),
            env_supath: OsString::from("PATH=/sbin:/bin:/usr/sbin:/usr/bin"),
            fail_delay_seconds: 3,
            hushlogin_file: Some(OsString::from(".hushlogin")), // Relative to the user's home
            lastlog_enabled: true,
            lastlog_uid_max: Some(u32::MAX),
            log_unknown_username_failures_enabled: false,
            login_retries_max: 3,
            login_timeout_seconds: 60,
            motd_file_path: OsString::from("/etc/motd"),
            nologins_file_path: OsString::from("/etc/nologins"),
            password_max_days: None,      // Disabled
            password_min_days: None,      // Disabled
            password_warn_age_days: None, // No warning (shadow-utils default)
            default_umask: 0o022,
            allow_login_if_no_home: false,
            faillog_enabled: true,
            log_successful_logins_enabled: false,
            prevent_no_auth_policy: PreventNoAuthPolicy::SuperuserOnly,
            secure_tty_file_path: OsString::from("/etc/securetty"),
            environment_timezone: None, // Empty means not set by login.defs
            tty_group_name_or_id: None, // Empty means use user's primary group
            tty_permissions: 0o600,     // Default secure TTY permissions
        }
    }
}

impl LoginDefs {
    /// Parses `login.defs` configuration from the given reader.
    ///
    /// Lines are read byte by byte to handle potentially non-UTF8 characters in values
    /// (especially for paths). Comments (lines starting with '#' after trimming whitespace,
    /// or text after the first '#' on a line) and blank lines are ignored.
    /// Malformed lines (e.g., a key without a value where one is expected) are skipped.
    ///
    /// Key names are treated case-sensitively. Values for boolean settings are typically "yes"
    /// (true) or any other value including "no" (false) if the key is present in the file.
    /// Numeric values can be decimal, octal (0-prefix), or hexadecimal (0x-prefix).
    ///
    /// If a setting is not found or cannot be parsed, its default value from `LoginDefs::default()`
    /// is retained.
    pub fn from_reader<R: Read>(reader: R) -> LoginDefsWithWarnings {
        let mut defs = LoginDefs::default();
        let mut warnings = Vec::new();
        let mut buf_reader = BufReader::new(reader);
        let mut line_buf = Vec::new(); // Reusable buffer for each line
        let mut line_number = 0;

        loop {
            line_number += 1;
            line_buf.clear();

            match read_line_with_limit(&mut buf_reader, &mut line_buf, LOGIN_DEFS_MAX_LINE_LENGTH) {
                Ok(bytes_read) => {
                    if bytes_read == 0 {
                        break; // EOF
                    }

                    // Check if the line was truncated (and not just ending naturally at the limit)
                    // If we read exactly MAX bytes and the last byte is NOT a newline, it means the line continues.
                    if bytes_read == LOGIN_DEFS_MAX_LINE_LENGTH && line_buf.last() != Some(&b'\n') {
                        warnings.push(LoginDefsWarning::LineTooLong {
                            line_number,
                            max_length: LOGIN_DEFS_MAX_LINE_LENGTH,
                        });

                        // Consume the rest of the line to recover
                        if let Err(e) = consume_rest_of_line(&mut buf_reader) {
                            warnings.push(LoginDefsWarning::IoErrorDuringRead(e));
                            break;
                        }
                        continue;
                    }

                    // Process the current known-good line
                    let processed_line = trim_ascii_whitespace_and_comment(&line_buf);

                    if !processed_line.is_empty() {
                        let (key_bytes, value_bytes_raw) = split_key_value(processed_line);
                        // Valid keys are expected to be ASCII/UTF-8
                        if let Ok(key_str) = str::from_utf8(key_bytes) {
                            defs.parse_and_set_value(key_str, value_bytes_raw, &mut warnings);
                        } else {
                            warnings.push(LoginDefsWarning::InvalidKey(
                                String::from_utf8_lossy(key_bytes).to_string(),
                            ));
                        }
                    }
                }
                Err(e) => {
                    warnings.push(LoginDefsWarning::IoErrorDuringRead(e));
                    break;
                }
            }
        }
        LoginDefsWithWarnings { defs, warnings }
    }

    /// Loads configuration from the specified path.
    ///
    /// If the file cannot be opened or read (e.g., due to permissions or non-existence),
    /// the default `LoginDefs` values are returned along with appropriate warnings.
    pub fn load(path: &Path) -> LoginDefsWithWarnings {
        let mut warnings = Vec::new();
        let path_str = path.to_string_lossy().to_string();

        match File::open(path) {
            Ok(file) => Self::from_reader(file),
            Err(e) => {
                if e.kind() == io::ErrorKind::NotFound {
                    warnings.push(LoginDefsWarning::FileNotFound(path_str));
                } else {
                    warnings.push(LoginDefsWarning::FileOpenError {
                        path: path_str,
                        error: e,
                    });
                }
                LoginDefsWithWarnings {
                    defs: LoginDefs::default(),
                    warnings,
                }
            }
        }
    }

    /// Loads configuration from the standard `/etc/login.defs` path.
    ///
    /// If the file cannot be opened or read (e.g., due to permissions or non-existence),
    /// the default `LoginDefs` values are returned along with appropriate warnings.
    pub fn load_default() -> LoginDefsWithWarnings {
        Self::load(Path::new("/etc/login.defs"))
    }

    fn parse_and_set_value(
        &mut self,
        key: &str,
        value_bytes: &[u8],
        warnings: &mut Vec<LoginDefsWarning>,
    ) {
        match key {
            "ENV_PATH" => self.env_path = OsStr::from_bytes(value_bytes).to_os_string(),
            "ENV_SUPATH" => self.env_supath = OsStr::from_bytes(value_bytes).to_os_string(),
            "FAIL_DELAY" => match parse_numeric_flexible_radix::<u32>(value_bytes) {
                Ok(v) => self.fail_delay_seconds = v,
                Err(e) => warnings.push(LoginDefsWarning::InvalidValue {
                    key: key.to_string(),
                    value: value_bytes.to_vec(),
                    expected_type: format!("numeric (u32): {}", e),
                }),
            },
            "HUSHLOGIN_FILE" => {
                self.hushlogin_file = if value_bytes.is_empty() {
                    None
                } else {
                    Some(OsStr::from_bytes(value_bytes).to_os_string())
                }
            }
            "LASTLOG_ENAB" => match parse_bool(value_bytes) {
                Ok(v) => self.lastlog_enabled = v,
                Err(e) => warnings.push(LoginDefsWarning::InvalidValue {
                    key: key.to_string(),
                    value: value_bytes.to_vec(),
                    expected_type: format!("boolean: {}", e),
                }),
            },
            "LASTLOG_UID_MAX" => match parse_numeric_flexible_radix::<u32>(value_bytes) {
                Ok(v) => self.lastlog_uid_max = Some(v),
                Err(e) => warnings.push(LoginDefsWarning::InvalidValue {
                    key: key.to_string(),
                    value: value_bytes.to_vec(),
                    expected_type: format!("numeric (u32): {}", e),
                }),
            },
            "LOG_UNKFAIL_ENAB" => match parse_bool(value_bytes) {
                Ok(v) => self.log_unknown_username_failures_enabled = v,
                Err(e) => warnings.push(LoginDefsWarning::InvalidValue {
                    key: key.to_string(),
                    value: value_bytes.to_vec(),
                    expected_type: format!("boolean: {}", e),
                }),
            },
            "LOGIN_RETRIES" => match parse_numeric_flexible_radix::<u32>(value_bytes) {
                Ok(v) => self.login_retries_max = v,
                Err(e) => warnings.push(LoginDefsWarning::InvalidValue {
                    key: key.to_string(),
                    value: value_bytes.to_vec(),
                    expected_type: format!("numeric (u32): {}", e),
                }),
            },
            "LOGIN_TIMEOUT" => match parse_numeric_flexible_radix::<u32>(value_bytes) {
                Ok(v) => self.login_timeout_seconds = v,
                Err(e) => warnings.push(LoginDefsWarning::InvalidValue {
                    key: key.to_string(),
                    value: value_bytes.to_vec(),
                    expected_type: format!("numeric (u32): {}", e),
                }),
            },
            "MOTD_FILE" => self.motd_file_path = OsStr::from_bytes(value_bytes).to_os_string(),
            "NOLOGINS_FILE" => {
                self.nologins_file_path = OsStr::from_bytes(value_bytes).to_os_string()
            }
            "PASS_MAX_DAYS" => match parse_numeric_flexible_radix::<i32>(value_bytes) {
                Ok(v) => {
                    self.password_max_days = if v < 0 { None } else { Some(v as u32) };
                }
                Err(e) => warnings.push(LoginDefsWarning::InvalidValue {
                    key: key.to_string(),
                    value: value_bytes.to_vec(),
                    expected_type: format!("numeric (i32): {}", e),
                }),
            },
            "PASS_MIN_DAYS" => match parse_numeric_flexible_radix::<i32>(value_bytes) {
                Ok(v) => {
                    self.password_min_days = if v < 0 {
                        None
                    } else {
                        NonZeroU32::new(v as u32)
                    };
                }
                Err(e) => warnings.push(LoginDefsWarning::InvalidValue {
                    key: key.to_string(),
                    value: value_bytes.to_vec(),
                    expected_type: format!("numeric (i32): {}", e),
                }),
            },
            "PASS_WARN_AGE" => match parse_numeric_flexible_radix::<i32>(value_bytes) {
                Ok(v) => {
                    self.password_warn_age_days = if v < 0 { None } else { Some(v as u32) };
                }
                Err(e) => warnings.push(LoginDefsWarning::InvalidValue {
                    key: key.to_string(),
                    value: value_bytes.to_vec(),
                    expected_type: format!("numeric (i32): {}", e),
                }),
            },
            "UMASK" => match parse_numeric_flexible_radix::<u32>(value_bytes) {
                Ok(v) => self.default_umask = v,
                Err(e) => warnings.push(LoginDefsWarning::InvalidValue {
                    key: key.to_string(),
                    value: value_bytes.to_vec(),
                    expected_type: format!("numeric (u32): {}", e),
                }),
            },
            "DEFAULT_HOME" => match parse_bool(value_bytes) {
                Ok(v) => self.allow_login_if_no_home = v,
                Err(e) => warnings.push(LoginDefsWarning::InvalidValue {
                    key: key.to_string(),
                    value: value_bytes.to_vec(),
                    expected_type: format!("boolean: {}", e),
                }),
            },
            "FAILLOG_ENAB" => match parse_bool(value_bytes) {
                Ok(v) => self.faillog_enabled = v,
                Err(e) => warnings.push(LoginDefsWarning::InvalidValue {
                    key: key.to_string(),
                    value: value_bytes.to_vec(),
                    expected_type: format!("boolean: {}", e),
                }),
            },
            "LOG_OK_LOGINS" => match parse_bool(value_bytes) {
                Ok(v) => self.log_successful_logins_enabled = v,
                Err(e) => warnings.push(LoginDefsWarning::InvalidValue {
                    key: key.to_string(),
                    value: value_bytes.to_vec(),
                    expected_type: format!("boolean: {}", e),
                }),
            },
            "PREVENT_NO_AUTH" => match value_bytes.try_into() {
                Ok(policy) => self.prevent_no_auth_policy = policy,
                Err(warning) => warnings.push(warning),
            },
            "CONSOLE" => self.secure_tty_file_path = OsStr::from_bytes(value_bytes).to_os_string(), // `CONSOLE` is sometimes used for the secure TTY file path
            "ENV_TZ" => {
                self.environment_timezone = if value_bytes.is_empty() {
                    None
                } else {
                    Some(OsStr::from_bytes(value_bytes).to_os_string())
                }
            } // Can be an empty string
            "TTYGROUP" => {
                self.tty_group_name_or_id = if value_bytes.is_empty() {
                    None
                } else {
                    Some(OsStr::from_bytes(value_bytes).to_os_string())
                }
            } // Can be empty
            "TTYPERM" => match parse_numeric_flexible_radix::<u32>(value_bytes) {
                Ok(v) => self.tty_permissions = v,
                Err(e) => warnings.push(LoginDefsWarning::InvalidValue {
                    key: key.to_string(),
                    value: value_bytes.to_vec(),
                    expected_type: format!("numeric (u32): {}", e),
                }),
            },
            _ => {
                // Add a warning for unknown keys
                warnings.push(LoginDefsWarning::UnknownKey(key.to_string()));
            }
        }
    }
}

/// Trims leading/trailing ASCII whitespace from a byte slice.
fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let first = bytes
        .iter()
        .position(|&b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let last = bytes
        .iter()
        .rposition(|&b| !b.is_ascii_whitespace())
        .map_or(0, |p| p + 1); // if not found, 0 makes slice empty
    if first >= last {
        &[]
    } else {
        &bytes[first..last]
    }
}

/// Trims ASCII whitespace from start/end of line and removes text after the first '#' comment character.
fn trim_ascii_whitespace_and_comment(line_bytes: &[u8]) -> &[u8] {
    let mut data_end_pos = line_bytes.len();
    if let Some(comment_start_pos) = line_bytes.iter().position(|&b| b == b'#') {
        data_end_pos = comment_start_pos;
    }
    trim_ascii_whitespace(&line_bytes[0..data_end_pos])
}

/// Splits a line into key and value byte slices.
/// The split occurs on the first sequence of ASCII whitespace.
/// Assumes a non-empty string is passed
fn split_key_value(line_bytes: &[u8]) -> (&[u8], &[u8]) {
    debug_assert!(!line_bytes.is_empty());
    let mut parts = line_bytes.splitn(2, |&b| b.is_ascii_whitespace());
    let key = parts
        .next()
        .expect("Expected at least one non-whitespace initial byte");

    let value = parts.next().unwrap_or_default(); // value is optional but may have leading whitespace
    (key, trim_ascii_whitespace(value))
}

/// Parses a boolean value from bytes. "yes" (case-insensitive) is true.
/// All other values (including "no", garbage, or non-UTF8) result in false.
/// Returns a Result with an error message if the value is not valid UTF-8.
fn parse_bool(bytes: &[u8]) -> Result<bool, String> {
    match str::from_utf8(bytes) {
        Ok(s) => Ok(s.trim().eq_ignore_ascii_case("yes")),
        Err(_) => Err("Not valid UTF-8".to_string()),
    }
}

/// Helper trait for generic numeric parsing from string with radix.
trait RadixNum<T>: Sized {
    fn from_str_radix(s: &str, radix: u32) -> Result<T, String>;
}
impl RadixNum<u32> for u32 {
    fn from_str_radix(s: &str, radix: u32) -> Result<u32, String> {
        u32::from_str_radix(s, radix).map_err(|e| e.to_string())
    }
}
impl RadixNum<i32> for i32 {
    fn from_str_radix(s: &str, radix: u32) -> Result<i32, String> {
        i32::from_str_radix(s, radix).map_err(|e| e.to_string())
    }
}

/// Parses a numeric value that can be decimal, octal (0-prefix), or hex (0x-prefix).
fn parse_numeric_flexible_radix<T: RadixNum<T>>(bytes: &[u8]) -> Result<T, String> {
    let s = match str::from_utf8(bytes) {
        Ok(s_val) => s_val.trim(),
        Err(_) => return Err("Not valid UTF-8".to_string()),
    };

    if s.is_empty() {
        return Err("Empty string".to_string());
    }

    if s.starts_with("0x") || s.starts_with("0X") {
        if s.len() == 2 {
            return Err("Invalid hexadecimal number".to_string());
        }
        T::from_str_radix(&s[2..], 16)
    } else if s.starts_with('0') && s.len() > 1 {
        T::from_str_radix(s, 8)
    } else {
        T::from_str_radix(s, 10)
    }
}

/// Reads a line from the reader into the buffer, up to a maximum number of bytes.
///
/// Returns the number of bytes read. If the limit is reached before a newline,
/// it returns the limit. The buffer will contain the bytes read so far.
fn read_line_with_limit<R: BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    limit: usize,
) -> io::Result<usize> {
    let mut handle = reader.take(limit as u64);
    handle.read_until(b'\n', buf)
}

/// Consumes and discards bytes from the reader until a newline is found or EOF.
///
/// This function uses `fill_buf` to inspect the internal buffer of the `BufReader`
/// directly, ensuring that we stop exactly after the newline and do not discard
/// any subsequent data (like the next line) that might have been buffered.
fn consume_rest_of_line<R: BufRead>(reader: &mut R) -> io::Result<()> {
    loop {
        let available = reader.fill_buf()?;
        let length = available.len();
        if length == 0 {
            return Ok(()); // EOF
        }

        match available.iter().position(|&b| b == b'\n') {
            Some(i) => {
                reader.consume(i + 1);
                return Ok(());
            }
            None => {
                reader.consume(length);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_osstring(s: &str) -> OsString {
        OsString::from(s)
    }

    #[test]
    fn test_defaults() {
        let defs = LoginDefs::default();
        assert_eq!(defs.env_path, make_osstring("PATH=/bin:/usr/bin"));
        assert_eq!(defs.login_timeout_seconds, 60);
        assert_eq!(defs.default_umask, 0o022);
        assert_eq!(
            defs.prevent_no_auth_policy,
            PreventNoAuthPolicy::SuperuserOnly
        );
        assert_eq!(defs.password_warn_age_days, None);
        assert_eq!(defs.tty_permissions, 0o600);
        assert_eq!(defs.tty_group_name_or_id, None);
    }

    #[test]
    fn test_no_warnings_for_valid_values() {
        let data = "ENV_PATH\t/usr/local/bin:/usr/bin\n\
                    LOGIN_TIMEOUT 120\n\
                    LASTLOG_ENAB yes\n\
                    UMASK 022\n\
                    PREVENT_NO_AUTH yes";
        let result = LoginDefs::from_reader(Cursor::new(data));

        // Verify no warnings were generated
        assert!(
            result.warnings.is_empty(),
            "Expected no warnings, got: {:?}",
            result.warnings
        );

        // Verify values were correctly parsed
        assert_eq!(
            result.defs.env_path,
            make_osstring("/usr/local/bin:/usr/bin")
        );
        assert_eq!(result.defs.login_timeout_seconds, 120);
        assert_eq!(result.defs.lastlog_enabled, true);
        assert_eq!(result.defs.default_umask, 0o22);
        assert_eq!(result.defs.prevent_no_auth_policy, PreventNoAuthPolicy::Yes);
    }

    #[test]
    fn test_invalid_numeric_value_warning() {
        let data = "LOGIN_TIMEOUT abc\n\
                    LASTLOG_ENAB yes";
        let result = LoginDefs::from_reader(Cursor::new(data));

        // Verify we got exactly one warning
        assert_eq!(
            result.warnings.len(),
            1,
            "Expected 1 warning, got: {:?}",
            result.warnings
        );

        // Verify it's an InvalidValue warning for LOGIN_TIMEOUT
        match &result.warnings[0] {
            LoginDefsWarning::InvalidValue {
                key,
                value,
                expected_type,
            } => {
                assert_eq!(key, "LOGIN_TIMEOUT");
                assert_eq!(value, b"abc");
                assert!(
                    expected_type.contains("numeric (u32)"),
                    "Expected type should mention 'numeric (u32)', got: {}",
                    expected_type
                );
            }
            _ => panic!(
                "Expected InvalidValue warning, got: {:?}",
                result.warnings[0]
            ),
        }

        // Verify default value was retained for LOGIN_TIMEOUT
        assert_eq!(
            result.defs.login_timeout_seconds,
            LoginDefs::default().login_timeout_seconds
        );

        // Verify other values were still parsed correctly
        assert_eq!(result.defs.lastlog_enabled, true);
    }

    #[test]
    fn test_unknown_key_warning() {
        let data = "UNKNOWN_KEY some_value\n\
                    LOGIN_TIMEOUT 120";
        let result = LoginDefs::from_reader(Cursor::new(data));

        // Verify we got exactly one warning
        assert_eq!(
            result.warnings.len(),
            1,
            "Expected 1 warning, got: {:?}",
            result.warnings
        );

        // Verify it's an UnknownKey warning
        match &result.warnings[0] {
            LoginDefsWarning::UnknownKey(key) => {
                assert_eq!(key, "UNKNOWN_KEY");
            }
            _ => panic!("Expected UnknownKey warning, got: {:?}", result.warnings[0]),
        }

        // Verify known values were still parsed correctly
        assert_eq!(result.defs.login_timeout_seconds, 120);
    }

    #[test]
    fn test_multiple_warnings() {
        let data = "UNKNOWN_KEY1 some_value\n\
                    LOGIN_TIMEOUT invalid_number\n\
                    UNKNOWN_KEY2 another_value\n\
                    ENV_PATH /usr/bin";
        let result = LoginDefs::from_reader(Cursor::new(data));

        // Verify we got exactly 4 warnings
        assert_eq!(
            result.warnings.len(),
            3,
            "Expected 3 warnings, got: {:?}",
            result.warnings
        );

        // Count the different types of warnings
        let mut unknown_key_count = 0;
        let mut invalid_value_count = 0;

        for warning in &result.warnings {
            match warning {
                LoginDefsWarning::UnknownKey(_) => unknown_key_count += 1,
                LoginDefsWarning::InvalidValue { .. } => invalid_value_count += 1,
                _ => panic!("Unexpected warning type: {:?}", warning),
            }
        }

        assert_eq!(unknown_key_count, 2, "Expected 2 UnknownKey warnings");
        assert_eq!(invalid_value_count, 1, "Expected 1 InvalidValue warnings");

        // Verify known values were still parsed correctly
        assert_eq!(result.defs.env_path, make_osstring("/usr/bin"));

        // Verify default values were retained for invalid entries
        assert_eq!(
            result.defs.login_timeout_seconds,
            LoginDefs::default().login_timeout_seconds
        );
        assert_eq!(
            result.defs.lastlog_enabled,
            LoginDefs::default().lastlog_enabled
        );
    }

    #[test]
    fn test_simple_parsing() {
        let data = "ENV_PATH\t/usr/local/bin:/usr/bin\n\
                    LOGIN_TIMEOUT 120\n\
                    LASTLOG_ENAB yes\n\
                    FAILLOG_ENAB no\n\
                    UMASK 077\n\
                    PREVENT_NO_AUTH yes\n\
                    TTYPERM 0620";
        let defs = LoginDefs::from_reader(Cursor::new(data)).defs;

        assert_eq!(defs.env_path, make_osstring("/usr/local/bin:/usr/bin"));
        assert_eq!(defs.login_timeout_seconds, 120);
        assert_eq!(defs.lastlog_enabled, true);
        assert_eq!(defs.faillog_enabled, false); // "no" becomes false
        assert_eq!(defs.default_umask, 0o077); // Parsed as octal 77 (decimal 63)
        assert_eq!(defs.prevent_no_auth_policy, PreventNoAuthPolicy::Yes);
        assert_eq!(defs.tty_permissions, 0o0620); // Parsed as octal 620 (decimal 400)
    }

    #[test]
    fn test_comments_and_blanks() {
        let data = "\n\
                    # This is a full line comment\n\
                    LOGIN_RETRIES   5  # Inline comment\n\
                    \t  \n\
                    FAIL_DELAY\t10\n";
        let defs = LoginDefs::from_reader(Cursor::new(data)).defs;
        assert_eq!(defs.login_retries_max, 5);
        assert_eq!(defs.fail_delay_seconds, 10);
    }

    #[test]
    fn test_numeric_parsing_radix() {
        assert_eq!(parse_numeric_flexible_radix::<u32>(b"010").unwrap(), 8); // Octal
        assert_eq!(parse_numeric_flexible_radix::<u32>(b"10").unwrap(), 10); // Decimal
        assert_eq!(parse_numeric_flexible_radix::<u32>(b"0x10").unwrap(), 16); // Hex
        assert_eq!(parse_numeric_flexible_radix::<u32>(b"0").unwrap(), 0); // Decimal 0
        assert_eq!(parse_numeric_flexible_radix::<u32>(b"0x0").unwrap(), 0); // Hex 0
        assert_eq!(parse_numeric_flexible_radix::<i32>(b"-1").unwrap(), -1);
        assert_eq!(
            parse_numeric_flexible_radix::<u32>(b"  022 ").unwrap(),
            0o22
        ); // With spaces
        assert!(parse_numeric_flexible_radix::<u32>(b"0x").is_err()); // Incomplete hex
        assert!(parse_numeric_flexible_radix::<u32>(b"09").is_err()); // Invalid octal '9'
    }

    #[test]
    fn test_umask_parsing() {
        let data_octal = "UMASK 022";
        let defs_octal = LoginDefs::from_reader(Cursor::new(data_octal)).defs;
        assert_eq!(defs_octal.default_umask, 0o22); // 18 decimal

        let data_decimal = "UMASK 18";
        let defs_decimal = LoginDefs::from_reader(Cursor::new(data_decimal)).defs;
        assert_eq!(defs_decimal.default_umask, 18);

        let data_hex = "UMASK 0x12";
        let defs_hex = LoginDefs::from_reader(Cursor::new(data_hex)).defs;
        assert_eq!(defs_hex.default_umask, 0x12); // 18 decimal
    }

    #[test]
    fn test_boolean_parsing_variants() {
        assert_eq!(parse_bool(b"yes"), Ok(true));
        assert_eq!(parse_bool(b"YES"), Ok(true));
        assert_eq!(parse_bool(b"  yes  "), Ok(true));
        assert_eq!(parse_bool(b"no"), Ok(false));
        assert_eq!(parse_bool(b"NO"), Ok(false));
        assert_eq!(parse_bool(b"anythingelse"), Ok(false));
        assert_eq!(parse_bool(b""), Ok(false)); // Empty string is not "yes"
        let non_utf8_bytes = &[0xC3, 0x28]; // Invalid UTF-8
        assert!(parse_bool(non_utf8_bytes).is_err()); // Should return an error for invalid UTF-8
    }

    #[test]
    fn test_prevent_no_auth_policy_parsing() {
        let data_yes = "PREVENT_NO_AUTH yes";
        assert_eq!(
            LoginDefs::from_reader(Cursor::new(data_yes))
                .defs
                .prevent_no_auth_policy,
            PreventNoAuthPolicy::Yes
        );

        let data_superuser = "PREVENT_NO_AUTH superuser";
        assert_eq!(
            LoginDefs::from_reader(Cursor::new(data_superuser))
                .defs
                .prevent_no_auth_policy,
            PreventNoAuthPolicy::SuperuserOnly
        );

        let data_no = "PREVENT_NO_AUTH no";
        assert_eq!(
            LoginDefs::from_reader(Cursor::new(data_no))
                .defs
                .prevent_no_auth_policy,
            PreventNoAuthPolicy::Disabled
        );

        let data_invalid = "PREVENT_NO_AUTH foobar"; // Invalid value
        assert_eq!(
            LoginDefs::from_reader(Cursor::new(data_invalid))
                .defs
                .prevent_no_auth_policy,
            LoginDefs::default().prevent_no_auth_policy
        ); // Should keep default

        let data_empty = "PREVENT_NO_AUTH"; // Empty value
        assert_eq!(
            LoginDefs::from_reader(Cursor::new(data_empty))
                .defs
                .prevent_no_auth_policy,
            LoginDefs::default().prevent_no_auth_policy
        );
    }

    #[test]
    fn test_non_utf8_path() {
        let non_utf8_path_bytes = [b'/', 0xC3, 0x28, b'p', b'a', b't', b'h']; // Invalid UTF-8 sequence C3 28

        // Simulate reading raw bytes for the value part
        let mut input_data = b"MOTD_FILE\t".to_vec();
        input_data.extend_from_slice(&non_utf8_path_bytes);
        input_data.push(b'\n');

        let defs = LoginDefs::from_reader(Cursor::new(input_data)).defs;
        assert_eq!(
            defs.motd_file_path,
            OsStr::from_bytes(&non_utf8_path_bytes).to_os_string()
        );
    }

    #[test]
    fn test_empty_values_for_specific_fields() {
        let data = "ENV_TZ\n\
                    HUSHLOGIN_FILE\t\n\
                    TTYGROUP      "; // Key with effectively empty value after trimming
        let defs = LoginDefs::from_reader(Cursor::new(data)).defs;
        assert_eq!(defs.environment_timezone, None);
        assert_eq!(defs.hushlogin_file, None);
        assert_eq!(defs.tty_group_name_or_id, None);

        // Check that a numeric field with empty value keeps default
        let data_num_empty = "LOGIN_TIMEOUT\t";
        let defs_num_empty = LoginDefs::from_reader(Cursor::new(data_num_empty)).defs;
        assert_eq!(
            defs_num_empty.login_timeout_seconds,
            LoginDefs::default().login_timeout_seconds
        );
    }

    #[test]
    fn test_malformed_lines() {
        let data = "MALFORMED_KEY_ONLY\n\
                    \tLOGIN_TIMEOUT_GOOD 60\n\
                    "; // Key without subsequent value on same line (if split logic is strict)
        // My split_key_value gives empty slice for value if no whitespace.
        let defs = LoginDefs::from_reader(Cursor::new(data)).defs;
        // MALFORMED_KEY_ONLY's value would be empty. If it were a known numeric key, parse would fail, default remains.
        // If it were OsString, it'd be empty OsString.
        // Since it's not a known key, it's ignored.
        assert_eq!(defs.login_timeout_seconds, 60);
    }

    #[test]
    fn test_split_key_value_logic() {
        assert_eq!(split_key_value(b"KEY value"), (&b"KEY"[..], &b"value"[..]));
        assert_eq!(
            split_key_value(b"KEY\t value with spaces"),
            (&b"KEY"[..], &b"value with spaces"[..])
        );
        assert_eq!(split_key_value(b"KEYONLY"), (&b"KEYONLY"[..], &b""[..])); // Value is empty slice
    }

    #[test]
    fn test_trim_whitespace_and_comment() {
        assert_eq!(
            trim_ascii_whitespace_and_comment(b"  KEY val # comment"),
            b"KEY val"
        );
        assert_eq!(
            trim_ascii_whitespace_and_comment(b"KEY val#comment"),
            b"KEY val"
        );
        assert_eq!(trim_ascii_whitespace_and_comment(b"# Full comment"), b"");
        assert_eq!(
            trim_ascii_whitespace_and_comment(b"  # Indented comment"),
            b""
        );
        assert_eq!(
            trim_ascii_whitespace_and_comment(b"KEY_NO_VAL"),
            b"KEY_NO_VAL"
        );
        assert_eq!(trim_ascii_whitespace_and_comment(b""), b"");
        assert_eq!(trim_ascii_whitespace_and_comment(b"  \t "), b"");
    }

    #[test]
    fn test_load_existing_file() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create a temporary file with some login.defs content
        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        writeln!(temp_file, "LOGIN_TIMEOUT 120").expect("Failed to write to temp file");
        writeln!(temp_file, "LASTLOG_ENAB yes").expect("Failed to write to temp file");
        writeln!(temp_file, "UMASK 077").expect("Failed to write to temp file");

        // Load the configuration using the temporary file path
        let result = LoginDefs::load(temp_file.path());

        // Verify no warnings
        assert!(result.warnings.is_empty());

        // Verify the configuration was loaded correctly
        assert_eq!(result.defs.login_timeout_seconds, 120);
        assert_eq!(result.defs.lastlog_enabled, true);
        assert_eq!(result.defs.default_umask, 0o077);
    }

    #[test]
    fn test_load_nonexistent_file() {
        use tempfile::TempDir;

        // Create a temporary directory
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        // Create a path to a file that doesn't exist
        let nonexistent_path = temp_dir.path().join("nonexistent_file.defs");
        let nonexistent_path_str = nonexistent_path.to_string_lossy().to_string();

        // Load the configuration
        let result = LoginDefs::load(&nonexistent_path);

        // Verify we got a FileNotFound warning
        assert_eq!(result.warnings.len(), 1);
        match &result.warnings[0] {
            LoginDefsWarning::FileNotFound(path) => {
                assert_eq!(path, &nonexistent_path_str);
            }
            _ => panic!(
                "Expected FileNotFound warning, got {:?}",
                result.warnings[0]
            ),
        }

        // Verify we got default values
        assert_eq!(
            result.defs.login_timeout_seconds,
            LoginDefs::default().login_timeout_seconds
        );
    }

    #[test]
    fn test_load_permission_error() {
        use std::fs::Permissions;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use tempfile::NamedTempFile;

        // Create a temporary file with some login.defs content
        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        writeln!(temp_file, "LOGIN_TIMEOUT 120").expect("Failed to write to temp file");

        // Get the path as a string
        let temp_path = temp_file.path().to_string_lossy().to_string();

        // Make the file non-readable (this simulates a permission error)
        std::fs::set_permissions(temp_file.path(), Permissions::from_mode(0o000))
            .expect("Failed to set permissions");

        // Load the configuration
        let result = LoginDefs::load(temp_file.path());

        // Verify we got a FileOpenError warning
        assert_eq!(result.warnings.len(), 1);
        match &result.warnings[0] {
            LoginDefsWarning::FileOpenError { path, error: _ } => {
                assert_eq!(path, &temp_path);
            }
            _ => panic!(
                "Expected FileOpenError warning, got {:?}",
                result.warnings[0]
            ),
        }

        // Verify we got default values
        assert_eq!(result.defs, LoginDefs::default());

        // Reset permissions to allow cleanup
        std::fs::set_permissions(temp_file.path(), Permissions::from_mode(0o644))
            .expect("Failed to reset permissions");
    }

    #[test]
    fn test_io_error_during_read() {
        use std::io::{Error, ErrorKind, Read};

        // Create a reader that will return an IO error when read is called
        struct ErrorReader;
        impl Read for ErrorReader {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(Error::new(ErrorKind::Other, "Simulated IO error"))
            }
        }

        // Parse the configuration using our error-generating reader
        let result = LoginDefs::from_reader(ErrorReader);

        // Verify we got an IoErrorDuringRead warning
        assert_eq!(result.warnings.len(), 1);
        match &result.warnings[0] {
            LoginDefsWarning::IoErrorDuringRead(error) => {
                assert!(error.to_string().contains("Simulated IO error"));
            }
            _ => panic!(
                "Expected IoErrorDuringRead warning, got {:?}",
                result.warnings[0]
            ),
        }

        // Verify we got default values
        assert_eq!(result.defs, LoginDefs::default());
    }

    #[test]
    fn test_display_implementation() {
        let warning = LoginDefsWarning::InvalidKey("BAD_KEY".to_string());
        assert_eq!(warning.to_string(), "Invalid key found: BAD_KEY");

        let warning = LoginDefsWarning::FileNotFound("/etc/login.defs".to_string());
        assert_eq!(
            warning.to_string(),
            "Configuration file not found: /etc/login.defs"
        );
    }

    #[test]
    fn test_line_too_long() {
        // Create a line that is slightly longer than the limit
        let limit = LOGIN_DEFS_MAX_LINE_LENGTH;
        let mut long_line = vec![b'a'; limit];
        long_line.extend_from_slice(b" extra\n");
        let normal_line = b"LOGIN_TIMEOUT 30\n";

        let mut data = long_line;
        data.extend_from_slice(normal_line);

        let result = LoginDefs::from_reader(Cursor::new(data));

        // Should have 1 warning
        assert_eq!(result.warnings.len(), 1);
        match &result.warnings[0] {
            LoginDefsWarning::LineTooLong {
                line_number,
                max_length,
            } => {
                assert_eq!(*line_number, 1);
                assert_eq!(*max_length, limit);
            }
            _ => panic!("Expected LineTooLong warning"),
        }

        // The valid line should still be parsed
        assert_eq!(result.defs.login_timeout_seconds, 30);
    }

    #[test]
    fn test_duplicate_keys_last_wins() {
        let data = "LOGIN_TIMEOUT 60\n\
                    LOGIN_TIMEOUT 30\n";
        let result = LoginDefs::from_reader(Cursor::new(data));

        assert!(result.warnings.is_empty());
        assert_eq!(result.defs.login_timeout_seconds, 30);
    }

    #[test]
    fn test_key_with_no_value() {
        let data = "LOGIN_TIMEOUT\n\
                     HUSHLOGIN_FILE   \n"; // Trailing spaces but no value chars

        let result = LoginDefs::from_reader(Cursor::new(data));

        // LOGIN_TIMEOUT expects a numeric value. If the value part is empty,
        // parse_numeric_flexible_radix returns "Empty string" error.

        assert_eq!(result.warnings.len(), 1);
        match &result.warnings[0] {
            LoginDefsWarning::InvalidValue { key, .. } => {
                assert_eq!(key, "LOGIN_TIMEOUT");
            }
            _ => panic!("Expected InvalidValue warning"),
        }

        // Verify values:
        // TIMEOUT should be default (60)
        // HUSHLOGIN should be empty
        assert_eq!(result.defs.login_timeout_seconds, 60);
        assert_eq!(result.defs.hushlogin_file, None);
    }

    #[test]
    fn test_magic_values_to_option() {
        let data = "PASS_MAX_DAYS -1\n\
                    PASS_MIN_DAYS 0\n\
                    PASS_WARN_AGE -1\n\
                    ENV_TZ\n\
                    TTYGROUP\n\
                    HUSHLOGIN_FILE";
        let defs = LoginDefs::from_reader(Cursor::new(data)).defs;

        assert_eq!(defs.password_max_days, None);
        assert_eq!(defs.password_min_days, None);
        assert_eq!(defs.password_warn_age_days, None);
        assert_eq!(defs.environment_timezone, None);
        assert_eq!(defs.tty_group_name_or_id, None);
        assert_eq!(defs.hushlogin_file, None);

        // Test normal values
        let data_set = "PASS_MAX_DAYS 90\n\
                        PASS_MIN_DAYS 7\n\
                        PASS_WARN_AGE 14";
        let defs_set = LoginDefs::from_reader(Cursor::new(data_set)).defs;
        assert_eq!(defs_set.password_max_days, Some(90));
        assert_eq!(defs_set.password_min_days, NonZeroU32::new(7));
        assert_eq!(defs_set.password_warn_age_days, Some(14));
    }
}
