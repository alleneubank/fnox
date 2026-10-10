//! Authentication prompt handling for providers.
//!
//! When a provider fails due to authentication issues, this module handles
//! prompting the user to run the appropriate auth command and retrying.

use crate::config::Config;
use crate::error::{FnoxError, Result};
use crate::providers::ProviderConfig;
use demand::Confirm;
use std::io::IsTerminal;
use std::process::Command;

/// Prompts the user to run an auth command and executes it if they agree.
///
/// Returns `Ok(true)` if the auth command was run successfully,
/// `Ok(false)` if the user declined or no auth command is available,
/// `Err` if the auth command failed.
pub fn prompt_and_run_auth(
    config: &Config,
    provider_config: &ProviderConfig,
    provider_name: &str,
    error: &FnoxError,
) -> Result<bool> {
    if !error.is_auth_error() {
        return Ok(false);
    }

    if !config.should_prompt_auth() {
        return Ok(false);
    }

    let Some(auth_command) = provider_config.default_auth_command() else {
        return Ok(false);
    };

    // Show the error and prompt
    eprintln!(
        "Authentication failed for provider '{}': {}",
        provider_name, error
    );

    // A configured auth_command can embed credentials, so none of it is shown.
    let user_confirmed = Confirm::new(format!(
        "Run the auth command for provider '{provider_name}' to authenticate?"
    ))
    .affirmative("Yes")
    .negative("No")
    .run()
    .map_err(|e| FnoxError::Provider(format!("Failed to show prompt: {}", e)))?;

    if !user_confirmed {
        return Ok(false);
    }

    // Run the auth command
    eprintln!("Running the auth command for provider '{provider_name}'");

    let status = run_auth_command(auth_command);

    match status {
        Ok(exit_status) if exit_status.success() => {
            eprintln!("Authentication successful, retrying...");
            Ok(true)
        }
        Ok(exit_status) => Err(FnoxError::Provider(format!(
            "Auth command failed with exit code: {}",
            exit_status.code().unwrap_or(-1)
        ))),
        Err(e) => Err(FnoxError::Provider(format!(
            "Failed to run auth command: {}",
            e
        ))),
    }
}

// WAIVER(provider output stays off stderr): the auth command's stderr is
// inherited, and when fnox's stderr is a terminal its stdout is shown there
// too, so a token it prints (bw unlock --raw, op signin) reaches the screen of
// the user who just confirmed running it, as if they had run it themselves.
// aws sso login prints its device code on stdout and interactive logins prompt
// on stderr, so withholding either breaks them. When stderr is not a terminal,
// stdout is discarded. Permanent — the only alternative breaks interactive logins.
fn run_auth_command(auth_command: &str) -> std::io::Result<std::process::ExitStatus> {
    let (shell, flag) = if cfg!(target_os = "windows") {
        ("cmd", "/C")
    } else {
        ("sh", "-c")
    };
    let stdout = if std::io::stderr().is_terminal() {
        std::process::Stdio::from(std::io::stderr())
    } else {
        std::process::Stdio::null()
    };
    Command::new(shell)
        .args([flag, auth_command])
        .stdout(stdout)
        .status()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ProviderDetails;
    use crate::providers::OptionStringOrSecretRef;

    fn provider_with_auth_command() -> ProviderConfig {
        ProviderConfig::OnePassword {
            vault: OptionStringOrSecretRef::literal("default"),
            account: OptionStringOrSecretRef::none(),
            token: OptionStringOrSecretRef::none(),
            auth_command: None,
            daemon_cache: None,
        }
    }

    // Integration-level: non-auth errors return Ok(false) from prompt_and_run_auth
    #[test]
    fn non_auth_error_skips_prompt() {
        let config = Config::new();
        let provider_config = provider_with_auth_command();
        let error = FnoxError::ProviderSecretNotFound {
            provider: "test".to_string(),
            secret: "MY_SECRET".to_string(),
            hint: "check".to_string(),
            url: "https://example.com".to_string(),
        };
        let result = prompt_and_run_auth(&config, &provider_config, "1password", &error);
        assert!(!result.unwrap());
    }

    #[test]
    fn cli_failed_error_skips_prompt() {
        let config = Config::new();
        let provider_config = provider_with_auth_command();
        let error = FnoxError::ProviderCliFailed {
            provider: "test".to_string(),
            details: ProviderDetails::authored("field does not exist"),
            hint: "check".to_string(),
            url: "https://example.com".to_string(),
        };
        let result = prompt_and_run_auth(&config, &provider_config, "1password", &error);
        assert!(!result.unwrap());
    }

    #[test]
    fn auth_command_stdout_is_dropped_when_stderr_is_not_a_terminal() {
        const CHILD_ENV: &str = "FNOX_TEST_AUTH_COMMAND_STDOUT";
        const MARKER: &str = "auth-command-output-marker";

        if std::env::var(CHILD_ENV).ok().as_deref() == Some("1") {
            run_auth_command(&format!("echo {MARKER}")).unwrap();
            return;
        }

        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "auth_prompt::tests::auth_command_stdout_is_dropped_when_stderr_is_not_a_terminal",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .output()
            .unwrap();

        assert!(output.status.success());
        assert!(!String::from_utf8_lossy(&output.stdout).contains(MARKER));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(MARKER));
    }
}
