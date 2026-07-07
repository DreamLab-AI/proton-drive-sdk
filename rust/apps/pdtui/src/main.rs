//! `pdtui` — two-pane Proton Drive browser (local | remote).
//!
//! Personal use only (ADR-0007). Run from source: `cargo run -p pdtui`.
//!
//! Subcommands:
//!   pdtui            launch the TUI
//!   pdtui login      authenticate via SRP and persist the session to the keyring
//!   pdtui mvp        headless live round-trip: list, upload, byte-identical download
//!   pdtui mcp        serve the Model Context Protocol over stdio (agentic control
//!                    and hash-based local/remote sync, ADR-0013)
//!   pdtui probe      run live-API diagnostic probes against the configured
//!                    session, print one JSON object per probe to stdout
//!   pdtui logout     clear the keyring entry and truncate session.json
//!   pdtui where      print where the session config file should live

#![forbid(unsafe_code)]

mod account;
mod app;
mod auth;
mod events_bridge;
mod http;
mod keymap;
mod mcp;
mod mvp;
mod panes;
mod probe;
mod session;
mod transfer;
mod ui;

use std::io;
use std::process::ExitCode;
use std::sync::Arc;

use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    init_tracing();
    info!(version = proton_drive::VERSION, "pdtui starting");

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("login") => run_login().await,
        Some("mvp") => run_mvp().await,
        Some("mcp") => run_mcp().await,
        Some("probe") => run_probe().await,
        Some("logout") => run_logout().await,
        Some("where") => {
            println!("{}", session::Session::config_path().display());
            ExitCode::SUCCESS
        }
        Some("help") | Some("--help") | Some("-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("unknown subcommand: {other}");
            print_help();
            ExitCode::from(2)
        }
        None => run_tui().await,
    }
}

fn print_help() {
    println!(
        "pdtui v{version}

USAGE:
    pdtui                 launch the TUI
    pdtui login           authenticate via SRP and persist session
    pdtui mvp             live round-trip: list root, upload + download a file
    pdtui mcp             serve the MCP tool surface over stdio (agent control)
    pdtui probe           run live-API diagnostic probes (M1 + M3 e2e)
    pdtui logout          clear keyring + truncate session.json
    pdtui where           print where the session config file should live
    pdtui help            show this help

CONFIG:
    Session: $XDG_CONFIG_HOME/pdtui/session.json (or ~/.config/pdtui/session.json)
    Keyring: OS secret-service (Linux) / Keychain (macOS) under service 'pdtui-proton-drive'
    Logs:    set PDTUI_LOG=debug for verbose output
",
        version = proton_drive::VERSION
    );
}

async fn run_login() -> ExitCode {
    let base_url = "https://drive.proton.me/api";
    let app_version = format!("external-drive-pdtui@{}-stable", proton_drive::VERSION);
    match auth::login_interactive(base_url, &app_version).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("login failed: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run_mvp() -> ExitCode {
    match mvp::run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mvp failed: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run_mcp() -> ExitCode {
    // stdout is the MCP transport — never print to it on this path; the tracing
    // subscriber (init_tracing) writes diagnostics to stderr.
    match mcp::run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mcp failed: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run_probe() -> ExitCode {
    let session = match session::Session::load() {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "no session loaded ({e}).\n\nCreate {} containing:\n  {{\"AccessToken\": \"...\", \"UID\": \"...\"}}\n",
                session::Session::config_path().display()
            );
            return ExitCode::from(2);
        }
    };
    let client = match http::ReqwestHttpClient::new(&session.base_url, &session.app_version) {
        Ok(c) => Arc::new(c) as Arc<dyn proton_drive::ProtonDriveHttpClient>,
        Err(e) => {
            eprintln!("http client init: {e}");
            return ExitCode::FAILURE;
        }
    };
    let results = probe::run_all(client, &session).await;
    let any_fail = results.iter().any(|r| !r.ok);
    for r in &results {
        match serde_json::to_string(r) {
            Ok(line) => println!("{line}"),
            Err(e) => eprintln!("serialize probe result: {e}"),
        }
    }
    if any_fail {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

async fn run_logout() -> ExitCode {
    let session = match session::Session::load() {
        Ok(s) => s,
        Err(_) => {
            println!("no active session — nothing to log out");
            return ExitCode::SUCCESS;
        }
    };
    let http = match http::ReqwestHttpClient::new(&session.base_url, &session.app_version) {
        Ok(c) => Arc::new(c) as Arc<dyn proton_drive::ProtonDriveHttpClient>,
        Err(e) => {
            eprintln!("http client init: {e}");
            return ExitCode::FAILURE;
        }
    };
    match session::SessionManager::from_keyring(http).await {
        Ok(mgr) => match mgr.logout().await {
            Ok(()) => {
                println!("logged out: keyring entry deleted, session.json truncated");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("logout failed: {e}");
                ExitCode::FAILURE
            }
        },
        Err(e) => {
            eprintln!("could not load session to log out: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run_tui() -> ExitCode {
    // Restore the terminal on panic before the default hook prints the message,
    // otherwise raw mode + alternate screen leave the user's shell unusable.
    install_panic_hook();

    let mut term = match enter_terminal() {
        Ok(t) => t,
        Err(e) => {
            error!(error = %e, "terminal setup failed");
            return ExitCode::FAILURE;
        }
    };
    let result = app::App::new().run(&mut term).await;
    if let Err(e) = leave_terminal(&mut term) {
        error!(error = %e, "terminal cleanup failed");
    }
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pdtui exited with error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("PDTUI_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .try_init();
}

type Term = Terminal<CrosstermBackend<io::Stdout>>;

fn enter_terminal() -> io::Result<Term> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend)
}

fn leave_terminal(term: &mut Term) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(
        term.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture,
    )?;
    term.show_cursor()?;
    Ok(())
}

/// Install a panic hook that best-effort restores the terminal (leaves raw
/// mode and the alternate screen) before delegating to the previous hook, so a
/// panic inside the TUI does not leave the user's shell garbled.
fn install_panic_hook() {
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
        original(info);
    }));
}
