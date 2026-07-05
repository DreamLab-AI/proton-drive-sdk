//! Rendering — PRD §7.1 layout.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Clear, Gauge, List, ListItem, Paragraph};

use crate::app::{LoginField, LoginForm, Screen};
use crate::panes::{Focus, Pane, Panes};
use crate::transfer::{Transfer, TransferDirection, TransferState};

pub fn render(
    frame: &mut Frame<'_>,
    panes: &Panes,
    focus: Focus,
    screen: &Screen,
    status: Option<&str>,
    transfers: &[Transfer],
) {
    let area = frame.area();

    // Compute the height needed for the transfer panel (up to 3 rows each).
    let transfer_rows = transfers.len().min(3) as u16;
    // Each transfer: 1 label line + 1 gauge line = 2 rows, plus a 1-row heading.
    let transfer_height = if transfers.is_empty() {
        0
    } else {
        1 + transfer_rows * 2
    };

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),               // header
            Constraint::Min(1),                  // panes
            Constraint::Length(transfer_height), // transfer panel
            Constraint::Length(1),               // status
            Constraint::Length(1),               // key bar
        ])
        .split(area);

    render_header(frame, layout[0]);
    render_panes(frame, layout[1], panes, focus);
    if !transfers.is_empty() {
        render_transfers(frame, layout[2], transfers);
    }
    render_status(frame, layout[3], status);
    render_keybar(frame, layout[4], screen);

    // Login / auth overlay renders on top of everything else.
    match screen {
        Screen::Main => {}
        Screen::Login(form) => render_login_overlay(frame, area, form, false),
        Screen::Authenticating(_) => render_login_overlay(frame, area, &LoginForm::new(), true),
        Screen::SecondFactor(form) => render_second_factor_overlay(
            frame,
            area,
            form.username(),
            &form.code,
            form.error.as_deref(),
            false,
        ),
        Screen::SubmittingSecondFactor { pending, .. } => {
            render_second_factor_overlay(frame, area, pending.username(), "", None, true)
        }
    }
}

fn render_header(frame: &mut Frame<'_>, area: Rect) {
    let line = format!(" pdtui v{}  —  personal use", proton_drive::VERSION);
    frame.render_widget(Paragraph::new(line), area);
}

fn render_panes(frame: &mut Frame<'_>, area: Rect, panes: &Panes, focus: Focus) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    render_pane(frame, cols[0], &panes.local, "LOCAL", focus == Focus::Local);
    render_pane(
        frame,
        cols[1],
        &panes.remote,
        "REMOTE",
        focus == Focus::Remote,
    );
}

fn render_pane(frame: &mut Frame<'_>, area: Rect, pane: &Pane, label: &str, focused: bool) {
    let mut block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" {label}  {} ", pane.cwd.display()));
    if focused {
        block = block.border_style(Style::default().add_modifier(Modifier::BOLD));
    }

    if let Some(err) = &pane.error {
        let body = Paragraph::new(format!("\n  {err}")).block(block);
        frame.render_widget(body, area);
        return;
    }

    let items: Vec<ListItem<'_>> = pane
        .entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let marker = if i == pane.cursor { "▶ " } else { "  " };
            let sel = if e.selected { "*" } else { " " };
            let kind = if e.is_dir { "/" } else { " " };
            let size = e
                .size_bytes
                .map(human_bytes)
                .unwrap_or_else(|| "        -".to_owned());
            ListItem::new(Line::raw(format!(
                "{marker}{sel} {name}{kind:<1}  {size}",
                name = e.name
            )))
        })
        .collect();

    let list = List::new(items).block(block);
    frame.render_widget(list, area);
}

// ---------------------------------------------------------------------------
// Transfer panel
// ---------------------------------------------------------------------------

fn render_transfers(frame: &mut Frame<'_>, area: Rect, transfers: &[Transfer]) {
    if area.height == 0 {
        return;
    }

    // Heading row.
    let heading = Paragraph::new(" Transfers").style(Style::default().add_modifier(Modifier::BOLD));
    frame.render_widget(heading, Rect { height: 1, ..area });

    // Render up to 3 transfers, each taking 2 rows.
    let visible: Vec<&Transfer> = transfers.iter().rev().take(3).collect();
    for (i, t) in visible.iter().enumerate() {
        let row_y = area.y + 1 + (i as u16) * 2;
        if row_y + 1 >= area.y + area.height {
            break;
        }
        let label_area = Rect {
            x: area.x,
            y: row_y,
            width: area.width,
            height: 1,
        };
        let gauge_area = Rect {
            x: area.x,
            y: row_y + 1,
            width: area.width,
            height: 1,
        };
        render_transfer_row(frame, label_area, gauge_area, t);
    }
}

fn render_transfer_row(frame: &mut Frame<'_>, label_area: Rect, gauge_area: Rect, t: &Transfer) {
    let dir_icon = match t.direction {
        TransferDirection::Upload => "↑",
        TransferDirection::Download => "↓",
    };

    let state_text = match &t.state {
        TransferState::Pending => "pending".to_owned(),
        TransferState::Running => {
            let pct = (t.progress.fraction() * 100.0) as u64;
            let done = human_bytes(t.progress.bytes_done);
            match t.progress.bytes_total {
                Some(total) => format!("{}%  {} / {}", pct, done, human_bytes(total)),
                None => format!("{}  transferring…", done),
            }
        }
        TransferState::Completed => "completed".to_owned(),
        // Data is intact (every block's ciphertext hash matched) but the
        // manifest signature couldn't be verified against the signer's known
        // keys — surfaced distinctly rather than looking identical to a
        // fully authenticated download.
        TransferState::CompletedUnverified => "completed (signature unverified)".to_owned(),
        TransferState::Cancelled => "cancelled".to_owned(),
        TransferState::Failed(msg) => format!("failed: {msg}"),
    };

    let label_style = match &t.state {
        TransferState::Completed => Style::default().fg(Color::Green),
        TransferState::CompletedUnverified => Style::default().fg(Color::Yellow),
        TransferState::Failed(_) => Style::default().fg(Color::Red),
        TransferState::Cancelled => Style::default().fg(Color::DarkGray),
        _ => Style::default(),
    };

    let label_line = format!(" {dir_icon} {}  {state_text}", t.label);
    frame.render_widget(
        Paragraph::new(Span::styled(label_line, label_style)),
        label_area,
    );

    // Gauge — filled only while running; terminal states show full/empty bar.
    let ratio = match &t.state {
        TransferState::Completed | TransferState::CompletedUnverified => 1.0,
        TransferState::Cancelled | TransferState::Failed(_) => 0.0,
        _ => t.progress.fraction(),
    };

    let gauge_style = match &t.state {
        TransferState::Completed => Style::default().fg(Color::Green),
        TransferState::CompletedUnverified => Style::default().fg(Color::Yellow),
        TransferState::Failed(_) => Style::default().fg(Color::Red),
        TransferState::Cancelled => Style::default().fg(Color::DarkGray),
        _ => Style::default().fg(Color::Cyan),
    };

    let gauge = Gauge::default().gauge_style(gauge_style).ratio(ratio);

    frame.render_widget(gauge, gauge_area);
}

fn render_status(frame: &mut Frame<'_>, area: Rect, status: Option<&str>) {
    let text = status.unwrap_or(" idle");
    frame.render_widget(Paragraph::new(text), area);
}

fn render_keybar(frame: &mut Frame<'_>, area: Rect, screen: &Screen) {
    let text = match screen {
        Screen::Login(_) => " Tab next field   Enter submit   Esc cancel",
        Screen::Authenticating(_) => " Authenticating...   Esc cancel",
        Screen::SecondFactor(_) => " Enter submit code   Esc cancel login",
        Screen::SubmittingSecondFactor { .. } => " Validating code...   Esc cancel",
        Screen::Main => " F4 login   F3 upload   F2 download   F5 refresh   Tab switch   q quit",
    };
    frame.render_widget(Paragraph::new(text), area);
}

// ---------------------------------------------------------------------------
// Login overlay
// ---------------------------------------------------------------------------

fn render_login_overlay(frame: &mut Frame<'_>, area: Rect, form: &LoginForm, authenticating: bool) {
    const W: u16 = 54;
    const H: u16 = 10;
    let popup = centered_rect(W, H, area);

    frame.render_widget(Clear, popup);

    let title = if authenticating {
        " Authenticating... "
    } else {
        " Login — Proton Drive "
    };
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let cursor = if authenticating { "" } else { "▌" };
    let email_active = !authenticating && form.field == LoginField::Email;
    let pass_active = !authenticating && form.field == LoginField::Password;

    let email_val = if email_active {
        format!("{}{}", form.email, cursor)
    } else {
        form.email.clone()
    };
    let pass_val = if pass_active {
        format!("{}{}", "•".repeat(form.password.len()), cursor)
    } else {
        "•".repeat(form.password.len())
    };

    let active_style = Style::default().add_modifier(Modifier::BOLD);
    let normal_style = Style::default();

    let mut lines: Vec<Line<'_>> = vec![
        Line::raw(""),
        Line::from(vec![
            Span::styled(
                format!(" {} Email    : ", if email_active { "▶" } else { " " }),
                if email_active {
                    active_style
                } else {
                    normal_style
                },
            ),
            Span::raw(email_val),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled(
                format!(" {} Password : ", if pass_active { "▶" } else { " " }),
                if pass_active {
                    active_style
                } else {
                    normal_style
                },
            ),
            Span::raw(pass_val),
        ]),
        Line::raw(""),
    ];

    if authenticating {
        lines.push(Line::raw("  Authenticating, please wait..."));
    } else if let Some(err) = &form.error {
        lines.push(Line::from(Span::styled(
            format!("  {err}"),
            Style::default().fg(Color::Red),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "  Tab: next field   Enter: submit   Esc: cancel",
            Style::default().fg(Color::DarkGray),
        )));
    }

    frame.render_widget(Paragraph::new(Text::from(lines)), inner);
}

/// TOTP second-factor overlay. Rendered after SRP succeeds on a 2FA-enabled
/// account: one code field, in clear (a TOTP code expires within seconds and
/// is displayed on the user's own authenticator — masking it only hurts
/// entry).
fn render_second_factor_overlay(
    frame: &mut Frame<'_>,
    area: Rect,
    username: &str,
    code: &str,
    error: Option<&str>,
    submitting: bool,
) {
    const W: u16 = 54;
    const H: u16 = 9;
    let popup = centered_rect(W, H, area);

    frame.render_widget(Clear, popup);

    let title = if submitting {
        " Validating code... "
    } else {
        " Two-factor authentication "
    };
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let code_val = if submitting {
        code.to_owned()
    } else {
        format!("{code}▌")
    };

    let mut lines: Vec<Line<'_>> = vec![
        Line::raw(""),
        Line::raw(format!("  Account : {username}")),
        Line::raw(""),
        Line::from(vec![
            Span::styled(
                " ▶ Code     : ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(code_val),
        ]),
        Line::raw(""),
    ];

    if submitting {
        lines.push(Line::raw("  Validating second factor, please wait..."));
    } else if let Some(err) = error {
        lines.push(Line::from(Span::styled(
            format!("  {err}"),
            Style::default().fg(Color::Red),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "  Enter the code from your authenticator app",
            Style::default().fg(Color::DarkGray),
        )));
    }

    frame.render_widget(Paragraph::new(Text::from(lines)), inner);
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let x = area.x.saturating_add(area.width.saturating_sub(width) / 2);
    let y = area
        .y
        .saturating_add(area.height.saturating_sub(height) / 2);
    Rect {
        x,
        y,
        width: width.min(area.width),
        height: height.min(area.height),
    }
}

fn human_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:8.1} {}", UNITS[u])
}

#[cfg(test)]
mod tests {
    use super::human_bytes;

    #[test]
    fn formats_bytes() {
        assert!(human_bytes(0).contains("B"));
        assert!(human_bytes(512).contains("B"));
    }

    #[test]
    fn formats_kib() {
        assert!(human_bytes(2048).contains("KiB"));
    }

    #[test]
    fn formats_mib() {
        assert!(human_bytes(2 * 1024 * 1024).contains("MiB"));
    }

    #[test]
    fn formats_gib() {
        assert!(human_bytes(3 * 1024 * 1024 * 1024).contains("GiB"));
    }
}
