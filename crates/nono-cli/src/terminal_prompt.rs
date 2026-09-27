//! Guarded terminal input for security-sensitive line prompts.

use nix::libc;
use nono::{ApprovalDecision, NonoError, Result};
use std::io::{IsTerminal, Read, Write};
use std::os::fd::AsRawFd;
use std::time::Duration;

const CONSENT_INPUT_DELAY: Duration = Duration::from_secs(1);

/// Return whether a controlling terminal is available for a consent prompt.
pub(crate) fn consent_prompt_available() -> bool {
    open_tty().is_ok_and(|tty| tty.is_terminal())
}

/// Read a line from the controlling terminal after discarding type-ahead.
pub(crate) fn read_consent_line(prompt: &str) -> Result<String> {
    read_consent_line_from(open_tty()?, prompt, CONSENT_INPUT_DELAY)
}

pub(crate) enum ConsentInput {
    Terminal(String),
    Remote(ApprovalDecision),
}

pub(crate) fn read_consent_line_racing(
    prompt: &str,
    race: &crate::approval_race::ApprovalRace,
) -> Result<ConsentInput> {
    read_consent_line_inner(open_tty()?, prompt, CONSENT_INPUT_DELAY, Some(race))
}

fn open_tty() -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(NonoError::Io)
}

fn read_consent_line_from(tty: std::fs::File, prompt: &str, delay: Duration) -> Result<String> {
    match read_consent_line_inner(tty, prompt, delay, None)? {
        ConsentInput::Terminal(line) => Ok(line),
        ConsentInput::Remote(_) => unreachable!("no remote responder was supplied"),
    }
}

fn read_consent_line_inner(
    mut tty: std::fs::File,
    prompt: &str,
    delay: Duration,
    race: Option<&crate::approval_race::ApprovalRace>,
) -> Result<ConsentInput> {
    let saved = nix::sys::termios::tcgetattr(&tty).map_err(termios_error)?;
    let restore_tty = tty.try_clone().map_err(NonoError::Io)?;
    let _guard = TermiosRestoreGuard {
        tty: restore_tty,
        saved: saved.clone(),
    };

    let mut prompt_termios = saved;
    configure_line_input(&mut prompt_termios);
    nix::sys::termios::tcsetattr(&tty, nix::sys::termios::SetArg::TCSANOW, &prompt_termios)
        .map_err(termios_error)?;

    write!(tty, "Input enables in 1 second · early keys ignored").map_err(NonoError::Io)?;
    tty.flush().map_err(NonoError::Io)?;
    let enables = std::time::Instant::now() + delay;
    while std::time::Instant::now() < enables {
        if let Some(input) = race.and_then(|race| take_remote_answer(&mut tty, race)) {
            return Ok(input);
        }
        check_cancelled()?;
        std::thread::sleep(
            Duration::from_millis(20)
                .min(enables.saturating_duration_since(std::time::Instant::now())),
        );
    }
    if let Some(input) = race.and_then(|race| take_remote_answer(&mut tty, race)) {
        return Ok(input);
    }
    check_cancelled()?;

    nix::sys::termios::tcflush(&tty, nix::sys::termios::FlushArg::TCIFLUSH)
        .map_err(termios_error)?;
    write!(tty, "\r\x1b[2K{prompt}").map_err(NonoError::Io)?;
    tty.flush().map_err(NonoError::Io)?;

    let mut input = Vec::new();
    loop {
        if let Some(input) = race.and_then(|race| take_remote_answer(&mut tty, race)) {
            return Ok(input);
        }
        check_cancelled()?;
        // select supports the macOS controlling-terminal device, which rejects poll.
        let fd = tty.as_raw_fd();
        if fd < 0 || fd as usize >= libc::FD_SETSIZE {
            return Err(NonoError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Approval terminal descriptor exceeds select limit",
            )));
        }
        // SAFETY: fd is owned by tty and checked against fd_set's fixed capacity.
        let ready = unsafe {
            let mut readable: libc::fd_set = std::mem::zeroed();
            libc::FD_ZERO(&mut readable);
            libc::FD_SET(fd, &mut readable);
            let mut timeout = libc::timeval {
                tv_sec: 0,
                tv_usec: 50_000,
            };
            libc::select(
                fd + 1,
                &mut readable,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut timeout,
            )
        };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(NonoError::Io(error));
        }
        if ready == 0 {
            continue;
        }
        if let Some(input) = race.and_then(|race| take_remote_answer(&mut tty, race)) {
            return Ok(input);
        }
        check_cancelled()?;
        let mut byte = [0];
        if tty.read(&mut byte).map_err(NonoError::Io)? == 0 {
            break;
        }
        input.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
        if input.len() > 4096 {
            return Err(NonoError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Approval response too long",
            )));
        }
    }
    if let Some(input) = race.and_then(|race| take_remote_answer(&mut tty, race)) {
        return Ok(input);
    }
    check_cancelled()?;
    Ok(ConsentInput::Terminal(
        String::from_utf8_lossy(&input).into_owned(),
    ))
}

fn race_answer(race: &crate::approval_race::ApprovalRace) -> Option<ApprovalDecision> {
    match race.poll() {
        crate::approval_race::RacePoll::Answer(decision)
        | crate::approval_race::RacePoll::Exhausted(decision) => Some(decision),
        crate::approval_race::RacePoll::Expired => Some(ApprovalDecision::Timeout),
        crate::approval_race::RacePoll::Pending => None,
    }
}

fn take_remote_answer(
    tty: &mut std::fs::File,
    race: &crate::approval_race::ApprovalRace,
) -> Option<ConsentInput> {
    let decision = race_answer(race)?;
    let _ = nix::sys::termios::tcflush(&mut *tty, nix::sys::termios::FlushArg::TCIFLUSH);
    let _ = write!(tty, "\r\x1b[2K");
    let _ = tty.flush();
    Some(ConsentInput::Remote(decision))
}

fn check_cancelled() -> Result<()> {
    if crate::approval_terminal_handoff::cancelled() {
        return Err(NonoError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "Approval cancelled or expired",
        )));
    }
    Ok(())
}

fn termios_error(error: nix::errno::Errno) -> NonoError {
    NonoError::Io(std::io::Error::from_raw_os_error(error as i32))
}

fn configure_line_input(termios: &mut nix::sys::termios::Termios) {
    use nix::sys::termios::{
        ControlFlags, InputFlags, LocalFlags, OutputFlags, SpecialCharacterIndices,
    };

    termios.input_flags.remove(
        InputFlags::IGNBRK
            | InputFlags::BRKINT
            | InputFlags::PARMRK
            | InputFlags::ISTRIP
            | InputFlags::INLCR
            | InputFlags::IGNCR,
    );
    termios
        .input_flags
        .insert(InputFlags::ICRNL | InputFlags::IXON);
    termios.output_flags.insert(OutputFlags::OPOST);
    termios.local_flags.insert(
        LocalFlags::ECHO
            | LocalFlags::ECHONL
            | LocalFlags::ICANON
            | LocalFlags::ISIG
            | LocalFlags::IEXTEN,
    );
    termios
        .control_flags
        .remove(ControlFlags::CSIZE | ControlFlags::PARENB);
    termios.control_flags.insert(ControlFlags::CS8);
    termios.control_chars[SpecialCharacterIndices::VMIN as usize] = 1;
    termios.control_chars[SpecialCharacterIndices::VTIME as usize] = 0;
}

struct TermiosRestoreGuard {
    tty: std::fs::File,
    saved: nix::sys::termios::Termios,
}

impl Drop for TermiosRestoreGuard {
    fn drop(&mut self) {
        let _ = nix::sys::termios::tcsetattr(
            &self.tty,
            nix::sys::termios::SetArg::TCSANOW,
            &self.saved,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::pty::{OpenptyResult, openpty};

    #[test]
    fn compat_terminal_timeout_stops_reader_and_restores_line_settings() {
        let OpenptyResult {
            master: _master,
            slave,
        } = openpty(None, None).expect("openpty");
        let original = nix::sys::termios::tcgetattr(&slave).expect("original termios");
        let reader = nix::unistd::dup(&slave).expect("reader fd");
        let (sender, receiver) = std::sync::mpsc::channel();
        let decision = crate::approval_terminal_handoff::run_with_timeout(
            Duration::from_millis(50),
            move || {
                let result = read_consent_line_from(
                    std::fs::File::from(reader),
                    "Continue? ",
                    Duration::ZERO,
                );
                assert!(result.is_err());
                sender.send(()).expect("reader returned");
                Ok(nono::ApprovalDecision::Timeout)
            },
        )
        .expect("deadline result");
        assert!(!decision.is_granted());
        receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("no orphan reader");
        assert_eq!(
            nix::sys::termios::tcgetattr(&slave).expect("restored termios"),
            original
        );
    }

    #[test]
    fn consent_reader_discards_early_input_and_accepts_fresh_response() {
        let OpenptyResult { master, slave } = openpty(None, None).expect("openpty");
        nix::unistd::write(&master, b"y\n").expect("queue early approval");

        let writer_master = nix::unistd::dup(&master).expect("duplicate pty master");
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            nix::unistd::write(writer_master, b"n\n").expect("write fresh response");
        });

        let response = read_consent_line_from(
            std::fs::File::from(slave),
            "Continue? [y/N] ",
            Duration::ZERO,
        )
        .expect("read guarded response");
        writer.join().expect("join response writer");

        assert_eq!(response.trim(), "n");
    }
}
