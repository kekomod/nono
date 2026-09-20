//! In-process handoff of worker approvals to the supervisor's terminal owner.
//! No policy decisions are made here; expiry and unavailable UI fail closed.
use nix::libc;
use nono::{ApprovalBackend, ApprovalDecision, ApprovalRequest, Result};
use std::cell::RefCell;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc,
};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

static SESSION: Mutex<Option<Session>> = Mutex::new(None);
static INTERRUPTS: AtomicU64 = AtomicU64::new(0);
thread_local! { static CONTEXT: RefCell<Option<Context>> = const { RefCell::new(None) }; }
#[derive(Clone)]
struct Context {
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
    interrupt: u64,
    child: i32,
}
struct Pending {
    request: ApprovalRequest,
    context: Context,
    reply: mpsc::SyncSender<Result<ApprovalDecision>>,
}
struct Session {
    owner: ThreadId,
    sender: mpsc::SyncSender<Pending>,
    child: i32,
}
pub(crate) struct Owner {
    receiver: mpsc::Receiver<Pending>,
}

pub(crate) fn interrupted() {
    INTERRUPTS.fetch_add(1, Ordering::SeqCst);
}

pub(crate) fn register(child: i32) -> Owner {
    let (sender, receiver) = mpsc::sync_channel(16);
    if let Ok(mut session) = SESSION.lock() {
        *session = Some(Session {
            owner: std::thread::current().id(),
            sender,
            child,
        });
    }
    Owner { receiver }
}
impl Drop for Owner {
    fn drop(&mut self) {
        if let Ok(mut session) = SESSION.lock() {
            *session = None;
        }
    }
}

struct ContextGuard(Option<Context>);
impl Drop for ContextGuard {
    fn drop(&mut self) {
        CONTEXT.with(|slot| {
            slot.replace(self.0.take());
        });
    }
}
fn enter(context: Context) -> ContextGuard {
    ContextGuard(CONTEXT.with(|slot| slot.replace(Some(context))))
}

/// Preserve the original approval deadline across webhook chains and queued UI.
pub(crate) fn run_with_timeout<F>(timeout: Duration, f: F) -> Result<ApprovalDecision>
where
    F: FnOnce() -> Result<ApprovalDecision> + Send + 'static,
{
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return Ok(ApprovalDecision::Timeout);
    };
    let context = Context {
        deadline,
        cancelled: Arc::new(AtomicBool::new(false)),
        interrupt: INTERRUPTS.load(Ordering::SeqCst),
        child: 0,
    };
    let deadline = context.deadline;
    let cancellation = context.cancelled.clone();
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _guard = enter(context);
        let _ = sender.send(f());
    });
    let result = receiver
        .recv_timeout(timeout)
        .unwrap_or(Ok(ApprovalDecision::Timeout));
    cancellation.store(true, Ordering::SeqCst);
    if Instant::now() >= deadline {
        Ok(ApprovalDecision::Timeout)
    } else {
        result
    }
}

pub(crate) fn cancelled() -> bool {
    CONTEXT.with(|slot| slot.borrow().as_ref().is_some_and(expired))
}
fn expired(context: &Context) -> bool {
    if Instant::now() >= context.deadline
        || context.cancelled.load(Ordering::SeqCst)
        || context.interrupt != INTERRUPTS.load(Ordering::SeqCst)
    {
        return true;
    }
    if context.child > 0 {
        // Observe exit without consuming the supervisor's wait status.
        // SAFETY: siginfo_t is a C POD output buffer initialized before waitid.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: valid output pointer; WNOWAIT does not reap the owned child.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                context.child as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        // SAFETY: waitid initialized the SIGCHLD union on successful return.
        if result == 0 && unsafe { info.si_pid() } != 0 {
            return true;
        }
        if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
            return true;
        }
    }
    false
}

/// None means this thread already owns the terminal (or no session relay exists).
pub(crate) fn request(request: &ApprovalRequest) -> Option<Result<ApprovalDecision>> {
    let (sender, child) = {
        let Ok(session) = SESSION.lock() else {
            return Some(Ok(ApprovalDecision::Timeout));
        };
        let Some(session) = session.as_ref() else {
            return CONTEXT.with(|slot| {
                slot.borrow()
                    .as_ref()
                    .map(|_| Ok(ApprovalDecision::Timeout))
            });
        };
        if session.owner == std::thread::current().id() {
            return None;
        }
        (session.sender.clone(), session.child)
    };
    let mut context = CONTEXT
        .with(|slot| slot.borrow().clone())
        .unwrap_or(Context {
            deadline: Instant::now() + Duration::from_secs(60),
            cancelled: Arc::new(AtomicBool::new(false)),
            interrupt: INTERRUPTS.load(Ordering::SeqCst),
            child,
        });
    context.child = child;
    if expired(&context) {
        return Some(Ok(ApprovalDecision::Timeout));
    }
    let (reply, receiver) = mpsc::sync_channel(1);
    let deadline = context.deadline;
    let cancelled = context.cancelled.clone();
    if sender
        .try_send(Pending {
            request: request.clone(),
            context,
            reply,
        })
        .is_err()
    {
        return Some(Ok(ApprovalDecision::Denied {
            reason: "Terminal approval queue unavailable".into(),
        }));
    }
    Some(
        match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(result) => result,
            Err(_) => {
                cancelled.store(true, Ordering::SeqCst);
                Ok(ApprovalDecision::Timeout)
            }
        },
    )
}

struct RelayGuard<'a>(Option<&'a mut crate::pty_proxy::PtyProxy>);
impl Drop for RelayGuard<'_> {
    fn drop(&mut self) {
        if let Some(pty) = self.0.as_mut() {
            pty.resume_terminal_after_prompt();
        }
    }
}
impl Owner {
    /// Called by the existing 200ms supervisor poll loop; process one UI at a time.
    pub(crate) fn service(&self, pty: Option<&mut crate::pty_proxy::PtyProxy>) {
        let Ok(pending) = self.receiver.try_recv() else {
            return;
        };
        if expired(&pending.context) {
            let _ = pending.reply.send(Ok(ApprovalDecision::Timeout));
            return;
        }
        let guard = match pty {
            Some(pty) => {
                if pty.pause_terminal_for_prompt() {
                    RelayGuard(Some(pty))
                } else {
                    let _ = pending.reply.send(Ok(ApprovalDecision::Denied {
                        reason: "No attached terminal for approval".into(),
                    }));
                    return;
                }
            }
            None => RelayGuard(None),
        };
        let _context = enter(pending.context.clone());
        let result = crate::terminal_approval::TerminalApproval.request_approval(&pending.request);
        let result = if expired(&pending.context) {
            Ok(ApprovalDecision::Timeout)
        } else {
            result
        };
        drop(guard);
        let _ = pending.reply.send(result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compat_terminal_chain_completion_preserves_next_backend() {
        // The coordinator is process-local; isolate this owner fixture from other tests.
        if std::env::var_os("NONO_COMPAT_HANDOFF_CHILD").is_none() {
            let status = std::process::Command::new(std::env::current_exe().expect("test binary"))
                .args(["--exact", "approval_terminal_handoff::tests::compat_terminal_chain_completion_preserves_next_backend"])
                .env("NONO_COMPAT_HANDOFF_CHILD", "1").status().expect("isolated coordinator");
            assert!(status.success());
            return;
        }
        let owner = register(0);
        let worker = std::thread::spawn(|| {
            run_with_timeout(Duration::from_secs(2), || {
                let action = ApprovalRequest::Command {
                    request_id: "same-native-request".into(),
                    command: "echo".into(),
                    args: vec!["echo".into()],
                    caller: "session".into(),
                    intercept_rule: "fixture".into(),
                    reason: None,
                    child_pid: 0,
                    session_id: "fixture".into(),
                };
                assert!(
                    !request(&action)
                        .expect("queued first backend")?
                        .is_granted()
                );
                request(&action).expect("queued second backend")
            })
        });
        let first = owner
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("first request");
        first
            .reply
            .send(Ok(ApprovalDecision::Denied {
                reason: "first native backend denied".into(),
            }))
            .expect("first reply");
        let second = owner
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("second backend still active");
        assert!(!expired(&second.context));
        assert_eq!(first.request.request_id(), second.request.request_id());
        second
            .reply
            .send(Ok(ApprovalDecision::Granted))
            .expect("second reply");
        assert!(
            worker
                .join()
                .expect("worker")
                .expect("native decision")
                .is_granted()
        );
    }

    #[test]
    fn compat_terminal_deadline_cancels_worker_and_rejects_late_grant() {
        let (sender, receiver) = mpsc::channel();
        let result = run_with_timeout(Duration::from_millis(30), move || {
            while !cancelled() {
                std::thread::sleep(Duration::from_millis(2));
            }
            sender.send(()).expect("worker stopped reading");
            Ok(ApprovalDecision::Timeout)
        })
        .expect("deadline decision");
        assert!(!result.is_granted());
        receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("cancelled worker exits");
        assert!(!cancelled(), "worker context must not leak to caller");
    }

    #[test]
    fn compat_terminal_child_exit_is_observed_without_reaping() {
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()
            .expect("disposable child");
        let context = Context {
            deadline: Instant::now() + Duration::from_secs(2),
            cancelled: Arc::new(AtomicBool::new(false)),
            interrupt: INTERRUPTS.load(Ordering::SeqCst),
            child: child.id() as i32,
        };
        let started = Instant::now();
        while !expired(&context) && started.elapsed() < Duration::from_secs(1) {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(expired(&context));
        assert!(child.wait().expect("owner still reaps child").success());
    }
}
