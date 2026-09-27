//! First-human-response coordination for opt-in approval backend races.
use nono::ApprovalDecision;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub(crate) enum RacePoll {
    Pending,
    Answer(ApprovalDecision),
    Expired,
    Exhausted(ApprovalDecision),
}

enum State {
    Pending {
        remaining: usize,
        failures: Vec<String>,
    },
    Answer(ApprovalDecision),
    Expired,
    Exhausted(ApprovalDecision),
}

/// Shared first-answer state. Errors and unavailable responders retire only
/// their own branch; they never turn into an implicit human denial.
pub(crate) struct ApprovalRace {
    deadline: Instant,
    state: Mutex<State>,
    changed: Condvar,
}

impl ApprovalRace {
    pub(crate) fn new(timeout: Duration, branches: usize) -> Self {
        let started = Instant::now();
        Self {
            deadline: started.checked_add(timeout).unwrap_or(started),
            state: Mutex::new(State::Pending {
                remaining: branches,
                failures: Vec::new(),
            }),
            changed: Condvar::new(),
        }
    }

    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(crate) fn answer(&self, decision: ApprovalDecision) -> ApprovalDecision {
        if !matches!(
            decision,
            ApprovalDecision::Granted | ApprovalDecision::Denied { .. }
        ) {
            return decision;
        }
        let Ok(mut state) = self.state.lock() else {
            return decision;
        };
        if matches!(*state, State::Pending { .. }) && Instant::now() >= self.deadline {
            *state = State::Expired;
        }
        let winner = match &*state {
            State::Pending { .. } => {
                *state = State::Answer(decision.clone());
                decision
            }
            State::Answer(winner) => winner.clone(),
            State::Expired => ApprovalDecision::Timeout,
            State::Exhausted(winner) => winner.clone(),
        };
        self.changed.notify_all();
        winner
    }

    pub(crate) fn retire(&self, name: &str, timed_out: bool) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let State::Pending {
            remaining,
            failures,
        } = &mut *state
        else {
            return;
        };
        *remaining = remaining.saturating_sub(1);
        failures.push(format!(
            "{name} {}",
            if timed_out {
                "timed out"
            } else {
                "unavailable"
            }
        ));
        if *remaining == 0 {
            let reason = format!("No approval responder answered ({})", failures.join("; "));
            *state = State::Exhausted(ApprovalDecision::Denied { reason });
        }
        self.changed.notify_all();
    }

    pub(crate) fn poll(&self) -> RacePoll {
        let Ok(mut state) = self.state.lock() else {
            return RacePoll::Exhausted(ApprovalDecision::Denied {
                reason: "Approval race state unavailable".into(),
            });
        };
        if matches!(*state, State::Pending { .. }) && Instant::now() >= self.deadline {
            *state = State::Expired;
            self.changed.notify_all();
        }
        match &*state {
            State::Pending { .. } => RacePoll::Pending,
            State::Answer(decision) => RacePoll::Answer(decision.clone()),
            State::Expired => RacePoll::Expired,
            State::Exhausted(decision) => RacePoll::Exhausted(decision.clone()),
        }
    }

    pub(crate) fn wait(&self, cancelled: impl Fn() -> bool) -> ApprovalDecision {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => {
                return ApprovalDecision::Denied {
                    reason: "Approval race state unavailable".into(),
                };
            }
        };
        loop {
            if matches!(*state, State::Pending { .. }) && Instant::now() >= self.deadline {
                *state = State::Expired;
            }
            match &*state {
                State::Answer(decision) | State::Exhausted(decision) => return decision.clone(),
                State::Expired => return ApprovalDecision::Timeout,
                State::Pending { .. } => {}
            }
            if cancelled() {
                *state = State::Expired;
                return ApprovalDecision::Timeout;
            }
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            let interval = remaining.min(Duration::from_millis(50));
            match self.changed.wait_timeout(state, interval) {
                Ok((next, _)) => state = next,
                Err(_) => {
                    return ApprovalDecision::Denied {
                        reason: "Approval race state unavailable".into(),
                    };
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_human_answer_wins_and_unavailable_terminal_is_not_a_denial() {
        let race = ApprovalRace::new(Duration::from_secs(1), 2);
        race.retire("terminal", false);
        assert!(matches!(race.poll(), RacePoll::Pending));
        assert!(race.answer(ApprovalDecision::Granted).is_granted());
        assert!(
            race.answer(ApprovalDecision::Denied {
                reason: "late".into()
            })
            .is_granted()
        );
    }

    #[test]
    fn race_deadline_expires_without_granting() {
        let race = ApprovalRace::new(Duration::from_millis(1), 1);
        std::thread::sleep(Duration::from_millis(2));
        assert!(matches!(race.poll(), RacePoll::Expired));
    }

    #[test]
    fn late_answer_expires_without_a_prior_poll() {
        let race = ApprovalRace::new(Duration::from_millis(1), 1);
        std::thread::sleep(Duration::from_millis(2));
        assert!(matches!(
            race.answer(ApprovalDecision::Granted),
            ApprovalDecision::Timeout
        ));
        assert!(matches!(race.poll(), RacePoll::Expired));
    }

    #[test]
    fn timely_recorded_answer_survives_wait_after_the_deadline() {
        let race = ApprovalRace::new(Duration::from_millis(20), 1);
        assert!(race.answer(ApprovalDecision::Granted).is_granted());
        std::thread::sleep(Duration::from_millis(25));
        assert!(race.wait(|| false).is_granted());
    }
}
