use crate::command_policy::{
    ApprovalBackendConfig, ApprovalBackendType, ApprovalChainMode, CommandPoliciesConfig,
};
use crate::terminal_approval::TerminalApproval;
use nono::{ApprovalBackend, ApprovalDecision, ApprovalRequest, NonoError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

const WEBHOOK_RESPONSE_LIMIT_BYTES: u64 = 64 * 1024;

pub(crate) fn build_proxy_approval_registry(
    config: Option<&CommandPoliciesConfig>,
) -> Result<Option<nono_proxy::approval::ApprovalBackendRegistry>> {
    let Some(config) = config else {
        return Ok(None);
    };
    if config.approval_backends.is_empty() {
        return Ok(None);
    }

    Ok(Some(build_approval_registry_from(
        &config.approval_backends,
        config.approval_defaults.backend.clone(),
    )?))
}

pub(crate) fn build_approval_registry(
    config: &CommandPoliciesConfig,
) -> Result<nono_proxy::approval::ApprovalBackendRegistry> {
    build_approval_registry_from(
        &config.approval_backends,
        config.approval_defaults.backend.clone(),
    )
}

/// Build an approval registry from a raw backend map and an optional default
/// backend name. Shared by the `command_policies` path and the profile
/// `security.approval_backends` path so both surfaces resolve backends through
/// the same builder (including chain-cycle detection and webhook construction).
pub(crate) fn build_approval_registry_from(
    backends: &BTreeMap<String, ApprovalBackendConfig>,
    default_backend_name: Option<String>,
) -> Result<nono_proxy::approval::ApprovalBackendRegistry> {
    let built = build_approval_backends_from(backends)?;
    Ok(nono_proxy::approval::ApprovalBackendRegistry::new(
        default_backend_name,
        built,
    ))
}

/// Work out which approval backend should answer supervised-mode file and
/// capability prompts, based on the profile `security` section.
///
/// Returns `Ok(None)` when nothing is configured, so the caller keeps the
/// interactive terminal prompt (existing behavior is unchanged). When a backend
/// IS configured, any failure to build it or pick the default is a hard error —
/// we never quietly fall back to the weaker terminal prompt.
pub(crate) fn resolve_supervised_approval_backend(
    backends: &BTreeMap<String, ApprovalBackendConfig>,
    default_backend_name: Option<String>,
) -> Result<Option<Arc<dyn ApprovalBackend>>> {
    if backends.is_empty() {
        return Ok(None);
    }
    let registry = build_approval_registry_from(backends, default_backend_name)?;
    let (_name, backend) = registry.resolve(None)?;
    Ok(Some(backend))
}

fn build_approval_backends_from(
    backends: &BTreeMap<String, ApprovalBackendConfig>,
) -> Result<BTreeMap<String, Arc<dyn ApprovalBackend>>> {
    let mut built = BTreeMap::new();
    let mut webhooks = BTreeMap::new();
    let mut visiting = BTreeSet::new();
    for name in backends.keys() {
        build_approval_backend(name, backends, &mut built, &mut webhooks, &mut visiting)?;
    }
    Ok(built)
}

fn build_approval_backend(
    name: &str,
    backends: &BTreeMap<String, ApprovalBackendConfig>,
    built: &mut BTreeMap<String, Arc<dyn ApprovalBackend>>,
    webhooks: &mut BTreeMap<String, Arc<WebhookApproval>>,
    visiting: &mut BTreeSet<String>,
) -> Result<Arc<dyn ApprovalBackend>> {
    if let Some(backend) = built.get(name) {
        return Ok(Arc::clone(backend));
    }
    if !visiting.insert(name.to_string()) {
        return Err(NonoError::ConfigParse(format!(
            "approval backend chain contains a cycle at '{name}'"
        )));
    }

    let backend_config = backends
        .get(name)
        .ok_or_else(|| NonoError::ConfigParse(format!("unknown approval backend '{name}'")))?;
    let backend: Arc<dyn ApprovalBackend> = match backend_config.backend_type {
        ApprovalBackendType::Terminal => Arc::new(NamedTerminalApproval {
            name: name.to_string(),
        }),
        ApprovalBackendType::Webhook => {
            let webhook = Arc::new(WebhookApproval::new(name, backend_config)?);
            webhooks.insert(name.to_string(), Arc::clone(&webhook));
            webhook
        }
        ApprovalBackendType::Chain => {
            let mode = backend_config.mode.ok_or_else(|| {
                NonoError::ConfigParse(format!("approval backend '{name}' chain missing mode"))
            })?;
            let mut children = Vec::with_capacity(backend_config.backends.len());
            for child in &backend_config.backends {
                children.push(build_approval_backend(
                    child, backends, built, webhooks, visiting,
                )?);
            }
            if mode == ApprovalChainMode::Race {
                let terminal_indices: Vec<usize> = backend_config
                    .backends
                    .iter()
                    .enumerate()
                    .filter_map(|(index, child)| {
                        backends
                            .get(child)
                            .is_some_and(|config| {
                                config.backend_type == ApprovalBackendType::Terminal
                            })
                            .then_some(index)
                    })
                    .collect();
                if terminal_indices.len() != 1
                    || children.len() < 2
                    || children.len() > crate::command_policy::MAX_APPROVAL_RACE_BACKENDS
                {
                    return Err(NonoError::ConfigParse(format!(
                        "approval backend '{name}' race requires one terminal backend and one to three other backends"
                    )));
                }
                if backend_config.backends.iter().any(|child| {
                    backends
                        .get(child)
                        .is_some_and(|config| config.backend_type == ApprovalBackendType::Chain)
                }) {
                    return Err(NonoError::ConfigParse(format!(
                        "approval backend '{name}' race cannot contain chained backends"
                    )));
                }
                Arc::new(RaceApproval {
                    name: name.to_string(),
                    cancellation_webhooks: backend_config
                        .backends
                        .iter()
                        .filter_map(|child| webhooks.get(child).cloned())
                        .collect(),
                    backends: backend_config
                        .backends
                        .iter()
                        .cloned()
                        .zip(children)
                        .collect(),
                    terminal_index: terminal_indices[0],
                    timeout: Duration::from_secs(
                        backend_config
                            .timeout_secs
                            .unwrap_or(crate::command_policy::APPROVAL_RACE_DEFAULT_TIMEOUT_SECS),
                    ),
                })
            } else {
                Arc::new(ChainApproval {
                    name: name.to_string(),
                    mode,
                    backends: children,
                })
            }
        }
    };

    visiting.remove(name);
    built.insert(name.to_string(), Arc::clone(&backend));
    Ok(backend)
}

struct NamedTerminalApproval {
    name: String,
}

impl ApprovalBackend for NamedTerminalApproval {
    fn request_approval(&self, request: &ApprovalRequest) -> Result<ApprovalDecision> {
        TerminalApproval.request_approval(request)
    }

    fn backend_name(&self) -> &str {
        &self.name
    }
}

/// Path of the platform's enrolled approval ingest, relative to the enrolled
/// platform URL. The poll route is `<this>/{request_id}`.
const PLATFORM_APPROVALS_PATH: &str = "/api/v1/approvals";
/// Pause between polls when the server answers `pending` immediately instead
/// of holding the request open.
const PLATFORM_POLL_BACKOFF: Duration = Duration::from_millis(250);
/// Header carrying the client's remaining patience so the server-side hold and
/// deadline match this backend's `timeout_secs`.
const HEADER_TIMEOUT_SECS: &str = "X-Nono-Timeout-Secs";

struct WebhookApproval {
    name: String,
    url: String,
    timeout: Duration,
    http: ureq::Agent,
    /// Present when `auth: "platform"`: sign each request with the enrolled
    /// key and follow the platform's submit-and-poll contract.
    platform: Option<crate::platform_client::PlatformState>,
    poll_backoff: Duration,
}

#[derive(Serialize)]
struct WebhookApprovalRequest<'a> {
    backend: &'a str,
    request: &'a ApprovalRequest,
}

#[derive(Deserialize)]
struct WebhookDecisionResponse {
    decision: String,
    #[serde(default)]
    reason: Option<String>,
}

/// Platform submit/poll response (`platform-protocol::approvals::ApprovalStatus`).
#[derive(Deserialize)]
struct PlatformApprovalStatus {
    state: String,
    #[serde(default)]
    reason: Option<String>,
}

/// One hop of the platform exchange.
enum PlatformStep<'a> {
    Submit(&'a [u8]),
    Poll { request_id: &'a str },
}

struct HttpReply {
    status: u16,
    body: String,
}

/// HTTP agent for approval webhooks. Redirects are disabled: a decision must
/// come from the configured URL itself, otherwise a redirect (including HTTPS
/// to HTTP) could carry the signed `X-Nono-*` headers to another host and let
/// that host answer `granted`. A 3xx therefore surfaces as a non-2xx status
/// and is treated as a denial.
fn build_agent(timeout: Duration) -> ureq::Agent {
    let tls_config = ureq::tls::TlsConfig::builder()
        .root_certs(ureq::tls::RootCerts::PlatformVerifier)
        .build();
    ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .max_redirects(0)
        .max_redirects_will_error(false)
        .tls_config(tls_config)
        .build()
        .new_agent()
}

impl WebhookApproval {
    fn new(name: &str, config: &ApprovalBackendConfig) -> Result<Self> {
        let platform = match config.auth {
            Some(crate::command_policy::ApprovalBackendAuth::Platform) => Some(
                crate::platform_client::load_state()?.ok_or_else(|| {
                    NonoError::ConfigParse(format!(
                        "approval backend '{name}' uses auth platform but this client is not enrolled; run `nono platform enroll` first"
                    ))
                })?,
            ),
            None => None,
        };
        let url = match (&config.url, &platform) {
            (Some(url), _) => url.clone(),
            (None, Some(state)) => {
                crate::platform_client::endpoint_url(&state.platform_url, PLATFORM_APPROVALS_PATH)?
            }
            (None, None) => {
                return Err(NonoError::ConfigParse(format!(
                    "approval backend '{name}' webhook missing url"
                )));
            }
        };
        if platform.is_some() && !crate::command_policy::is_platform_grade_url(&url) {
            return Err(NonoError::ConfigParse(format!(
                "approval backend '{name}' with auth platform must use an https URL (plain http is allowed only for loopback)"
            )));
        }
        let timeout = Duration::from_secs(config.timeout_secs.unwrap_or(60));
        let http = build_agent(timeout);
        Ok(Self {
            name: name.to_string(),
            url,
            timeout,
            http,
            platform,
            poll_backoff: PLATFORM_POLL_BACKOFF,
        })
    }

    fn parse_response(&self, body: &str) -> Result<ApprovalDecision> {
        if let Ok(decision) = serde_json::from_str::<ApprovalDecision>(body) {
            return Ok(decision);
        }

        let response: WebhookDecisionResponse = serde_json::from_str(body).map_err(|e| {
            NonoError::SandboxInit(format!(
                "approval webhook '{}' returned invalid JSON: {e}",
                self.name
            ))
        })?;
        match response.decision.trim().to_ascii_lowercase().as_str() {
            "grant" | "granted" | "approve" | "approved" | "allow" | "allowed" => {
                Ok(ApprovalDecision::Granted)
            }
            "deny" | "denied" | "reject" | "rejected" | "block" | "blocked" => {
                Ok(ApprovalDecision::Denied {
                    reason: response.reason.unwrap_or_else(|| {
                        format!("approval webhook '{}' denied request", self.name)
                    }),
                })
            }
            "timeout" | "timed_out" => Ok(ApprovalDecision::Timeout),
            other => Err(NonoError::SandboxInit(format!(
                "approval webhook '{}' returned unknown decision '{other}'",
                self.name
            ))),
        }
    }

    fn http_status_denial(&self, status: u16, elapsed: Duration) -> ApprovalDecision {
        ApprovalDecision::Denied {
            reason: format!(
                "approval webhook '{}' returned HTTP {status} after {}s",
                self.name,
                elapsed.as_secs()
            ),
        }
    }

    /// A non-success status remains fail-closed for ordinary webhook policies.
    /// In a human race it only makes this responder unavailable; an explicit
    /// 2xx denial is still the branch's human answer.
    fn http_status_result(&self, status: u16, elapsed: Duration) -> Result<ApprovalDecision> {
        if crate::approval_terminal_handoff::active_race().is_some() {
            return Err(NonoError::SandboxInit(format!(
                "approval webhook '{}' returned HTTP {status} during an approval race",
                self.name
            )));
        }
        Ok(self.http_status_denial(status, elapsed))
    }

    fn read_body(&self, response: &mut ureq::http::Response<ureq::Body>) -> Result<String> {
        response
            .body_mut()
            .with_config()
            .limit(WEBHOOK_RESPONSE_LIMIT_BYTES)
            .read_to_string()
            .map_err(|e| {
                NonoError::SandboxInit(format!(
                    "failed to read approval webhook '{}' response: {e}",
                    self.name
                ))
            })
    }

    /// Unsigned contract: one blocking POST, the response body is the
    /// decision. Any approval endpoint that does not verify enrolled
    /// identities speaks this (`docs/protocols/approval-webhook-v1.md`).
    fn request_unsigned(&self, body: &[u8], started: Instant) -> Result<ApprovalDecision> {
        let mut response = self
            .http
            .post(&self.url)
            .config()
            .http_status_as_error(false)
            .build()
            .header("Content-Type", "application/json")
            .header(
                "User-Agent",
                &format!("nono-cli/{}", env!("CARGO_PKG_VERSION")),
            )
            .header(HEADER_TIMEOUT_SECS, &self.timeout.as_secs().to_string())
            .send(body)
            .map_err(|e| {
                NonoError::SandboxInit(format!("approval webhook '{}' failed: {e}", self.name))
            })?;

        let status = response.status().as_u16();
        let response_body = self.read_body(&mut response)?;
        if !(200..300).contains(&status) {
            return self.http_status_result(status, started.elapsed());
        }
        self.parse_response(&response_body)
    }

    /// Best-effort cancellation for a pending unsigned webhook when another
    /// human responder wins. The detached caller gives this request its own
    /// short deadline, so transport cleanup never delays native approval.
    fn cancel_unsigned(&self, request: &ApprovalRequest) {
        if self.platform.is_some() {
            return;
        }
        let Ok(body) = serde_json::to_vec(&WebhookApprovalRequest {
            backend: &self.name,
            request,
        }) else {
            return;
        };
        let timeout = Duration::from_secs(2);
        let http = build_agent(timeout);
        let _ = http
            .delete(&self.url)
            .config()
            .http_status_as_error(false)
            .timeout_global(Some(timeout))
            .build()
            .force_send_body()
            .header("Content-Type", "application/json")
            .header(
                "User-Agent",
                &format!("nono-cli/{}", env!("CARGO_PKG_VERSION")),
            )
            .send(&body);
    }

    /// Signed contract (`docs/protocols/approval-webhook-v1.md`): submit, then
    /// poll `GET <url>/{request_id}` with signed requests until a final state
    /// or this backend's timeout. Each hop is given only the remaining budget,
    /// both as the server hold hint and as its own HTTP timeout. The transport
    /// is injected so the state machine is testable without HTTP.
    fn drive_platform_approval(
        &self,
        request_id: &str,
        body: &[u8],
        started: Instant,
        send: impl FnMut(PlatformStep<'_>, Duration) -> Result<HttpReply>,
    ) -> Result<ApprovalDecision> {
        self.drive_platform_approval_with_elapsed(request_id, body, || started.elapsed(), send)
    }

    /// The poll-loop state machine with an injected monotonic elapsed-time
    /// source. Keeping time separate from transport lets its deadline behavior
    /// be tested without wall-clock sleeps or scheduler-dependent assertions.
    fn drive_platform_approval_with_elapsed(
        &self,
        request_id: &str,
        body: &[u8],
        mut elapsed: impl FnMut() -> Duration,
        mut send: impl FnMut(PlatformStep<'_>, Duration) -> Result<HttpReply>,
    ) -> Result<ApprovalDecision> {
        let mut submitted = false;
        loop {
            if crate::approval_terminal_handoff::cancelled() {
                return Ok(ApprovalDecision::Timeout);
            }
            let remaining = self.timeout.saturating_sub(elapsed());
            if remaining.is_zero() {
                return Ok(ApprovalDecision::Timeout);
            }
            let step = if submitted {
                PlatformStep::Poll { request_id }
            } else {
                PlatformStep::Submit(body)
            };
            let reply = send(step, remaining)?;
            // The deadline is checked again after the round trip: a decision
            // that arrives once this backend's timeout has elapsed is never
            // applied, however long the individual request took.
            let elapsed_after_reply = elapsed();
            if elapsed_after_reply >= self.timeout {
                return Ok(ApprovalDecision::Timeout);
            }
            if !(200..300).contains(&reply.status) {
                return self.http_status_result(reply.status, elapsed_after_reply);
            }
            let status: PlatformApprovalStatus =
                serde_json::from_str(&reply.body).map_err(|e| {
                    NonoError::SandboxInit(format!(
                        "approval webhook '{}' returned invalid JSON: {e}",
                        self.name
                    ))
                })?;
            match status.state.as_str() {
                "pending" => {
                    submitted = true;
                    if !self.poll_backoff.is_zero() {
                        std::thread::sleep(self.poll_backoff.min(remaining));
                    }
                }
                "granted" => return Ok(ApprovalDecision::Granted),
                "denied" => {
                    return Ok(ApprovalDecision::Denied {
                        reason: status.reason.unwrap_or_else(|| {
                            format!("approval webhook '{}' denied request", self.name)
                        }),
                    });
                }
                "timeout" => return Ok(ApprovalDecision::Timeout),
                other => {
                    return Err(NonoError::SandboxInit(format!(
                        "approval webhook '{}' returned unknown state '{other}'",
                        self.name
                    )));
                }
            }
        }
    }

    /// Stamp the six `nono-request-v1` headers plus the timeout hint for one
    /// platform request. `path` is the URL path as the server will see it.
    fn platform_headers(
        state: &crate::platform_client::PlatformState,
        method: &str,
        path: &str,
        body: &[u8],
        remaining: Duration,
    ) -> Result<Vec<(&'static str, String)>> {
        let signed = crate::platform_client::sign_request_v1(
            state,
            method,
            path,
            uuid::Uuid::now_v7(),
            body,
        )?;
        Ok(vec![
            (
                "X-Nono-Protocol-Version",
                crate::platform_client::REQUEST_PROTOCOL_V1.to_string(),
            ),
            ("X-Nono-Subject-Id", state.subject_id.clone()),
            ("X-Nono-Timestamp", signed.timestamp),
            ("X-Nono-Request-Id", signed.request_id),
            ("X-Nono-Content-SHA256", signed.body_digest),
            ("X-Nono-Signature", signed.signature),
            (HEADER_TIMEOUT_SECS, remaining.as_secs().max(1).to_string()),
        ])
    }

    fn send_platform(
        &self,
        state: &crate::platform_client::PlatformState,
        step: PlatformStep<'_>,
        remaining: Duration,
    ) -> Result<HttpReply> {
        let mut url = url::Url::parse(&self.url).map_err(|e| {
            NonoError::ConfigParse(format!(
                "approval backend '{}' has an invalid url: {e}",
                self.name
            ))
        })?;
        let (method, body) = match step {
            PlatformStep::Submit(body) => ("POST", body),
            PlatformStep::Poll { request_id } => {
                url.path_segments_mut()
                    .map_err(|_| {
                        NonoError::ConfigParse(format!(
                            "approval backend '{}' url cannot take a path",
                            self.name
                        ))
                    })?
                    .pop_if_empty()
                    .push(request_id);
                ("GET", &[][..])
            }
        };
        let headers = Self::platform_headers(state, method, url.path(), body, remaining)?;
        // Bound this hop by what is left of the backend timeout, not the whole
        // configured timeout, so a late poll cannot outlive the deadline.
        let hop_timeout = remaining.max(Duration::from_secs(1));
        let user_agent = format!("nono-cli/{}", env!("CARGO_PKG_VERSION"));
        let failed = |e: ureq::Error| {
            NonoError::SandboxInit(format!("approval webhook '{}' failed: {e}", self.name))
        };
        let mut response = if method == "POST" {
            let mut request = self
                .http
                .post(url.as_str())
                .config()
                .http_status_as_error(false)
                .timeout_global(Some(hop_timeout))
                .build()
                .header("Content-Type", "application/json")
                .header("User-Agent", &user_agent);
            for (name, value) in &headers {
                request = request.header(*name, value);
            }
            request.send(body).map_err(failed)?
        } else {
            let mut request = self
                .http
                .get(url.as_str())
                .config()
                .http_status_as_error(false)
                .timeout_global(Some(hop_timeout))
                .build()
                .header("User-Agent", &user_agent);
            for (name, value) in &headers {
                request = request.header(*name, value);
            }
            request.call().map_err(failed)?
        };
        let status = response.status().as_u16();
        let body = self.read_body(&mut response)?;
        Ok(HttpReply { status, body })
    }
}

impl ApprovalBackend for WebhookApproval {
    fn request_approval(&self, request: &ApprovalRequest) -> Result<ApprovalDecision> {
        if crate::approval_terminal_handoff::cancelled() {
            return Ok(ApprovalDecision::Timeout);
        }
        let body = serde_json::to_vec(&WebhookApprovalRequest {
            backend: &self.name,
            request,
        })
        .map_err(|e| {
            NonoError::SandboxInit(format!(
                "failed to serialize approval webhook request '{}': {e}",
                self.name
            ))
        })?;
        let started = Instant::now();
        match &self.platform {
            None => self.request_unsigned(&body, started),
            Some(state) => self.drive_platform_approval(
                request.request_id(),
                &body,
                started,
                |step, remaining| self.send_platform(state, step, remaining),
            ),
        }
    }

    fn backend_name(&self) -> &str {
        &self.name
    }
}

struct ChainApproval {
    name: String,
    mode: ApprovalChainMode,
    backends: Vec<Arc<dyn ApprovalBackend>>,
}

struct RaceApproval {
    name: String,
    backends: Vec<(String, Arc<dyn ApprovalBackend>)>,
    cancellation_webhooks: Vec<Arc<WebhookApproval>>,
    terminal_index: usize,
    timeout: Duration,
}

impl ApprovalBackend for RaceApproval {
    fn request_approval(&self, request: &ApprovalRequest) -> Result<ApprovalDecision> {
        let race = Arc::new(crate::approval_race::ApprovalRace::new(
            self.timeout,
            self.backends.len(),
        ));
        let decision =
            crate::approval_terminal_handoff::with_race_context(Arc::clone(&race), || {
                let inline_terminal = crate::approval_terminal_handoff::is_owner_thread();

                for (index, (name, backend)) in self.backends.iter().enumerate() {
                    if inline_terminal && index == self.terminal_index {
                        continue;
                    }
                    let name = name.clone();
                    let backend = Arc::clone(backend);
                    let request = request.clone();
                    let branch_race = Arc::clone(&race);
                    let branch_name = name.clone();
                    if std::thread::Builder::new()
                        .spawn(move || {
                            let result = crate::approval_terminal_handoff::with_race_context(
                                Arc::clone(&branch_race),
                                || backend.request_approval(&request),
                            );
                            report_race_result(&branch_race, &name, result);
                        })
                        .is_err()
                    {
                        race.retire(&branch_name, false);
                    }
                }

                if inline_terminal {
                    let (name, backend) = &self.backends[self.terminal_index];
                    let result = crate::approval_terminal_handoff::with_race_context(
                        Arc::clone(&race),
                        || backend.request_approval(request),
                    );
                    report_race_result(&race, name, result);
                }

                race.wait(crate::approval_terminal_handoff::context_expired)
            });
        self.cancel_pending_webhooks(request);
        Ok(decision)
    }

    fn backend_name(&self) -> &str {
        &self.name
    }
}

impl RaceApproval {
    fn cancel_pending_webhooks(&self, request: &ApprovalRequest) {
        for webhook in &self.cancellation_webhooks {
            let webhook = Arc::clone(webhook);
            let request = request.clone();
            let _ = std::thread::Builder::new()
                .name("nono-approval-cancel".into())
                .spawn(move || webhook.cancel_unsigned(&request));
        }
    }
}

fn report_race_result(
    race: &crate::approval_race::ApprovalRace,
    name: &str,
    result: Result<ApprovalDecision>,
) {
    match result {
        Ok(ApprovalDecision::Granted) => {
            race.answer(ApprovalDecision::Granted);
        }
        Ok(ApprovalDecision::Denied { reason }) => {
            race.answer(ApprovalDecision::Denied { reason });
        }
        Ok(ApprovalDecision::Timeout) => race.retire(name, true),
        Err(_) => race.retire(name, false),
    }
}

impl ApprovalBackend for ChainApproval {
    fn request_approval(&self, request: &ApprovalRequest) -> Result<ApprovalDecision> {
        match self.mode {
            ApprovalChainMode::All => self.request_all(request),
            ApprovalChainMode::Any => Ok(self.request_any(request)),
            ApprovalChainMode::Race => unreachable!("race mode uses RaceApproval"),
        }
    }

    fn backend_name(&self) -> &str {
        &self.name
    }
}

impl ChainApproval {
    fn request_all(&self, request: &ApprovalRequest) -> Result<ApprovalDecision> {
        for backend in &self.backends {
            match backend.request_approval(request)? {
                ApprovalDecision::Granted => {}
                ApprovalDecision::Denied { reason } => {
                    return Ok(ApprovalDecision::Denied {
                        reason: format!(
                            "{} denied via {}: {reason}",
                            self.name,
                            backend.backend_name()
                        ),
                    });
                }
                ApprovalDecision::Timeout => {
                    return Ok(ApprovalDecision::Denied {
                        reason: format!("{} timed out via {}", self.name, backend.backend_name()),
                    });
                }
            }
        }
        Ok(ApprovalDecision::Granted)
    }

    fn request_any(&self, request: &ApprovalRequest) -> ApprovalDecision {
        let mut reasons = Vec::new();
        for backend in &self.backends {
            match backend.request_approval(request) {
                Ok(ApprovalDecision::Granted) => return ApprovalDecision::Granted,
                Ok(ApprovalDecision::Denied { reason }) => {
                    reasons.push(format!("{} denied: {reason}", backend.backend_name()));
                }
                Ok(ApprovalDecision::Timeout) => {
                    reasons.push(format!("{} timed out", backend.backend_name()));
                }
                Err(err) => {
                    reasons.push(format!("{} errored: {err}", backend.backend_name()));
                }
            }
        }
        ApprovalDecision::Denied {
            reason: format!(
                "{} had no granting backend ({})",
                self.name,
                reasons.join("; ")
            ),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use sha2::Digest as _;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    struct StaticBackend {
        name: &'static str,
        decision: ApprovalDecision,
    }

    impl ApprovalBackend for StaticBackend {
        fn request_approval(&self, _request: &ApprovalRequest) -> Result<ApprovalDecision> {
            Ok(self.decision.clone())
        }

        fn backend_name(&self) -> &str {
            self.name
        }
    }

    struct UnavailableBackend;

    impl ApprovalBackend for UnavailableBackend {
        fn request_approval(&self, _request: &ApprovalRequest) -> Result<ApprovalDecision> {
            Err(NonoError::SandboxInit("test responder unavailable".into()))
        }

        fn backend_name(&self) -> &str {
            "terminal-human"
        }
    }

    fn request() -> ApprovalRequest {
        ApprovalRequest::Endpoint {
            request_id: "req-1".to_string(),
            route_id: "internal-api".to_string(),
            upstream: "https://api.internal.example".to_string(),
            method: "POST".to_string(),
            path: "/v1/tasks/1/comments".to_string(),
            rule_label: "endpoint_policy.approve[POST /v1/tasks/*/comments]".to_string(),
            reason: None,
            child_pid: 0,
            session_id: "proxy".to_string(),
        }
    }

    #[test]
    fn chain_all_requires_every_backend_to_grant() {
        let chain = ChainApproval {
            name: "all".to_string(),
            mode: ApprovalChainMode::All,
            backends: vec![
                Arc::new(StaticBackend {
                    name: "a",
                    decision: ApprovalDecision::Granted,
                }),
                Arc::new(StaticBackend {
                    name: "b",
                    decision: ApprovalDecision::Denied {
                        reason: "no".to_string(),
                    },
                }),
            ],
        };

        assert!(chain.request_approval(&request()).unwrap().is_denied());
    }

    #[test]
    fn chain_any_grants_if_one_backend_grants() {
        let chain = ChainApproval {
            name: "any".to_string(),
            mode: ApprovalChainMode::Any,
            backends: vec![
                Arc::new(StaticBackend {
                    name: "a",
                    decision: ApprovalDecision::Denied {
                        reason: "no".to_string(),
                    },
                }),
                Arc::new(StaticBackend {
                    name: "b",
                    decision: ApprovalDecision::Granted,
                }),
            ],
        };

        assert!(chain.request_approval(&request()).unwrap().is_granted());
    }

    #[test]
    fn race_keeps_remote_responder_live_when_terminal_is_unavailable() {
        let race = RaceApproval {
            name: "human".to_string(),
            cancellation_webhooks: Vec::new(),
            backends: vec![
                ("terminal-human".to_string(), Arc::new(UnavailableBackend)),
                (
                    "remote-human".to_string(),
                    Arc::new(StaticBackend {
                        name: "remote",
                        decision: ApprovalDecision::Granted,
                    }),
                ),
            ],
            terminal_index: 0,
            timeout: Duration::from_secs(1),
        };

        assert!(race.request_approval(&request()).unwrap().is_granted());
    }

    #[test]
    fn race_keeps_terminal_responder_live_when_remote_fails() {
        let race = RaceApproval {
            name: "human".to_string(),
            cancellation_webhooks: Vec::new(),
            backends: vec![
                ("remote-human".to_string(), Arc::new(UnavailableBackend)),
                (
                    "terminal-human".to_string(),
                    Arc::new(StaticBackend {
                        name: "terminal",
                        decision: ApprovalDecision::Granted,
                    }),
                ),
            ],
            terminal_index: 1,
            timeout: Duration::from_secs(1),
        };

        assert!(race.request_approval(&request()).unwrap().is_granted());
    }

    #[test]
    fn compat_no_tty_race_uses_remote_human_without_terminal_denial() {
        const CHILD_ENV: &str = "NONO_COMPAT_RACE_APPROVAL_CHILD";
        if std::env::var_os(CHILD_ENV).is_none() {
            let status = std::process::Command::new(std::env::current_exe().expect("test binary"))
                .args([
                    "--exact",
                    "approval_runtime::tests::compat_no_tty_race_uses_remote_human_without_terminal_denial",
                ])
                .env(CHILD_ENV, "1")
                .status()
                .expect("isolated no-TTY race test");
            assert!(status.success());
            return;
        }
        if crate::terminal_prompt::consent_prompt_available() {
            return;
        }

        let _owner = crate::approval_terminal_handoff::register(0);
        let race = RaceApproval {
            name: "human".to_string(),
            cancellation_webhooks: Vec::new(),
            backends: vec![
                ("terminal-human".to_string(), Arc::new(TerminalApproval)),
                (
                    "remote-human".to_string(),
                    Arc::new(StaticBackend {
                        name: "remote",
                        decision: ApprovalDecision::Granted,
                    }),
                ),
            ],
            terminal_index: 0,
            timeout: Duration::from_secs(1),
        };

        assert!(race.request_approval(&request()).unwrap().is_granted());
    }

    #[test]
    fn supervised_backend_resolves_configured_webhook() {
        let mut backends = BTreeMap::new();
        backends.insert(
            "security-review".to_string(),
            ApprovalBackendConfig {
                backend_type: ApprovalBackendType::Webhook,
                url: Some("https://approval.example".to_string()),
                timeout_secs: Some(5),
                mode: None,
                backends: Vec::new(),
                auth: None,
            },
        );

        let resolved =
            resolve_supervised_approval_backend(&backends, Some("security-review".to_string()))
                .unwrap();
        match resolved {
            Some(backend) => assert_eq!(backend.backend_name(), "security-review"),
            None => panic!("configured backend should resolve to Some"),
        }
    }

    #[test]
    fn supervised_backend_resolves_single_backend_without_explicit_default() {
        let mut backends = BTreeMap::new();
        backends.insert(
            "gate".to_string(),
            ApprovalBackendConfig {
                backend_type: ApprovalBackendType::Terminal,
                url: None,
                timeout_secs: None,
                mode: None,
                backends: Vec::new(),
                auth: None,
            },
        );

        // No default name given, but the registry default must be present for a
        // supervised resolve to succeed — a lone backend is not auto-selected,
        // so resolve(None) fails closed rather than guess. `Ok(Option<Arc<dyn
        // ApprovalBackend>>)` is not `Debug`, so assert on the `Err` arm directly.
        match resolve_supervised_approval_backend(&backends, None) {
            Ok(_) => panic!("a lone backend without a default must fail closed"),
            Err(err) => assert!(err.to_string().contains("missing approval backend")),
        }
    }

    #[test]
    fn supervised_backend_none_when_unconfigured() {
        let backends = BTreeMap::new();
        let resolved = resolve_supervised_approval_backend(&backends, None).unwrap();
        assert!(
            resolved.is_none(),
            "no configured backends must fall back to terminal (None)"
        );
    }

    #[test]
    fn supervised_backend_unknown_default_is_hard_error() {
        let mut backends = BTreeMap::new();
        backends.insert(
            "gate".to_string(),
            ApprovalBackendConfig {
                backend_type: ApprovalBackendType::Terminal,
                url: None,
                timeout_secs: None,
                mode: None,
                backends: Vec::new(),
                auth: None,
            },
        );

        match resolve_supervised_approval_backend(&backends, Some("missing".to_string())) {
            Ok(_) => panic!("an unknown default backend must be a hard error"),
            Err(err) => assert!(err.to_string().contains("unknown approval backend")),
        }
    }

    #[test]
    fn webhook_response_parser_accepts_simple_decision_shape() {
        let backend = test_webhook(Duration::from_secs(1));

        assert!(
            backend
                .parse_response(r#"{"decision":"granted"}"#)
                .unwrap()
                .is_granted()
        );
        assert!(
            backend
                .parse_response(r#"{"decision":"denied","reason":"policy"}"#)
                .unwrap()
                .is_denied()
        );
    }

    #[test]
    fn unsigned_race_cancellation_uses_the_same_request_envelope() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request_bytes = Vec::new();
            let mut chunk = [0_u8; 1024];
            let body_start = loop {
                let count = stream.read(&mut chunk).unwrap();
                assert_ne!(count, 0);
                request_bytes.extend_from_slice(&chunk[..count]);
                if let Some(index) = request_bytes
                    .windows(4)
                    .position(|part| part == b"\r\n\r\n")
                {
                    break index + 4;
                }
            };
            let headers = String::from_utf8_lossy(&request_bytes[..body_start]).into_owned();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|value| value.trim().parse::<usize>().ok())
                })
                .unwrap();
            while request_bytes.len() < body_start + content_length {
                let count = stream.read(&mut chunk).unwrap();
                assert_ne!(count, 0);
                request_bytes.extend_from_slice(&chunk[..count]);
            }
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            (
                headers.lines().next().unwrap().to_string(),
                String::from_utf8(request_bytes[body_start..body_start + content_length].to_vec())
                    .unwrap(),
            )
        });

        let mut backend = test_webhook(Duration::from_secs(1));
        backend.url = format!("http://{address}/approval");
        backend.cancel_unsigned(&request());
        let (request_line, body) = server.join().unwrap();
        assert!(request_line.starts_with("DELETE /approval HTTP/1.1"));
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["backend"], "security-review");
        assert_eq!(body["request"]["request_id"], "req-1");
        assert_eq!(body["request"]["session_id"], "proxy");
    }

    fn test_webhook(timeout: Duration) -> WebhookApproval {
        WebhookApproval {
            name: "security-review".to_string(),
            url: "https://approval.example/api/v1/approvals".to_string(),
            timeout,
            http: ureq::Agent::new_with_defaults(),
            platform: None,
            poll_backoff: Duration::ZERO,
        }
    }

    fn local_status_webhook(status: u16) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut chunk = [0_u8; 1024];
            let body_start = loop {
                let count = stream.read(&mut chunk).unwrap();
                assert_ne!(count, 0);
                bytes.extend_from_slice(&chunk[..count]);
                if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    break index + 4;
                }
            };
            let headers = String::from_utf8_lossy(&bytes[..body_start]).into_owned();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|value| value.trim().parse::<usize>().ok())
                })
                .unwrap();
            while bytes.len() < body_start + content_length {
                let count = stream.read(&mut chunk).unwrap();
                assert_ne!(count, 0);
                bytes.extend_from_slice(&chunk[..count]);
            }
            let (reason, body) = match status {
                503 => ("Service Unavailable", "unavailable"),
                _ => ("Fixture Status", "fixture"),
            };
            write!(
                stream,
                "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        (format!("http://{address}/approval"), server)
    }

    #[test]
    fn unsigned_http_status_retires_only_a_race_branch() {
        let race = Arc::new(crate::approval_race::ApprovalRace::new(
            Duration::from_secs(1),
            2,
        ));
        let (url, server) = local_status_webhook(503);
        let mut backend = test_webhook(Duration::from_secs(1));
        backend.url = url;
        let result = crate::approval_terminal_handoff::with_race_context(Arc::clone(&race), || {
            backend.request_approval(&request())
        });
        server.join().unwrap();

        report_race_result(&race, "remote-human", result);
        assert!(matches!(
            race.poll(),
            crate::approval_race::RacePoll::Pending
        ));
        assert!(race.answer(ApprovalDecision::Granted).is_granted());
    }

    #[test]
    fn ordinary_unsigned_http_status_remains_a_denial() {
        let (url, server) = local_status_webhook(503);
        let mut backend = test_webhook(Duration::from_secs(1));
        backend.url = url;

        let result = backend.request_approval(&request()).unwrap();
        server.join().unwrap();
        match result {
            ApprovalDecision::Denied { reason } => assert!(reason.contains("HTTP 503")),
            other => panic!("expected denial, got {other:?}"),
        }
    }

    #[test]
    fn platform_http_status_retires_only_a_race_branch() {
        let race = Arc::new(crate::approval_race::ApprovalRace::new(
            Duration::from_secs(1),
            2,
        ));
        let backend = test_webhook(Duration::from_secs(1));
        let result = crate::approval_terminal_handoff::with_race_context(Arc::clone(&race), || {
            backend.drive_platform_approval("req-1", b"{}", Instant::now(), |_, _| {
                Ok(reply(503, "unavailable"))
            })
        });

        report_race_result(&race, "remote-human", result);
        assert!(matches!(
            race.poll(),
            crate::approval_race::RacePoll::Pending
        ));
        assert!(race.answer(ApprovalDecision::Granted).is_granted());
    }

    fn reply(status: u16, body: &str) -> HttpReply {
        HttpReply {
            status,
            body: body.to_string(),
        }
    }

    #[test]
    fn platform_poll_loop_submits_then_polls_until_granted() {
        let backend = test_webhook(Duration::from_secs(30));
        let mut steps = Vec::new();
        let decision = backend
            .drive_platform_approval("req-1", b"{}", Instant::now(), |step, remaining| {
                assert!(remaining <= Duration::from_secs(30));
                match step {
                    PlatformStep::Submit(body) => {
                        assert_eq!(body, b"{}");
                        steps.push("submit");
                        Ok(reply(202, r#"{"request_id":"req-1","state":"pending"}"#))
                    }
                    PlatformStep::Poll { request_id } => {
                        assert_eq!(request_id, "req-1");
                        steps.push("poll");
                        if steps.len() < 3 {
                            Ok(reply(202, r#"{"request_id":"req-1","state":"pending"}"#))
                        } else {
                            Ok(reply(
                                200,
                                r#"{"request_id":"req-1","state":"granted","decision":"granted"}"#,
                            ))
                        }
                    }
                }
            })
            .unwrap();
        assert!(decision.is_granted());
        assert_eq!(steps, vec!["submit", "poll", "poll"]);
    }

    #[test]
    fn platform_poll_loop_gives_up_at_the_configured_timeout() {
        let backend = test_webhook(Duration::from_millis(40));
        let elapsed = std::rc::Rc::new(std::cell::Cell::new(Duration::ZERO));
        let clock = std::rc::Rc::clone(&elapsed);
        let mut polls = 0;
        let decision = backend
            .drive_platform_approval_with_elapsed(
                "req-2",
                b"{}",
                || clock.get(),
                |_step, _remaining| {
                    polls += 1;
                    elapsed.set(elapsed.get() + Duration::from_millis(10));
                    Ok(reply(202, r#"{"state":"pending"}"#))
                },
            )
            .unwrap();
        assert!(matches!(decision, ApprovalDecision::Timeout));
        assert_eq!(
            polls, 4,
            "the fourth 10 ms reply reaches the 40 ms deadline"
        );
    }

    #[test]
    fn platform_poll_loop_rejects_a_grant_that_arrives_after_the_deadline() {
        let backend = test_webhook(Duration::from_millis(40));
        let elapsed = std::rc::Rc::new(std::cell::Cell::new(Duration::ZERO));
        let clock = std::rc::Rc::clone(&elapsed);
        let decision = backend
            .drive_platform_approval_with_elapsed(
                "req-late",
                b"{}",
                || clock.get(),
                |_, remaining| {
                    // The hop is handed only the remaining budget...
                    assert_eq!(remaining, Duration::from_millis(40));
                    // ...but a server response can still arrive after it.
                    elapsed.set(Duration::from_millis(60));
                    Ok(reply(200, r#"{"state":"granted","decision":"granted"}"#))
                },
            )
            .unwrap();
        assert!(
            matches!(decision, ApprovalDecision::Timeout),
            "a late grant must not be applied"
        );
    }

    #[test]
    fn approval_webhook_agent_never_follows_redirects() {
        let agent = build_agent(Duration::from_secs(5));
        assert_eq!(agent.config().max_redirects(), 0);
        assert!(!agent.config().max_redirects_will_error());
        assert_eq!(
            agent.config().timeouts().global,
            Some(Duration::from_secs(5))
        );
    }

    #[test]
    fn platform_poll_loop_reports_immediate_deny_and_server_timeout() {
        let backend = test_webhook(Duration::from_secs(5));
        let denied = backend
            .drive_platform_approval("req-3", b"{}", Instant::now(), |step, _| {
                assert!(matches!(step, PlatformStep::Submit(_)));
                Ok(reply(
                    200,
                    r#"{"state":"denied","decision":"denied","reason":"not today"}"#,
                ))
            })
            .unwrap();
        match denied {
            ApprovalDecision::Denied { reason } => assert_eq!(reason, "not today"),
            other => panic!("expected denial, got {other:?}"),
        }

        let timed_out = backend
            .drive_platform_approval("req-4", b"{}", Instant::now(), |_, _| {
                Ok(reply(200, r#"{"state":"timeout","decision":"timeout"}"#))
            })
            .unwrap();
        assert!(matches!(timed_out, ApprovalDecision::Timeout));
    }

    #[test]
    fn platform_poll_loop_reports_elapsed_time_on_http_errors() {
        let backend = test_webhook(Duration::from_secs(5));
        let decision = backend
            .drive_platform_approval("req-5", b"{}", Instant::now(), |_, _| {
                Ok(reply(404, r#"{"error":"not_found"}"#))
            })
            .unwrap();
        match decision {
            ApprovalDecision::Denied { reason } => {
                assert!(reason.contains("HTTP 404"), "{reason}");
                assert!(reason.contains("after 0s"), "{reason}");
            }
            other => panic!("expected denial, got {other:?}"),
        }
    }

    #[test]
    fn platform_headers_stamp_the_signed_request_contract() {
        use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
        use base64::Engine as _;

        let dir =
            std::env::temp_dir().join(format!("nono-approval-headers-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let key_path = dir.join("key");
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &aws_lc_rs::rand::SystemRandom::new(),
        )
        .unwrap();
        std::fs::write(
            &key_path,
            base64::engine::general_purpose::STANDARD.encode(pkcs8.as_ref()),
        )
        .unwrap();
        let state = crate::platform_client::PlatformState {
            protocol_version: "1".to_string(),
            platform_url: "https://platform.example.com".to_string(),
            tenant_id: "019f0000-0000-7000-8000-000000000001".to_string(),
            subject_id: "019f0000-0000-7000-8000-000000000002".to_string(),
            subject_kind: "workload".to_string(),
            management_mode: "audit_only".to_string(),
            key_algorithm: "ecdsa_p256_sha256_fixed".to_string(),
            key_ref: format!("file://{}", key_path.display()),
            enrolled_at: "2026-09-01T00:00:00Z".to_string(),
        };

        let headers = WebhookApproval::platform_headers(
            &state,
            "POST",
            "/api/v1/approvals",
            b"{\"request\":{}}",
            Duration::from_secs(90),
        )
        .unwrap();
        let names: Vec<&str> = headers.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            vec![
                "X-Nono-Protocol-Version",
                "X-Nono-Subject-Id",
                "X-Nono-Timestamp",
                "X-Nono-Request-Id",
                "X-Nono-Content-SHA256",
                "X-Nono-Signature",
                "X-Nono-Timeout-Secs",
            ]
        );
        let value = |name: &str| {
            headers
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| v.clone())
                .unwrap()
        };
        assert_eq!(value("X-Nono-Protocol-Version"), "1");
        assert_eq!(value("X-Nono-Subject-Id"), state.subject_id);
        assert_eq!(value("X-Nono-Timeout-Secs"), "90");
        assert!(value("X-Nono-Signature").starts_with("p256-sha256="));
        // Body digest is the platform's `sha256:<hex>` shape over the exact bytes.
        assert_eq!(
            value("X-Nono-Content-SHA256"),
            format!(
                "sha256:{}",
                sha2::Sha256::digest(b"{\"request\":{}}")
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            )
        );
        uuid::Uuid::parse_str(&value("X-Nono-Request-Id")).unwrap();
        value("X-Nono-Timestamp").parse::<u128>().unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[derive(Deserialize)]
    struct StatusFixture {
        name: String,
        http_status: u16,
        body: serde_json::Value,
        expected: String,
    }

    #[derive(Deserialize)]
    struct LegacyFixture {
        name: String,
        body: serde_json::Value,
        expected: String,
    }

    #[derive(Deserialize)]
    struct ApprovalStatusFixtures {
        signed: Vec<StatusFixture>,
        unsigned: Vec<LegacyFixture>,
    }

    fn decision_name(decision: &ApprovalDecision) -> &'static str {
        match decision {
            ApprovalDecision::Granted => "granted",
            ApprovalDecision::Denied { .. } => "denied",
            ApprovalDecision::Timeout => "timeout",
        }
    }

    /// The documented response shapes (`docs/protocols/approval-webhook-v1.md`)
    /// map to the decisions the protocol promises.
    #[test]
    fn approval_status_fixtures_match_protocol_document() {
        let fixtures: ApprovalStatusFixtures = serde_json::from_str(include_str!(
            "../../../tests/fixtures/approval-status-v1.json"
        ))
        .expect("valid approval status fixture");
        let backend = test_webhook(Duration::from_secs(30));

        for fixture in &fixtures.signed {
            let body = fixture.body.to_string();
            let mut polls = 0;
            let decision = backend
                .drive_platform_approval("req-fixture", b"{}", Instant::now(), |_, _| {
                    polls += 1;
                    if polls == 1 {
                        Ok(reply(fixture.http_status, &body))
                    } else {
                        // A pending fixture is followed by a grant so the loop ends.
                        Ok(reply(200, r#"{"state":"granted","decision":"granted"}"#))
                    }
                })
                .expect(&fixture.name);
            if fixture.expected == "pending" {
                assert_eq!(polls, 2, "{}: pending must be polled again", fixture.name);
                assert!(decision.is_granted(), "{}", fixture.name);
            } else {
                assert_eq!(polls, 1, "{}: final states end the exchange", fixture.name);
                assert_eq!(
                    decision_name(&decision),
                    fixture.expected,
                    "{}",
                    fixture.name
                );
            }
        }

        for fixture in &fixtures.unsigned {
            let decision = backend
                .parse_response(&fixture.body.to_string())
                .expect(&fixture.name);
            assert_eq!(
                decision_name(&decision),
                fixture.expected,
                "{}",
                fixture.name
            );
        }
    }

    #[derive(Deserialize)]
    struct CanonicalFixture {
        method: String,
        path: String,
        subject_id: String,
        timestamp_ms: String,
        request_id: String,
        body_digest: String,
        canonical: String,
    }

    /// The poll is a bodiless GET: its content digest is the SHA-256 of zero
    /// bytes, and the canonical string follows `nono-request-v1` unchanged.
    #[test]
    fn approval_poll_canonical_request_matches_fixture() {
        let fixture: CanonicalFixture = serde_json::from_str(include_str!(
            "../../../tests/fixtures/approval-poll-request-v1.json"
        ))
        .expect("valid poll fixture");
        assert_eq!(
            crate::platform_client::canonical_request_v1(
                &fixture.method,
                &fixture.path,
                &fixture.subject_id,
                &fixture.timestamp_ms,
                &fixture.request_id,
                &fixture.body_digest,
            ),
            fixture.canonical
        );
        let empty_digest = format!(
            "sha256:{}",
            sha2::Sha256::digest(b"")
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        assert_eq!(fixture.body_digest, empty_digest);
    }
}
