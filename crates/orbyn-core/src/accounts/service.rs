//! Account construction and the shared request context helpers.

use super::*;
use sqlx::PgPool;
use std::net::IpAddr;
use std::sync::Arc;
use uuid::Uuid;

impl Accounts {
    pub fn new(pool: PgPool, secrets: AuthSecrets) -> Self {
        Self {
            pool,
            secrets: Arc::new(secrets),
            limits: Limits::default(),
            clock: Clock(Arc::new(|| u64::try_from(unix_now_secs()).unwrap_or(0))),
            trace: None,
            account_url: None,
            signup: crate::SignupMode::Invite,
            policy: SignupPolicy::default(),
        }
    }

    /// The service over secrets that are shared with another part of the process.
    pub fn with_shared_secrets(pool: PgPool, secrets: Arc<AuthSecrets>) -> Self {
        Self {
            pool,
            secrets,
            limits: Limits::default(),
            clock: Clock(Arc::new(|| u64::try_from(unix_now_secs()).unwrap_or(0))),
            trace: None,
            account_url: None,
            signup: crate::SignupMode::Invite,
            policy: SignupPolicy::default(),
        }
    }

    /// The address the account site is served at (`https://account.example.com`); the deletion
    /// email's cancel link points to `<url>/cancel-deletion#<token>`. Without it the email carries
    /// the token alone.
    pub fn with_account_url(mut self, url: impl Into<String>) -> Self {
        self.account_url = Some(url.into().trim_end_matches('/').to_owned());
        self
    }

    /// Who may sign up: with `Invite`, `register/finish` needs a valid invite code and
    /// `email/verify` uses it up.
    pub fn with_signup(mut self, mode: crate::SignupMode) -> Self {
        self.signup = mode;
        self
    }

    /// Replaces the sign-up pacing. For tests (and for an operator who wants a different floor).
    pub fn with_signup_policy(mut self, policy: SignupPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Waits out what is left of the response floor since `started`.
    pub(super) async fn pad(&self, started: std::time::Instant) {
        let wait = self.policy.response_floor.saturating_sub(started.elapsed());
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }

    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Replaces the clock TOTP codes and device signatures are judged against. For tests.
    pub fn with_clock(mut self, now: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.clock = Clock(Arc::new(now));
        self
    }

    /// Records the steps of the email verification paths in `sink`. For tests.
    pub fn with_step_trace(mut self, sink: Arc<std::sync::Mutex<Vec<&'static str>>>) -> Self {
        self.trace = Some(sink);
        self
    }

    pub(super) fn step(&self, name: &'static str) {
        if let Some(sink) = &self.trace {
            sink.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(name);
        }
    }

    /// The keyed digest of the client's address prefix: an IPv4 /24, or an IPv6 /64.
    pub(super) fn ip_prefix_digest(&self, client: &Client) -> [u8; 32] {
        let text = match client.ip {
            Some(IpAddr::V4(ip)) => {
                let o = ip.octets();
                format!("{}.{}.{}.0/24", o[0], o[1], o[2])
            }
            Some(IpAddr::V6(ip)) => match ip.to_ipv4_mapped() {
                Some(v4) => {
                    let o = v4.octets();
                    format!("{}.{}.{}.0/24", o[0], o[1], o[2])
                }
                None => {
                    let s = ip.segments();
                    format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
                }
            },
            None => "unknown".to_owned(),
        };
        self.secrets.digest("ip-prefix", text.as_bytes())
    }

    /// The keyed digest of the client's address. IPv6 addresses count by their
    /// /64, the block one connection usually controls.
    pub(super) fn ip_digest(&self, client: &Client) -> [u8; 32] {
        let text = match client.ip {
            Some(IpAddr::V4(ip)) => ip.to_string(),
            Some(IpAddr::V6(ip)) => match ip.to_ipv4_mapped() {
                Some(v4) => v4.to_string(),
                None => {
                    let s = ip.segments();
                    format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
                }
            },
            None => "unknown".to_owned(),
        };
        self.secrets.digest("ip", text.as_bytes())
    }

    pub(super) async fn audit<'e, E>(
        &self,
        executor: E,
        client: &Client,
        account_id: Option<Uuid>,
        device_id: Option<Uuid>,
        action: AuditAction,
    ) -> Result<()>
    where
        E: sqlx::PgExecutor<'e>,
    {
        // The account row is share-locked while the row is written: a deletion in flight holds it
        // exclusively, so this waits for it and then writes nothing (the account is gone, its
        // history is scrubbed, and a late row would name it again), and a deletion that comes
        // later waits for this row and scrubs it with the rest.
        sqlx::query(
            "INSERT INTO audit_log (account_id, device_id, action, ip_hash)
             SELECT $1, $2, $3, $4 WHERE $1::uuid IS NULL
                OR EXISTS (SELECT 1 FROM accounts WHERE id = $1 FOR SHARE)",
        )
        .bind(account_id)
        .bind(device_id)
        .bind(action.as_str())
        .bind(self.ip_digest(client).as_slice())
        .execute(executor)
        .await?;
        Ok(())
    }
}
