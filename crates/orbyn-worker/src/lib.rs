//! Runs queued jobs until asked to stop. Each job kind has one handler; an
//! unknown kind fails, so a typo never silently drops work.

mod smtp;

pub use smtp::{OPERATOR_ERROR, OPERATOR_WARNING, Smtp};

use orbyn_core::accounts::AuthSecrets;
use orbyn_core::mail::{self, Delivery, Sender};
use orbyn_core::{Database, jobs};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

const LEASE: Duration = Duration::from_secs(60);
/// How often expired sign-in data is removed.
const PRUNE_EVERY: Duration = Duration::from_secs(5 * 60);
const IDLE: Duration = Duration::from_secs(2);
/// How often tombstones and deleted zones past their retention are purged.
const PURGE_EVERY: Duration = Duration::from_secs(10 * 60);
/// Rows removed per purge step, and steps per run, so a run is bounded and a
/// backlog drains over several runs instead of holding the database.
const PURGE_BATCH: i64 = 1000;
/// How often accounts whose deletion is due are deleted, and how many in one run.
const DELETE_EVERY: Duration = Duration::from_secs(60);
const DELETE_BATCH: i64 = 20;
/// Finished jobs are kept this long (their payloads name accounts and devices), and removed in
/// batches on the prune schedule.
const FINISHED_JOBS_KEPT: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const FINISHED_JOBS_BATCH: i64 = 1000;
const PURGE_STEPS: usize = 50;

/// The log line for an email job given up on, with its kind in words: `email job <id>
/// (<kind>) gave up: <reason>`. The reason is one of the designed sentences (the message couldn't
/// be built, the mail server refused it for good, it waited in the queue and expired) and never
/// holds an address or the body.
pub fn email_gave_up_line(job: impl std::fmt::Display, kind: &str, reason: &str) -> String {
    format!(
        "email job {job} ({}) gave up: {reason}",
        mail::kind_in_words(kind)
    )
}

/// The log line for an email job whose account was deleted under it.
pub fn email_dropped_line(job: impl std::fmt::Display, kind: &str) -> String {
    format!(
        "email job {job} ({}) dropped: its account was deleted",
        mail::kind_in_words(kind)
    )
}

/// What a handler decided about a job.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Done,
    Retry(String),
    /// Stop for good: the job cannot succeed or is no longer wanted.
    GiveUp(String),
}

/// What the worker needs to send email: the setup that opens a queued message (without it a
/// message is logged as not sent) and the sender, SMTP or [`mail::LogOnly`].
#[derive(Clone)]
pub struct Mailer {
    pub secrets: Option<Arc<AuthSecrets>>,
    /// Where the account site is served (`ORBYN_ACCOUNT_URL`), for the link in the unused-account
    /// deletion email. Without it that email has no link.
    pub account_url: Option<String>,
    pub sender: Arc<dyn Sender>,
    /// Who delivers silent pushes; the default sends nothing and logs nothing.
    pub push: Arc<dyn orbyn_core::push::PushSender>,
    /// Whom to tell to retire an account's service key (the key service's client). Without it a
    /// retire job waits and is retried, so a worker started later with it does the work.
    pub key_service: Option<Arc<dyn ServiceKeyRetirer>>,
}

/// What the worker asks of the key service: to retire an account's service key. The real one is the
/// key service's client (mutual TLS); a test stands in with its own. Retiring is idempotent there.
pub trait ServiceKeyRetirer: Send + Sync {
    fn retire(
        &self,
        account: [u8; 16],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), orbyn_keyservice_client::ClientError>>
                + Send
                + '_,
        >,
    >;
}

impl ServiceKeyRetirer for orbyn_keyservice_client::Client {
    fn retire(
        &self,
        account: [u8; 16],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), orbyn_keyservice_client::ClientError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move { orbyn_keyservice_client::Client::retire(self, &account).await })
    }
}

impl std::fmt::Debug for Mailer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Mailer(..)")
    }
}

impl Mailer {
    /// A mailer that sends nothing and logs each message as not sent.
    pub fn log_only() -> Self {
        Self {
            secrets: None,
            account_url: None,
            sender: Arc::new(mail::LogOnly),
            push: Arc::new(orbyn_core::push::NoPush),
            key_service: None,
        }
    }
}

/// Delivers one email job. Failures are retried by the queue's backoff until the message is 24
/// hours old.
pub async fn deliver_email(job: &jobs::Job, mailer: &Mailer) -> Outcome {
    match mail::deliver(job, mailer.secrets.as_deref(), mailer.sender.as_ref()).await {
        Delivery::Sent => Outcome::Done,
        Delivery::Retry(reason) => Outcome::Retry(reason),
        Delivery::GiveUp(reason) => Outcome::GiveUp(reason),
    }
}

/// Decides one request for an unused-account deletion link: the email is queued only for an
/// unused account (the decision is made here so the request itself never reads the account). A
/// worker with no auth setup cannot open the request and gives it up.
async fn delete_unused_request(job: &jobs::Job, db: &Database, mailer: &Mailer) -> Outcome {
    let Some(secrets) = mailer.secrets.clone() else {
        return Outcome::GiveUp("this worker has no ORBYN_AUTH_SETUP to open the request".into());
    };
    let mut accounts = orbyn_core::Accounts::with_shared_secrets(db.pool().clone(), secrets);
    if let Some(url) = &mailer.account_url {
        accounts = accounts.with_account_url(url);
    }
    match accounts.run_delete_unused_request(job).await {
        Ok(()) => Outcome::Done,
        Err(_) => Outcome::Retry("the request could not be decided".into()),
    }
}

/// Tells the key service to retire the service key of an account that switched to Advanced. It
/// runs again until the key service has done it (retiring is idempotent there), and it is skipped
/// if the account is Standard again by the time it runs: the copy is gone either way (the switch
/// removed the service envelopes), so the key opens nothing, and destroying a key the person
/// went back to would lose it.
pub async fn service_key_retire(job: &jobs::Job, db: &Database, mailer: &Mailer) -> Outcome {
    let Some(account) = job.payload["account_id"]
        .as_str()
        .and_then(|text| uuid::Uuid::parse_str(text).ok())
    else {
        return Outcome::GiveUp("the retire job names no account".into());
    };
    let level: Result<Option<String>, _> = orbyn_core::sqlx::query_scalar(
        "SELECT level FROM protection_settings WHERE account_id = $1 ORDER BY seq DESC LIMIT 1",
    )
    .bind(account)
    .fetch_optional(db.pool())
    .await;
    match level {
        Ok(Some(level)) if level != "advanced" => return Outcome::Done,
        Ok(_) => {}
        Err(_) => return Outcome::Retry("the account's protection could not be read".into()),
    }
    let Some(key_service) = &mailer.key_service else {
        return Outcome::Retry("this worker has no key service to retire the key with".into());
    };
    match key_service.retire(*account.as_bytes()).await {
        Ok(()) => Outcome::Done,
        // Whatever went wrong, trying again is safe; the queue gives up after its attempts, and
        // the job stays in the table for an operator to see.
        Err(error) => {
            tracing::warn!(kind = ?error, job = %job.id, "could not retire a service key yet");
            Outcome::Retry("the key service could not retire the key yet".into())
        }
    }
}

/// Wakes the devices that subscribed to a zone that changed: through the push sender, content-free.
/// With the default sender nothing is read or sent.
async fn zone_changed(job: &jobs::Job, db: &Database, mailer: &Mailer) -> Outcome {
    match orbyn_core::push::handle_zone_changed(
        db.pool(),
        mailer.secrets.as_deref(),
        mailer.push.as_ref(),
        job,
    )
    .await
    {
        orbyn_core::push::PushDelivery::Done => Outcome::Done,
        orbyn_core::push::PushDelivery::Retry(reason) => Outcome::Retry(reason),
        orbyn_core::push::PushDelivery::GiveUp(reason) => Outcome::GiveUp(reason),
    }
}

/// Runs one job. Kinds arrive with later phases (push, reminders, rotation).
///
/// Delivery is at least once: a job can run again after a crash or a lost lease,
/// so a handler must be idempotent, using `job.id` or `job.idempotency_key` as the
/// operation identity for every external effect.
pub async fn handle(job: &jobs::Job) -> Outcome {
    match job.kind.as_str() {
        "noop" => Outcome::Done,
        // A zone changed and another device subscribed to it. The hook for
        // silent push: with APNs and FCM it sends one push per subscribed
        // device, using the job's idempotency key (zone and token) as the
        // provider's operation identity. Until then there is nothing to send.
        "zone_changed" => Outcome::Done,
        other => Outcome::Retry(format!("no handler for job kind {other:?}")),
    }
}

/// Drives `work` to completion while calling `renew` every `period`. Returns
/// `None` when a renewal reports the lease lost (the caller must abandon the
/// result); a renewal that errors is logged and tried again next period.
async fn supervise<W, R, Fut>(work: W, period: Duration, mut renew: R) -> Option<Outcome>
where
    W: std::future::Future<Output = Outcome>,
    R: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<bool, orbyn_core::sqlx::Error>>,
{
    tokio::pin!(work);
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            outcome = &mut work => return Some(outcome),
            _ = ticker.tick() => match renew().await {
                Ok(true) => {}
                Ok(false) => return None,
                Err(err) => tracing::warn!(error = %err, "could not renew the job lease"),
            },
        }
    }
}

/// Deletes the accounts whose scheduled deletion is due, each re-checked under its own lock. Needs
/// the auth setup, which the digests that key the account's rate-limit rows come from: without it
/// nothing is deleted, and that is logged.
///
/// A worker with no auth setup (development with `ORBYN_MAIL=log`) cannot do them: it logs an error
/// on each tick that finds one due and carries on with everything else (purging, pruning, mail), so
/// one due account never takes the worker down.
async fn delete_due_accounts(db: &Database, mailer: &Mailer) {
    let Some(secrets) = mailer.secrets.clone() else {
        let due: Result<bool, _> = orbyn_core::sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM accounts WHERE deletion_scheduled_at <= now())",
        )
        .fetch_one(db.pool())
        .await;
        if due.unwrap_or(false) {
            tracing::error!(
                "account deletions are due, but this worker has no ORBYN_AUTH_SETUP to delete them; skipping them"
            );
        }
        return;
    };
    let accounts = orbyn_core::Accounts::with_shared_secrets(db.pool().clone(), secrets);
    match accounts.due_for_deletion(DELETE_BATCH).await {
        Ok(due) => {
            for id in due {
                match accounts.delete_if_due(id).await {
                    Ok(true) => tracing::info!(account = %id, "deleted an account"),
                    Ok(false) => {}
                    Err(err) => {
                        tracing::error!(account = %id, error = %err, "could not delete an account")
                    }
                }
            }
        }
        Err(err) => tracing::warn!(error = %err, "could not look for accounts due for deletion"),
    }
}

/// Claims and runs jobs until `stop` turns true.
///
/// `retention` is how long tombstones and deleted zones are kept before the
/// scheduled purge removes them.
pub async fn run(
    db: Database,
    worker_id: String,
    retention: Duration,
    mailer: Mailer,
    mut stop: watch::Receiver<bool>,
) {
    tracing::info!(worker = %worker_id, "worker started");
    let mut next_prune = tokio::time::Instant::now();
    let mut next_purge = tokio::time::Instant::now();
    let mut next_delete = tokio::time::Instant::now();
    while !*stop.borrow() {
        // Housekeeping on a schedule, not on requests, so a flood of refused
        // requests can never stop it. Every replica may run it; deletes are batched.
        if tokio::time::Instant::now() >= next_prune {
            match orbyn_core::accounts::limits::prune(db.pool()).await {
                Ok(n) if n > 0 => tracing::info!(removed = n, "pruned expired sign-in data"),
                Ok(_) => {}
                Err(err) => tracing::warn!(error = %err, "could not prune sign-in data"),
            }
            match jobs::prune_finished(db.pool(), FINISHED_JOBS_KEPT, FINISHED_JOBS_BATCH).await {
                Ok(n) if n > 0 => tracing::info!(removed = n, "pruned finished jobs"),
                Ok(_) => {}
                Err(err) => tracing::warn!(error = %err, "could not prune finished jobs"),
            }
            next_prune = tokio::time::Instant::now() + PRUNE_EVERY;
        }
        if tokio::time::Instant::now() >= next_delete {
            next_delete = tokio::time::Instant::now() + DELETE_EVERY;
            delete_due_accounts(&db, &mailer).await;
        }
        if tokio::time::Instant::now() >= next_purge {
            match orbyn_store::purge(db.pool(), retention, PURGE_BATCH, PURGE_STEPS).await {
                Ok(p) if p.records > 0 || p.zones > 0 => {
                    tracing::info!(
                        tombstones = p.records,
                        zones = p.zones,
                        "purged expired records"
                    );
                    // A full run may have left more; come back soon, not in ten minutes.
                    let full = p.records >= (PURGE_BATCH as u64) * (PURGE_STEPS as u64) / 2;
                    next_purge =
                        tokio::time::Instant::now() + if full { IDLE } else { PURGE_EVERY };
                }
                Ok(_) => next_purge = tokio::time::Instant::now() + PURGE_EVERY,
                Err(err) => {
                    tracing::warn!(error = %err, "could not purge expired records");
                    next_purge = tokio::time::Instant::now() + PURGE_EVERY;
                }
            }
        }
        match jobs::claim(db.pool(), &worker_id, LEASE).await {
            Ok(Some(job)) => {
                let pool = db.pool();
                let work = async {
                    if job.kind == mail::JOB_KIND {
                        deliver_email(&job, &mailer).await
                    } else if job.kind == orbyn_store::ZONE_CHANGED_JOB {
                        zone_changed(&job, &db, &mailer).await
                    } else if job.kind == orbyn_store::SERVICE_KEY_RETIRE_JOB {
                        service_key_retire(&job, &db, &mailer).await
                    } else if job.kind == orbyn_core::accounts::DELETE_UNUSED_JOB_KIND {
                        delete_unused_request(&job, &db, &mailer).await
                    } else {
                        handle(&job).await
                    }
                };
                let outcome = supervise(work, LEASE / 3, || {
                    jobs::renew(pool, job.id, &worker_id, LEASE)
                })
                .await;
                let Some(outcome) = outcome else {
                    tracing::warn!(job = %job.id, kind = %job.kind, "lease lost; result abandoned");
                    continue;
                };
                let email_kind = (job.kind == mail::JOB_KIND)
                    .then(|| job.payload["kind"].as_str().unwrap_or("").to_owned());
                let result = match outcome {
                    Outcome::Done => jobs::complete(db.pool(), job.id, &worker_id).await,
                    Outcome::GiveUp(reason) => {
                        match &email_kind {
                            Some(kind) => {
                                tracing::warn!("{}", email_gave_up_line(job.id, kind, &reason));
                            }
                            None => {
                                tracing::warn!(job = %job.id, kind = %job.kind, "job given up: {reason}");
                            }
                        }
                        jobs::abandon(db.pool(), job.id, &worker_id, &reason).await
                    }
                    Outcome::Retry(reason) => {
                        tracing::warn!(job = %job.id, kind = %job.kind, attempts = job.attempts, "job failed");
                        jobs::fail(
                            db.pool(),
                            job.id,
                            &worker_id,
                            &reason,
                            jobs::backoff(job.attempts),
                        )
                        .await
                    }
                };
                // An email job whose row is gone was deleted with its account (that deletion removes
                // the jobs that name it): say so, once, and nothing more.
                if let (Ok(false), Some(kind)) = (&result, &email_kind)
                    && matches!(jobs::exists(db.pool(), job.id).await, Ok(false))
                {
                    tracing::info!("{}", email_dropped_line(job.id, kind));
                    continue;
                }
                if let Err(err) = result {
                    tracing::error!(job = %job.id, error = %err, "could not record the job result");
                }
            }
            Ok(None) => {
                let _ = tokio::time::timeout(IDLE, stop.changed()).await;
            }
            Err(err) => {
                tracing::error!(error = %err, "could not claim a job");
                let _ = tokio::time::timeout(IDLE * 5, stop.changed()).await;
            }
        }
    }
    tracing::info!(worker = %worker_id, "worker stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(kind: &str) -> jobs::Job {
        jobs::Job {
            id: Default::default(),
            kind: kind.into(),
            payload: Default::default(),
            attempts: 1,
            idempotency_key: None,
        }
    }

    #[tokio::test]
    async fn an_email_job_is_done_retried_or_given_up_by_what_the_sender_says() {
        use orbyn_core::mail::{Capture, Kind, Mail, SendError, SendFuture};

        struct Says(Result<(), SendError>);
        impl Sender for Says {
            fn send<'a>(&'a self, _: &'a Mail) -> SendFuture<'a> {
                let answer = self.0.clone();
                Box::pin(async move { answer })
            }
        }
        let secrets = Arc::new(AuthSecrets::from_encoded(&AuthSecrets::generate()).expect("setup"));
        let mail = Mail {
            kind: Kind::VerifyEmail,
            account: Some(uuid::Uuid::new_v4()),
            to: "sam@example.com".into(),
            code: Some("123456".into()),
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let mut j = job(mail::JOB_KIND);
        j.payload = mail::payload(&secrets, j.id, &mail, now).expect("payload");
        let mailer = |sender: Arc<dyn Sender>| Mailer {
            secrets: Some(secrets.clone()),
            account_url: None,
            push: Arc::new(orbyn_core::push::NoPush),
            sender,
            key_service: None,
        };

        let capture = Capture::default();
        assert_eq!(
            deliver_email(&j, &mailer(Arc::new(capture.clone()))).await,
            Outcome::Done
        );
        assert_eq!(capture.sent(), vec![mail.clone()]);
        let busy = Says(Err(SendError {
            reason: "the mail server did not take the message".into(),
            permanent: false,
        }));
        assert!(matches!(
            deliver_email(&j, &mailer(Arc::new(busy))).await,
            Outcome::Retry(_)
        ));
        let refused = Says(Err(SendError {
            reason: "refused".into(),
            permanent: true,
        }));
        assert_eq!(
            deliver_email(&j, &mailer(Arc::new(refused))).await,
            Outcome::GiveUp("refused".into())
        );
        // With no SMTP, the log-only mailer finishes the job and sends nothing.
        assert_eq!(deliver_email(&j, &Mailer::log_only()).await, Outcome::Done);
    }

    #[tokio::test]
    async fn known_kinds_finish_and_unknown_kinds_retry() {
        assert_eq!(handle(&job("noop")).await, Outcome::Done);
        assert_eq!(handle(&job("zone_changed")).await, Outcome::Done);
        assert!(matches!(handle(&job("typo")).await, Outcome::Retry(_)));
    }

    /// A key service that records the accounts it was told to retire and answers as told.
    struct FakeRetirer {
        told: std::sync::Mutex<Vec<[u8; 16]>>,
        answer: Result<(), orbyn_keyservice_client::ClientError>,
    }

    impl ServiceKeyRetirer for FakeRetirer {
        fn retire(
            &self,
            account: [u8; 16],
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<(), orbyn_keyservice_client::ClientError>>
                    + Send
                    + '_,
            >,
        > {
            self.told.lock().expect("lock").push(account);
            let answer = self.answer.clone();
            Box::pin(async move { answer })
        }
    }

    async fn account_with_level(db: &Database, level: Option<&str>) -> uuid::Uuid {
        let id = uuid::Uuid::new_v4();
        orbyn_core::sqlx::query(
            "INSERT INTO accounts (id, email, password_file) VALUES ($1, $2, decode('01', 'hex'))",
        )
        .bind(id)
        .bind(format!("retire-{id}@example.com"))
        .execute(db.pool())
        .await
        .expect("account");
        if let Some(level) = level {
            orbyn_core::sqlx::query(
                "INSERT INTO protection_settings
                     (account_id, seq, level, prev, hash, signed_at, signer_device_id, signature)
                 VALUES ($1, 1, $2, decode(repeat('00', 32), 'hex'), decode(repeat('11', 32), 'hex'),
                         1, $1, decode(repeat('22', 64), 'hex'))",
            )
            .bind(id)
            .bind(level)
            .execute(db.pool())
            .await
            .expect("setting");
        }
        id
    }

    fn retire_job(account: uuid::Uuid) -> jobs::Job {
        let mut j = job(orbyn_store::SERVICE_KEY_RETIRE_JOB);
        j.payload = serde_json::json!({"account_id": account});
        j
    }

    #[tokio::test]
    #[ignore = "needs DATABASE_URL"]
    async fn a_retire_job_tells_the_key_service_and_is_safe_to_run_again() {
        let url =
            std::env::var("DATABASE_URL").expect("set DATABASE_URL to run the Postgres tests");
        let db = Database::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        let account = account_with_level(&db, Some("advanced")).await;
        let fake = Arc::new(FakeRetirer {
            told: Default::default(),
            answer: Ok(()),
        });
        let mailer = Mailer {
            key_service: Some(fake.clone()),
            ..Mailer::log_only()
        };
        assert_eq!(
            service_key_retire(&retire_job(account), &db, &mailer).await,
            Outcome::Done
        );
        // At least once: running it again tells the service again, which is idempotent there.
        assert_eq!(
            service_key_retire(&retire_job(account), &db, &mailer).await,
            Outcome::Done
        );
        assert_eq!(
            *fake.told.lock().expect("lock"),
            vec![*account.as_bytes(); 2]
        );
    }

    #[tokio::test]
    #[ignore = "needs DATABASE_URL"]
    async fn a_retire_job_waits_when_the_service_is_down_or_missing_and_skips_a_standard_account() {
        let url =
            std::env::var("DATABASE_URL").expect("set DATABASE_URL to run the Postgres tests");
        let db = Database::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        let advanced = account_with_level(&db, Some("advanced")).await;
        // The key service is down: retry, never done and never given up, so the key is not left.
        let down = Arc::new(FakeRetirer {
            told: Default::default(),
            answer: Err(orbyn_keyservice_client::ClientError::Unavailable),
        });
        let mailer = Mailer {
            key_service: Some(down.clone()),
            ..Mailer::log_only()
        };
        assert!(matches!(
            service_key_retire(&retire_job(advanced), &db, &mailer).await,
            Outcome::Retry(_)
        ));
        assert_eq!(down.told.lock().expect("lock").len(), 1);
        // No key service on this worker: retry too, so a worker that has one does it later.
        assert!(matches!(
            service_key_retire(&retire_job(advanced), &db, &Mailer::log_only()).await,
            Outcome::Retry(_)
        ));
        // The account went back to Standard before the job ran: the service is not told.
        let standard = account_with_level(&db, Some("standard")).await;
        let fake = Arc::new(FakeRetirer {
            told: Default::default(),
            answer: Ok(()),
        });
        let mailer = Mailer {
            key_service: Some(fake.clone()),
            ..Mailer::log_only()
        };
        assert_eq!(
            service_key_retire(&retire_job(standard), &db, &mailer).await,
            Outcome::Done
        );
        assert!(fake.told.lock().expect("lock").is_empty());
        // An account that is gone still gets its key retired.
        let gone = uuid::Uuid::new_v4();
        assert_eq!(
            service_key_retire(&retire_job(gone), &db, &mailer).await,
            Outcome::Done
        );
        assert_eq!(*fake.told.lock().expect("lock"), vec![*gone.as_bytes()]);
        // A job that names no account is given up on, not retried for ever.
        let mut bad = job(orbyn_store::SERVICE_KEY_RETIRE_JOB);
        bad.payload = serde_json::json!({"account_id": "not a uuid"});
        assert!(matches!(
            service_key_retire(&bad, &db, &mailer).await,
            Outcome::GiveUp(_)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn a_long_job_renews_its_lease_until_it_finishes() {
        let renewals = std::cell::Cell::new(0);
        let work = async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Outcome::Done
        };
        let out = supervise(work, Duration::from_secs(3), || {
            renewals.set(renewals.get() + 1);
            async { Ok(true) }
        })
        .await;
        assert_eq!(out, Some(Outcome::Done));
        assert_eq!(renewals.get(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_lost_lease_abandons_the_result() {
        let work = async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Outcome::Done
        };
        let out = supervise(work, Duration::from_secs(3), || async { Ok(false) }).await;
        assert_eq!(out, None);
    }

    /// With deletions due and no auth setup the worker cannot delete them, so it skips them and says
    /// so, and keeps running its other work: a queued job still runs and the worker still stops when
    /// asked.
    #[tokio::test]
    #[ignore = "needs DATABASE_URL"]
    async fn a_worker_that_cannot_delete_due_accounts_skips_them_and_keeps_working() {
        let url =
            std::env::var("DATABASE_URL").expect("set DATABASE_URL to run the Postgres tests");
        let db = Database::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        let id = uuid::Uuid::new_v4();
        orbyn_core::sqlx::query(
            "INSERT INTO accounts (id, email, password_file, deletion_scheduled_at)
             VALUES ($1, $2, decode('01', 'hex'), now() - interval '1 minute')",
        )
        .bind(id)
        .bind(format!("worker-{id}@example.com"))
        .execute(db.pool())
        .await
        .expect("account");
        let job = jobs::enqueue(db.pool(), "noop", Default::default(), None)
            .await
            .expect("job");
        let (stop, rx) = watch::channel(false);
        let mut worker = tokio::spawn(run(
            db.clone(),
            "worker-test".into(),
            Duration::from_secs(86_400),
            Mailer::log_only(),
            rx,
        ));
        // The queued job is done although a deletion was due (and skipped) on the first tick.
        let mut state = String::new();
        for _ in 0..40 {
            state = orbyn_core::sqlx::query_scalar("SELECT state FROM jobs WHERE id = $1")
                .bind(job)
                .fetch_one(db.pool())
                .await
                .expect("job state");
            if state == "done" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        assert!(
            !worker.is_finished(),
            "the worker stopped with deletions due"
        );
        stop.send(true).expect("stop");
        tokio::time::timeout(Duration::from_secs(10), &mut worker)
            .await
            .expect("it stops when asked")
            .expect("task");
        let left: i64 =
            orbyn_core::sqlx::query_scalar("SELECT count(*) FROM accounts WHERE id = $1")
                .bind(id)
                .fetch_one(db.pool())
                .await
                .expect("count");
        orbyn_core::sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(id)
            .execute(db.pool())
            .await
            .expect("clean");
        assert_eq!(left, 1, "nothing was deleted");
        assert_eq!(state, "done", "the other work ran");
    }

    #[test]
    fn the_email_log_lines_have_the_job_and_the_kind_in_words_and_nothing_personal() {
        let id = uuid::Uuid::nil();
        let nil = "00000000-0000-0000-0000-000000000000";
        for (kind, words) in [
            ("verify_email", "verification code"),
            ("sign_up_attempt", "sign-up notice"),
            ("deletion_scheduled", "account deletion notice"),
        ] {
            assert_eq!(
                email_gave_up_line(id, kind, "the message couldn't be built (it has no code)"),
                format!(
                    "email job {nil} ({words}) gave up: the message couldn't be built (it has no code)"
                )
            );
            assert_eq!(
                email_dropped_line(id, kind),
                format!("email job {nil} ({words}) dropped: its account was deleted")
            );
        }
        assert_eq!(
            email_gave_up_line(
                id,
                "verify_email",
                "the mail server refused it for good (550 5.1.1 <address>: user unknown)"
            ),
            format!(
                "email job {nil} (verification code) gave up: the mail server refused it for good (550 5.1.1 <address>: user unknown)"
            )
        );
        assert_eq!(
            email_gave_up_line(
                id,
                "verify_email",
                "it waited in the queue for 24 hours 3 minutes and expired"
            ),
            format!(
                "email job {nil} (verification code) gave up: it waited in the queue for 24 hours 3 minutes and expired"
            )
        );
        // No "after N tries" in any of them.
        assert!(!email_gave_up_line(id, "verify_email", "x").contains("tries"));
    }
}
