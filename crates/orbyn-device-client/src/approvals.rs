//! Approving a new device and removing one: the device's side of the two-way comparison, over
//! HTTP. Every signature and every check is the engine's (`orbyn_client::Engine`); this file only
//! moves messages between the engine and the server and keeps the order of the steps.
//!
//! The approver (a trusted device) calls [`DeviceClient::start_approval`], then
//! [`DeviceClient::approval_state`] until it shows digits, and when the person sees the same digits
//! on the new device [`DeviceClient::confirm_approval`]. The new device calls
//! [`DeviceClient::join_approval`] when [`DeviceClient::pending_approval`] shows one, then
//! [`DeviceClient::device_digits`] until it shows digits, and when the person confirms there (or
//! types the approver's digits) [`DeviceClient::finish_approval`]. Either side cancels with
//! `deny_*`. Every approval is used once.

use crate::client::{DeviceClient, json, parse};
use crate::sync::segment;
use crate::{Clock, DeviceApi, DeviceError, KeyStore, Method};
use orbyn_client::{ApproverPairing, ClientError, DevicePairing, Engine};
use orbyn_contracts as wire;
use std::time::Duration;

/// How many times the reveal is sent before a network failure is reported. The approval is not
/// cancelled by a network failure: the person can ask again.
const REVEAL_TRIES: usize = 3;

fn mismatch(error: ClientError) -> DeviceError {
    match error {
        ClientError::Mismatch => DeviceError::ApprovalMismatch,
        ClientError::InvalidInput => {
            DeviceError::InvalidInput("the device cannot be used for this")
        }
        other => crate::sync::engine_error(other),
    }
}

/// An approval this trusted device started. Use it once.
pub struct ApproverApproval {
    pairing: ApproverPairing,
    revealed: bool,
    /// The reveal the engine made, kept until the server has it: the engine makes it once, so a
    /// network failure must be answered by sending this again, not by asking the engine again.
    unsent_reveal: Option<wire::ApprovalNonce>,
    /// When the server will close the approval, Unix seconds, as it last said.
    expires_at: Option<i64>,
}

impl ApproverApproval {
    pub fn id(&self) -> &str {
        self.pairing.approval_id()
    }
}

/// Unix seconds of an RFC 3339 time in UTC (`2026-11-12T01:02:03.456Z`, as the server writes it).
/// Any other offset is `None`: the caller then shows no countdown rather than a wrong one.
fn rfc3339_secs(text: &str) -> Option<i64> {
    let text = text
        .strip_suffix('Z')
        .or_else(|| text.strip_suffix("+00:00"))?;
    let (date, time) = text.split_once('T')?;
    let mut d = date.split('-');
    let (year, month, day): (i64, i64, i64) = (
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
    );
    let time = time.split('.').next()?;
    let mut t = time.split(':');
    let (h, m, sec): (i64, i64, i64) = (
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
    );
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || h > 23 || m > 59 || sec > 60 {
        return None;
    }
    // Days since 1970-01-01 (the civil-from-days algorithm, inverted).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + m * 60 + sec)
}

/// What the approver's screen shows. Its `Debug` hides the digits and the fingerprint.
#[derive(Clone, PartialEq, Eq)]
pub enum ApproverState {
    /// The new device has not joined yet.
    Waiting,
    /// Show these on this screen and ask the person whether the new device shows the same.
    Digits {
        digits: String,
        /// The new device's key fingerprint, to show beside the digits.
        fingerprint: String,
    },
}

impl std::fmt::Debug for ApproverState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Waiting => f.write_str("Waiting"),
            Self::Digits { .. } => f.write_str("Digits { .. }"),
        }
    }
}

/// An approval the new device joined. Use it once.
pub struct JoinedApproval {
    pairing: DevicePairing,
}

impl JoinedApproval {
    pub fn id(&self) -> &str {
        self.pairing.approval_id()
    }
}

impl<A: DeviceApi, S: KeyStore, C: Clock> DeviceClient<A, S, C> {
    /// The path of an approval or one of its steps. The id is percent-encoded: on the new
    /// device's side it comes from the server.
    fn approval_path(id: &str, step: Option<&str>) -> String {
        let id = segment(id);
        match step {
            Some(step) => format!("/v1/devices/approvals/{id}/{step}"),
            None => format!("/v1/devices/approvals/{id}"),
        }
    }

    fn device_path(id: &str) -> String {
        format!("/v1/devices/{}", segment(id))
    }

    /// Best effort: a cancel that fails changes nothing, and the approval ends in ten minutes.
    async fn cancel_quietly(&self, id: &str) {
        let _ = self
            .authed(Method::Post, &Self::approval_path(id, Some("cancel")), None)
            .await;
    }

    // ---- the approver ----

    /// Starts approving `device_id`, a device from [`DeviceClient::devices`] that this device does
    /// not trust by its own view. Refused for a device it trusts or revoked, whatever the server
    /// lists.
    pub async fn start_approval(
        &self,
        engine: &Engine,
        device_id: &str,
    ) -> Result<ApproverApproval, DeviceError> {
        let devices = self.devices().await?;
        let device =
            devices
                .devices
                .iter()
                .find(|d| d.id == device_id)
                .ok_or(DeviceError::InvalidInput(
                    "the device is not in the account",
                ))?;
        let (pairing, create) = engine
            .start_approval(device, self.clock.now_secs())
            .map_err(mismatch)?;
        let response = self
            .authed(Method::Post, "/v1/devices/approvals", Some(json(&create)?))
            .await?;
        let created: wire::ApprovalCreated = parse(&response.body)?;
        if created.id != pairing.approval_id() {
            return Err(DeviceError::ApprovalMismatch);
        }
        Ok(ApproverApproval {
            pairing,
            revealed: false,
            unsent_reveal: None,
            expires_at: rfc3339_secs(&created.expires_at),
        })
    }

    /// Asks the server how far the approval is. Once the new device joined, reveals this device's
    /// nonce (once) and returns the digits. A server that shows other keys than this device
    /// started with cancels the approval: [`DeviceError::ApprovalMismatch`].
    pub async fn approval_state(
        &self,
        approval: &mut ApproverApproval,
    ) -> Result<ApproverState, DeviceError> {
        let id = approval.id().to_owned();
        let response = self
            .authed(Method::Get, &Self::approval_path(&id, None), None)
            .await?;
        let view: wire::PendingApproval = parse(&response.body)?;
        approval.expires_at = rfc3339_secs(&view.expires_at).or(approval.expires_at);
        if view.device_nonce.is_none() {
            return Ok(ApproverState::Waiting);
        }
        if !approval.revealed {
            let reveal = match approval.unsent_reveal.clone() {
                Some(reveal) => reveal,
                None => match approval.pairing.reveal(&view) {
                    Ok(reveal) => reveal,
                    Err(error) => {
                        self.cancel_quietly(&id).await;
                        return Err(mismatch(error));
                    }
                },
            };
            approval.unsent_reveal = Some(reveal.clone());
            self.send_reveal(&id, &reveal).await?;
            approval.revealed = true;
            approval.unsent_reveal = None;
        }
        let digits = approval
            .pairing
            .sas()
            .ok_or(DeviceError::ApprovalMismatch)?;
        Ok(ApproverState::Digits {
            digits,
            fingerprint: approval.pairing.device_fingerprint(),
        })
    }

    /// Sends the reveal, again if the network fails. A failure never cancels the approval: this
    /// device's nonce may have arrived, so before sending again the server is asked whether it
    /// holds it. Only an answer from the server that refuses the reveal ends the approval, and the
    /// server does that itself.
    async fn send_reveal(&self, id: &str, reveal: &wire::ApprovalNonce) -> Result<(), DeviceError> {
        let mut last = DeviceError::Transport;
        for _ in 0..REVEAL_TRIES {
            let sent = self
                .authed(
                    Method::Post,
                    &Self::approval_path(id, Some("reveal")),
                    Some(json(reveal)?),
                )
                .await;
            match sent {
                Ok(_) => return Ok(()),
                Err(DeviceError::Transport) => {
                    last = DeviceError::Transport;
                    let held = self
                        .authed(Method::Get, &Self::approval_path(id, None), None)
                        .await
                        .ok()
                        .and_then(|r| parse::<wire::PendingApproval>(&r.body).ok())
                        .is_some_and(|v| v.approver_nonce.as_deref() == Some(&reveal.nonce));
                    if held {
                        return Ok(());
                    }
                }
                Err(other) => return Err(other),
            }
        }
        Err(last)
    }

    /// How long the server will keep the approval open, from the time it gave when it opened it
    /// (refreshed by [`DeviceClient::approval_state`]) and this device's clock. `None` when the
    /// server's time could not be read. Zero once it passed: the server then answers
    /// [`DeviceError::ApprovalExpired`]. A clock that is off by seconds shows a countdown that is
    /// off by seconds; the server decides, not this.
    pub fn time_left(&self, approval: &ApproverApproval) -> Option<Duration> {
        let left = approval.expires_at? - self.clock.now_secs();
        Some(Duration::from_secs(u64::try_from(left).unwrap_or(0)))
    }

    /// The person confirmed that both screens show the same digits: signs the approval with the
    /// devices this device trusts and sends it. Not before: [`DeviceError::ApprovalMismatch`] if
    /// the digits were never shown. The host then calls [`DeviceClient::send_keys`] for each zone
    /// so the new device can read them.
    pub async fn confirm_approval(
        &self,
        engine: &mut Engine,
        approval: ApproverApproval,
    ) -> Result<(), DeviceError> {
        let id = approval.id().to_owned();
        let devices = self.devices().await?;
        let confirm = engine
            .confirm_approval(approval.pairing, &devices)
            .map_err(mismatch)?;
        self.authed(
            Method::Post,
            &Self::approval_path(&id, Some("confirm")),
            Some(json(&confirm)?),
        )
        .await?;
        Ok(())
    }

    /// The person said the digits differ, or cancelled: ends the approval on the server.
    pub async fn deny_approval(&self, approval: ApproverApproval) -> Result<(), DeviceError> {
        // An approval that already ended (expired, answered, used or cancelled by either device)
        // is `ApprovalExpired` here: the server answers 410 to this read, nothing is sent to end
        // it again and nothing is approved.
        self.authed(Method::Get, &Self::approval_path(approval.id(), None), None)
            .await?;
        self.authed(
            Method::Post,
            &Self::approval_path(approval.id(), Some("cancel")),
            None,
        )
        .await?;
        Ok(())
    }

    // ---- the new device ----

    /// The approval a trusted device started for this device, if there is one.
    pub async fn pending_approval(&self) -> Result<Option<wire::PendingApproval>, DeviceError> {
        let response = self
            .authed(Method::Get, "/v1/devices/current", None)
            .await?;
        let current: wire::CurrentDevice = parse(&response.body)?;
        Ok(current.approval)
    }

    /// Joins the approval a trusted device started, sending this device's nonce while it holds
    /// only the approver's commitment. `None` when there is no approval. A device that named its
    /// app joins with the description it signed in with, so the digits it shows only match the
    /// approver's if the approver was shown the same.
    pub async fn join_approval(
        &self,
        engine: &Engine,
    ) -> Result<Option<JoinedApproval>, DeviceError> {
        let Some(view) = self.pending_approval().await? else {
            return Ok(None);
        };
        let now = self.clock.now_secs();
        let (pairing, nonce) = match self.config.app {
            Some(app) => engine.join_approval_labelled(
                &view,
                now,
                &self.config.device_name,
                self.config.platform,
                app,
            ),
            None => engine.join_approval(&view, now),
        }
        .map_err(mismatch)?;
        self.authed(
            Method::Post,
            &Self::approval_path(&view.id, Some("nonce")),
            Some(json(&nonce)?),
        )
        .await?;
        Ok(Some(JoinedApproval { pairing }))
    }

    /// The digits to show, once the approver revealed its nonce; `None` before. A reveal that does
    /// not match the commitment is [`DeviceError::ApprovalMismatch`] and cancels the approval.
    pub async fn device_digits(
        &self,
        joined: &JoinedApproval,
    ) -> Result<Option<String>, DeviceError> {
        let view = self
            .pending_approval()
            .await?
            .filter(|v| v.id == joined.id())
            .ok_or(DeviceError::ApprovalExpired)?;
        if view.approver_nonce.is_none() {
            return Ok(None);
        }
        match joined.pairing.sas(&view) {
            Ok(digits) => Ok(Some(digits)),
            Err(error) => {
                self.cancel_quietly(joined.id()).await;
                Err(mismatch(error))
            }
        }
    }

    /// The person confirmed on this device that the digits match, or typed the approver's digits
    /// as `typed`. The engine checks the reveal, the age, the approver's signature and its
    /// endorsement and pins the approver and the devices it endorsed; only then are the digits
    /// sent, once. On any failure nothing new is trusted and the approval is cancelled.
    pub async fn finish_approval(
        &self,
        engine: &mut Engine,
        joined: JoinedApproval,
        typed: Option<&str>,
    ) -> Result<(), DeviceError> {
        let id = joined.id().to_owned();
        let view = self
            .pending_approval()
            .await?
            .filter(|v| v.id == id)
            .ok_or(DeviceError::ApprovalExpired)?;
        let digits =
            match engine.finish_approval(joined.pairing, &view, typed, self.clock.now_secs()) {
                Ok(digits) => digits,
                Err(error) => {
                    self.cancel_quietly(&id).await;
                    return Err(mismatch(error));
                }
            };
        self.authed(
            Method::Post,
            &Self::approval_path(&id, Some("code")),
            Some(json(&wire::ApprovalCode { code: digits })?),
        )
        .await?;
        Ok(())
    }

    /// The person said the digits differ, or cancelled: ends the approval on the server.
    pub async fn deny_joined(&self, joined: JoinedApproval) -> Result<(), DeviceError> {
        self.authed(
            Method::Post,
            &Self::approval_path(joined.id(), Some("cancel")),
            None,
        )
        .await?;
        Ok(())
    }

    // ---- devices ----

    /// Removes `device_id` from the account, signed by this device. A session whose password
    /// sign-in is older than ten minutes is [`DeviceError::ReauthenticationRequired`]; the last
    /// trusted device is [`DeviceError::LastTrustedDevice`].
    pub async fn remove_device(&self, engine: &Engine, device_id: &str) -> Result<(), DeviceError> {
        let devices = self.devices().await?;
        let device =
            devices
                .devices
                .iter()
                .find(|d| d.id == device_id)
                .ok_or(DeviceError::InvalidInput(
                    "the device is not in the account",
                ))?;
        let body = engine.sign_removal(device).map_err(mismatch)?;
        self.authed(
            Method::Delete,
            &Self::device_path(&device.id),
            Some(json(&body)?),
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HttpApi, MemoryStore, SystemClock};

    type Client = DeviceClient<HttpApi, MemoryStore, SystemClock>;

    #[test]
    fn ids_are_percent_encoded_in_every_path() {
        assert_eq!(
            Client::approval_path("a/b?c", Some("reveal")),
            "/v1/devices/approvals/a%2Fb%3Fc/reveal"
        );
        assert_eq!(
            Client::approval_path("a/b?c", None),
            "/v1/devices/approvals/a%2Fb%3Fc"
        );
        assert_eq!(Client::device_path("a/b?c"), "/v1/devices/a%2Fb%3Fc");
        // A uuid is unchanged.
        let id = "0000000a-0000-4000-8000-00000000000a";
        assert_eq!(
            Client::approval_path(id, Some("nonce")),
            format!("/v1/devices/approvals/{id}/nonce")
        );
    }

    #[test]
    fn the_server_time_is_read_as_utc_and_nothing_else_is_guessed() {
        assert_eq!(rfc3339_secs("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            rfc3339_secs("2027-01-15T08:00:00.123Z"),
            Some(1_800_000_000)
        );
        assert_eq!(
            rfc3339_secs("2024-02-29T12:00:00+00:00"),
            Some(1_709_208_000)
        );
        assert_eq!(rfc3339_secs("1969-12-31T23:59:59Z"), Some(-1));
        for bad in [
            "2027-01-15T10:00:00+02:00",
            "2027-01-15 08:00:00Z",
            "2027-13-15T08:00:00Z",
            "2027-01-15T25:00:00Z",
            "garbage",
            "",
        ] {
            assert_eq!(rfc3339_secs(bad), None, "{bad}");
        }
    }
}
