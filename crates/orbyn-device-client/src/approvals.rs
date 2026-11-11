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
use crate::{Clock, DeviceApi, DeviceError, KeyStore, Method};
use orbyn_client::{ApproverPairing, ClientError, DevicePairing, Engine};
use orbyn_contracts as wire;

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
}

impl ApproverApproval {
    pub fn id(&self) -> &str {
        self.pairing.approval_id()
    }
}

/// What the approver's screen shows.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    fn approval_path(id: &str, step: Option<&str>) -> String {
        match step {
            Some(step) => format!("/v1/devices/approvals/{id}/{step}"),
            None => format!("/v1/devices/approvals/{id}"),
        }
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
        if view.device_nonce.is_none() {
            return Ok(ApproverState::Waiting);
        }
        if !approval.revealed {
            let reveal = match approval.pairing.reveal(&view) {
                Ok(reveal) => reveal,
                Err(error) => {
                    self.cancel_quietly(&id).await;
                    return Err(mismatch(error));
                }
            };
            self.authed(
                Method::Post,
                &Self::approval_path(&id, Some("reveal")),
                Some(json(&reveal)?),
            )
            .await?;
            approval.revealed = true;
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
            &format!("/v1/devices/{}", device.id),
            Some(json(&body)?),
        )
        .await?;
        Ok(())
    }
}
