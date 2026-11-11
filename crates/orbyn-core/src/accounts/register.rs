//! Sign-up: the first OPAQUE step and the pending sign-up record.

use super::*;
use uuid::Uuid;

impl Accounts {
    async fn allow_register(&self, client: &Client) -> Result<()> {
        let ip = self.ip_digest(client);
        if limits::allow(&self.pool, "register", &ip, self.limits.register_per_ip).await? {
            Ok(())
        } else {
            Err(AccountError::TooManyAttempts)
        }
    }

    /// The first sign-up step. It touches no account, so it says nothing about
    /// whether the email is taken.
    pub async fn register_start(
        &self,
        client: &Client,
        email: &str,
        request: &[u8],
    ) -> Result<Vec<u8>> {
        let email = normalize_email(email).ok_or(AccountError::InvalidEmail)?;
        self.allow_register(client).await?;
        let request = RegistrationRequest::<Suite>::deserialize(request)
            .map_err(|_| AccountError::InvalidRequest)?;
        let start =
            ServerRegistration::<Suite>::start(self.secrets.setup(), request, email.as_bytes())
                .map_err(|_| AccountError::InvalidRequest)?;
        Ok(start.message.serialize().to_vec())
    }

    /// The second sign-up step. It makes no account and no session: it keeps the password record
    /// and the first device as a pending sign-up, sends the address a code and answers a sign-up
    /// id, to be sent back with the code to [`Accounts::email_verify`]. The answer is the same for
    /// every address and every state of the limits: an address that is taken, has five pending
    /// sign-ups already, or is over its mail caps gets an id of the same shape that belongs to
    /// nobody.
    #[allow(clippy::too_many_arguments)]
    pub async fn register_finish(
        &self,
        client: &Client,
        email: &str,
        upload: &[u8],
        device: &NewDevice,
        signature: &[u8; 64],
        invite: Option<&str>,
        proof: Option<(&str, u32)>,
    ) -> Result<Uuid> {
        let started = std::time::Instant::now();
        let result = self
            .register_finish_inner(client, email, upload, device, signature, invite, proof)
            .await;
        self.pad(started).await;
        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn register_finish_inner(
        &self,
        client: &Client,
        email: &str,
        upload: &[u8],
        device: &NewDevice,
        signature: &[u8; 64],
        invite: Option<&str>,
        proof: Option<(&str, u32)>,
    ) -> Result<Uuid> {
        let email = normalize_email(email).ok_or(AccountError::InvalidEmail)?;
        let name = device.checked_name()?;
        self.allow_register(client).await?;
        // The invite is judged before anything about the address, and before the slow work: a
        // sign-up that cannot continue costs nothing and says nothing about the address.
        let invite_id = self.check_invite(client, invite).await?;
        let record = RegistrationUpload::<Suite>::deserialize(upload)
            .map_err(|_| AccountError::InvalidRequest)?;
        let (context, message) = device.register_proof(&name, &email, upload);
        orbyn_crypto::verify(&device.keys, context, &message, signature)
            .map_err(|_| AccountError::InvalidSignature)?;
        let password_file = ServerRegistration::<Suite>::finish(record)
            .serialize()
            .to_vec();

        // The throttle keys on the client's prefix and never on the address, and runs before a
        // transaction opens, so nothing about the answer depends on the address's state.
        self.throttle_start(client, proof).await?;
        self.start_signup(client, &email, &password_file, device, &name, invite_id)
            .await
    }
}
