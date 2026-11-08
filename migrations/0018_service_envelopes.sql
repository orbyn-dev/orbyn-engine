-- Service envelopes (docs/key-service.md, "Writing service envelopes"): a zone key sealed to the
-- account's service key, kept beside the envelopes sealed to its devices. The server stores the
-- bytes and never opens them. Nothing is moved or made for an existing account: every existing row
-- is a device row and stays one, and the new table starts empty.

-- The old primary key (recipient_device_id, zone, key_id) cannot hold a null, so it goes first and
-- is replaced below by one unique index for device rows and one for service rows. Sending the same
-- key again still replaces the envelope.
ALTER TABLE key_envelopes DROP CONSTRAINT key_envelopes_pkey;

-- Who the envelope is for. A device envelope names its recipient device; a service envelope names
-- none (it is the account's, one per zone and key id) and carries the statement hash of the
-- certification it was sealed against, so the server can refuse one sealed to a key that is no
-- longer the account's.
ALTER TABLE key_envelopes
    ADD COLUMN recipient_kind text NOT NULL DEFAULT 'device'
        CHECK (recipient_kind IN ('device', 'service')),
    ADD COLUMN service_statement_hash bytea
        CHECK (service_statement_hash IS NULL OR length(service_statement_hash) = 32),
    ALTER COLUMN recipient_device_id DROP NOT NULL;
ALTER TABLE key_envelopes
    ADD CONSTRAINT key_envelopes_recipient_matches_kind
        CHECK ((recipient_kind = 'device') = (recipient_device_id IS NOT NULL)
           AND (recipient_kind = 'service') = (service_statement_hash IS NOT NULL));

CREATE UNIQUE INDEX key_envelopes_device ON key_envelopes (recipient_device_id, zone, key_id)
    WHERE recipient_kind = 'device';
CREATE UNIQUE INDEX key_envelopes_service ON key_envelopes (account_id, zone, key_id)
    WHERE recipient_kind = 'service';
CREATE INDEX key_envelopes_account_zone_key ON key_envelopes (account_id, zone, key_id);

-- The account's service key as the key service certified it, cached by the record server. All of it
-- is public: the identity's signature over the statement, which names the account and the key.
-- Devices check it themselves; the server compares only the statement hash a service envelope
-- carries with this one.
CREATE TABLE account_service_keys (
    account_id       uuid        PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    identity_version integer     NOT NULL CHECK (identity_version >= 1),
    -- The compressed P-256 service public key.
    public_key       bytea       NOT NULL CHECK (length(public_key) = 33),
    statement        bytea       NOT NULL CHECK (length(statement) = 77),
    statement_hash   bytea       NOT NULL CHECK (length(statement_hash) = 32),
    signature        bytea       NOT NULL CHECK (length(signature) = 64),
    created_at       timestamptz NOT NULL DEFAULT now()
);
