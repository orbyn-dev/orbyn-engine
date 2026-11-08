-- Sign-up throttle redesign (engine#42). The code of an address is no longer a digest copied
-- between rows; it is derived from the server's secret, the address and a salt, so a
-- code can be mailed again without being stored. One row per address holds the random salt the code
-- is derived from (a new salt is a new code), when it lives until, when it was last mailed and how
-- many wrong guesses it has had in its whole life.
-- Every address with a live pending sign-up has one, whether or not it already has an account, so
-- the paths do not differ by the address's state.
CREATE TABLE signup_codes (
    email         text        PRIMARY KEY,
    salt          bytea       NOT NULL CHECK (length(salt) = 16),
    expires_at    timestamptz NOT NULL,
    mailed_at     timestamptz NOT NULL DEFAULT now(),
    wrong_guesses integer     NOT NULL DEFAULT 0 CHECK (wrong_guesses >= 0)
);
CREATE INDEX signup_codes_expiry ON signup_codes (expires_at);

-- A pending row no longer holds a code or counts attempts (the address's code record does), and
-- remembers which client prefix started it, to cap the rows one prefix can hold for an address.
ALTER TABLE pending_signups
    DROP COLUMN code_digest,
    DROP COLUMN attempts,
    ADD COLUMN prefix_digest bytea;
CREATE INDEX pending_signups_prefix ON pending_signups (email, prefix_digest);
