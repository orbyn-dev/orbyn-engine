# orbyn-keyservice-client

The client for the key service's internal API, and the wire types both sides share.
It presents a client certificate, trusts only the CA it was given, and calls the
three endpoints: create or get an account's service key, get it, and retire it. It
cannot open an envelope, derive a secret or sign caller-chosen bytes.
