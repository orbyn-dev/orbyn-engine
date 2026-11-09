# orbyn-keyservice-daemon

The key service's internal API over mutual TLS, the publisher, the audit sink and
the `orbyn-keyservice` CLI. Each endpoint checks the client certificate's name; the
route table is the whole surface and a test lists it. No endpoint opens an
envelope, derives a secret, returns a private key or signs caller-chosen bytes.
