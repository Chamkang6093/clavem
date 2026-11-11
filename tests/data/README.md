The certificate and private key in this directory are public, test-only fixtures
for a loopback server. They are not deployment credentials and must never be used
outside tests. The client trusts this certificate only in the explicit certificate
fallback regression; the system trust store is never modified.
