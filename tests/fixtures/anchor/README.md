# RFC-3161 timestamp fixture

Real token fetched once on 2026-11-09 from the public DigiCert timestamp service (http://timestamp.digicert.com)
for the SHA-256 digest of the ASCII string `viper-anchor-fixture-v1`:

    digest  = 4c3da67688a064a39d3ce310a3d9d3ea0a54e1161b734e204d140766f9f7b6e2
    genTime = 2026-11-09 04:24:53 UTC (epoch 1794198293)

- `digicert.tsr` - the DER timestamp response (TimeStampResp).
- `digicert-trusted-root-g4.pem` - the self-signed trust anchor, copied from the `certifi` bundle so tests stay stable.
- `unrelated-root-isrg-x1.pem` - a different real root, used to prove verification fails against the wrong anchor.

Verify by hand:

    openssl ts -verify -in digicert.tsr -digest 4c3da676...b6e2 -sha256 \
        -CAfile digicert-trusted-root-g4.pem -attime 1794198293

Timestamp-signing certificates are short-lived, so verification must be done as of the token's own genTime (`-attime`).
Revocation (CRL/OCSP) is not checked.
