package admin

import "embed"

// embeddedCA is the fixed root CA baked into the binary, shared by the Android AAR
// and the desktop build so both serve leaves signed by the same trust anchor. It is
// the single source of the CA (the Android assets extraction it replaces was
// removed — a device installs this CA once, and neither an app reinstall nor an
// admin_cert_sans edit invalidates it). certs/ was generated at build time with
// openssl (ECDSA P-256, CA:TRUE/keyCertSign, 20-year validity) and is never rotated
// without planning a reinstall on every device that already trusts the old CA.
// To rotate it, run `make ca-cert` (regenerates certs/ in place with openssl,
// keeping the exact same parameters), then rebuild the binary and AAR.
//
//go:embed certs/admin_ca.crt certs/admin_ca.key
var embeddedCA embed.FS
