Vendored qrcodejs 1.0.0, MIT license (see LICENSE).

Upstream: https://github.com/davidshimjs/qrcodejs
Source Git blob: 993e88f396640f881b69f98db7a4d17401ef83ca

The build removes trailing line feeds and verifies SHA-512 against the existing
cdnjs 1.0.0 SRI before copying to staging assets. No other code changes.
The bundled bytes match the existing external script exactly. No build-time or
runtime network download is required. Production assets and CSP are unchanged.
