from __future__ import annotations

import unittest
from pathlib import Path


class ProductAuthContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[1]
        self.auth = (
            self.root / "control-plane" / "cloudflare" / "src" / "product_auth.ts"
        ).read_text(encoding="utf-8")
        self.worker = (
            self.root / "control-plane" / "cloudflare" / "src" / "index.ts"
        ).read_text(encoding="utf-8")

    def test_product_auth_is_jwks_signature_based_and_fail_closed(self) -> None:
        self.assertIn('new Set(["RS256", "ES256"])', self.auth)
        self.assertIn("crypto.subtle.verify", self.auth)
        self.assertIn("product_auth_unconfigured", self.auth)
        self.assertIn("product_signature_invalid", self.auth)
        self.assertIn('redirect: "manual"', self.auth)
        self.assertNotIn('redirect: "error"', self.auth)
        self.assertNotIn('"none"', self.auth)
        self.assertNotIn('"HS256"', self.auth)

    def test_jwks_fetch_uses_canonical_bounded_stream_parser(self) -> None:
        self.assertIn('import { readBoundedJsonObject } from "./request_json.ts";', self.auth)
        self.assertIn("readBoundedJsonObject(response, MAX_JWKS_RESPONSE_BYTES)", self.auth)
        self.assertIn("const MAX_JWKS_KEYS = 64;", self.auth)
        self.assertNotIn("await response.json()", self.auth)
        reader = (
            self.root / "control-plane" / "cloudflare" / "src" / "request_json.ts"
        ).read_text(encoding="utf-8")
        self.assertIn("request: Request | Response", reader)
        self.assertIn("if (bytes > maxBytes) return null", reader)

    def test_product_identity_requires_explicit_issuer_audience_and_https_jwks(self) -> None:
        self.assertIn("PRODUCT_AUTH_ISSUER", self.auth)
        self.assertIn("PRODUCT_AUTH_AUDIENCE", self.auth)
        self.assertIn("PRODUCT_AUTH_JWKS_URL", self.auth)
        self.assertIn('parsed.protocol !== "https:"', self.auth)
        self.assertIn("payload.iss !== issuer", self.auth)
        self.assertIn("audienceMatches(payload.aud, audience)", self.auth)
        self.assertIn("exp <= now - CLOCK_SKEW_SECONDS", self.auth)

    def test_product_mcp_identity_requires_signed_oauth_client_claim(self) -> None:
        # MCP client identity is derived only after the asymmetric JWT
        # signature has been verified by the canonical issuer.
        self.assertIn("authenticateProductMcpClientRequest(", self.auth)
        self.assertIn("const identity = await authenticateProductRequest(request, env)", self.auth)
        self.assertIn("role !== \"authenticated\"", self.auth)
        self.assertIn("isCanonicalUuid(identity.subjectId)", self.auth)
        self.assertIn(
            'canonicalRemoteClient(identity.subjectId, "product-mcp", identity.clientId)',
            self.auth,
        )
        self.assertIn("clientId: client.p_client_id", self.auth)
        self.assertIn("product_mcp_oauth_client_required", self.auth)
        self.assertIn('typeof payload.client_id === "string"', self.auth)
        self.assertNotIn('request.headers.get("x-ordax-client-id")', self.auth)

    def test_product_session_does_not_reuse_operator_or_device_auth(self) -> None:
        session_start = self.worker.index("async function productSession")
        session_end = self.worker.index("async function getProductAction", session_start)
        session_source = self.worker[session_start:session_end]

        self.assertIn("authenticateProductRequest", session_source)
        self.assertNotIn("operatorAuthorized", session_source)
        self.assertNotIn("authenticateDevice", session_source)
        self.assertIn('"/v3/product/session"', self.worker)

    def test_product_session_is_identity_only_not_execution(self) -> None:
        session_start = self.worker.index("async function productSession")
        session_end = self.worker.index("async function getProductAction", session_start)
        session_source = self.worker[session_start:session_end]

        self.assertNotIn("enqueueJob", session_source)
        self.assertNotIn("resolveProductGrantForContext", session_source)
        self.assertNotIn("wakeDeviceSession", session_source)
        self.assertIn("subject_id", session_source)


if __name__ == "__main__":
    unittest.main()
