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

    def test_product_owner_session_and_mcp_client_have_distinct_authorization(self) -> None:
        self.assertIn('return productOwnerAccountSession(request, env)', self.worker)
        self.assertIn('"/v3/product/session"', self.worker)
        self.assertIn('export async function productOwnerAccountSession(', self.auth)
        self.assertIn('const identity = await authenticateProductRequest(request, env)', self.auth)
        self.assertIn('identity.role !== "authenticated"', self.auth)
        self.assertIn('!isCanonicalUuid(identity.subjectId)', self.auth)
        self.assertIn('"product_owner_identity_invalid"', self.auth)
        self.assertIn('"cache-control": "no-store"', self.auth)
        self.assertNotIn('createCanonicalProductMcpReadHandlers(env).session(request)', self.worker)
        mcp = (
            self.root / "control-plane" / "cloudflare" / "src" / "product_mcp_reads.ts"
        ).read_text(encoding="utf-8")
        self.assertIn("authenticateProductMcpClientRequest(request, env)", mcp)
        self.assertIn("client_id: identity.clientId", mcp)

    def test_owner_session_never_mints_grant_or_dispatches_action(self) -> None:
        start = self.auth.index("export async function productOwnerAccountSession(")
        body = self.auth[start:]
        self.assertIn('subject_id: identity.subjectId', body)
        self.assertNotIn("enqueueProductAction", body)
        self.assertNotIn("replaceRemoteGrantGroup", body)
        self.assertNotIn("wakeDeviceSession", body)
        self.assertNotIn('client_id: identity.clientId', body)


if __name__ == "__main__":
    unittest.main()
