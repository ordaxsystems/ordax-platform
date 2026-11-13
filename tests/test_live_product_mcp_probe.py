"""Pure regression tests for the canonical public MCP probe classification."""
import unittest
from scripts.cloudflare.probe_live_product_mcp import analyze, load_identity


class PublicProbeClassification(unittest.TestCase):
    def setUp(self):
        self.issuer, self.worker = load_identity()
        self.metadata = {
            "issuer": self.issuer,
            "authorization_endpoint": self.issuer + "/oauth/authorize",
            "token_endpoint": self.issuer + "/oauth/token",
            "registration_endpoint": self.issuer + "/oauth/clients",
            "code_challenge_methods_supported": ["S256"],
            "grant_types_supported": ["authorization_code"],
            "response_types_supported": ["code"],
            "token_endpoint_auth_methods_supported": ["none"],
        }

    def responses(self, *, oauth_http=404, worker_ready_http=503):
        return {
            "health": (200, {"service": "ordax-platform-mcp",
                             "mode": "attested-device-control",
                             "supports_remote_actions": True,
                             "postgres_configured": True}),
            "resource": (200, {"resource": self.worker + "/mcp",
                               "authorization_servers": [self.issuer]}),
            "ready": (worker_ready_http, {
                "oauth_discovery_ready": worker_ready_http == 200,
                "supports_remote_actions": True,
            }),
            "oauth": (oauth_http, self.metadata if oauth_http == 200 else
                      {"code": 404, "message": "feature_disabled"}),
            "legacy_get": (404, {"error": "not_found"}),
            "retired_canary": (404, None),
        }

    def probe(self, **kwargs):
        return analyze(self.issuer, self.worker, self.responses(**kwargs))

    def test_identity_is_the_canonical_custom_domain_not_workers_dev(self):
        self.assertEqual(self.worker, "https://mcp.ordax.com.br")
        self.assertNotIn("workers.dev", self.worker)

    def test_disabled_supabase_is_reported_as_blocker_not_successful_oauth(self):
        p = self.probe()
        self.assertEqual(p["public_surface"], "PASS_CANONICAL")
        self.assertEqual(p["oauth_state"], "BLOCKED_BY_AUTH_SERVER")
        self.assertEqual(p["ready_http"], 503)
        self.assertEqual(p["central_remote_actions"], "NOT_TESTED_BY_READ_ONLY_PROBE")
        self.assertEqual(p["legacy_worker_retired"], "PASS")

    def test_valid_oauth_discovery_and_worker_ready_are_distinct_from_real_consent(self):
        p = self.probe(oauth_http=200, worker_ready_http=200)
        self.assertEqual(p["public_surface"], "PASS_CANONICAL")
        self.assertEqual(p["oauth_state"], "DISCOVERY_READY")
        self.assertEqual(p["central_remote_actions"], "NOT_TESTED_BY_READ_ONLY_PROBE")

    def test_legacy_canary_must_remain_absent(self):
        responses = self.responses()
        responses["retired_canary"] = (200, {"service": "ordax-platform-mcp"})
        p = analyze(self.issuer, self.worker, responses)
        self.assertEqual(p["legacy_worker_retired"], "INCONCLUSIVE")
        self.assertEqual(p["public_surface"], "INCONCLUSIVE")

    def test_public_surface_drift_is_not_treated_as_safe(self):
        for target, transform in [
            ("health", lambda x: {**x, "supports_remote_actions": False}),
            ("health", lambda x: {**x, "mode": "read-only-canary"}),
            ("resource", lambda x: {**x, "authorization_servers": ["https://other.invalid"]}),
            ("resource", lambda x: {**x, "resource": "https://legacy.invalid/mcp"}),
        ]:
            responses = self.responses()
            status, obj = responses[target]
            responses[target] = (status, transform(obj))
            outcome = analyze(self.issuer, self.worker, responses)
            self.assertEqual(outcome["public_surface"], "INCONCLUSIVE", target)
        responses = self.responses()
        responses["legacy_get"] = (200, {})
        self.assertEqual(
            analyze(self.issuer, self.worker, responses)["public_surface"],
            "INCONCLUSIVE",
        )

    def test_worker_claims_ready_while_supabase_is_disabled_is_unsafe(self):
        p = self.probe(worker_ready_http=200)
        self.assertEqual(p["oauth_state"], "BLOCKED_BY_AUTH_SERVER")
        self.assertEqual(p["public_surface"], "UNSAFE_FALSE_READY")

    def test_enabled_oauth_with_broken_worker_ready_is_a_regression(self):
        p = self.probe(oauth_http=200)
        self.assertEqual(p["oauth_state"], "DISCOVERY_READY")
        self.assertEqual(p["public_surface"], "INCONSISTENT_READINESS")

    def test_network_failure_is_not_reclassified_as_successful_oauth(self):
        responses = self.responses()
        responses["oauth"] = (None, None)
        p = analyze(self.issuer, self.worker, responses)
        self.assertEqual(p["oauth_state"], "NETWORK_UNAVAILABLE")
        self.assertNotEqual(p["oauth_state"], "DISCOVERY_READY")


if __name__ == "__main__":
    unittest.main()
