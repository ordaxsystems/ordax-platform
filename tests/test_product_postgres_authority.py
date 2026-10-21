from pathlib import Path
import subprocess
import json
import unittest

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "control-plane" / "supabase" / "migrations" / "20261007150000_product_remote_authority_v1.sql"
HARDENING = ROOT / "control-plane" / "supabase" / "migrations" / "20261007152000_product_remote_authority_hardening.sql"
REMOTE_ROLE_HARDENING = ROOT / "control-plane" / "supabase" / "migrations" / "20261007184000_product_remote_service_role_direct_access_revoke.sql"
CAPABILITY_V2 = ROOT / "control-plane" / "supabase" / "migrations" / "20261007184500_product_capability_contract_v2.sql"
GRANT_GROUPS_V2 = ROOT / "control-plane" / "supabase" / "migrations" / "20261007185000_product_grant_groups_v2.sql"
PRODUCT_SERVICE_ROLE_FAIL_CLOSED = ROOT / "control-plane" / "supabase" / "migrations" / "20261007190000_product_service_role_fail_closed.sql"
PUBLIC_SCHEMA_FAIL_CLOSED = ROOT / "control-plane" / "supabase" / "migrations" / "20261007191500_public_schema_usage_fail_closed.sql"
CLIENT_MUTATION_POLICY_CLEANUP = ROOT / "control-plane" / "supabase" / "migrations" / "20261007192000_remove_dead_authenticated_mutation_policies.sql"
SUBJECT_AUTHORIZATION_SSOT = ROOT / "control-plane" / "supabase" / "migrations" / "20261007192500_subject_authorization_ssot_v1.sql"
SPACE_AUTHORITY_V1 = ROOT / "control-plane" / "supabase" / "migrations" / "20261007193000_space_authority_v1.sql"
PROJECT_AUTHORITY_V1 = ROOT / "control-plane" / "supabase" / "migrations" / "20261007193500_project_authority_v1.sql"
PROJECT_CONNECTION_CONTRACT = ROOT / "control-plane" / "supabase" / "migrations" / "20261007194000_project_connection_contract_hardening_v1.sql"
MEMORY_AUTHORITY_V1 = ROOT / "control-plane" / "supabase" / "migrations" / "20261007194500_memory_authority_v1.sql"
CLIENT_ISOLATION_MIGRATION = ROOT / "control-plane" / "supabase" / "migrations" / "20261007203000_product_client_grant_isolation_v1.sql"
STATUS_CLIENT_MIGRATION = ROOT / "control-plane" / "supabase" / "migrations" / "20261007204500_product_client_scoped_action_status_v1.sql"
MIGRATION_REGISTRY = ROOT / "control-plane" / "supabase" / "migration-registry.json"
ADAPTER = ROOT / "control-plane" / "cloudflare" / "src" / "product_postgres_store.ts"


class ProductPostgresAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sql = MIGRATION.read_text(encoding="utf-8")
        cls.hardening = HARDENING.read_text(encoding="utf-8")
        cls.remote_role_hardening = REMOTE_ROLE_HARDENING.read_text(encoding="utf-8")
        cls.capability_v2 = CAPABILITY_V2.read_text(encoding="utf-8")
        cls.grant_groups_v2 = GRANT_GROUPS_V2.read_text(encoding="utf-8")
        cls.product_service_role_fail_closed = PRODUCT_SERVICE_ROLE_FAIL_CLOSED.read_text(encoding="utf-8")
        cls.public_schema_fail_closed = PUBLIC_SCHEMA_FAIL_CLOSED.read_text(encoding="utf-8")
        cls.client_mutation_policy_cleanup = CLIENT_MUTATION_POLICY_CLEANUP.read_text(encoding="utf-8")
        cls.subject_authorization_ssot = SUBJECT_AUTHORIZATION_SSOT.read_text(encoding="utf-8")
        cls.space_authority_v1 = SPACE_AUTHORITY_V1.read_text(encoding="utf-8")
        cls.project_authority_v1 = PROJECT_AUTHORITY_V1.read_text(encoding="utf-8")
        cls.project_connection_contract = PROJECT_CONNECTION_CONTRACT.read_text(encoding="utf-8")
        cls.memory_authority_v1 = MEMORY_AUTHORITY_V1.read_text(encoding="utf-8")
        cls.migration_registry = json.loads(MIGRATION_REGISTRY.read_text(encoding="utf-8"))
        cls.adapter = ADAPTER.read_text(encoding="utf-8")

    def test_device_scope_never_requires_synthetic_project(self) -> None:
        self.assertIn("scope_kind in ('device','project')", self.sql)
        self.assertIn("alter column project_id drop not null", self.sql)
        self.assertIn("scope_kind = 'device' and project_id is null", self.sql)
        self.assertIn("scope_kind = 'project' and project_id is not null", self.sql)
        self.assertIn("foreign key (project_id, space_id)", self.sql)
        self.assertNotIn(
            "check (\n    (project_id is null)\n    or exists",
            self.sql,
        )

    def test_product_remote_queue_is_not_engineering_queue(self) -> None:
        self.assertIn(
            "create table if not exists private.ordax_product_action_requests",
            self.sql,
        )
        self.assertIn(
            "create table if not exists private.ordax_product_action_events",
            self.sql,
        )
        self.assertIn(
            "create table if not exists private.ordax_product_action_audit",
            self.sql,
        )
        self.assertNotIn("references public.ordax_develop_jobs", self.sql)
        self.assertNotIn("insert into public.ordax_develop_jobs", self.sql)
        self.assertNotIn("update public.ordax_develop_jobs", self.sql)

    def test_remote_authority_has_idempotency_fencing_and_terminal_replay(self) -> None:
        for token in (
            "unique (owner_user_id, idempotency_key)",
            "effect_id",
            "attempt_id",
            "lease_id",
            "execution_epoch",
            "agent_instance_id",
            "boot_id",
            "report_id",
            "idempotency_conflict",
            "terminal_report_conflict",
            "for update skip locked",
            "pg_advisory_xact_lock",
        ):
            self.assertIn(token, self.sql.lower())

    def test_private_tables_are_not_a_client_api(self) -> None:
        for table in (
            "private.ordax_product_action_requests",
            "private.ordax_product_action_events",
            "private.ordax_product_action_audit",
        ):
            self.assertIn(
                f"revoke all on table {table}",
                self.sql,
            )
            self.assertIn(
                f"alter table {table} enable row level security",
                self.hardening,
            )
        self.assertIn("from public, anon, authenticated, service_role", self.sql)
        self.assertIn(
            "grant execute on function public.ordax_enqueue_product_action_v1",
            self.sql,
        )
        self.assertIn("to service_role;", self.sql)

    def test_product_action_foreign_keys_are_indexed(self) -> None:
        for index_fragment in (
            "ordax_product_action_project_space_idx",
            "ordax_product_action_space_idx",
            "ordax_product_action_grant_idx",
        ):
            self.assertIn(index_fragment, self.hardening)

    def test_presence_is_coalesced_instead_of_persisting_every_heartbeat(self) -> None:
        self.assertIn("ordax_record_product_presence_v1", self.sql)
        self.assertIn("interval '5 minutes'", self.sql)
        self.assertIn("p_force boolean default false", self.sql)

    def test_worker_adapter_uses_hyperdrive_without_backend_secret(self) -> None:
        lowered = self.adapter.lower()
        self.assertIn('import { openpostgressession } from "./data_postgres_driver.ts"', lowered)
        driver = (ROOT / "control-plane/cloudflare/src/data_postgres_driver.ts").read_text(encoding="utf-8").lower()
        self.assertIn('import { client } from "pg"', driver)
        self.assertIn("env.postgres?.connectionstring", lowered)
        self.assertIn("await client.connect()", lowered)
        self.assertIn("client.query(query, values)", lowered)
        self.assertNotIn("sql.unsafe", lowered)
        self.assertNotIn("supabase_server_key", lowered)
        self.assertNotIn("supabase_service_role_key", lowered)
        self.assertNotIn("/rest/v1/rpc/", lowered)
        self.assertNotIn("apikey:", lowered)
        # A Product authorization RPC name is not a backend HTTP credential.
        self.assertNotIn('"authorization"', lowered)
        self.assertNotIn("headers.authorization", lowered)
        self.assertNotIn("bearer ", lowered)
        self.assertNotIn("d1database", lowered)

    def test_adapter_is_rpc_only_not_direct_table_mutation(self) -> None:
        self.assertIn("select public.", self.adapter)
        self.assertNotIn("/rest/v1/ordax_", self.adapter)
        for rpc in (
            "ordax_enqueue_product_action_v1",
            "ordax_claim_product_action_v1",
            "ordax_start_product_action_v1",
            "ordax_renew_product_action_lease_v1",
            "ordax_progress_product_action_v1",
            "ordax_report_product_action_v1",
            "ordax_get_product_action_v1",
            "ordax_record_product_presence_v1",
        ):
            self.assertIn(rpc, self.adapter)

    def test_service_role_has_no_direct_remote_authority(self) -> None:
        lowered = self.remote_role_hardening.lower()
        for table in (
            "ordax_product_devices",
            "ordax_device_presence",
            "ordax_space_devices",
            "ordax_device_project_bindings",
            "ordax_remote_capability_grants",
        ):
            self.assertIn(
                f"revoke all on table public.{table} from service_role",
                lowered,
            )

    def test_capability_contract_supports_real_action_names(self) -> None:
        lowered = self.capability_v2.lower()
        self.assertIn("^[a-z][a-z0-9._-]+$", lowered)
        self.assertIn(
            "check (private.ordax_product_capability_name_valid(capability))",
            lowered,
        )
        self.assertIn("to ordax_edge_executor;", lowered)
        self.assertNotIn("to service_role;", lowered)

    def test_grant_groups_fail_closed_without_legacy_backfill(self) -> None:
        lowered = self.grant_groups_v2.lower()
        self.assertIn("requires an empty canonical grant table", lowered)
        self.assertIn("add column grant_group_id uuid not null", lowered)
        self.assertIn("add column profile_key text not null", lowered)
        self.assertIn("ordax_remote_grants_group_capability_uidx", lowered)
        self.assertNotIn("'legacy'", lowered)

    def test_grant_group_rpcs_use_dedicated_executor_only(self) -> None:
        lowered = self.grant_groups_v2.lower()
        for rpc in (
            "ordax_replace_remote_grant_group_v1",
            "ordax_revoke_remote_grant_group_v1",
            "ordax_list_product_targets_v1",
        ):
            self.assertIn(f"grant execute on function public.{rpc}", lowered)
        self.assertIn("to ordax_edge_executor;", lowered)
        self.assertNotIn("to service_role;", lowered)
        self.assertIn(
            "from public, anon, authenticated, service_role, ordax_edge_executor",
            lowered,
        )

    def test_project_grants_require_real_authority_chain(self) -> None:
        lowered = self.grant_groups_v2.lower()
        for token in (
            "device_grant_space_not_allowed",
            "device_not_owned",
            "project_grant_space_required",
            "space_admin_required",
            "project_not_found",
            "space_device_execute_required",
            "project_device_binding_required",
            "capability_not_bound_to_project",
        ):
            self.assertIn(token, lowered)

    def test_targets_are_derived_from_active_nonexpired_grants(self) -> None:
        lowered = self.grant_groups_v2.lower()
        self.assertIn("g.state = 'active'", lowered)
        self.assertIn("g.valid_until is null or g.valid_until >", lowered)
        self.assertIn("pg_catalog.statement_timestamp()", lowered)
        self.assertIn("'grant_groups'", lowered)
        self.assertIn("'capabilities'", lowered)

    def test_generic_service_role_has_no_product_table_authority(self) -> None:
        lowered = self.product_service_role_fail_closed.lower()
        for table in (
            "ordax_accounts",
            "ordax_spaces",
            "ordax_space_members",
            "ordax_entitlement_grants",
            "ordax_profile_packs",
            "ordax_space_profile_packs",
            "ordax_memory_items",
            "ordax_memory_embeddings",
            "ordax_project_connections",
            "ordax_projects",
            "ordax_product_devices",
            "ordax_device_presence",
            "ordax_space_devices",
            "ordax_device_project_bindings",
            "ordax_remote_capability_grants",
        ):
            self.assertIn(
                f"revoke all on table public.{table} from service_role",
                lowered,
            )
        self.assertNotIn("grant ", lowered)

    def test_public_schema_is_opt_in_for_custom_roles(self) -> None:
        lowered = self.public_schema_fail_closed.lower()
        self.assertIn("revoke usage, create on schema public from public", lowered)
        self.assertIn("required explicit role usage missing", lowered)
        self.assertIn("public schema privilege survived", lowered)
        self.assertIn("ordax_edge_executor", lowered)
        self.assertIn("private", lowered)

    def test_dead_authenticated_mutation_policies_are_removed(self) -> None:
        lowered = self.client_mutation_policy_cleanup.lower()
        for policy in (
            "ordax_spaces_insert_own",
            "ordax_spaces_update_admin",
            "ordax_spaces_delete_owner",
            "ordax_space_members_insert_admin",
            "ordax_space_members_update_admin",
            "ordax_space_members_delete_admin",
            "ordax_memory_items_insert_own",
            "ordax_memory_items_update_own",
            "ordax_memory_items_delete_own",
        ):
            self.assertIn(f"drop policy if exists {policy}", lowered)
        self.assertNotIn("grant ", lowered)

    def test_subject_authorization_is_centralized_for_server_executors(self) -> None:
        lowered = self.subject_authorization_ssot.lower()
        for helper in (
            "ordax_subject_can_access_space_v1",
            "ordax_subject_can_admin_space_v1",
            "ordax_subject_can_access_project_v1",
            "ordax_subject_can_access_product_device_v1",
        ):
            self.assertIn(f"create function private.{helper}", lowered)
        self.assertIn("from public, anon, authenticated, service_role, ordax_edge_executor", lowered)
        self.assertIn("to authenticated;", lowered)
        self.assertNotIn("to service_role;", lowered)
        self.assertNotIn("to ordax_edge_executor;", lowered)

    def test_space_authority_has_dedicated_nologin_executor(self) -> None:
        lowered = self.space_authority_v1.lower()
        self.assertIn("create role ordax_space_executor", lowered)
        self.assertIn("noinherit", lowered)
        self.assertIn("nologin", lowered)
        self.assertIn("nobypassrls", lowered)
        self.assertIn("grant usage on schema public to ordax_space_executor", lowered)
        self.assertNotIn("grant select", lowered)
        self.assertNotIn("grant insert", lowered)
        self.assertNotIn("grant update", lowered)
        self.assertNotIn("grant delete", lowered)

    def test_space_owner_is_single_source_of_truth(self) -> None:
        lowered = self.space_authority_v1.lower()
        self.assertIn("owner_user_id is the single owner ssot", lowered)
        self.assertIn("where role = 'owner'", lowered)
        self.assertIn("check (role in ('admin', 'member', 'viewer'))", lowered)
        self.assertIn("space_owner_membership_forbidden", lowered)

    def test_space_mutations_are_rpc_only(self) -> None:
        lowered = self.space_authority_v1.lower()
        for rpc in (
            "ordax_create_space_v1",
            "ordax_update_space_v1",
            "ordax_set_space_member_v1",
            "ordax_remove_space_member_v1",
        ):
            self.assertIn(f"create function public.{rpc}", lowered)
        self.assertIn("to ordax_space_executor;", lowered)
        self.assertNotIn("to service_role;", lowered)
        self.assertNotIn("to authenticated;", lowered)
        self.assertIn("ordax_subject_can_admin_space_v1", lowered)

    def test_project_authority_is_dedicated_and_rpc_only(self) -> None:
        lowered = self.project_authority_v1.lower()
        self.assertIn("create role ordax_project_executor", lowered)
        self.assertIn("noinherit", lowered)
        self.assertIn("nologin", lowered)
        self.assertIn("nobypassrls", lowered)
        self.assertIn("ordax_subject_can_admin_space_v1", lowered)
        for rpc in ("ordax_create_project_v1", "ordax_update_project_v1"):
            self.assertIn(f"create function public.{rpc}", lowered)
        self.assertIn("to ordax_project_executor;", lowered)
        self.assertNotIn("to service_role;", lowered)
        self.assertNotIn("to authenticated;", lowered)
        self.assertNotIn("grant select", lowered)
        self.assertNotIn("grant insert", lowered)
        self.assertNotIn("grant update", lowered)
        self.assertNotIn("grant delete", lowered)

    def test_project_connection_contract_stays_read_only_and_explicit(self) -> None:
        lowered = self.project_connection_contract.lower()
        self.assertIn("repository_full_name is not null", lowered)
        self.assertIn("repository_id > 0", lowered)
        self.assertIn("installation_id > 0", lowered)
        self.assertIn("ordax_project_connections_project_github_repository_uidx", lowered)
        self.assertIn("mutation authority unexpectedly present", lowered)
        self.assertNotIn("create function", lowered)
        self.assertNotIn("grant ", lowered)

    def test_memory_authority_is_canonical_and_rpc_only(self) -> None:
        lowered = self.memory_authority_v1.lower()
        self.assertIn("create role ordax_memory_executor", lowered)
        self.assertIn("nologin", lowered)
        self.assertIn("noinherit", lowered)
        self.assertIn("nobypassrls", lowered)
        self.assertIn("drop column project_ref", lowered)
        self.assertIn("add column project_id uuid", lowered)
        self.assertIn("scope in ('account', 'space', 'project')", lowered)
        self.assertIn("ordax_memory_items_project_space_fk", lowered)
        self.assertIn("ordax_subject_can_access_space_v1", lowered)
        self.assertIn("ordax_subject_can_access_project_v1", lowered)
        self.assertIn("ordax_create_memory_item_v1", lowered)
        self.assertIn("ordax_update_memory_item_v1", lowered)
        self.assertIn("to ordax_memory_executor;", lowered)
        self.assertNotIn("to service_role;", lowered)
        self.assertNotIn("to authenticated;", lowered)
        self.assertNotIn("scope = 'device'", lowered)
        self.assertNotIn("scope = 'session'", lowered)
        self.assertNotIn("grant select", lowered)
        self.assertNotIn("grant insert", lowered)
        self.assertNotIn("grant update", lowered)
        self.assertNotIn("grant delete", lowered)

    def test_migration_registry_pins_canonical_database_and_history(self) -> None:
        registry = self.migration_registry
        self.assertEqual(registry["canonical_database"]["project_name"], "ordax-platform")
        self.assertEqual(
            registry["canonical_database"]["project_ref"],
            "jhfphsjptrpmtnzkpwud",
        )
        self.assertEqual(registry["canonical_database"]["region"], "sa-east-1")
        self.assertFalse(
            registry["policy"]["additional_historical_migrations_are_authorized_for_replay"]
        )
        self.assertFalse(registry["policy"]["reapply_applied_migration_allowed"])
        self.assertFalse(registry["policy"]["merge_with_pending_registry_entry_allowed"])

        entries = registry["migrations"]
        self.assertTrue(entries)
        self.assertTrue(all(entry["state"] == "applied" for entry in entries))
        self.assertEqual(
            len({entry["name"] for entry in entries}),
            len(entries),
        )
        self.assertEqual(
            len({entry["applied_version"] for entry in entries}),
            len(entries),
        )

    def test_registry_pins_every_canonical_migration_git_blob(self) -> None:
        migrations_root = ROOT / "control-plane" / "supabase" / "migrations"
        entries = {
            entry["name"]: entry
            for entry in self.migration_registry["migrations"]
            if entry["source"]["path"].startswith("control-plane/supabase/migrations/")
        }
        source_files = sorted(migrations_root.glob("*.sql"))
        self.assertEqual(
            {path.stem for path in source_files},
            set(entries),
        )

        for path in source_files:
            # The registry records the canonical Git blob after attributes
            # normalize Windows CRLF; raw worktree bytes are not Git object bytes.
            relative = path.relative_to(ROOT).as_posix()
            git_blob = subprocess.check_output(
                ["git", "hash-object", f"--path={relative}", relative],
                cwd=ROOT, text=True,
            ).strip()
            self.assertEqual(
                git_blob,
                entries[path.stem]["source"]["blob_sha"],
                path.name,
            )

    def test_registry_only_whitelists_historical_bootstrap_0001_to_0007(self) -> None:
        historical = [
            entry
            for entry in self.migration_registry["migrations"]
            if entry["source"]["repository"] == "washingtonmsdj/prototipo-ordax-os"
        ]
        self.assertEqual(
            [entry["name"] for entry in historical],
            [
                "0001_product_foundation",
                "0002_product_foundation_indexes",
                "0003_spaces_single_profile_pack_owner",
                "0004_server_authoritative_mutations",
                "0005_private_indexes_and_active_pack_catalog",
                "0006_projects_devices_remote_grants",
                "0007_projects_devices_fk_indexes",
            ],
        )
        self.assertTrue(
            all(
                entry["ledger_source_relation"] in {
                    "exact",
                    "sql-equivalent-format-or-comment-only",
                }
                for entry in self.migration_registry["migrations"]
            )
        )


    def test_product_execution_grant_is_bound_to_exact_client_identity(self) -> None:
        sql = CLIENT_ISOLATION_MIGRATION.read_text(encoding="utf-8")
        lower = sql.lower()
        self.assertIn("drop function public.ordax_enqueue_product_action_v1(", lower)
        self.assertIn("drop function private.ordax_resolve_product_remote_grant_v1(", lower)
        self.assertNotIn(" cascade;", lower)
        self.assertNotIn(" cascade\n", lower)
        self.assertIn("and g.client_id = p_client_id", sql)
        self.assertIn("or p_client_id is null", sql)
        self.assertIn("and v_existing.client_id = p_client_id", sql)
        self.assertIn("add column client_id text", sql)
        self.assertEqual(sql.count("add column client_id text"), 2)
        self.assertEqual(sql.count("insert into private.ordax_product_action_audit("), 3)
        self.assertIn("client_kind, client_id, capability, access_mode, payload", sql)
        self.assertIn("grant execute on function public.ordax_enqueue_product_action_v1(", lower)
        self.assertIn(") to ordax_edge_executor;", lower)
        self.assertNotIn("to authenticated;", lower)
        self.assertNotIn("to service_role;", lower)

    def test_product_action_status_rpc_cannot_read_other_oauth_client(self) -> None:
        sql = STATUS_CLIENT_MIGRATION.read_text(encoding="utf-8")
        self.assertIn("drop function public.ordax_get_product_action_v1(uuid, uuid)", sql)
        self.assertNotIn(" cascade;", sql.lower())
        self.assertIn("p_client_kind text", sql)
        self.assertIn("p_client_id text", sql)
        self.assertIn("r.client_kind = p_client_kind", sql)
        self.assertIn("r.client_id = p_client_id", sql)
        self.assertIn("r.owner_user_id = p_owner_user_id", sql)
        self.assertIn("r.request_id = p_request_id", sql)
        self.assertIn("p_client_id is not null", sql)
        self.assertIn(
            "grant execute on function public.ordax_get_product_action_v1(uuid, text, text, uuid)",
            sql,
        )
        self.assertIn("to ordax_edge_executor;", sql)
        self.assertNotIn("to authenticated;", sql)
        self.assertNotIn("to service_role;", sql)

    def test_product_action_status_adapter_never_uses_owner_only_scope(self) -> None:
        self.assertIn(
            'keys: ["p_owner_user_id", "p_client_kind", "p_client_id", "p_request_id"]',
            self.adapter,
        )
        self.assertIn('casts: ["uuid", "text", "text", "uuid"]', self.adapter)
        self.assertIn("clientKind: RemoteClientKind;", self.adapter)
        self.assertIn("clientId: string;", self.adapter)
        self.assertIn(
            "canonicalRemoteClient(input.ownerUserId, input.clientKind, input.clientId)",
            self.adapter,
        )
        self.assertIn("!client || client.p_client_id === null", self.adapter)
        self.assertIn("p_request_id: input.requestId", self.adapter)

    def test_product_adapter_requires_nonnull_canonical_client_id_for_enqueue(self) -> None:
        self.assertIn('"p_client_kind",\n      "p_client_id",\n      "p_capability"', self.adapter)
        self.assertIn("clientId: string;", self.adapter)
        self.assertIn(
            "canonicalRemoteClient(input.ownerUserId, input.clientKind, input.clientId)",
            self.adapter,
        )
        self.assertIn("if (!client || client.p_client_id === null)", self.adapter)
        self.assertIn("p_client_id: client.p_client_id", self.adapter)

    def test_grant_group_rpc_boundary_matches_canonical_migration(self) -> None:
        for rpc in (
            "ordax_replace_remote_grant_group_v1",
            "ordax_revoke_remote_grant_group_v1",
            "ordax_list_product_targets_v1",
        ):
            self.assertIn(f"create or replace function public.{rpc}", self.grant_groups_v2)
            self.assertIn(f"grant execute on function public.{rpc}", self.grant_groups_v2)
            self.assertIn(rpc + ": {", self.adapter)
        self.assertIn("p_capabilities text[]", self.grant_groups_v2)
        self.assertIn("p_access_modes text[]", self.grant_groups_v2)
        self.assertIn('casts: ["uuid", "uuid", "uuid", "uuid", "text", "text", "text", "text[]", "text[]", "timestamptz"]', self.adapter)
        self.assertIn("return encodePostgresTextArrayLiteral(value)", self.adapter)
        self.assertNotIn("sql.array(value, 25)", self.adapter)
        self.assertIn("canonicalRemoteGrantGroup(input)", self.adapter)
        self.assertIn("canonicalRemoteClient(input.ownerUserId", self.adapter)
        self.assertNotIn("ordax_product_grants", self.adapter)


if __name__ == "__main__":
    unittest.main()
