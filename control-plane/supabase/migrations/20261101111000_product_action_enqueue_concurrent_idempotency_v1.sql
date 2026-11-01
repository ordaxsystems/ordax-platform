-- Serialize concurrent Product action enqueue retries in the canonical
-- PostgreSQL authority. This migration ONLY replaces the existing RPC body:
-- no table, index, role, grant, public endpoint, alternative queue or runtime.
-- The preflight deliberately rejects unexpected drift. Apply with the normal
-- authorized Supabase migration process, not by changing Cloudflare bindings.
begin;

do $preflight$
declare
  v_rpc regprocedure := pg_catalog.to_regprocedure(
    'public.ordax_enqueue_product_action_v1(uuid,uuid,uuid,uuid,text,text,text,text,jsonb,text,timestamp with time zone)');
  v_definition text;
begin
  if v_rpc is null or pg_catalog.to_regclass('private.ordax_product_action_requests') is null
    or pg_catalog.to_regprocedure('private.ordax_trusted_actor_auth_eligible_v1(uuid)') is null
  then raise exception 'enqueue idempotency: canonical authority missing'; end if;

  select pg_catalog.pg_get_functiondef(p.oid) into v_definition
    from pg_catalog.pg_proc p
   where p.oid=v_rpc::oid and p.prosecdef and p.provolatile='v';
  if v_definition is null
    or position('ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)' in v_definition)=0
    or position('v_existing.space_id is not distinct from p_space_id' in v_definition)=0
    or position('v_existing.client_id = p_client_id' in v_definition)=0
    or position('v_existing.payload_sha256 = v_payload_sha256' in v_definition)=0
    or position('idempotency_key = p_idempotency_key' in v_definition)=0
    or position('pg_catalog.pg_advisory_xact_lock(' in v_definition)>0
    or not pg_catalog.has_function_privilege('ordax_edge_executor',v_rpc::oid,'EXECUTE')
    or pg_catalog.has_function_privilege('authenticated',v_rpc::oid,'EXECUTE')
    or pg_catalog.has_function_privilege('anon',v_rpc::oid,'EXECUTE')
    or pg_catalog.has_function_privilege('service_role',v_rpc::oid,'EXECUTE')
  then raise exception 'enqueue idempotency: RPC definition or ACL drift'; end if;
end;
$preflight$;

CREATE OR REPLACE FUNCTION public.ordax_enqueue_product_action_v1(p_owner_user_id uuid, p_space_id uuid, p_project_id uuid, p_device_id uuid, p_client_kind text, p_client_id text, p_capability text, p_access_mode text, p_payload jsonb, p_idempotency_key text, p_expires_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_grant_id uuid;
  v_payload_sha256 text;
  v_existing private.ordax_product_action_requests%rowtype;
  v_request_id uuid;
  v_effect_id uuid;
begin
  if p_owner_user_id is null
     or p_device_id is null
     or p_client_kind not in ('ordax-web','ordax-mobile','product-mcp')
     or p_client_id is null
     or char_length(p_client_id) not between 8 and 160
     or p_client_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]+$'
     or p_access_mode not in ('read','write')
     or p_capability is null
     or char_length(p_capability) not between 2 and 120
     or not private.ordax_product_capability_name_valid(p_capability)
     or p_payload is null
     or jsonb_typeof(p_payload) <> 'object'
     or pg_catalog.octet_length(p_payload::text) > 131072
     or p_idempotency_key is null
     or char_length(p_idempotency_key) not between 8 and 128
     or p_idempotency_key !~ '^[A-Za-z0-9][A-Za-z0-9._:-]+$'
     or p_expires_at is null
     or p_expires_at <= v_now
     or p_expires_at > v_now + interval '24 hours'
  then
    return jsonb_build_object('ok', false, 'error', 'product_action_invalid');
  end if;

  -- The service is responsible for actor-to-caller proof. This DB guard
  -- confirms account eligibility and locks the Auth identity before the
  -- first replay, device enrollment or remote authority mutation.
  if not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id) then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','product_owner_auth_ineligible');
  end if;

  v_payload_sha256 := pg_catalog.encode(
    extensions.digest(pg_catalog.convert_to(p_payload::text, 'UTF8'), 'sha256'),
    'hex'
  );

  -- The Auth eligibility helper takes FOR SHARE locks: concurrent requests
  -- for one Owner still overlap. Serialize by Owner and canonical idempotency
  -- key BEFORE the first read, so a retry observes the committed original
  -- receipt instead of racing into the unique(owner_user_id,idempotency_key)
  -- constraint. Hash collisions can delay an unrelated request, never grant
  -- access; the existing unique constraint and payload check remain final.
  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(p_owner_user_id::text || ':' || p_idempotency_key, 0)
  );

  select *
    into v_existing
    from private.ordax_product_action_requests
   where owner_user_id = p_owner_user_id
     and idempotency_key = p_idempotency_key
   limit 1;

  if found then
    if v_existing.space_id is not distinct from p_space_id
       and v_existing.project_id is not distinct from p_project_id
       and v_existing.device_id = p_device_id
       and v_existing.client_kind = p_client_kind
       and v_existing.client_id = p_client_id
       and v_existing.capability = p_capability
       and v_existing.access_mode = p_access_mode
       and v_existing.payload_sha256 = v_payload_sha256
    then
      return jsonb_build_object(
        'ok', true,
        'replayed', true,
        'request_id', v_existing.request_id,
        'effect_id', v_existing.effect_id,
        'status', v_existing.status
      );
    end if;

    insert into private.ordax_product_action_audit(
      request_id, owner_user_id, space_id, project_id, device_id, grant_id,
      client_kind, client_id, capability, access_mode, phase, decision, reason
    ) values (
      v_existing.request_id, p_owner_user_id, p_space_id, p_project_id, p_device_id,
      v_existing.grant_id, p_client_kind, p_client_id, p_capability, p_access_mode,
      'decision', 'deny', 'idempotency_conflict'
    );

    return jsonb_build_object('ok', false, 'error', 'idempotency_conflict');
  end if;

  v_grant_id := private.ordax_resolve_product_remote_grant_v1(
    p_owner_user_id,
    p_space_id,
    p_project_id,
    p_device_id,
    p_client_kind,
    p_client_id,
    p_capability,
    p_access_mode
  );

  if v_grant_id is null then
    insert into private.ordax_product_action_audit(
      owner_user_id, space_id, project_id, device_id, client_kind,
      client_id, capability, access_mode, phase, decision, reason
    ) values (
      p_owner_user_id, p_space_id, p_project_id, p_device_id, p_client_kind,
      p_client_id, p_capability, p_access_mode, 'decision', 'deny', 'product_grant_not_resolved'
    );

    return jsonb_build_object('ok', false, 'error', 'product_grant_not_resolved');
  end if;

  v_request_id := extensions.gen_random_uuid();
  v_effect_id := extensions.gen_random_uuid();

  insert into private.ordax_product_action_requests(
    request_id, owner_user_id, space_id, project_id, device_id, grant_id,
    client_kind, client_id, capability, access_mode, payload, payload_sha256,
    idempotency_key, effect_id, status, expires_at
  ) values (
    v_request_id, p_owner_user_id, p_space_id, p_project_id, p_device_id, v_grant_id,
    p_client_kind, p_client_id, p_capability, p_access_mode, p_payload, v_payload_sha256,
    p_idempotency_key, v_effect_id, 'queued', p_expires_at
  );

  insert into private.ordax_product_action_audit(
    request_id, owner_user_id, space_id, project_id, device_id, grant_id,
    client_kind, client_id, capability, access_mode, phase, decision, reason
  ) values (
    v_request_id, p_owner_user_id, p_space_id, p_project_id, p_device_id, v_grant_id,
    p_client_kind, p_client_id, p_capability, p_access_mode, 'decision', 'allow', 'grant_resolved'
  );

  return jsonb_build_object(
    'ok', true,
    'replayed', false,
    'request_id', v_request_id,
    'effect_id', v_effect_id,
    'status', 'queued'
  );
end;
$function$
;

-- The OID and EXECUTE ACL remain unchanged by CREATE OR REPLACE; assert both
-- along with lock ordering and the original Owner/client/payload replay fence.
do $postflight$
declare
  v_rpc regprocedure := pg_catalog.to_regprocedure(
    'public.ordax_enqueue_product_action_v1(uuid,uuid,uuid,uuid,text,text,text,text,jsonb,text,timestamp with time zone)');
  v_definition text;
  v_lock integer;
  v_lookup integer;
begin
  if v_rpc is null then raise exception 'enqueue idempotency: missing RPC'; end if;
  select pg_catalog.pg_get_functiondef(p.oid) into v_definition
    from pg_catalog.pg_proc p
   where p.oid=v_rpc::oid and p.prosecdef and p.provolatile='v';
  v_lock := position('pg_catalog.pg_advisory_xact_lock(' in v_definition);
  v_lookup := position('idempotency_key = p_idempotency_key' in v_definition);
  if v_definition is null or v_lock=0 or v_lookup=0 or v_lock>=v_lookup
    or position('hashtextextended(p_owner_user_id::text' in v_definition)=0
    or position('v_existing.client_id = p_client_id' in v_definition)=0
    or position('v_existing.payload_sha256 = v_payload_sha256' in v_definition)=0
    or not pg_catalog.has_function_privilege('ordax_edge_executor',v_rpc::oid,'EXECUTE')
    or pg_catalog.has_function_privilege('authenticated',v_rpc::oid,'EXECUTE')
    or pg_catalog.has_function_privilege('anon',v_rpc::oid,'EXECUTE')
    or pg_catalog.has_function_privilege('service_role',v_rpc::oid,'EXECUTE')
  then raise exception 'enqueue idempotency: postflight failed'; end if;
end;
$postflight$;

commit;
