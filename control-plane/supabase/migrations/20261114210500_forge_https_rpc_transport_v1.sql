begin;

create or replace function private.ordax_forge_native_oauth_client_id_v1()
returns text
language sql
immutable
security definer
set search_path = ''
as $$
  select '6a94ae80-a59c-4f48-a32c-2e15da34374f'::text;
$$;

revoke all on function private.ordax_forge_native_oauth_client_id_v1()
  from public,anon,authenticated,service_role,ordax_edge_runtime,ordax_edge_executor;

create or replace function private.ordax_forge_http_identity_v1(p_native boolean)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_claims jsonb := '{}'::jsonb;
  v_owner uuid;
  v_client text;
  v_role text;
begin
  begin
    v_claims := coalesce(
      nullif(pg_catalog.current_setting('request.jwt.claims', true),''),
      '{}'
    )::jsonb;
  exception when others then
    return jsonb_build_object('ok',false,'error','forge_http_identity_required');
  end;

  begin
    v_owner := nullif(v_claims->>'sub','')::uuid;
  exception when others then
    v_owner := null;
  end;
  v_client := lower(coalesce(v_claims->>'client_id',''));
  v_role := coalesce(v_claims->>'role','');

  if v_role <> 'authenticated'
     or v_owner is null
     or v_client !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  then
    return jsonb_build_object('ok',false,'error','forge_http_identity_required');
  end if;

  if not private.ordax_forge_oauth_client_authorized_v1(v_owner,v_client) then
    return jsonb_build_object('ok',false,'error','forge_http_oauth_consent_required');
  end if;

  if p_native and v_client <> private.ordax_forge_native_oauth_client_id_v1() then
    return jsonb_build_object('ok',false,'error','forge_native_oauth_client_required');
  end if;

  return jsonb_build_object(
    'ok',true,
    'owner_user_id',v_owner,
    'client_id',v_client
  );
end;
$$;

revoke all on function private.ordax_forge_http_identity_v1(boolean)
  from public,anon,authenticated,service_role,ordax_edge_runtime,ordax_edge_executor;

create or replace function public.ordax_forge_http_rpc_v1(
  p_operation text,
  p_payload jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_native boolean;
  v_identity jsonb;
  v_owner uuid;
  v_client text;
  v_started boolean;
  v_renewed timestamptz;
begin
  if p_payload is null or jsonb_typeof(p_payload) <> 'object' then
    return jsonb_build_object('ok',false,'error','forge_http_payload_invalid');
  end if;

  v_native := p_operation in (
    'native_register','native_presence','native_claim',
    'native_start','native_renew','native_report'
  );
  if p_operation not in (
    'mcp_resolve','mcp_enqueue','mcp_get',
    'native_register','native_presence','native_claim',
    'native_start','native_renew','native_report'
  ) then
    return jsonb_build_object('ok',false,'error','forge_http_operation_invalid');
  end if;

  v_identity := private.ordax_forge_http_identity_v1(v_native);
  if coalesce((v_identity->>'ok')::boolean,false) is not true then
    return v_identity;
  end if;
  v_owner := (v_identity->>'owner_user_id')::uuid;
  v_client := v_identity->>'client_id';

  if p_operation='mcp_resolve' then
    return public.ordax_resolve_forge_mcp_instance_v1(v_owner,v_client);
  elsif p_operation='mcp_enqueue' then
    return public.ordax_enqueue_forge_action_v1(
      v_owner,v_client,
      (p_payload->>'instance_id')::uuid,
      p_payload->>'tool_name',
      p_payload->>'access_mode',
      p_payload->'arguments',
      p_payload->>'idempotency_key',
      (p_payload->>'expires_at')::timestamptz
    );
  elsif p_operation='mcp_get' then
    return public.ordax_get_forge_action_v1(
      v_owner,v_client,(p_payload->>'request_id')::uuid
    );
  elsif p_operation='native_register' then
    return public.ordax_register_forge_instance_v1(
      v_owner,
      (p_payload->>'instance_id')::uuid,
      p_payload->>'display_name',
      p_payload->>'app_version',
      p_payload->'catalog',
      p_payload->>'catalog_digest'
    );
  elsif p_operation='native_presence' then
    return public.ordax_update_forge_presence_v1(
      v_owner,
      (p_payload->>'instance_id')::uuid,
      (p_payload->>'online')::boolean,
      p_payload->>'app_version',
      p_payload->'catalog',
      p_payload->>'catalog_digest'
    );
  elsif p_operation='native_claim' then
    return public.ordax_claim_forge_action_v1(
      v_owner,
      (p_payload->>'instance_id')::uuid,
      (p_payload->>'agent_instance_id')::uuid,
      p_payload->>'boot_id'
    );
  elsif p_operation='native_start' then
    v_started := public.ordax_start_forge_action_v1(
      v_owner,
      (p_payload->>'instance_id')::uuid,
      (p_payload->>'request_id')::uuid,
      (p_payload->>'attempt_id')::uuid,
      (p_payload->>'lease_id')::uuid,
      (p_payload->>'agent_instance_id')::uuid,
      p_payload->>'boot_id'
    );
    return jsonb_build_object('ok',v_started);
  elsif p_operation='native_renew' then
    v_renewed := public.ordax_renew_forge_action_v1(
      v_owner,
      (p_payload->>'instance_id')::uuid,
      (p_payload->>'request_id')::uuid,
      (p_payload->>'attempt_id')::uuid,
      (p_payload->>'lease_id')::uuid,
      (p_payload->>'agent_instance_id')::uuid,
      p_payload->>'boot_id'
    );
    return jsonb_build_object(
      'ok',v_renewed is not null,
      'lease_expires_at',v_renewed
    );
  end if;

  return public.ordax_report_forge_action_v1(
    v_owner,
    (p_payload->>'instance_id')::uuid,
    (p_payload->>'request_id')::uuid,
    (p_payload->>'attempt_id')::uuid,
    (p_payload->>'lease_id')::uuid,
    (p_payload->>'agent_instance_id')::uuid,
    p_payload->>'boot_id',
    (p_payload->>'succeeded')::boolean,
    p_payload->'result',
    nullif(p_payload->>'error_code','')
  );
exception
  when invalid_text_representation or datetime_field_overflow or numeric_value_out_of_range then
    return jsonb_build_object('ok',false,'error','forge_http_payload_invalid');
end;
$$;

revoke all on function public.ordax_forge_http_rpc_v1(text,jsonb)
  from public,anon,authenticated,service_role,ordax_edge_runtime,ordax_edge_executor;
grant execute on function public.ordax_forge_http_rpc_v1(text,jsonb)
  to authenticated;

commit;
