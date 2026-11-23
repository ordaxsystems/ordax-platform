begin;

-- An authenticated MCP client must choose a Forge instance explicitly.
-- No switch follows an offline heartbeat and no cross-account enumeration.
create or replace function public.ordax_list_forge_mcp_instances_v1(
  p_owner_user_id uuid,
  p_client_id text
)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_bound uuid;
  v_count integer;
  v_list jsonb;
  v_now timestamptz := pg_catalog.clock_timestamp();
begin
  if p_owner_user_id is null or p_client_id is null
     or p_client_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     or not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)
     or not private.ordax_forge_oauth_client_authorized_v1(p_owner_user_id,p_client_id)
  then
    return jsonb_build_object('ok',false,'error','forge_mcp_authorization_required');
  end if;

  select b.instance_id into v_bound
  from private.ordax_forge_mcp_bindings b
  where b.owner_user_id=p_owner_user_id and b.client_id=p_client_id
    and b.revoked_at is null;

  select count(*)::integer into v_count
  from private.ordax_forge_instances i
  where i.owner_user_id=p_owner_user_id and i.revoked_at is null;

  select coalesce(pg_catalog.jsonb_agg(
    jsonb_build_object(
      'instance_id',chosen.instance_id,
      'display_name',chosen.display_name,
      'app_version',chosen.app_version,
      'last_seen_at',chosen.last_seen_at,
      'online',chosen.online,
      'selected',chosen.instance_id is not distinct from v_bound
    ) order by chosen.online desc,chosen.last_seen_at desc nulls last,chosen.instance_id
  ),'[]'::jsonb) into v_list
  from (
    select i.instance_id,i.display_name,i.app_version,i.last_seen_at,
      (i.reported_online
       and i.last_seen_at is not null
       and i.last_seen_at >= v_now - interval '75 seconds'
       and i.last_seen_at <= v_now + interval '15 seconds') as online
    from private.ordax_forge_instances i
    where i.owner_user_id=p_owner_user_id and i.revoked_at is null
    order by online desc,i.last_seen_at desc nulls last,i.instance_id
    limit 32
  ) chosen;

  return jsonb_build_object('ok',true,
    'bound_instance_id',v_bound,'candidate_count',v_count,
    'truncated',v_count>32,'instances',v_list);
end;
$$;

revoke all on function public.ordax_list_forge_mcp_instances_v1(uuid,text)
  from public,anon,authenticated,service_role,ordax_edge_runtime,ordax_edge_executor;

-- Atomic per-client compare-and-swap: merely listing an instance cannot
-- redirect the user's Forge MCP transport. No grants/tasks are moved.
create or replace function public.ordax_select_forge_mcp_instance_v1(
  p_owner_user_id uuid,
  p_client_id text,
  p_target_instance_id uuid,
  p_expected_instance_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_current uuid;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_updated integer := 0;
begin
  if p_owner_user_id is null or p_client_id is null
     or p_client_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     or not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)
     or not private.ordax_forge_oauth_client_authorized_v1(p_owner_user_id,p_client_id)
  then
    return jsonb_build_object('ok',false,'error','forge_mcp_authorization_required');
  end if;
  if p_target_instance_id is null then
    return jsonb_build_object('ok',false,'error','forge_instance_selection_invalid');
  end if;

  select b.instance_id into v_current
  from private.ordax_forge_mcp_bindings b
  where b.owner_user_id=p_owner_user_id and b.client_id=p_client_id
    and b.revoked_at is null
  for update of b;

  if v_current is distinct from p_expected_instance_id then
    return jsonb_build_object('ok',false,'error','forge_instance_binding_conflict');
  end if;

  if not exists (
    select 1 from private.ordax_forge_instances i
    where i.instance_id=p_target_instance_id
      and i.owner_user_id=p_owner_user_id and i.revoked_at is null
      and i.reported_online
      and i.last_seen_at between v_now - interval '75 seconds'
                             and v_now + interval '15 seconds'
  ) then
    return jsonb_build_object('ok',false,'error','forge_instance_target_unavailable');
  end if;

  if v_current = p_target_instance_id then
    return jsonb_build_object('ok',true,'instance_id',p_target_instance_id,
      'previous_instance_id',v_current,'changed',false);
  end if;

  -- Switching does not cancel another instance's already accepted action.
  -- Refuse the switch while any request for this exact OAuth client is
  -- queued, leased or running; terminal receipts stay queryable by id.
  if exists (
    select 1 from private.ordax_forge_action_requests a
    where a.owner_user_id=p_owner_user_id and a.client_id=p_client_id
      and a.status in ('queued','leased','running')
      and a.expires_at>v_now
  ) then
    return jsonb_build_object('ok',false,'error','forge_instance_selection_pending_actions');
  end if;

  if v_current is null then
    insert into private.ordax_forge_mcp_bindings(
      owner_user_id,client_id,instance_id,bound_at,revoked_at
    ) values (p_owner_user_id,p_client_id,p_target_instance_id,v_now,null)
    on conflict(owner_user_id,client_id) do update
      set instance_id=excluded.instance_id,bound_at=v_now,revoked_at=null
      where private.ordax_forge_mcp_bindings.revoked_at is not null;
  else
    update private.ordax_forge_mcp_bindings
       set instance_id=p_target_instance_id,bound_at=v_now
     where owner_user_id=p_owner_user_id and client_id=p_client_id
       and instance_id=v_current and revoked_at is null;
  end if;
  get diagnostics v_updated = row_count;
  if v_updated<>1 then
    return jsonb_build_object('ok',false,'error','forge_instance_binding_conflict');
  end if;

  return jsonb_build_object('ok',true,'instance_id',p_target_instance_id,
    'previous_instance_id',v_current,'changed',true);
end;
$$;

revoke all on function public.ordax_select_forge_mcp_instance_v1(uuid,text,uuid,uuid)
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
    'mcp_resolve','mcp_instances_list','mcp_instance_select','mcp_enqueue','mcp_get',
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
  elsif p_operation='mcp_instances_list' then
    if p_payload <> '{}'::jsonb then
      return jsonb_build_object('ok',false,'error','forge_http_payload_invalid');
    end if;
    return public.ordax_list_forge_mcp_instances_v1(v_owner,v_client);
  elsif p_operation='mcp_instance_select' then
    if p_payload is null
       or jsonb_typeof(p_payload) <> 'object'
       or (select count(*) from jsonb_object_keys(p_payload)) <> 2
       or not p_payload ? 'target_instance_id'
       or not p_payload ? 'expected_instance_id'
    then
      return jsonb_build_object('ok',false,'error','forge_http_payload_invalid');
    end if;
    return public.ordax_select_forge_mcp_instance_v1(
      v_owner,v_client,
      (p_payload->>'target_instance_id')::uuid,
      (p_payload->>'expected_instance_id')::uuid
    );
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
