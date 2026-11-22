begin;
do $guard$
declare
  v_proc oid := 'public.ordax_get_product_action_v1(uuid,text,text,uuid)'::regprocedure;
begin
  if not exists (select 1 from information_schema.columns where table_schema='private' and table_name='ordax_product_action_requests' and column_name='space_id' and data_type='uuid')
    or md5(pg_get_functiondef(v_proc)) <> '8fcf5d146d5a4b9b7449f994bc7fb41f'
    or not has_function_privilege('ordax_edge_executor',v_proc,'EXECUTE')
    or has_function_privilege('anon',v_proc,'EXECUTE')
    or has_function_privilege('authenticated',v_proc,'EXECUTE')
  then
    raise exception 'product action Space projection must match the verified restricted existing SQL authority';
  end if;
end;
$guard$;

-- Preserve existing owner/exact OAuth-client checks, expiry, revocation,
-- orphan-lease retirement and function ACL. Only add canonical row Space.
CREATE OR REPLACE FUNCTION public.ordax_get_product_action_v1(
  p_owner_user_id uuid, p_client_kind text, p_client_id text, p_request_id uuid
)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_device_id uuid;
  v_response jsonb;
begin
  -- Never mutate or reveal an action until all existing owner and exact
  -- OAuth client checks pass. No arbitrary-ID expiry side channel.
  if p_owner_user_id is null
     or p_request_id is null
     or p_client_kind not in ('ordax-web','ordax-mobile','product-mcp')
     or p_client_id is null
     or char_length(p_client_id) not between 8 and 160
     or p_client_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]+$'
  then
    return null;
  end if;

  select r.device_id into v_device_id
    from private.ordax_product_action_requests r
   where r.owner_user_id = p_owner_user_id
     and r.client_kind = p_client_kind
     and r.client_id = p_client_id
     and r.request_id = p_request_id;

  if not found then return null; end if;

  perform private.ordax_expire_queued_product_actions_v1(v_device_id, p_request_id);
  perform private.ordax_retire_unauthorized_queued_product_actions_v1(v_device_id, p_request_id);
  perform private.ordax_retire_orphaned_running_product_actions_v1(v_device_id, p_request_id);

  select pg_catalog.jsonb_build_object(
    'ok', true,
    'request_id', r.request_id,
    'device_id', r.device_id,
    'space_id', r.space_id,
    'project_id', r.project_id,
    'capability', r.capability,
    'status', r.status,
    'effect_id', r.effect_id,
    'result', r.result,
    'error_code', r.error_code,
    'execution_runtime_kind', r.execution_runtime_kind,
    'execution_agent_version', r.execution_agent_version,
    'created_at', r.created_at,
    'started_at', r.started_at,
    'finished_at', r.finished_at
  ) into v_response
    from private.ordax_product_action_requests r
   where r.owner_user_id = p_owner_user_id
     and r.client_kind = p_client_kind
     and r.client_id = p_client_id
     and r.request_id = p_request_id;

  return v_response;
end;
$function$;

do $postflight$
declare
  v_proc oid := 'public.ordax_get_product_action_v1(uuid,text,text,uuid)'::regprocedure;
  v_definition text;
begin
  v_definition := pg_get_functiondef(v_proc);
  if strpos(v_definition,'''space_id'', r.space_id') = 0
    or strpos(v_definition,'ordax_retire_unauthorized_queued_product_actions_v1') = 0
    or strpos(v_definition,'ordax_expire_queued_product_actions_v1') = 0
    or strpos(v_definition,'ordax_retire_orphaned_running_product_actions_v1') = 0
    or not (select prosecdef and provolatile='v' from pg_proc where oid=v_proc)
    or not has_function_privilege('ordax_edge_executor',v_proc,'EXECUTE')
    or has_function_privilege('anon',v_proc,'EXECUTE')
    or has_function_privilege('authenticated',v_proc,'EXECUTE')
  then
    raise exception 'Product action Space projection postflight rejected';
  end if;
end;
$postflight$;
commit;