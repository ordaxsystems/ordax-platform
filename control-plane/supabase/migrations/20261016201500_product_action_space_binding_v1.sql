begin;

-- Studio Runtime v3 result binding must use the Space recorded by the
-- canonical Product action authority. Do not reconstruct Space from client
-- input or device/project metadata after the action has been accepted.
create or replace function public.ordax_get_product_action_v1(
  p_owner_user_id uuid,
  p_client_kind text,
  p_client_id text,
  p_request_id uuid
)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select jsonb_build_object(
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
  )
  from private.ordax_product_action_requests r
  where p_owner_user_id is not null
    and p_request_id is not null
    and p_client_kind in ('ordax-web','ordax-mobile','product-mcp')
    and p_client_id is not null
    and char_length(p_client_id) between 8 and 160
    and p_client_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]+$'
    and r.owner_user_id = p_owner_user_id
    and r.client_kind = p_client_kind
    and r.client_id = p_client_id
    and r.request_id = p_request_id;
$$;

revoke all on function public.ordax_get_product_action_v1(uuid, text, text, uuid)
  from public, anon, authenticated, service_role, ordax_edge_executor;
grant execute on function public.ordax_get_product_action_v1(uuid, text, text, uuid)
  to ordax_edge_executor;

commit;
