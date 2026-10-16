begin;

-- Snapshot the Runtime that actually executes an external effect. Presence is
-- current device state and must never be used to retroactively attribute an
-- older action after an upgrade/restart.
alter table private.ordax_product_action_requests
  add column execution_runtime_kind text,
  add column execution_agent_version text;

alter table private.ordax_product_action_requests
  add constraint ordax_product_action_execution_runtime_kind_check
    check (
      execution_runtime_kind is null
      or execution_runtime_kind in ('ordax-os','desktop-agent','mobile-client','other')
    ),
  add constraint ordax_product_action_execution_agent_version_check
    check (
      execution_agent_version is null
      or (
        char_length(execution_agent_version) between 1 and 80
        and execution_agent_version = btrim(execution_agent_version)
        and execution_agent_version !~ '[[:cntrl:]]'
      )
    ),
  add constraint ordax_product_action_execution_provenance_pair_check
    check ((execution_runtime_kind is null) = (execution_agent_version is null));

create function public.ordax_bind_product_action_runtime_provenance_v1(
  p_device_id uuid,
  p_request_id uuid,
  p_effect_id uuid,
  p_attempt_id uuid,
  p_lease_id uuid,
  p_execution_epoch bigint,
  p_agent_instance_id uuid,
  p_boot_id text,
  p_runtime_kind text,
  p_agent_version text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_row private.ordax_product_action_requests%rowtype;
begin
  if p_runtime_kind not in ('ordax-os','desktop-agent','mobile-client','other')
     or p_agent_version is null
     or char_length(p_agent_version) not between 1 and 80
     or p_agent_version <> pg_catalog.btrim(p_agent_version)
     or p_agent_version ~ '[[:cntrl:]]'
  then
    return false;
  end if;

  select *
    into v_row
    from private.ordax_product_action_requests
   where request_id = p_request_id
     and device_id = p_device_id
   for update;

  if not found
     or v_row.effect_id <> p_effect_id
     or v_row.attempt_id <> p_attempt_id
     or v_row.lease_id <> p_lease_id
     or v_row.execution_epoch <> p_execution_epoch
     or v_row.agent_instance_id <> p_agent_instance_id
     or v_row.boot_id <> p_boot_id
     or v_row.status not in ('leased','running','succeeded','failed','cancelled')
  then
    return false;
  end if;

  if v_row.execution_runtime_kind is not null then
    return v_row.execution_runtime_kind = p_runtime_kind
       and v_row.execution_agent_version = p_agent_version;
  end if;

  update private.ordax_product_action_requests
     set execution_runtime_kind = p_runtime_kind,
         execution_agent_version = p_agent_version
   where request_id = p_request_id;
  return true;
end;
$$;

comment on function public.ordax_bind_product_action_runtime_provenance_v1(
  uuid, uuid, uuid, uuid, uuid, bigint, uuid, text, text, text
) is 'Binds immutable execution-time Runtime kind/version to an exactly fenced Product action. Terminal binding is used only after an accepted/replayed terminal report; presence metadata is never substituted for historical action provenance.';

revoke all on function public.ordax_bind_product_action_runtime_provenance_v1(
  uuid, uuid, uuid, uuid, uuid, bigint, uuid, text, text, text
) from public, anon, authenticated, service_role;
grant execute on function public.ordax_bind_product_action_runtime_provenance_v1(
  uuid, uuid, uuid, uuid, uuid, bigint, uuid, text, text, text
) to ordax_edge_executor;

-- Keep the existing client-scoped read boundary and add only immutable action
-- provenance. Historical rows remain null instead of being misattributed to
-- the device's current presence version.
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
