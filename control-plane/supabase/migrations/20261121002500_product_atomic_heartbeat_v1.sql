begin;

-- One authenticated Device heartbeat, one PostgreSQL transaction: presence
-- and actual reported capacity share the same commit, without a second
-- Hyperdrive SQL round trip. The existing functions remain the sole
-- authorities for presence freshness and capacity admission locks.
create or replace function public.ordax_record_product_heartbeat_v1(
  p_device_id uuid,
  p_online boolean,
  p_runtime_kind text,
  p_agent_version text,
  p_capability_digest text,
  p_force boolean,
  p_max_concurrent_jobs integer
)
returns jsonb
language plpgsql
security definer
set search_path to ''
as $function$
declare
  v_recorded boolean;
  v_capacity_recorded boolean;
begin
  -- Worker validation is not a grant. Recheck the bounded Device contract
  -- before either write, including explicit capacity for old four-worker Agents.
  if p_device_id is null or p_online is null or p_force is null
     or p_runtime_kind not in ('ordax-os','desktop-agent','mobile-client','other')
     or p_runtime_kind is null
     or p_agent_version is null or char_length(p_agent_version) not between 1 and 80
     or p_capability_digest is null or p_capability_digest !~ '^[0-9a-f]{64}$'
     or p_max_concurrent_jobs is null or p_max_concurrent_jobs not between 1 and 32
  then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'product_capacity_unavailable');
  end if;

  begin
    v_recorded := public.ordax_record_product_presence_v1(
      p_device_id, p_online, p_runtime_kind, p_agent_version,
      p_capability_digest, p_force
    );
    if p_online then
      v_capacity_recorded := public.ordax_record_product_capacity_v1(
        p_device_id, p_max_concurrent_jobs
      );
      if not coalesce(v_capacity_recorded, false) then
        -- A failed online capacity write rolls back the presence change.
        raise exception 'atomic device capacity unavailable' using errcode='P4102';
      end if;
    elsif p_force and not coalesce(v_recorded, false) then
      -- Forced offline reports must not silently claim success.
      raise exception 'atomic offline presence unavailable' using errcode='P4102';
    end if;
    return pg_catalog.jsonb_build_object('ok', true, 'recorded', v_recorded);
  exception when sqlstate 'P4102' then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'product_capacity_unavailable');
  end;
end;
$function$;

revoke all on function public.ordax_record_product_heartbeat_v1(
  uuid, boolean, text, text, text, boolean, integer
) from public, anon, authenticated, service_role, ordax_edge_executor;
grant execute on function public.ordax_record_product_heartbeat_v1(
  uuid, boolean, text, text, text, boolean, integer
) to ordax_edge_executor;
comment on function public.ordax_record_product_heartbeat_v1(
  uuid, boolean, text, text, text, boolean, integer
) is 'Atomic Device presence and attested capacity heartbeat; one SQL call after unchanged device authentication.';

commit;
