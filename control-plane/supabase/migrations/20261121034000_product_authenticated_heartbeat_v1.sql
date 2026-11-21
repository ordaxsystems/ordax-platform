begin;

-- One SQL statement per valid Device heartbeat. Authenticate against the
-- existing credential authority BEFORE changing any presence/capacity state.
-- The atomic heartbeat function remains the only writer and enforces all
-- existing presence, attestation and capacity semantics unchanged.
create or replace function public.ordax_authenticated_product_heartbeat_v1(
  p_device_id uuid,
  p_token_sha256 text,
  p_online boolean,
  p_runtime_kind text,
  p_agent_version text,
  p_capability_digest text,
  p_force boolean,
  p_max_concurrent_jobs integer
) returns jsonb
language plpgsql security definer set search_path to ''
as $function$
begin
  if p_device_id is null or p_token_sha256 is null
     or p_token_sha256 !~ '^[0-9a-f]{64}$'
     or not coalesce(public.ordax_authenticate_product_device_v1(
       p_device_id, p_token_sha256),false)
  then
    return pg_catalog.jsonb_build_object('ok',false,'error','invalid_device_token');
  end if;

  return public.ordax_record_product_heartbeat_v1(
    p_device_id,p_online,p_runtime_kind,p_agent_version,
    p_capability_digest,p_force,p_max_concurrent_jobs);
end;
$function$;

revoke all on function public.ordax_authenticated_product_heartbeat_v1(
  uuid,text,boolean,text,text,text,boolean,integer
) from public,anon,authenticated,service_role,ordax_edge_executor;
grant execute on function public.ordax_authenticated_product_heartbeat_v1(
  uuid,text,boolean,text,text,text,boolean,integer
) to ordax_edge_executor;
comment on function public.ordax_authenticated_product_heartbeat_v1(
  uuid,text,boolean,text,text,text,boolean,integer
) is 'Single SQL authenticated heartbeat delegates to the canonical atomic presence and capacity function; no cached credentials.';

commit;
