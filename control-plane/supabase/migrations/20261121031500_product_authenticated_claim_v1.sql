begin;
-- One authenticated Device claim, one Hyperdrive SQL statement. Preserve
-- the enrolled credential and canonical lease/grant authorities.
create or replace function public.ordax_authenticated_claim_product_action_v1(
  p_device_id uuid, p_token_sha256 text, p_agent_instance_id uuid,
  p_boot_id text, p_lease_seconds integer
) returns jsonb language plpgsql security definer set search_path to ''
as $function$
begin
  -- Authenticate before taking or renewing any lease.
  if p_device_id is null or p_token_sha256 is null
     or p_token_sha256 !~ '^[0-9a-f]{64}$'
     or not coalesce(public.ordax_authenticate_product_device_v1(
       p_device_id,p_token_sha256),false)
  then
    return pg_catalog.jsonb_build_object('ok',false,'error','invalid_device_token');
  end if;

  -- Original function alone owns capacity, grants, expiry, fencing,
  -- lease acquisition and SKIP LOCKED semantics.
  return public.ordax_claim_product_action_v1(
    p_device_id,p_agent_instance_id,p_boot_id,p_lease_seconds);
end;
$function$;
revoke all on function public.ordax_authenticated_claim_product_action_v1(
  uuid,text,uuid,text,integer
) from public,anon,authenticated,service_role,ordax_edge_executor;
grant execute on function public.ordax_authenticated_claim_product_action_v1(
  uuid,text,uuid,text,integer
) to ordax_edge_executor;
comment on function public.ordax_authenticated_claim_product_action_v1(
  uuid,text,uuid,text,integer
) is 'One SQL device authentication and canonical action claim; no second grant or lease authority.';
commit;
