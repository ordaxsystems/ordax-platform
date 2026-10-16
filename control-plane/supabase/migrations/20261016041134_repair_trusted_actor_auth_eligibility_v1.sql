-- Repair drift in the live Product PostgreSQL authority: downstream Product RPCs
-- already reference this canonical helper, but the helper itself was absent.
-- Keep the repair narrow: restore only the missing helper and its ACL contract.

do $preflight$
begin
  if to_regclass('auth.users') is null
     or to_regclass('public.ordax_accounts') is null
     or to_regprocedure('private.ordax_trusted_actor_auth_eligible_v1(uuid)') is not null
  then raise exception 'trusted actor helper repair preflight failed'; end if;
end;
$preflight$;

create function private.ordax_trusted_actor_auth_eligible_v1(p_actor_user_id uuid)
returns boolean
language plpgsql
volatile
security invoker
set search_path = ''
as $function$
begin
  if p_actor_user_id is null then
    return false;
  end if;

  perform 1
  from auth.users u
  join public.ordax_accounts a on a.user_id=u.id
  where u.id=p_actor_user_id
    and u.deleted_at is null
    and u.is_anonymous is false
    and u.confirmed_at is not null
    and (u.banned_until is null
       or u.banned_until<=pg_catalog.clock_timestamp())
  for share of u,a;

  return found;
end;
$function$;

revoke all on function private.ordax_trusted_actor_auth_eligible_v1(uuid)
from public, anon, authenticated, service_role,
     ordax_edge_executor, ordax_edge_runtime,
     ordax_space_executor, ordax_project_executor,
     ordax_memory_executor, ordax_profile_pack_executor,
     ordax_entitlement_default_executor;

do $postflight$
begin
  if not exists(
    select 1
    from pg_proc p
    where p.oid='private.ordax_trusted_actor_auth_eligible_v1(uuid)'::regprocedure
      and not p.prosecdef
      and p.provolatile='v'
      and pg_get_userbyid(p.proowner)='postgres'
  )
  or has_function_privilege('authenticated','private.ordax_trusted_actor_auth_eligible_v1(uuid)','EXECUTE')
  or has_function_privilege('anon','private.ordax_trusted_actor_auth_eligible_v1(uuid)','EXECUTE')
  or has_function_privilege('service_role','private.ordax_trusted_actor_auth_eligible_v1(uuid)','EXECUTE')
  or has_function_privilege('ordax_edge_executor','private.ordax_trusted_actor_auth_eligible_v1(uuid)','EXECUTE')
  or has_function_privilege('ordax_edge_runtime','private.ordax_trusted_actor_auth_eligible_v1(uuid)','EXECUTE')
  or has_table_privilege('authenticated','auth.users','SELECT')
  or has_table_privilege('ordax_edge_runtime','auth.users','SELECT')
  then raise exception 'trusted actor helper repair postflight failed'; end if;
end;
$postflight$;
