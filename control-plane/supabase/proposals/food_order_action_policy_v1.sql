-- REVIEW ONLY. FOOD-001 execution is deferred. Do not apply to canonical
-- Supabase, register as a migration, or expose this function to any app role.
-- This policy reuses the OWNED Space/member authority, NOT the MCP grant table.
-- Real callers MUST derive actor from authenticated server session/transport,
-- never from a Food request body, and run checks in the same SQL transaction.
begin;

do $preflight$
begin
  if to_regprocedure('private.ordax_trusted_actor_auth_eligible_v1(uuid)') is null
     or to_regclass('public.ordax_spaces') is null
     or to_regclass('public.ordax_space_members') is null
     or to_regprocedure(
       'private.ordax_food_action_eligible_v1(uuid,uuid,text)'
     ) is not null
  then
    raise exception 'food_action_policy_owner_preflight_failed';
  end if;
end;
$preflight$;

-- A Space role is NOT a general Product grant. This is a deliberately narrow
-- first-party Food order policy: only the owner and active admins may mutate;
-- members and viewers can read. The owner is not a membership row.
-- No new grant ledger or second Space membership table is introduced.
-- Row share locks serialize with concurrent role/session/Space revocation,
-- PROVIDED the backend uses the same transaction and rechecks at commit.
create function private.ordax_food_action_eligible_v1(
  p_actor_user_id uuid,
  p_space_id uuid,
  p_action text
)
returns boolean
language plpgsql
volatile
security invoker
set search_path = ''
as $function$
declare
  v_owner_user_id uuid;
  v_role text;
begin
  if p_actor_user_id is null
    or p_space_id is null
    or p_action is null
    or p_action not in ('order.read', 'order.create', 'order.transition')
    or private.ordax_trusted_actor_auth_eligible_v1(p_actor_user_id) is not true
  then
    return false;
  end if;

  -- Space must really be the active first-party pizzeria owned by the OS.
  -- FOR SHARE fences archiving/reassignment during this transaction.
  select s.owner_user_id into v_owner_user_id
  from public.ordax_spaces s
  where s.space_id = p_space_id
    and s.state = 'active'
    and s.kind = 'professional'
    and s.domain = 'food'
    and s.subtype = 'pizzeria'
  for share of s;
  if not found then return false; end if;

  if v_owner_user_id = p_actor_user_id then
    return true;
  end if;

  -- One canonical membership row with active status; no MCP consent or
  -- synthetic permission from a caller-supplied capability name.
  select m.role into v_role
  from public.ordax_space_members m
  where m.space_id = p_space_id
    and m.user_id = p_actor_user_id
    and m.state = 'active'
  for share of m;
  if not found then return false; end if;

  if p_action = 'order.read' then
    return v_role in ('admin', 'member', 'viewer');
  end if;
  return v_role = 'admin';
end;
$function$;

-- SECURITY INVOKER + no public EXECUTE. A future narrowly scoped server role
-- may use this only after rollout approval; no grant is issued by this PR.
revoke all on function private.ordax_food_action_eligible_v1(
  uuid,uuid,text
) from public,anon,authenticated,service_role,
       ordax_edge_executor,ordax_edge_runtime;

commit;
