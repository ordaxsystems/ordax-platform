begin;

-- Final database guard for active Space capacity. The public creation RPC already
-- derives auth.uid() and serializes per-account creation, but commercial capacity
-- must remain enforced even if a future trusted service writes ordax_spaces through
-- a different path. This trigger therefore owns the last-line invariant.
--
-- Pre-billing policy is intentionally fail-safe:
-- - no explicit server grant -> canonical Free baseline (2 active Spaces);
-- - exactly one active spaces.active.max grant -> validated quota value;
-- - malformed or ambiguous grants -> fail closed;
-- - an independent 64-owned-Space abuse ceiling remains in force while paid plans
--   are not assignable.

create or replace function private.ordax_effective_space_active_limit_v1(
  p_user_id uuid
)
returns integer
language plpgsql
security definer
set search_path = ''
as $limit$
declare
  v_policy_count integer;
  v_policy_value jsonb;
  v_limit_text text;
  v_limit integer;
begin
  if p_user_id is null then
    raise exception 'space-quota-subject-required' using errcode = '22023';
  end if;

  select count(*)::integer
    into v_policy_count
  from public.ordax_entitlement_grants g
  where g.user_id = p_user_id
    and g.space_id is null
    and g.entitlement_key = 'spaces.active.max'
    and g.valid_from <= statement_timestamp()
    and (g.valid_until is null or g.valid_until > statement_timestamp());

  -- Until billing/paid assignment is activated, absence of an explicit grant is
  -- the canonical Free plan. This value is bound by tests to docs/contracts/entitlements.json.
  if v_policy_count = 0 then
    return 2;
  end if;
  if v_policy_count <> 1 then
    raise exception 'space-quota-policy-ambiguous' using errcode = '55000';
  end if;

  select g.entitlement_value
    into v_policy_value
  from public.ordax_entitlement_grants g
  where g.user_id = p_user_id
    and g.space_id is null
    and g.entitlement_key = 'spaces.active.max'
    and g.valid_from <= statement_timestamp()
    and (g.valid_until is null or g.valid_until > statement_timestamp())
  order by g.valid_from desc, g.grant_id
  limit 1
  for share;

  if jsonb_typeof(v_policy_value) <> 'object'
     or not (v_policy_value ? 'decision')
     or not (v_policy_value ? 'type')
     or not (v_policy_value ? 'unit')
     or not (v_policy_value ? 'limit')
     or (v_policy_value - array['decision','type','unit','limit']::text[]) <> '{}'::jsonb
     or v_policy_value->>'type' <> 'quota'
     or v_policy_value->>'unit' <> 'items'
     or v_policy_value->>'decision' not in ('allowed','denied') then
    raise exception 'space-quota-policy-invalid' using errcode = '22023';
  end if;

  if v_policy_value->>'decision' = 'denied' then
    if jsonb_typeof(v_policy_value->'limit') <> 'number'
       or (v_policy_value->>'limit') !~ '^0$' then
      raise exception 'space-quota-policy-invalid' using errcode = '22023';
    end if;
    return 0;
  end if;

  if jsonb_typeof(v_policy_value->'limit') <> 'number' then
    raise exception 'space-quota-policy-invalid' using errcode = '22023';
  end if;
  v_limit_text := v_policy_value->>'limit';
  if v_limit_text !~ '^[0-9]+$'
     or v_limit_text::numeric > 64 then
    raise exception 'space-quota-policy-invalid' using errcode = '22023';
  end if;
  v_limit := v_limit_text::integer;
  return v_limit;
end;
$limit$;

revoke all on function private.ordax_effective_space_active_limit_v1(uuid)
  from public, anon, authenticated, service_role;

create or replace function private.ordax_enforce_space_active_quota_v1()
returns trigger
language plpgsql
security definer
set search_path = ''
as $guard$
declare
  v_active_count integer;
  v_total_count integer;
  v_limit integer;
  v_check_activation boolean;
  v_check_total boolean;
begin
  if new.owner_user_id is null then
    raise exception 'space-owner-required' using errcode = '23502';
  end if;

  -- Serialize all capacity-changing operations for the same account, including
  -- INSERT, archived -> active, and ownership transfer.
  perform 1
  from public.ordax_accounts a
  where a.user_id = new.owner_user_id
  for update;
  if not found then
    raise exception 'ordax-account-required' using errcode = '23503';
  end if;

  v_check_activation := new.state = 'active' and (
    tg_op = 'INSERT'
    or old.state is distinct from 'active'
    or old.owner_user_id is distinct from new.owner_user_id
  );
  v_check_total := tg_op = 'INSERT'
    or old.owner_user_id is distinct from new.owner_user_id;

  if v_check_total then
    if tg_op = 'INSERT' then
      select count(*)::integer
        into v_total_count
      from public.ordax_spaces s
      where s.owner_user_id = new.owner_user_id;
    else
      select count(*)::integer
        into v_total_count
      from public.ordax_spaces s
      where s.owner_user_id = new.owner_user_id
        and s.space_id <> new.space_id;
    end if;
    if v_total_count >= 64 then
      raise exception 'owned-space-limit-reached' using errcode = '23514';
    end if;
  end if;

  if v_check_activation then
    v_limit := private.ordax_effective_space_active_limit_v1(new.owner_user_id);
    if tg_op = 'INSERT' then
      select count(*)::integer
        into v_active_count
      from public.ordax_spaces s
      where s.owner_user_id = new.owner_user_id
        and s.state = 'active';
    else
      select count(*)::integer
        into v_active_count
      from public.ordax_spaces s
      where s.owner_user_id = new.owner_user_id
        and s.state = 'active'
        and s.space_id <> new.space_id;
    end if;

    if v_active_count >= v_limit then
      raise exception 'spaces-active-quota-exceeded' using errcode = '23514';
    end if;
  end if;

  return new;
end;
$guard$;

revoke all on function private.ordax_enforce_space_active_quota_v1()
  from public, anon, authenticated, service_role;

drop trigger if exists enforce_ordax_space_active_quota_v1 on public.ordax_spaces;
create trigger enforce_ordax_space_active_quota_v1
before insert or update of owner_user_id, state on public.ordax_spaces
for each row execute function private.ordax_enforce_space_active_quota_v1();

commit;
