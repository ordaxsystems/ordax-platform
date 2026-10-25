-- Isolated PostgreSQL 17 CI fixture. NOT a migration or production seed.
-- Auth eligibility function mirrors the canonical existing owner function
-- (migration 20261007212000_trusted_actor_auth_eligibility_v1.sql).
-- Roles are cluster-scoped and already created by the one canonical
-- PostgreSQL service setup in the same GitHub Actions workflow.
create schema auth;
create schema private;
create table auth.users (
  id uuid primary key,
  deleted_at timestamptz,
  is_anonymous boolean not null default false,
  confirmed_at timestamptz,
  banned_until timestamptz
);
create table public.ordax_accounts (
  user_id uuid primary key references auth.users(id)
);
create table public.ordax_spaces (
  space_id uuid primary key,
  owner_user_id uuid not null references auth.users(id),
  kind text not null check (kind in ('personal','work','professional')),
  state text not null check (state in ('active','archived')),
  domain text,
  subtype text
);
create table public.ordax_space_members (
  space_id uuid not null references public.ordax_spaces(space_id),
  user_id uuid not null references auth.users(id),
  role text not null check (role in ('admin','member','viewer')),
  state text not null check (state in ('active','suspended')),
  primary key(space_id,user_id)
);

create function private.ordax_trusted_actor_auth_eligible_v1(p_actor_user_id uuid)
returns boolean language plpgsql volatile security invoker
set search_path = ''
as $function$
begin
  if p_actor_user_id is null then return false; end if;
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

insert into auth.users (id,confirmed_at)
select (lpad(to_hex(i),8,'0') ||
 '-0000-4000-8000-000000000000')::uuid,
'2026-10-01T00:00:00Z'::timestamptz
from generate_series(1,8) as i;
insert into public.ordax_accounts(user_id) select id from auth.users;
insert into public.ordax_spaces(space_id,owner_user_id,kind,state,domain,subtype)
values
('11111111-1111-4111-8111-111111111111','00000001-0000-4000-8000-000000000000',
 'professional','active','food','pizzeria'),
('22222222-2222-4222-8222-222222222222','00000007-0000-4000-8000-000000000000',
 'professional','active','food','pizzeria'),
('33333333-3333-4333-8333-333333333333','00000001-0000-4000-8000-000000000000',
 'professional','archived','food','pizzeria'),
('44444444-4444-4444-8444-444444444444','00000001-0000-4000-8000-000000000000',
 'professional','active','retail','store');
insert into public.ordax_space_members(space_id,user_id,role,state)
values
('11111111-1111-4111-8111-111111111111','00000002-0000-4000-8000-000000000000','admin','active'),
('11111111-1111-4111-8111-111111111111','00000003-0000-4000-8000-000000000000','member','active'),
('11111111-1111-4111-8111-111111111111','00000004-0000-4000-8000-000000000000','viewer','active'),
('11111111-1111-4111-8111-111111111111','00000005-0000-4000-8000-000000000000','admin','suspended'),
('11111111-1111-4111-8111-111111111111','00000006-0000-4000-8000-000000000000','admin','active');
update auth.users set banned_until='2099-01-01T00:00:00Z'::timestamptz
where id='00000006-0000-4000-8000-000000000000'::uuid;
