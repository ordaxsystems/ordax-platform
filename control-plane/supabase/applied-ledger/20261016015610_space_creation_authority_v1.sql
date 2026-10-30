begin;

-- Deployment projection of the canonical Space type catalog. This is not a second
-- product SSOT: tests require these rows to match the mvp-foundation definitions in
-- system/services/spaces/type-catalog.mjs exactly.
create table private.ordax_space_creation_type_projection (
  domain text not null,
  subtype text not null,
  space_kind text not null check (space_kind in ('personal','work','professional')),
  profile_slug text not null check (profile_slug ~ '^[a-z0-9][a-z0-9-]{1,79}$'),
  profile_version integer not null check (profile_version > 0),
  primary key (domain, subtype),
  check (domain ~ '^[a-z0-9][a-z0-9]*(?:[._-][a-z0-9]+)*$'),
  check (subtype ~ '^[a-z0-9][a-z0-9]*(?:[._-][a-z0-9]+)*$')
);

revoke all on table private.ordax_space_creation_type_projection
  from public, anon, authenticated, service_role;

insert into private.ordax_space_creation_type_projection(
  domain, subtype, space_kind, profile_slug, profile_version
) values
  ('food', 'pizzeria', 'professional', 'pizzaria-br', 1),
  ('fabrication', '3d-printing', 'professional', 'impressao-3d-br', 1);

create table private.ordax_space_creation_requests (
  user_id uuid not null references auth.users(id) on delete cascade,
  idempotency_key uuid not null,
  space_id uuid not null references public.ordax_spaces(space_id) on delete cascade,
  requested_name text not null,
  domain text not null,
  subtype text not null,
  created_at timestamptz not null default timezone('utc', now()),
  primary key (user_id, idempotency_key)
);

revoke all on table private.ordax_space_creation_requests
  from public, anon, authenticated, service_role;

-- Direct table INSERT was only a foundation capability. Canonical creation now goes
-- through the bounded RPC below so lifecycle/type/idempotency/quota checks cannot be
-- bypassed by a client writing ordax_spaces directly.
revoke insert on table public.ordax_spaces from authenticated;

create or replace function public.ordax_create_space_v1(
  p_name text,
  p_domain text,
  p_subtype text,
  p_idempotency_key uuid
)
returns table (
  space_id uuid,
  owner_user_id uuid,
  name text,
  kind text,
  state text,
  domain text,
  subtype text,
  profile_slug text,
  profile_version integer,
  created boolean
)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_actor uuid := (select auth.uid());
  v_name text;
  v_projection record;
  v_existing record;
  v_space_id uuid;
  v_owned_count integer;
begin
  if v_actor is null then
    raise exception using errcode = '42501', message = 'authentication-required';
  end if;
  if p_idempotency_key is null then
    raise exception using errcode = '22023', message = 'space-create-idempotency-key-required';
  end if;

  v_name := btrim(coalesce(p_name, ''));
  if char_length(v_name) < 1 or char_length(v_name) > 120 or v_name ~ '[[:cntrl:]]' then
    raise exception using errcode = '22023', message = 'invalid-space-name';
  end if;

  select p.space_kind, p.profile_slug, p.profile_version
    into v_projection
  from private.ordax_space_creation_type_projection p
  where p.domain = p_domain
    and p.subtype = p_subtype;
  if not found then
    raise exception using errcode = '22023', message = 'space-type-not-creatable';
  end if;

  perform 1
  from public.ordax_accounts a
  where a.user_id = v_actor
  for update;
  if not found then
    raise exception using errcode = '23503', message = 'ordax-account-required';
  end if;

  select r.space_id, r.requested_name, r.domain, r.subtype
    into v_existing
  from private.ordax_space_creation_requests r
  where r.user_id = v_actor
    and r.idempotency_key = p_idempotency_key;

  if found then
    if v_existing.requested_name <> v_name
      or v_existing.domain <> p_domain
      or v_existing.subtype <> p_subtype then
      raise exception using errcode = '22023', message = 'space-create-idempotency-conflict';
    end if;

    return query
    select s.space_id,
           s.owner_user_id,
           s.name,
           s.kind,
           s.state,
           s.domain,
           s.subtype,
           v_projection.profile_slug::text,
           v_projection.profile_version::integer,
           false
    from public.ordax_spaces s
    where s.space_id = v_existing.space_id
      and s.owner_user_id = v_actor;
    if not found then
      raise exception using errcode = 'P0001', message = 'space-create-idempotency-state-invalid';
    end if;
    return;
  end if;

  select count(*)::integer
    into v_owned_count
  from public.ordax_spaces s
  where s.owner_user_id = v_actor;
  if v_owned_count >= 64 then
    raise exception using errcode = '23514', message = 'owned-space-limit-reached';
  end if;

  insert into public.ordax_spaces(
    owner_user_id, name, kind, state, domain, subtype
  ) values (
    v_actor, v_name, v_projection.space_kind, 'active', p_domain, p_subtype
  )
  returning ordax_spaces.space_id into v_space_id;

  insert into public.ordax_space_members(
    space_id, user_id, role, state
  ) values (
    v_space_id, v_actor, 'owner', 'active'
  );

  insert into private.ordax_space_creation_requests(
    user_id, idempotency_key, space_id, requested_name, domain, subtype
  ) values (
    v_actor, p_idempotency_key, v_space_id, v_name, p_domain, p_subtype
  );

  return query
  select s.space_id,
         s.owner_user_id,
         s.name,
         s.kind,
         s.state,
         s.domain,
         s.subtype,
         v_projection.profile_slug::text,
         v_projection.profile_version::integer,
         true
  from public.ordax_spaces s
  where s.space_id = v_space_id;
end;
$$;

revoke all on function public.ordax_create_space_v1(text, text, text, uuid)
  from public, anon, authenticated, service_role;
grant execute on function public.ordax_create_space_v1(text, text, text, uuid)
  to authenticated;

commit;