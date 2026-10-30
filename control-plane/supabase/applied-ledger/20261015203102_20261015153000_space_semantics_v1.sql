-- Canonical Space domain semantics.
-- Adds nullable paired semantic identity for backward-compatible legacy Spaces while
-- making domain/subtype first-class account-owned data for all new canonical Spaces.
-- No Profile Pack backfill is performed: Profile Packs remain technical composition,
-- not the semantic owner of a Space.
begin;

alter table public.ordax_spaces
  add column domain text,
  add column subtype text;

alter table public.ordax_spaces
  add constraint ordax_spaces_semantic_pair_chk check (
    (domain is null and subtype is null)
    or (domain is not null and subtype is not null)
  ),
  add constraint ordax_spaces_domain_chk check (
    domain is null
    or (
      char_length(domain) between 1 and 80
      and domain ~ '^[a-z0-9][a-z0-9]*([._-][a-z0-9]+)*$'
    )
  ),
  add constraint ordax_spaces_subtype_chk check (
    subtype is null
    or (
      char_length(subtype) between 1 and 80
      and subtype ~ '^[a-z0-9][a-z0-9]*([._-][a-z0-9]+)*$'
    )
  );

-- Preserve the deployed least-privilege executor boundary while replacing the RPC.
grant create on schema public to ordax_account_export_executor;
alter function public.ordax_account_export_v1() owner to postgres;

create or replace function public.ordax_account_export_v1()
returns jsonb
language sql
security definer
set search_path = ''
as $$
  with me as (
    select public.ordax_request_subject_v1() as user_id
  ),
  account as (
    select coalesce(
      (
        select jsonb_build_object(
          'user_id', a.user_id,
          'display_name', a.display_name,
          'created_at', a.created_at,
          'updated_at', a.updated_at
        )
        from public.ordax_accounts a
        where a.user_id = (select user_id from me)
      ),
      '{}'::jsonb
    ) as value
  ),
  spaces as (
    select coalesce(jsonb_agg(
      jsonb_build_object(
        'space_id', s.space_id,
        'name', s.name,
        'kind', s.kind,
        'state', s.state,
        'domain', s.domain,
        'subtype', s.subtype,
        'created_at', s.created_at,
        'updated_at', s.updated_at
      )
      order by s.created_at, s.space_id
    ), '[]'::jsonb) as value
    from public.ordax_spaces s
    where s.owner_user_id = (select user_id from me)
  ),
  memberships as (
    select coalesce(jsonb_agg(
      jsonb_build_object(
        'space_id', m.space_id,
        'user_id', m.user_id,
        'role', m.role,
        'state', m.state,
        'created_at', m.created_at,
        'updated_at', m.updated_at
      )
      order by m.created_at, m.space_id
    ), '[]'::jsonb) as value
    from public.ordax_space_members m
    where m.user_id = (select user_id from me)
  ),
  profile_packs as (
    select coalesce(jsonb_agg(
      jsonb_build_object(
        'space_id', p.space_id,
        'pack_slug', p.pack_slug,
        'pack_version', p.pack_version,
        'config', p.config,
        'enabled_at', p.enabled_at,
        'enabled_by', p.enabled_by
      )
      order by p.space_id, p.pack_slug, p.pack_version
    ), '[]'::jsonb) as value
    from public.ordax_space_profile_packs p
    where exists (
      select 1
      from public.ordax_spaces s
      where s.space_id = p.space_id
        and s.owner_user_id = (select user_id from me)
    )
  ),
  entitlements as (
    select coalesce(jsonb_agg(
      jsonb_build_object(
        'grant_id', e.grant_id,
        'space_id', e.space_id,
        'entitlement_key', e.entitlement_key,
        'entitlement_value', e.entitlement_value,
        'source', e.source,
        'valid_from', e.valid_from,
        'valid_until', e.valid_until,
        'created_at', e.created_at
      )
      order by e.created_at, e.grant_id
    ), '[]'::jsonb) as value
    from public.ordax_entitlement_grants e
    where e.user_id = (select user_id from me)
  ),
  projects as (
    select coalesce(jsonb_agg(
      jsonb_build_object(
        'project_id', p.project_id,
        'space_id', p.space_id,
        'name', p.name,
        'kind', p.kind,
        'state', p.state,
        'created_at', p.created_at,
        'updated_at', p.updated_at
      )
      order by p.created_at, p.project_id
    ), '[]'::jsonb) as value
    from public.ordax_projects p
    where p.created_by_user_id = (select user_id from me)
  ),
  devices as (
    select coalesce(jsonb_agg(
      jsonb_build_object(
        'device_id', d.device_id,
        'device_public_id', d.device_public_id,
        'display_name', d.display_name,
        'device_kind', d.device_kind,
        'channel', d.channel,
        'state', d.state,
        'created_at', d.created_at,
        'updated_at', d.updated_at
      )
      order by d.created_at, d.device_id
    ), '[]'::jsonb) as value
    from public.ordax_product_devices d
    where d.owner_user_id = (select user_id from me)
  ),
  connections as (
    select coalesce(jsonb_agg(
      jsonb_build_object(
        'connection_id', c.connection_id,
        'space_id', c.space_id,
        'project_id', c.project_id,
        'provider', c.provider,
        'external_account_id', c.external_account_id,
        'installation_id', c.installation_id,
        'repository_id', c.repository_id,
        'repository_full_name', c.repository_full_name,
        'default_branch', c.default_branch,
        'access_mode', c.access_mode,
        'state', c.state,
        'created_at', c.created_at,
        'updated_at', c.updated_at
      )
      order by c.created_at, c.connection_id
    ), '[]'::jsonb) as value
    from public.ordax_project_connections c
    where c.owner_user_id = (select user_id from me)
  ),
  memory_items as (
    select coalesce(jsonb_agg(
      jsonb_build_object(
        'memory_id', m.memory_id,
        'space_id', m.space_id,
        'project_id', m.project_id,
        'scope', m.scope,
        'kind', m.kind,
        'sensitivity', m.sensitivity,
        'content', m.content,
        'provenance', m.provenance,
        'source_timestamp', m.source_timestamp,
        'confidence', m.confidence,
        'state', m.state,
        'created_at', m.created_at,
        'updated_at', m.updated_at
      )
      order by m.created_at, m.memory_id
    ), '[]'::jsonb) as value
    from public.ordax_memory_items m
    where m.owner_user_id = (select user_id from me)
  ),
  sync_objects as (
    select coalesce(jsonb_agg(
      jsonb_build_object(
        'sync_object_id', o.sync_object_id,
        'data_class', o.data_class,
        'stable_object_id', o.stable_object_id,
        'object_schema_version', o.object_schema_version,
        'resolver_version', o.resolver_version,
        'server_revision', o.server_revision,
        'tombstone', o.tombstone,
        'payload', o.payload,
        'updated_at', o.updated_at
      )
      order by o.data_class, o.stable_object_id
    ), '[]'::jsonb) as value
    from private.ordax_sync_objects o
    where o.owner_user_id = (select user_id from me)
  )
  select case
    when me.user_id is null then null
    else jsonb_build_object(
      '$schema', 'prototype-ordax.account-export/1',
      'subject', me.user_id,
      'exported_at', now(),
      'account', account.value,
      'spaces', spaces.value,
      'memberships', memberships.value,
      'space_profile_packs', profile_packs.value,
      'entitlements', entitlements.value,
      'projects', projects.value,
      'devices', devices.value,
      'project_connections', connections.value,
      'memory_items', memory_items.value,
      'sync_objects', sync_objects.value
    )
  end
  from me
  cross join account
  cross join spaces
  cross join memberships
  cross join profile_packs
  cross join entitlements
  cross join projects
  cross join devices
  cross join connections
  cross join memory_items
  cross join sync_objects;
$$;

alter function public.ordax_account_export_v1() owner to ordax_account_export_executor;
alter function public.ordax_account_export_v1() security definer;
alter function public.ordax_account_export_v1() set search_path = '';
revoke create on schema public from ordax_account_export_executor;

revoke all on function public.ordax_account_export_v1()
  from public, anon, authenticated, service_role;
grant execute on function public.ordax_account_export_v1() to authenticated;

commit;