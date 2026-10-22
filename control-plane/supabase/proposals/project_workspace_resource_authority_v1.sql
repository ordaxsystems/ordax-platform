begin;

-- Project-First M1: a Lab project binding is an identity mapping, NOT a grant.
-- Resource references below are subordinate to the existing canonical
-- ordax_remote_capability_grants ledger, never an alternative authority.
-- Only Owner-scoped revocation is proposed; no issuance/write privilege to
-- the Edge is granted. Issuance requires future attested Runtime picker proof.
do $preflight$
begin
  if to_regclass('private.ordax_lab_project_authorities') is not null
     or to_regclass('private.ordax_workspace_resource_bindings') is not null
     or to_regprocedure('public.ordax_verify_project_workspace_resource_v1(uuid,uuid,uuid,text,text,uuid,text)') is not null
     or to_regprocedure('public.ordax_revoke_project_workspace_resource_v1(uuid,uuid,text)') is not null
     or to_regprocedure('private.ordax_trusted_actor_auth_eligible_v1(uuid)') is null
     or to_regprocedure('private.ordax_subject_can_admin_space_v1(uuid,uuid)') is null
     or to_regprocedure('private.ordax_subject_can_access_project_v1(uuid,uuid)') is null
     or not exists (select 1 from pg_catalog.pg_roles where rolname='ordax_edge_runtime')
  then
    raise exception 'workspace_resource_preflight_failed';
  end if;
end;
$preflight$;

-- Unique mapping of an untrusted, local Lab ID to one Product project/Space.
-- Separate from resource instances to permit multiple roots without creating
-- duplicate project identities or copying projects into Lab SQLite.
create table private.ordax_lab_project_authorities (
  binding_id uuid primary key,
  owner_user_id uuid not null references public.ordax_accounts(user_id),
  client_id uuid not null,
  lab_project_id text not null check (
    char_length(lab_project_id) between 1 and 180
    and lab_project_id ~ '^[A-Za-z0-9_-]+$'
  ),
  space_id uuid not null,
  project_id uuid not null,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  revoked_at timestamptz,
  unique(owner_user_id, client_id, lab_project_id),
  foreign key(project_id,space_id)
    references public.ordax_projects(project_id,space_id)
);

-- Non-bearer resourceId is a reference to the Runtime-owned root; its
-- filesystem identity/path are NEVER stored in PostgreSQL or Lab SQLite.
-- Parent grant revocation is checked live on every verification, including
-- if the resource row is not itself revoked. No grants are minted here.
create table private.ordax_workspace_resource_bindings (
  resource_id text primary key check(
    char_length(resource_id) between 17 and 169
    and resource_id ~ '^resource_[A-Za-z0-9_-]{8,160}$'
  ),
  lab_binding_id uuid not null references
    private.ordax_lab_project_authorities(binding_id) on delete restrict,
  grant_id uuid not null references
    public.ordax_remote_capability_grants(grant_id) on delete restrict,
  actor_id uuid not null,
  workspace_session_id text not null check(
    char_length(workspace_session_id) between 1 and 180
    and workspace_session_id ~ '^[A-Za-z0-9_-]+$'
  ),
  device_id uuid not null references public.ordax_product_devices(device_id),
  issued_by text not null check(issued_by='trusted-runtime-picker'),
  issued_at timestamptz not null,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  check(expires_at > issued_at and expires_at <= issued_at + interval '24 hours')
);
create index ordax_workspace_resource_lab_idx
  on private.ordax_workspace_resource_bindings(lab_binding_id)
  where revoked_at is null;

alter table private.ordax_lab_project_authorities enable row level security;
alter table private.ordax_lab_project_authorities force row level security;
alter table private.ordax_workspace_resource_bindings enable row level security;
alter table private.ordax_workspace_resource_bindings force row level security;
revoke all on table private.ordax_lab_project_authorities
  from public,anon,authenticated,service_role,ordax_edge_executor,ordax_edge_runtime;
revoke all on table private.ordax_workspace_resource_bindings
  from public,anon,authenticated,service_role,ordax_edge_executor,ordax_edge_runtime;

-- READ-ONLY verifier for a caller whose identity has already been attested
-- by the Product transport. Neither resourceId nor the Lab project ID is
-- a bearer credential. This function is NOT exposed on any Worker route.
-- Every call re-evaluates the live owner/client OAuth consent, Product grant,
-- project/device scope, expiry and resource revocation in PostgreSQL.
create function public.ordax_verify_project_workspace_resource_v1(
  p_owner_user_id uuid, p_actor_id uuid, p_client_id uuid,
  p_workspace_session_id text, p_lab_project_id text,
  p_device_id uuid, p_resource_id text
)
returns jsonb
language plpgsql volatile security definer set search_path = ''
as $function$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_grant jsonb;
begin
  if p_owner_user_id is null or p_actor_id is null
     or p_client_id is null or p_device_id is null
     or p_lab_project_id is null
     or char_length(p_lab_project_id) not between 1 and 180
     or p_lab_project_id !~ '^[A-Za-z0-9_-]+$'
     or p_workspace_session_id is null
     or char_length(p_workspace_session_id) not between 1 and 180
     or p_workspace_session_id !~ '^[A-Za-z0-9_-]+$'
     or p_resource_id is null
     or p_resource_id !~ '^resource_[A-Za-z0-9_-]{8,160}$'
     or not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)
  then
    return pg_catalog.jsonb_build_object('ok',false,'error','workspace_authorization_required');
  end if;

  select pg_catalog.jsonb_build_object(
    'grant_id',g.grant_id,
    'owner_user_id',g.owner_user_id,
    'space_id',a.space_id,
    'project_id',a.project_id,
    'lab_project_id',a.lab_project_id,
    'actor_id',r.actor_id,
    'client_id',a.client_id,
    'workspace_session_id',r.workspace_session_id,
    'device_id',r.device_id,
    'resource_id',r.resource_id,
    'allowed_actions',pg_catalog.jsonb_build_array('read'),
    'issued_by',r.issued_by,
    'issued_at',r.issued_at,
    'valid_until',r.expires_at,
    'revoked_at',r.revoked_at,
    'active',true
  ) into v_grant
  from private.ordax_workspace_resource_bindings r
  join private.ordax_lab_project_authorities a
    on a.binding_id=r.lab_binding_id
  join public.ordax_remote_capability_grants g
    on g.grant_id=r.grant_id
   and g.owner_user_id=a.owner_user_id
   and g.space_id=a.space_id
   and g.project_id=a.project_id
   and g.client_kind='product-mcp'
   and g.client_id=a.client_id::text
   and g.device_id=r.device_id
   and g.scope_kind='project'
   and g.profile_key='project-workspace-read'
   and g.capability='workspace.project_snapshot'
   and g.access_mode='read'
   and g.approved_by_user_id=a.owner_user_id
   and g.state='active'
   and g.valid_until is not null
   and g.valid_until>=r.expires_at
   and g.valid_until>v_now
  join public.ordax_product_devices d
    on d.device_id=r.device_id
   and d.owner_user_id=a.owner_user_id
   and d.state='active'
  join public.ordax_spaces s
    on s.space_id=a.space_id and s.state='active'
  join public.ordax_projects p
    on p.project_id=a.project_id and p.space_id=a.space_id and p.state='active'
  join public.ordax_space_devices sd
    on sd.space_id=a.space_id and sd.device_id=r.device_id
   and sd.state='active' and sd.access_mode='execute'
  join public.ordax_device_project_bindings dp
    on dp.project_id=a.project_id and dp.device_id=r.device_id
   and dp.state='active'
   and 'workspace.project_snapshot'=any(dp.allowed_capabilities)
  join auth.oauth_clients oauth_client
    on oauth_client.id=a.client_id and oauth_client.deleted_at is null
  where r.resource_id=p_resource_id
    and r.actor_id=p_actor_id
    and r.workspace_session_id=p_workspace_session_id
    and r.device_id=p_device_id
    and r.revoked_at is null
    and r.issued_by='trusted-runtime-picker'
    and r.issued_at<=v_now
    and r.expires_at>v_now
    and a.owner_user_id=p_owner_user_id
    and a.client_id=p_client_id
    and a.lab_project_id=p_lab_project_id
    and a.revoked_at is null
    and private.ordax_subject_can_admin_space_v1(p_owner_user_id,a.space_id)
    and private.ordax_subject_can_access_project_v1(p_owner_user_id,a.project_id)
    and exists(
      select 1 from auth.oauth_consents consent
      where consent.user_id=a.owner_user_id
        and consent.client_id=a.client_id
        and consent.revoked_at is null
    )
  limit 1;

  if v_grant is null then
    return pg_catalog.jsonb_build_object('ok',false,'error','workspace_authorization_required');
  end if;
  return pg_catalog.jsonb_build_object(
    'ok',true,'schema','ordax.project-workspace-resource/1','grant',v_grant);
end;
$function$;

revoke all on function public.ordax_verify_project_workspace_resource_v1(
  uuid,uuid,uuid,text,text,uuid,text
) from public,anon,authenticated,service_role,ordax_edge_executor,ordax_edge_runtime;
grant execute on function public.ordax_verify_project_workspace_resource_v1(
  uuid,uuid,uuid,text,text,uuid,text
) to ordax_edge_runtime;

-- Revocation of an existing non-bearer resource is separate from issuance.
-- The Worker authenticates the signed Owner session and supplies the Owner
-- UUID. Neither an arbitrary client ID nor a resourceId is an authorization
-- secret; both must match the existing private Owner/client binding.
-- This function intentionally does NOT require a live OAuth consent/grant:
-- the Owner must still be able to revoke a resource after consent is withdrawn.
create function public.ordax_revoke_project_workspace_resource_v1(
  p_owner_user_id uuid, p_client_id uuid, p_resource_id text
)
returns boolean
language sql volatile security definer set search_path = ''
as $function$
  with revoked as (
    update private.ordax_workspace_resource_bindings as r
    set revoked_at = pg_catalog.clock_timestamp()
    from private.ordax_lab_project_authorities as a
    where r.lab_binding_id = a.binding_id
      and a.owner_user_id = p_owner_user_id
      and a.client_id = p_client_id
      and r.resource_id = p_resource_id
      and r.revoked_at is null
    returning r.resource_id
  )
  select pg_catalog.exists(select 1 from revoked);
$function$;

revoke all on function public.ordax_revoke_project_workspace_resource_v1(
  uuid,uuid,text
) from public,anon,authenticated,service_role,ordax_edge_executor,ordax_edge_runtime;
grant execute on function public.ordax_revoke_project_workspace_resource_v1(
  uuid,uuid,text
) to ordax_edge_runtime;

-- No issuance, insertion, grant mutation, local path resolution or network
-- route is authorized by this source-only proposal. The owner revoker is
-- inactive until the same governed migration as the read-only verifier.
commit;

  then
    return false;
  end if;

  update private.ordax_workspace_resource_bindings as r
  set revoked_at=pg_catalog.clock_timestamp()
  from private.ordax_lab_project_authorities as a
  where r.lab_binding_id=a.binding_id
    and a.owner_user_id=p_owner_user_id
    and a.client_id=p_client_id
    and r.resource_id=p_resource_id
    and r.revoked_at is null
  returning r.resource_id into v_revoked;

  return v_revoked is not null;
end;
$function$;

revoke all on function public.ordax_revoke_project_workspace_resource_v1(
  uuid,uuid,text
) from public,anon,authenticated,service_role,ordax_edge_executor,ordax_edge_runtime;
grant execute on function public.ordax_revoke_project_workspace_resource_v1(
  uuid,uuid,text
) to ordax_edge_runtime;

-- No issuance, insertion, grant mutation, local path resolution or network
-- route is authorized by this source-only proposal. The owner revoker is
-- inactive until the same governed migration as the read-only verifier.
commit;
