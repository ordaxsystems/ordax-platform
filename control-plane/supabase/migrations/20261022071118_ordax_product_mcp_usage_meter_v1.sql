begin;

-- Shadow usage measurement for the user-facing Product MCP. This ledger is
-- observational only: it creates no subscription rights, quota, or billing.
do $preflight$
begin
  if to_regprocedure('public.ordax_record_product_mcp_usage_v1(uuid,uuid,text,text)') is not null
     or to_regprocedure('public.ordax_prune_product_mcp_usage_v1()') is not null
  then raise exception 'Product MCP usage meter: unexpected existing RPC'; end if;
  if not exists(select 1 from pg_roles where rolname='ordax_edge_executor'
      and not rolcanlogin and not rolbypassrls)
  then raise exception 'Product MCP usage meter: executor role mismatch'; end if;
  if to_regclass('auth.oauth_clients') is null
     or to_regclass('auth.oauth_consents') is null
     or to_regprocedure('private.ordax_trusted_actor_auth_eligible_v1(uuid)') is null
  then raise exception 'Product MCP usage meter: canonical Auth prerequisites missing'; end if;
end;
$preflight$;

create table private.ordax_product_mcp_usage_monthly (
  owner_user_id uuid not null references auth.users(id) on delete cascade,
  usage_month date not null check (usage_month = date_trunc('month', usage_month)::date),
  tool_name text not null check (tool_name ~ '^[a-z][a-z0-9._-]{1,95}$'),
  tool_calls bigint not null default 0 check (tool_calls >= 0),
  updated_at timestamptz not null default pg_catalog.clock_timestamp(),
  primary key (owner_user_id, usage_month, tool_name)
);

create table private.ordax_product_mcp_usage_dedup (
  owner_user_id uuid not null,
  client_id uuid not null references auth.oauth_clients(id) on delete cascade,
  usage_month date not null,
  tool_name text not null check (tool_name ~ '^[a-z][a-z0-9._-]{1,95}$'),
  request_fingerprint text not null check (request_fingerprint ~ '^[a-f0-9]{64}$'),
  recorded_at timestamptz not null default pg_catalog.clock_timestamp(),
  primary key (owner_user_id, client_id, usage_month, request_fingerprint),
  foreign key (owner_user_id, usage_month, tool_name)
    references private.ordax_product_mcp_usage_monthly(owner_user_id, usage_month, tool_name)
    on delete cascade
);

create index ordax_product_mcp_usage_monthly_month_idx
  on private.ordax_product_mcp_usage_monthly(usage_month);
create index ordax_product_mcp_usage_dedup_recorded_at_idx
  on private.ordax_product_mcp_usage_dedup(recorded_at);

alter table private.ordax_product_mcp_usage_monthly enable row level security;
alter table private.ordax_product_mcp_usage_monthly force row level security;
alter table private.ordax_product_mcp_usage_dedup enable row level security;
alter table private.ordax_product_mcp_usage_dedup force row level security;

revoke all on table private.ordax_product_mcp_usage_monthly
  from public, anon, authenticated, service_role, ordax_edge_executor, ordax_edge_runtime;
revoke all on table private.ordax_product_mcp_usage_dedup
  from public, anon, authenticated, service_role, ordax_edge_executor, ordax_edge_runtime;

-- Account and OAuth consent are revalidated in PostgreSQL. The Worker passes
-- only the owner/client identities bound to its verified OAuth session.
create function public.ordax_record_product_mcp_usage_v1(
  p_owner_user_id uuid,
  p_client_id uuid,
  p_tool_name text,
  p_request_fingerprint text
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $function$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_month date;
  v_authorized_client uuid;
  v_inserted integer;
  v_tool_calls bigint;
begin
  v_month := pg_catalog.date_trunc('month', v_now at time zone 'UTC')::date;
  if p_owner_user_id is null or p_client_id is null
     or p_tool_name is null or p_tool_name !~ '^[a-z][a-z0-9._-]{1,95}$'
     or p_request_fingerprint is null or p_request_fingerprint !~ '^[a-f0-9]{64}$'
  then
    return pg_catalog.jsonb_build_object('ok', false, 'error', 'product_mcp_usage_input_invalid');
  end if;

  if not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id) then
    return pg_catalog.jsonb_build_object('ok', false, 'error', 'product_owner_auth_ineligible');
  end if;

  -- Lock the consent and public OAuth client against concurrent revocation
  -- while this sample is written. No user-provided client identity is trusted
  -- without the matching live consent row.
  select c.id into v_authorized_client
    from auth.oauth_clients c
    join auth.oauth_consents consent
      on consent.client_id = c.id
     and consent.user_id = p_owner_user_id
     and consent.revoked_at is null
   where c.id = p_client_id
     and c.deleted_at is null
     and c.client_type::text = 'public'
   for share of c, consent;

  if v_authorized_client is null then
    return pg_catalog.jsonb_build_object('ok', false, 'error', 'product_mcp_oauth_consent_required');
  end if;

  insert into private.ordax_product_mcp_usage_monthly(
    owner_user_id, usage_month, tool_name, tool_calls, updated_at
  ) values (p_owner_user_id, v_month, p_tool_name, 0, v_now)
  on conflict (owner_user_id, usage_month, tool_name) do nothing;

  insert into private.ordax_product_mcp_usage_dedup(
    owner_user_id, client_id, usage_month, tool_name, request_fingerprint, recorded_at
  ) values (p_owner_user_id, p_client_id, v_month, p_tool_name, p_request_fingerprint, v_now)
  on conflict (owner_user_id, client_id, usage_month, request_fingerprint) do nothing;
  get diagnostics v_inserted = row_count;

  if v_inserted = 1 then
    update private.ordax_product_mcp_usage_monthly
       set tool_calls = tool_calls + 1,
           updated_at = v_now
     where owner_user_id = p_owner_user_id
       and usage_month = v_month
       and tool_name = p_tool_name
     returning tool_calls into v_tool_calls;
  else
    select tool_calls into v_tool_calls
      from private.ordax_product_mcp_usage_monthly
     where owner_user_id = p_owner_user_id
       and usage_month = v_month
       and tool_name = p_tool_name;
  end if;

  return pg_catalog.jsonb_build_object(
    'ok', true,
    'recorded', v_inserted = 1,
    'usage_month', v_month,
    'tool_calls', v_tool_calls
  );
end;
$function$;

-- Keep only the current and previous UTC calendar month. Request fingerprints
-- are deleted after 24 hours and the daily schedule bounds normal retention to
-- about 48 hours; the aggregate contains no request arguments or content.
create function public.ordax_prune_product_mcp_usage_v1()
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $function$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_month date;
  v_fingerprints_deleted integer;
  v_months_deleted integer;
begin
  v_month := pg_catalog.date_trunc('month', v_now at time zone 'UTC')::date;
  delete from private.ordax_product_mcp_usage_dedup
   where recorded_at < v_now - interval '24 hours';
  get diagnostics v_fingerprints_deleted = row_count;

  delete from private.ordax_product_mcp_usage_monthly
   where usage_month < (v_month - interval '1 month')::date;
  get diagnostics v_months_deleted = row_count;

  return pg_catalog.jsonb_build_object(
    'ok', true,
    'fingerprints_deleted', v_fingerprints_deleted,
    'monthly_rows_deleted', v_months_deleted
  );
end;
$function$;

revoke all on function public.ordax_record_product_mcp_usage_v1(uuid,uuid,text,text)
  from public, anon, authenticated, service_role, ordax_edge_runtime;
revoke all on function public.ordax_prune_product_mcp_usage_v1()
  from public, anon, authenticated, service_role, ordax_edge_runtime;
grant execute on function public.ordax_record_product_mcp_usage_v1(uuid,uuid,text,text)
  to ordax_edge_executor;
grant execute on function public.ordax_prune_product_mcp_usage_v1()
  to ordax_edge_executor;

do $postflight$
declare
  v_table text;
  v_signature text;
begin
  foreach v_table in array array[
    'private.ordax_product_mcp_usage_monthly',
    'private.ordax_product_mcp_usage_dedup'
  ] loop
    if not (select relrowsecurity and relforcerowsecurity from pg_class where oid=v_table::regclass)
    then raise exception 'Product MCP usage meter: RLS is not forced on %', v_table; end if;
    if has_table_privilege('ordax_edge_executor',v_table,'SELECT')
       or has_table_privilege('ordax_edge_executor',v_table,'INSERT')
       or has_table_privilege('ordax_edge_executor',v_table,'UPDATE')
       or has_table_privilege('ordax_edge_executor',v_table,'DELETE')
       or has_table_privilege('ordax_edge_runtime',v_table,'SELECT')
       or has_table_privilege('ordax_edge_runtime',v_table,'INSERT')
       or has_table_privilege('ordax_edge_runtime',v_table,'UPDATE')
       or has_table_privilege('ordax_edge_runtime',v_table,'DELETE')
       or has_table_privilege('service_role',v_table,'SELECT')
       or has_table_privilege('service_role',v_table,'INSERT')
       or has_table_privilege('service_role',v_table,'UPDATE')
       or has_table_privilege('service_role',v_table,'DELETE')
    then raise exception 'Product MCP usage meter: direct table access remains on %', v_table; end if;
  end loop;

  foreach v_signature in array array[
    'public.ordax_record_product_mcp_usage_v1(uuid,uuid,text,text)',
    'public.ordax_prune_product_mcp_usage_v1()'
  ] loop
    if exists (
         select 1 from pg_catalog.pg_proc p,
           lateral pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
          where p.oid=pg_catalog.to_regprocedure(v_signature)
            and a.grantee=0 and a.privilege_type='EXECUTE'
       )
       or has_function_privilege('anon',v_signature,'EXECUTE')
       or has_function_privilege('authenticated',v_signature,'EXECUTE')
       or has_function_privilege('service_role',v_signature,'EXECUTE')
       or not has_function_privilege('ordax_edge_executor',v_signature,'EXECUTE')
    then raise exception 'Product MCP usage meter: function ACL mismatch on %', v_signature; end if;
  end loop;
end;
$postflight$;

commit;
