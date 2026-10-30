-- Canonical availability projection. A shutdown need not deliver online=false.
-- Presence writes coalesce unchanged heartbeats for five minutes; allow one
-- additional minute for transport jitter. Do not duplicate this TTL in MCP/UI.
-- This changes no grants, ownership, attestation or device-selection policy.
begin;

create or replace function private.ordax_product_presence_online_v1(
  p_online boolean, p_last_seen_at timestamptz, p_now timestamptz
)
returns boolean language sql immutable security invoker set search_path = ''
as $$
 select coalesce(p_online and p_last_seen_at <= p_now
   and p_last_seen_at > p_now - interval '6 minutes', false)
$$;
revoke all on function private.ordax_product_presence_online_v1(boolean,timestamptz,timestamptz)
  from public,anon,authenticated,service_role;

CREATE OR REPLACE FUNCTION public.ordax_list_product_targets_v1(p_owner_user_id uuid, p_client_kind text, p_client_id text)
 RETURNS jsonb
 LANGUAGE sql
 VOLATILE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select case
    -- Auth is owned by Supabase; the Worker must separately authenticate
    -- and bind this service-supplied owner ID to the verified caller.
    when not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)
      then pg_catalog.jsonb_build_object(
        'ok',false,'error','product_owner_auth_ineligible')
    else (
      with active as (
          select
            g.grant_group_id,
            g.profile_key,
            g.device_id,
            g.space_id,
            g.project_id,
            g.capability,
            g.access_mode,
            g.valid_until
          from public.ordax_remote_capability_grants g
          join public.ordax_product_devices d
            on d.device_id = g.device_id
           and d.state = 'active'
          where g.owner_user_id = p_owner_user_id
            and g.client_kind = p_client_kind
            and g.client_id is not distinct from p_client_id
            and g.state = 'active'
            and (g.valid_until is null or g.valid_until > pg_catalog.statement_timestamp())
        ),
        grant_groups as (
          select
            a.device_id,
            a.grant_group_id,
            a.profile_key,
            a.space_id,
            a.project_id,
            max(a.valid_until) as valid_until,
            jsonb_agg(
              jsonb_build_object(
                'capability', a.capability,
                'access_mode', a.access_mode
              )
              order by a.capability
            ) as capabilities
          from active a
          group by
            a.device_id,
            a.grant_group_id,
            a.profile_key,
            a.space_id,
            a.project_id
        ),
        targets as (
          select
            d.device_id,
            d.display_name,
            d.device_kind,
            d.channel,
            private.ordax_product_presence_online_v1(p.online, p.last_seen_at, pg_catalog.statement_timestamp()) as online,
            p.last_seen_at,
            jsonb_agg(
              jsonb_build_object(
                'grant_group_id', gg.grant_group_id,
                'profile_key', gg.profile_key,
                'space_id', gg.space_id,
                'project_id', gg.project_id,
                'valid_until', gg.valid_until,
                'capabilities', gg.capabilities
              )
              order by gg.profile_key, gg.grant_group_id
            ) as grant_groups
          from grant_groups gg
          join public.ordax_product_devices d on d.device_id = gg.device_id
          left join public.ordax_device_presence p on p.device_id = d.device_id
          group by
            d.device_id,
            d.display_name,
            d.device_kind,
            d.channel,
            p.online,
            p.last_seen_at
        )
        select jsonb_build_object(
          'ok', true,
          'targets', coalesce(
            jsonb_agg(
              jsonb_build_object(
                'device_id', t.device_id,
                'device_name', t.display_name,
                'device_kind', t.device_kind,
                'channel', t.channel,
                'online', t.online,
                'last_seen_at', t.last_seen_at,
                'grant_groups', t.grant_groups
              )
              order by t.display_name, t.device_id
            ),
            '[]'::jsonb
          )
        )
        from targets t
    )
  end;
$function$
;

create or replace function public.ordax_open_central_device_session_v1(
  p_owner_user_id uuid,p_client_id text,p_session_sha256 text
)
returns jsonb language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_now timestamptz:=pg_catalog.clock_timestamp();
  v_devices uuid[];
  v_device_id uuid;
  v_existing private.ordax_central_conversation_bindings%rowtype;
  v_challenge private.ordax_central_device_session_challenges%rowtype;
  v_challenge_id uuid;
  v_expires timestamptz;
  v_binding_expires timestamptz;
begin
 if p_owner_user_id is null
    or p_client_id is null or char_length(p_client_id) not between 8 and 160
    or p_client_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]+$'
    or p_session_sha256 is null or p_session_sha256 !~ '^[0-9a-f]{64}$'
    or not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)
 then return jsonb_build_object('ok',false,'error','central_session_invalid'); end if;

 perform pg_catalog.pg_advisory_xact_lock(
   pg_catalog.hashtext(p_owner_user_id::text||':'||p_client_id||':'||p_session_sha256)
 );

 -- Single authority for active, non-discovery grants. Opening a session
 -- and later resolving/reconfirming it MUST enforce the same predicate.
 -- Never duplicate grant filters here: a future grant type must not drift.
 select pg_catalog.array_agg(d.device_id order by d.device_id)
   into v_devices
   from public.ordax_product_devices d
  where d.owner_user_id=p_owner_user_id
    and d.state='active'
    and private.ordax_central_device_grant_eligible_v1(
      p_owner_user_id,p_client_id,d.device_id
    );

 if v_devices is null or pg_catalog.cardinality(v_devices)=0 then
   return jsonb_build_object('ok',false,'error','central_device_target_missing');
 end if;
 if pg_catalog.cardinality(v_devices)<>1 then
   return jsonb_build_object('ok',false,'error','central_device_target_ambiguous');
 end if;
 v_device_id:=v_devices[1];

 -- Presence is availability only, never authority or a target selector.
 -- Keep ambiguity/revocation decisions independent of which PC is online.

 select b.* into v_existing
   from private.ordax_central_conversation_bindings b
  where b.owner_user_id=p_owner_user_id
    and b.client_id=p_client_id
    and b.session_sha256=p_session_sha256
  limit 1;
 if found then
   if v_existing.device_id<>v_device_id
      or v_existing.space_id is not null or v_existing.project_id is not null then
     return jsonb_build_object('ok',false,'error','central_session_target_mismatch');
   end if;
   if v_existing.state='revoked' then
     return jsonb_build_object('ok',false,'error','central_session_revoked');
   end if;
 end if;

 if not exists (
   select 1 from public.ordax_device_presence p
   where p.device_id=v_device_id
     and private.ordax_product_presence_online_v1(p.online,p.last_seen_at,v_now)
 ) then
   return jsonb_build_object('ok',false,'error','central_device_offline');
 end if;

 if v_existing.device_id is not null then
   if v_existing.expires_at>v_now then
     return jsonb_build_object(
       'ok',true,'status','bound','device_id',v_device_id,
       'request_id',v_existing.request_id,'expires_at',v_existing.expires_at
     );
   end if;
 end if;

 update private.ordax_central_device_session_challenges
    set state='expired'
  where owner_user_id=p_owner_user_id and client_id=p_client_id
    and session_sha256=p_session_sha256 and state='pending' and expires_at<=v_now;

 select c.* into v_challenge
   from private.ordax_central_device_session_challenges c
  where c.owner_user_id=p_owner_user_id and c.client_id=p_client_id
    and c.session_sha256=p_session_sha256 and c.state='pending'
    and c.expires_at>v_now
  limit 1;
 if found then
   if v_challenge.device_id<>v_device_id then
     return jsonb_build_object('ok',false,'error','central_session_target_mismatch');
   end if;
   return jsonb_build_object(
     'ok',true,'status','pending','device_id',v_device_id,
     'challenge_id',v_challenge.challenge_id,'expires_at',v_challenge.expires_at
   );
 end if;

 v_challenge_id:=extensions.gen_random_uuid();
 v_expires:=v_now+interval '2 minutes';
 v_binding_expires:=v_now+interval '30 minutes';
 insert into private.ordax_central_device_session_challenges(
   challenge_id,owner_user_id,client_id,device_id,session_sha256,
   state,expires_at,binding_expires_at
 ) values (
   v_challenge_id,p_owner_user_id,p_client_id,v_device_id,p_session_sha256,
   'pending',v_expires,v_binding_expires
 );
 return jsonb_build_object(
   'ok',true,'status','pending','device_id',v_device_id,
   'challenge_id',v_challenge_id,'expires_at',v_expires
 );
end;
$$;

-- Preserve the existing server-only boundary after replacing the functions.
revoke all on function public.ordax_list_product_targets_v1(uuid,text,text)
  from public,anon,authenticated,service_role;
revoke all on function public.ordax_open_central_device_session_v1(uuid,text,text)
  from public,anon,authenticated,service_role;
grant execute on function public.ordax_list_product_targets_v1(uuid,text,text),
  public.ordax_open_central_device_session_v1(uuid,text,text) to ordax_edge_executor;

commit;
