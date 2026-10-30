-- OrdaX public account launch: durable server-authoritative auth rate limits.
--
-- The public host/WAF may provide an additional first layer, but this database
-- boundary is the launch authority. It stores only a SHA-256 digest of the
-- canonical client address, never the raw address, and grants no direct table
-- access. Public account activation remains disabled by the gateway switches.

begin;

create table private.ordax_public_auth_rate_limits (
  bucket text not null
    check (bucket in ('credentials', 'recovery-request', 'recovery-completion')),
  client_sha256 text not null
    check (client_sha256 ~ '^[0-9a-f]{64}$'),
  window_started_at timestamptz not null,
  attempt_count integer not null
    check (attempt_count >= 1),
  updated_at timestamptz not null,
  constraint ordax_public_auth_rate_limits_pkey primary key (bucket, client_sha256),
  check (updated_at >= window_started_at)
);

alter table private.ordax_public_auth_rate_limits enable row level security;

revoke all on table private.ordax_public_auth_rate_limits
  from public, anon, authenticated, service_role;

create index ordax_public_auth_rate_limits_updated_idx
  on private.ordax_public_auth_rate_limits(updated_at);

create or replace function public.ordax_consume_public_auth_rate_limit_v1(
  p_bucket text,
  p_client_address text
)
returns table (
  schema text,
  bucket text,
  decision text,
  limit_count integer,
  remaining integer,
  retry_after_seconds integer,
  reset_at timestamptz
)
language plpgsql
security definer
set search_path = ''
as $rate$
declare
  v_bucket text := lower(btrim(coalesce(p_bucket, '')));
  v_raw_address text := btrim(coalesce(p_client_address, ''));
  v_address inet;
  v_client_sha256 text;
  v_limit integer;
  v_now timestamptz := statement_timestamp();
  v_window_started_at timestamptz;
  v_attempt_count integer;
  v_reset_at timestamptz;
  v_retry_after integer;
begin
  v_limit := case v_bucket
    when 'credentials' then 10
    when 'recovery-request' then 3
    when 'recovery-completion' then 10
    else null
  end;

  if v_limit is null then
    raise exception 'public-auth-rate-limit-bucket-invalid'
      using errcode = '22023';
  end if;

  if v_raw_address = '' or char_length(v_raw_address) > 64 then
    raise exception 'public-auth-rate-limit-address-invalid'
      using errcode = '22023';
  end if;

  begin
    v_address := v_raw_address::inet;
  exception
    when invalid_text_representation then
      raise exception 'public-auth-rate-limit-address-invalid'
        using errcode = '22023';
  end;

  v_client_sha256 := encode(
    extensions.digest(convert_to(host(v_address), 'UTF8'), 'sha256'),
    'hex'
  );

  insert into private.ordax_public_auth_rate_limits as current_window (
    bucket,
    client_sha256,
    window_started_at,
    attempt_count,
    updated_at
  ) values (
    v_bucket,
    v_client_sha256,
    v_now,
    1,
    v_now
  )
  on conflict on constraint ordax_public_auth_rate_limits_pkey do update
  set
    window_started_at = case
      when current_window.window_started_at + interval '1 minute' <= v_now
        then v_now
      else current_window.window_started_at
    end,
    attempt_count = case
      when current_window.window_started_at + interval '1 minute' <= v_now
        then 1
      else current_window.attempt_count + 1
    end,
    updated_at = v_now
  returning
    current_window.window_started_at,
    current_window.attempt_count
  into v_window_started_at, v_attempt_count;

  v_reset_at := v_window_started_at + interval '1 minute';
  v_retry_after := case
    when v_attempt_count <= v_limit then null
    else greatest(
      1,
      least(
        60,
        ceil(extract(epoch from (v_reset_at - v_now)))::integer
      )
    )
  end;

  return query select
    'prototype-ordax.public-auth-rate-limit/1'::text,
    v_bucket,
    case when v_attempt_count <= v_limit then 'allowed' else 'rate_limited' end::text,
    v_limit,
    greatest(v_limit - v_attempt_count, 0),
    v_retry_after,
    v_reset_at;
end;
$rate$;

revoke all on function public.ordax_consume_public_auth_rate_limit_v1(text, text)
  from public, anon, authenticated;
grant execute on function public.ordax_consume_public_auth_rate_limit_v1(text, text)
  to service_role;

comment on table private.ordax_public_auth_rate_limits is
  'Private one-minute public-auth rate windows keyed by operation bucket and SHA-256 of canonical client IP. Raw IP addresses are not persisted.';

comment on function public.ordax_consume_public_auth_rate_limit_v1(text, text) is
  'Service-role-only atomic public auth rate limiter: credentials 10/min, recovery request 3/min, recovery completion 10/min per canonical client IP.';

commit;
