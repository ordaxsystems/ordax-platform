begin;

create table private.ordax_account_legal_policies (
  policy_id uuid primary key default gen_random_uuid(),
  privacy_version text not null
    check (privacy_version ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
  privacy_effective_date date not null,
  privacy_sha256 text not null
    check (privacy_sha256 ~ '^[0-9a-f]{64}$'),
  terms_version text not null
    check (terms_version ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
  terms_effective_date date not null,
  terms_sha256 text not null
    check (terms_sha256 ~ '^[0-9a-f]{64}$'),
  state text not null default 'draft'
    check (state in ('draft','active','retired')),
  created_at timestamptz not null default timezone('utc', now()),
  activated_at timestamptz,
  retired_at timestamptz,
  check (state <> 'active' or activated_at is not null),
  check (state <> 'retired' or retired_at is not null)
);

create unique index ordax_account_legal_policies_one_active_idx
  on private.ordax_account_legal_policies ((state))
  where state = 'active';

create table private.ordax_account_registration_intents (
  intent_id uuid primary key default gen_random_uuid(),
  policy_id uuid not null
    references private.ordax_account_legal_policies(policy_id)
    on delete restrict,
  email_sha256 text not null
    check (email_sha256 ~ '^[0-9a-f]{64}$'),
  acceptance_assertion text not null
    check (acceptance_assertion = 'affirmative'),
  created_at timestamptz not null default timezone('utc', now()),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  check (expires_at > created_at),
  check (expires_at <= created_at + interval '15 minutes'),
  check (consumed_at is null or consumed_at >= created_at)
);

create index ordax_account_registration_intents_expiry_idx
  on private.ordax_account_registration_intents(expires_at)
  where consumed_at is null;

create table private.ordax_account_legal_receipts (
  receipt_id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  policy_id uuid not null
    references private.ordax_account_legal_policies(policy_id)
    on delete restrict,
  registration_intent_id uuid not null unique,
  purpose text not null default 'account-registration'
    check (purpose = 'account-registration'),
  privacy_version text not null,
  privacy_effective_date date not null,
  privacy_sha256 text not null
    check (privacy_sha256 ~ '^[0-9a-f]{64}$'),
  terms_version text not null,
  terms_effective_date date not null,
  terms_sha256 text not null
    check (terms_sha256 ~ '^[0-9a-f]{64}$'),
  accepted_at timestamptz not null,
  created_at timestamptz not null default timezone('utc', now()),
  unique (user_id, purpose)
);

alter table private.ordax_account_legal_policies enable row level security;
alter table private.ordax_account_registration_intents enable row level security;
alter table private.ordax_account_legal_receipts enable row level security;

revoke all on table private.ordax_account_legal_policies
  from public, anon, authenticated;
revoke all on table private.ordax_account_registration_intents
  from public, anon, authenticated;
revoke all on table private.ordax_account_legal_receipts
  from public, anon, authenticated;

create or replace function public.ordax_begin_account_registration_legal_intent_v1(
  p_normalized_email text,
  p_accepted boolean
)
returns table (
  intent_id uuid,
  expires_at timestamptz
)
language plpgsql
security definer
set search_path = ''
as $legal$
declare
  v_email text := lower(btrim(coalesce(p_normalized_email, '')));
  v_email_sha256 text;
  v_policy private.ordax_account_legal_policies%rowtype;
  v_intent_id uuid;
  v_expires_at timestamptz := statement_timestamp() + interval '10 minutes';
begin
  if p_accepted is distinct from true then
    raise exception 'registration-legal-acceptance-required' using errcode = '22023';
  end if;
  if char_length(v_email) < 3
     or char_length(v_email) > 320
     or position(chr(0) in v_email) > 0 then
    raise exception 'registration-email-invalid' using errcode = '22023';
  end if;

  v_email_sha256 := encode(
    extensions.digest(convert_to(v_email, 'UTF8'), 'sha256'),
    'hex'
  );

  select p.* into v_policy
  from private.ordax_account_legal_policies p
  where p.state = 'active'
    and p.activated_at <= statement_timestamp()
    and p.privacy_effective_date <= current_date
    and p.terms_effective_date <= current_date
  order by p.activated_at desc, p.policy_id
  limit 1
  for share;

  if not found then
    raise exception 'registration-legal-policy-unavailable' using errcode = '55000';
  end if;

  delete from private.ordax_account_registration_intents i
  where (i.expires_at < statement_timestamp() - interval '1 day')
     or (i.consumed_at is not null and i.consumed_at < statement_timestamp() - interval '1 day');

  insert into private.ordax_account_registration_intents(
    policy_id,
    email_sha256,
    acceptance_assertion,
    expires_at
  ) values (
    v_policy.policy_id,
    v_email_sha256,
    'affirmative',
    v_expires_at
  )
  returning ordax_account_registration_intents.intent_id into v_intent_id;

  return query select v_intent_id, v_expires_at;
end;
$legal$;

revoke all on function public.ordax_begin_account_registration_legal_intent_v1(text, boolean)
  from public, anon, authenticated;
grant execute on function public.ordax_begin_account_registration_legal_intent_v1(text, boolean)
  to service_role;

create or replace function private.handle_ordax_account_created()
returns trigger
language plpgsql
security definer
set search_path = ''
as $account$
declare
  v_intent_id uuid;
  v_intent private.ordax_account_registration_intents%rowtype;
  v_policy private.ordax_account_legal_policies%rowtype;
  v_email text := lower(btrim(coalesce(new.email, '')));
  v_email_sha256 text;
begin
  if v_email = '' then
    raise exception 'ordax-registration-email-required' using errcode = '23514';
  end if;

  begin
    v_intent_id := nullif(
      coalesce(new.raw_user_meta_data, '{}'::jsonb)->>'ordax_registration_intent_id',
      ''
    )::uuid;
  exception
    when invalid_text_representation then
      raise exception 'ordax-registration-legal-intent-invalid' using errcode = '23514';
  end;

  if v_intent_id is null then
    raise exception 'ordax-registration-legal-intent-required' using errcode = '23514';
  end if;

  v_email_sha256 := encode(
    extensions.digest(convert_to(v_email, 'UTF8'), 'sha256'),
    'hex'
  );

  select i.* into v_intent
  from private.ordax_account_registration_intents i
  where i.intent_id = v_intent_id
    and i.consumed_at is null
    and i.expires_at > statement_timestamp()
  for update;

  if not found
     or v_intent.acceptance_assertion <> 'affirmative'
     or v_intent.email_sha256 <> v_email_sha256 then
    raise exception 'ordax-registration-legal-intent-invalid' using errcode = '23514';
  end if;

  select p.* into v_policy
  from private.ordax_account_legal_policies p
  where p.policy_id = v_intent.policy_id
    and p.state = 'active'
    and p.activated_at <= statement_timestamp()
    and p.privacy_effective_date <= current_date
    and p.terms_effective_date <= current_date
  for share;

  if not found then
    raise exception 'ordax-registration-legal-policy-stale' using errcode = '23514';
  end if;

  insert into public.ordax_accounts(user_id)
  values (new.id)
  on conflict (user_id) do nothing;

  insert into private.ordax_account_legal_receipts(
    user_id,
    policy_id,
    registration_intent_id,
    privacy_version,
    privacy_effective_date,
    privacy_sha256,
    terms_version,
    terms_effective_date,
    terms_sha256,
    accepted_at
  ) values (
    new.id,
    v_policy.policy_id,
    v_intent.intent_id,
    v_policy.privacy_version,
    v_policy.privacy_effective_date,
    v_policy.privacy_sha256,
    v_policy.terms_version,
    v_policy.terms_effective_date,
    v_policy.terms_sha256,
    v_intent.created_at
  );

  update private.ordax_account_registration_intents i
  set consumed_at = statement_timestamp()
  where i.intent_id = v_intent.intent_id
    and i.consumed_at is null;

  if not found then
    raise exception 'ordax-registration-legal-intent-consume-failed' using errcode = '40001';
  end if;

  return new;
end;
$account$;

revoke all on function private.handle_ordax_account_created()
  from public, anon, authenticated;

commit;
