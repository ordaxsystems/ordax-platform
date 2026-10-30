begin;

alter table private.ordax_account_legal_policies
  add column privacy_url text,
  add column terms_url text;

alter table private.ordax_account_legal_policies
  add constraint ordax_account_legal_policies_privacy_url_https_chk
    check (
      privacy_url is null
      or privacy_url ~ '^https://[^[:space:]?#]+(?:/[^[:space:]?#]*)?$'
    ),
  add constraint ordax_account_legal_policies_terms_url_https_chk
    check (
      terms_url is null
      or terms_url ~ '^https://[^[:space:]?#]+(?:/[^[:space:]?#]*)?$'
    ),
  add constraint ordax_account_legal_policies_active_urls_chk
    check (
      state <> 'active'
      or (
        privacy_url is not null
        and terms_url is not null
      )
    );

create or replace function private.ordax_guard_account_legal_policy_update_v1()
returns trigger
language plpgsql
security definer
set search_path = ''
as $guard$
begin
  if old.state in ('active', 'retired') and (
    new.privacy_version is distinct from old.privacy_version
    or new.privacy_effective_date is distinct from old.privacy_effective_date
    or new.privacy_sha256 is distinct from old.privacy_sha256
    or new.privacy_url is distinct from old.privacy_url
    or new.terms_version is distinct from old.terms_version
    or new.terms_effective_date is distinct from old.terms_effective_date
    or new.terms_sha256 is distinct from old.terms_sha256
    or new.terms_url is distinct from old.terms_url
    or new.created_at is distinct from old.created_at
    or new.activated_at is distinct from old.activated_at
  ) then
    raise exception 'ordax-account-legal-policy-immutable-after-activation'
      using errcode = '23514';
  end if;

  if old.state = 'retired' and new.state is distinct from old.state then
    raise exception 'ordax-account-legal-policy-retired-is-terminal'
      using errcode = '23514';
  end if;

  if old.state = 'active' and new.state not in ('active', 'retired') then
    raise exception 'ordax-account-legal-policy-active-may-only-retire'
      using errcode = '23514';
  end if;

  if old.state = 'draft' and new.state = 'active' and new.activated_at is null then
    raise exception 'ordax-account-legal-policy-activation-timestamp-required'
      using errcode = '23514';
  end if;

  return new;
end;
$guard$;

revoke all on function private.ordax_guard_account_legal_policy_update_v1()
  from public, anon, authenticated;

create trigger ordax_account_legal_policy_update_guard_v1
before update on private.ordax_account_legal_policies
for each row execute function private.ordax_guard_account_legal_policy_update_v1();

create or replace function public.ordax_get_account_registration_legal_policy_v1()
returns table (
  policy_id uuid,
  privacy_version text,
  privacy_effective_date date,
  privacy_sha256 text,
  privacy_url text,
  terms_version text,
  terms_effective_date date,
  terms_sha256 text,
  terms_url text,
  activated_at timestamptz
)
language sql
stable
security definer
set search_path = ''
as $policy$
  select
    p.policy_id,
    p.privacy_version,
    p.privacy_effective_date,
    p.privacy_sha256,
    p.privacy_url,
    p.terms_version,
    p.terms_effective_date,
    p.terms_sha256,
    p.terms_url,
    p.activated_at
  from private.ordax_account_legal_policies p
  where p.state = 'active'
    and p.activated_at <= statement_timestamp()
    and p.privacy_effective_date <= current_date
    and p.terms_effective_date <= current_date
    and p.privacy_url is not null
    and p.terms_url is not null
  order by p.activated_at desc, p.policy_id
  limit 1;
$policy$;

revoke all on function public.ordax_get_account_registration_legal_policy_v1()
  from public, anon, authenticated;
grant execute on function public.ordax_get_account_registration_legal_policy_v1()
  to service_role;

commit;
