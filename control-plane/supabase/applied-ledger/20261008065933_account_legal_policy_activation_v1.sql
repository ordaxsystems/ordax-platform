begin;

create or replace function public.ordax_activate_account_legal_policy_v1(
  p_privacy_version text,
  p_privacy_effective_date date,
  p_privacy_sha256 text,
  p_privacy_url text,
  p_terms_version text,
  p_terms_effective_date date,
  p_terms_sha256 text,
  p_terms_url text
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $activate$
declare
  v_current private.ordax_account_legal_policies%rowtype;
  v_policy_id uuid;
begin
  if p_privacy_version is null
     or p_privacy_effective_date is null
     or p_privacy_sha256 is null
     or p_privacy_url is null
     or p_terms_version is null
     or p_terms_effective_date is null
     or p_terms_sha256 is null
     or p_terms_url is null then
    raise exception 'ordax-account-legal-policy-fields-required'
      using errcode = '22023';
  end if;

  if p_privacy_version <> btrim(p_privacy_version)
     or p_terms_version <> btrim(p_terms_version)
     or p_privacy_url <> btrim(p_privacy_url)
     or p_terms_url <> btrim(p_terms_url) then
    raise exception 'ordax-account-legal-policy-whitespace-invalid'
      using errcode = '22023';
  end if;

  lock table private.ordax_account_legal_policies
    in share row exclusive mode;

  if exists (
    select 1
    from private.ordax_account_legal_policies p
    where p.privacy_version = p_privacy_version
      and (
        p.privacy_effective_date is distinct from p_privacy_effective_date
        or p.privacy_sha256 is distinct from p_privacy_sha256
        or p.privacy_url is distinct from p_privacy_url
      )
  ) then
    raise exception 'ordax-account-privacy-version-content-mismatch'
      using errcode = '23514';
  end if;

  if exists (
    select 1
    from private.ordax_account_legal_policies p
    where p.terms_version = p_terms_version
      and (
        p.terms_effective_date is distinct from p_terms_effective_date
        or p.terms_sha256 is distinct from p_terms_sha256
        or p.terms_url is distinct from p_terms_url
      )
  ) then
    raise exception 'ordax-account-terms-version-content-mismatch'
      using errcode = '23514';
  end if;

  select p.* into v_current
  from private.ordax_account_legal_policies p
  where p.state = 'active'
  order by p.activated_at desc, p.policy_id
  limit 1
  for update;

  if found
     and v_current.privacy_version = p_privacy_version
     and v_current.privacy_effective_date = p_privacy_effective_date
     and v_current.privacy_sha256 = p_privacy_sha256
     and v_current.privacy_url = p_privacy_url
     and v_current.terms_version = p_terms_version
     and v_current.terms_effective_date = p_terms_effective_date
     and v_current.terms_sha256 = p_terms_sha256
     and v_current.terms_url = p_terms_url then
    return v_current.policy_id;
  end if;

  if found then
    update private.ordax_account_legal_policies p
    set
      state = 'retired',
      retired_at = statement_timestamp()
    where p.policy_id = v_current.policy_id;
  end if;

  insert into private.ordax_account_legal_policies(
    privacy_version,
    privacy_effective_date,
    privacy_sha256,
    privacy_url,
    terms_version,
    terms_effective_date,
    terms_sha256,
    terms_url,
    state,
    activated_at
  ) values (
    p_privacy_version,
    p_privacy_effective_date,
    p_privacy_sha256,
    p_privacy_url,
    p_terms_version,
    p_terms_effective_date,
    p_terms_sha256,
    p_terms_url,
    'active',
    statement_timestamp()
  )
  returning policy_id into v_policy_id;

  return v_policy_id;
end;
$activate$;

revoke all on function public.ordax_activate_account_legal_policy_v1(
  text, date, text, text, text, date, text, text
) from public, anon, authenticated, service_role;

grant execute on function public.ordax_activate_account_legal_policy_v1(
  text, date, text, text, text, date, text, text
) to service_role;

commit;
