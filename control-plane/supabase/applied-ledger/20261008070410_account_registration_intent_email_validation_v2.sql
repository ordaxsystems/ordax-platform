-- Replace only the canonical account legal-intent RPC. PostgreSQL text cannot
-- contain NUL: chr(0) itself raises SQLSTATE 54000, rejecting every email.
-- No change to signup authority, legal policy, intent lifetime or grants.
begin;

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
     or char_length(v_email) > 320 then
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

commit;
