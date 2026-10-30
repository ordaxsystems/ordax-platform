begin;

create or replace function public.ordax_account_has_registration_legal_receipt_v1(
  p_user_id uuid
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $guard$
  select exists (
    select 1
    from private.ordax_account_legal_receipts r
    where r.user_id = p_user_id
      and r.purpose = 'account-registration'
  );
$guard$;

revoke all on function public.ordax_account_has_registration_legal_receipt_v1(uuid)
  from public, anon, authenticated, service_role;
grant execute on function public.ordax_account_has_registration_legal_receipt_v1(uuid)
  to service_role;

commit;
