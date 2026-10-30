begin;

create table private.ordax_account_legal_quarantine (
  user_id uuid primary key
    references auth.users(id)
    on delete cascade,
  reason text not null
    check (reason = 'legacy-no-registration-receipt'),
  quarantined_at timestamptz not null default timezone('utc', now()),
  released_at timestamptz,
  release_receipt_id uuid,
  check (
    (released_at is null and release_receipt_id is null)
    or (released_at is not null and release_receipt_id is not null)
  ),
  check (released_at is null or released_at >= quarantined_at)
);

alter table private.ordax_account_legal_quarantine enable row level security;

revoke all on table private.ordax_account_legal_quarantine
  from public, anon, authenticated, service_role;

create or replace function private.release_ordax_account_legal_quarantine_v1()
returns trigger
language plpgsql
security definer
set search_path = ''
as $release$
begin
  if new.purpose = 'account-registration' then
    update private.ordax_account_legal_quarantine q
    set
      released_at = statement_timestamp(),
      release_receipt_id = new.receipt_id
    where q.user_id = new.user_id
      and q.released_at is null;
  end if;
  return new;
end;
$release$;

revoke all on function private.release_ordax_account_legal_quarantine_v1()
  from public, anon, authenticated, service_role;

drop trigger if exists ordax_release_account_legal_quarantine_v1
  on private.ordax_account_legal_receipts;

create trigger ordax_release_account_legal_quarantine_v1
after insert on private.ordax_account_legal_receipts
for each row
execute function private.release_ordax_account_legal_quarantine_v1();

lock table private.ordax_account_legal_receipts in share row exclusive mode;
lock table public.ordax_accounts in share mode;

insert into private.ordax_account_legal_quarantine(
  user_id,
  reason
)
select
  a.user_id,
  'legacy-no-registration-receipt'
from public.ordax_accounts a
where not exists (
  select 1
  from private.ordax_account_legal_receipts r
  where r.user_id = a.user_id
    and r.purpose = 'account-registration'
)
on conflict (user_id) do nothing;

create or replace function public.ordax_account_legal_reconciliation_status_v1()
returns table (
  receiptless_accounts bigint,
  active_quarantined_accounts bigint,
  unreconciled_receiptless_accounts bigint
)
language sql
stable
security definer
set search_path = ''
as $status$
  with receiptless as (
    select a.user_id
    from public.ordax_accounts a
    where not exists (
      select 1
      from private.ordax_account_legal_receipts r
      where r.user_id = a.user_id
        and r.purpose = 'account-registration'
    )
  )
  select
    (select count(*)::bigint from receiptless),
    (
      select count(*)::bigint
      from receiptless r
      join private.ordax_account_legal_quarantine q
        on q.user_id = r.user_id
       and q.released_at is null
    ),
    (
      select count(*)::bigint
      from receiptless r
      where not exists (
        select 1
        from private.ordax_account_legal_quarantine q
        where q.user_id = r.user_id
          and q.released_at is null
      )
    );
$status$;

revoke all on function public.ordax_account_legal_reconciliation_status_v1()
  from public, anon, authenticated, service_role;

grant execute on function public.ordax_account_legal_reconciliation_status_v1()
  to service_role;

commit;
