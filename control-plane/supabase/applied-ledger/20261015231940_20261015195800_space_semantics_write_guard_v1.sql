-- Canonical Space semantics write guard.
-- Existing legacy rows may remain domain/subtype NULL and may be promoted later,
-- but every newly inserted Space must be born with explicit semantics. Once a
-- Space has explicit semantics, server-side writes cannot demote it back to the
-- legacy NULL/NULL state.
begin;

create or replace function private.ordax_enforce_space_semantics_write_v1()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if tg_op = 'INSERT' then
    if new.domain is null or new.subtype is null then
      raise exception using
        errcode = '23514',
        message = 'ordax_spaces requires canonical domain/subtype on insert';
    end if;
    return new;
  end if;

  if tg_op = 'UPDATE'
     and old.domain is not null
     and old.subtype is not null
     and (new.domain is null or new.subtype is null) then
    raise exception using
      errcode = '23514',
      message = 'ordax_spaces canonical semantics cannot regress to legacy nulls';
  end if;

  return new;
end;
$$;

revoke all on function private.ordax_enforce_space_semantics_write_v1()
  from public, anon, authenticated, service_role;

drop trigger if exists ordax_spaces_semantics_write_guard on public.ordax_spaces;
create trigger ordax_spaces_semantics_write_guard
before insert or update of domain, subtype on public.ordax_spaces
for each row execute function private.ordax_enforce_space_semantics_write_v1();

commit;