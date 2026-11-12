begin;

-- Single authoritative backend projection of the OrdaX OS
-- general.personal -> pessoal-basico@1 zero-component MVP Profile Pack.
-- The canonical type and manifest live in ordax-os, not here.
-- Preserve private ownership, RLS/session enforcement and existing grants.
insert into private.ordax_space_creation_type_projection (
  domain, subtype, space_kind, profile_slug, profile_version
) values (
  'general', 'personal', 'personal', 'pessoal-basico', 1
) on conflict (domain, subtype) do nothing;

-- Fail closed on an existing contradictory type/profile mapping.
do $$
begin
  if not exists (
    select 1
    from private.ordax_space_creation_type_projection
    where domain = 'general' and subtype = 'personal'
      and space_kind = 'personal'
      and profile_slug = 'pessoal-basico'
      and profile_version = 1
  ) then
    raise exception 'OrdaX general.personal profile projection is inconsistent';
  end if;

  if has_table_privilege('authenticated', 'private.ordax_space_creation_type_projection', 'SELECT') then
    raise exception 'OrdaX Space creation projection must remain private';
  end if;
end;
$$;

commit;
