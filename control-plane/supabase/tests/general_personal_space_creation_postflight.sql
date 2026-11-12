-- Verify the existing Account RPC and private projection after migration.
-- No user account or Space is created by this proof.
do $$
declare
  mapped integer;
begin
  select count(*) into mapped
    from private.ordax_space_creation_type_projection
   where domain = 'general' and subtype = 'personal'
     and space_kind = 'personal'
     and profile_slug = 'pessoal-basico' and profile_version = 1;
  if mapped <> 1 then
    raise exception 'Expected exact general.personal / pessoal-basico@1 mapping';
  end if;

  if has_table_privilege('authenticated',
      'private.ordax_space_creation_type_projection', 'SELECT') then
    raise exception 'Creation type projection became readable by authenticated users';
  end if;

  if to_regprocedure('public.ordax_create_space_v1(text,text,text,uuid)') is null then
    raise exception 'Canonical authenticated Space creation RPC is absent';
  end if;
end;
$$;
