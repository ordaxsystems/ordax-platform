begin;

-- Remove pre-canonical Space authority that accepted an explicit actor UUID.
-- The current authority is public.ordax_create_space_v1(text,text,text,uuid),
-- derives auth.uid() internally and is protected by the active-Space quota guard.
--
-- Intentionally no CASCADE: if any object still depends on either legacy object,
-- this migration must fail closed and force an explicit dependency review.

drop function if exists public.ordax_create_space_v1(uuid, text, text, jsonb);
drop function if exists private.ordax_trusted_actor_auth_eligible_v1(uuid);

commit;
