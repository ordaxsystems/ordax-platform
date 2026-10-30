begin;

create index if not exists ordax_account_registration_intents_policy_idx
  on private.ordax_account_registration_intents (policy_id);

create index if not exists ordax_account_legal_receipts_policy_idx
  on private.ordax_account_legal_receipts (policy_id);

commit;
