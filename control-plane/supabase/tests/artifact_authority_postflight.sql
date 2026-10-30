-- Canonical PostgreSQL artifacts authority postflight (issue #152).
-- Synthetic metadata ONLY: no R2 objects, no Runtime device, no actual credentials.
-- Run on jhfphsjptrpmtnzkpwud after reviewing grants. No direct production deploy.
-- IMPORTANT: assertions abort on failure; the entire test is rolled back.
BEGIN;
SET LOCAL statement_timeout = '20s';
DO $postflight$
DECLARE
  a uuid := pg_catalog.gen_random_uuid();
  j uuid := pg_catalog.gen_random_uuid();
  d uuid := pg_catalog.gen_random_uuid();
  r uuid := pg_catalog.gen_random_uuid();
  fx uuid := pg_catalog.gen_random_uuid();
  at uuid := pg_catalog.gen_random_uuid();
  lease uuid := pg_catalog.gen_random_uuid();
  agent uuid := pg_catalog.gen_random_uuid();
  key text;
  h text := repeat('a',64);
  old_token text := repeat('b',64);
  new_token text := repeat('c',64);
  z jsonb;
  checks integer := 0;
BEGIN
  key := d::text || '/' || j::text || '/' || a::text || '-postflight.txt';
  IF EXISTS (SELECT 1 FROM private.ordax_artifact_records WHERE artifact_id=a)
     OR EXISTS (SELECT 1 FROM private.ordax_artifact_upload_sessions WHERE artifact_id=a)
  THEN RAISE EXCEPTION 'artifact fixture UUID collision'; END IF;

  z := public.ordax_create_artifact_upload_v1(a,'product',j,d,'postflight-no-r2',
    key,'postflight.txt','log','text/plain',h,1,'{"test":"rollback-only"}'::jsonb);
  IF z->>'ok' IS DISTINCT FROM 'true' OR z->>'resumed' IS DISTINCT FROM 'false'
  THEN RAISE EXCEPTION 'multipart create failed: %',z; END IF;
  checks:=checks+1;

  z := public.ordax_create_artifact_upload_v1(a,'product',j,d,'postflight-no-r2',
    key,'postflight.txt','log','text/plain',h,1,'{"test":"rollback-only"}'::jsonb);
  IF z->>'ok' IS DISTINCT FROM 'true' OR z->>'resumed' IS DISTINCT FROM 'true'
  THEN RAISE EXCEPTION 'multipart resume failed: %',z; END IF;
  checks:=checks+1;

  z := public.ordax_create_artifact_upload_v1(a,'product',j,d,'postflight-no-r2',
    key,'conflicting.txt','log','text/plain',h,1,'{"test":"rollback-only"}'::jsonb);
  IF z->>'error' IS DISTINCT FROM 'multipart_upload_conflict'
  THEN RAISE EXCEPTION 'multipart conflict accepted'; END IF;
  checks:=checks+1;

  z := public.ordax_get_artifact_upload_v1(a,j,d);
  IF z->'upload'->>'upload_id' IS DISTINCT FROM 'postflight-no-r2'
  THEN RAISE EXCEPTION 'upload resume/lookup mismatch'; END IF;
  checks:=checks+1;

  z := public.ordax_get_artifact_upload_v1(a,j,pg_catalog.gen_random_uuid());
  IF z->'upload' IS DISTINCT FROM 'null'::jsonb
  THEN RAISE EXCEPTION 'cross-device upload exposed'; END IF;
  checks:=checks+1;

  z := public.ordax_publish_artifact_v1(a,'product',j,d,key,'postflight.txt',
    'log','text/plain',h,1,'{"test":"rollback-only"}'::jsonb,
    old_token,pg_catalog.clock_timestamp()+interval '10 minutes');
  IF z->>'ok' IS DISTINCT FROM 'true' OR z->>'replayed' IS DISTINCT FROM 'false'
  THEN RAISE EXCEPTION 'publish failed: %',z; END IF;
  checks:=checks+1;

  z := public.ordax_publish_artifact_v1(a,'product',j,d,key,'postflight.txt',
    'log','text/plain',h,1,'{"test":"rollback-only"}'::jsonb,
    old_token,pg_catalog.clock_timestamp()+interval '10 minutes');
  IF z->>'ok' IS DISTINCT FROM 'true' OR z->>'replayed' IS DISTINCT FROM 'true'
  THEN RAISE EXCEPTION 'publish replay failed: %',z; END IF;
  checks:=checks+1;

  z := public.ordax_publish_artifact_v1(a,'product',j,d,key,'postflight.txt',
    'log','text/plain',repeat('d',64),1,'{"test":"rollback-only"}'::jsonb,
    old_token,pg_catalog.clock_timestamp()+interval '10 minutes');
  IF z->>'error' IS DISTINCT FROM 'artifact_replay_conflict'
  THEN RAISE EXCEPTION 'changed content replay accepted'; END IF;
  checks:=checks+1;

  z := public.ordax_artifact_lookup_v1(a);
  IF z->'artifact'->>'storage_path' IS DISTINCT FROM key
  THEN RAISE EXCEPTION 'published artifact lookup failed'; END IF;
  checks:=checks+1;

  z := public.ordax_authorize_artifact_download_v1(a,old_token);
  IF z->>'ok' IS DISTINCT FROM 'true'
  THEN RAISE EXCEPTION 'legitimate artifact token denied'; END IF;
  checks:=checks+1;

  z := public.ordax_authorize_artifact_download_v1(a,repeat('0',64));
  IF z->>'error' IS DISTINCT FROM 'artifact_token_invalid_or_expired'
  THEN RAISE EXCEPTION 'invalid artifact token accepted'; END IF;
  checks:=checks+1;

  z := public.ordax_rotate_artifact_read_token_v1(
    a,j,d,new_token,pg_catalog.clock_timestamp()+interval '10 minutes');
  IF z->>'ok' IS DISTINCT FROM 'true'
  THEN RAISE EXCEPTION 'read token rotation failed'; END IF;
  checks:=checks+1;

  z := public.ordax_authorize_artifact_download_v1(a,old_token);
  IF z->>'error' IS DISTINCT FROM 'artifact_token_invalid_or_expired'
  THEN RAISE EXCEPTION 'revoked token still accepted'; END IF;
  checks:=checks+1;

  z := public.ordax_authorize_artifact_download_v1(a,new_token);
  IF z->>'ok' IS DISTINCT FROM 'true'
  THEN RAISE EXCEPTION 'rotated artifact token invalid'; END IF;
  checks:=checks+1;

  z := public.ordax_list_artifact_device_objects_v1(d);
  IF NOT (z->'artifacts' @>
      pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object('artifact_id',a)))
  THEN RAISE EXCEPTION 'device artifact lookup omitted synthetic record'; END IF;
  checks:=checks+1;

  -- Synthetic rows only: force fixture to the earliest possible retention slot,
  -- independent of legitimate user data/limit=100 and without touching R2.
  UPDATE private.ordax_artifact_records
     SET created_at='2000-01-01T00:00:00Z'::timestamptz
   WHERE artifact_id=a;
  UPDATE private.ordax_artifact_upload_sessions
     SET created_at='2000-01-01T00:00:00Z'::timestamptz
   WHERE artifact_id=a;
  z := public.ordax_list_artifact_retention_candidates_v1(
    pg_catalog.clock_timestamp()+interval '1 hour',
    pg_catalog.clock_timestamp()+interval '1 hour',100);
  IF NOT (z->'artifacts' @>
      pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object('artifact_id',a)))
  THEN RAISE EXCEPTION 'artifact retention candidate omitted fixture'; END IF;
  checks:=checks+1;
  IF NOT (z->'uploads' @>
      pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object('artifact_id',a)))
  THEN RAISE EXCEPTION 'upload retention candidate omitted fixture'; END IF;
  checks:=checks+1;

  z := public.ordax_begin_product_artifact_upload_v1(d,r,fx,at,lease,1,
    agent,'fake-boot',a,'postflight-no-r2',key,'postflight.txt','log','text/plain',
    1,h,'{}'::jsonb,old_token,pg_catalog.clock_timestamp()+interval '10 minutes',
    pg_catalog.clock_timestamp()+interval '1 day');
  IF z->>'error' IS DISTINCT FROM 'lease_not_active'
  THEN RAISE EXCEPTION 'unattested Product upload permitted'; END IF;
  checks:=checks+1;

  z := public.ordax_commit_product_artifact_v1(d,r,fx,at,lease,1,agent,
    'fake-boot',a,key,'postflight.txt','log','text/plain',1,h,'{}'::jsonb,
    old_token,pg_catalog.clock_timestamp()+interval '10 minutes',
    pg_catalog.clock_timestamp()+interval '1 day');
  IF z->>'error' IS DISTINCT FROM 'lease_not_active'
  THEN RAISE EXCEPTION 'unattested Product commit permitted'; END IF;
  checks:=checks+1;

  z := public.ordax_get_product_artifact_upload_v1(d,r,fx,at,lease,1,agent,
    'fake-boot',a);
  IF z->>'error' IS DISTINCT FROM 'lease_not_active'
  THEN RAISE EXCEPTION 'unattested Product read permitted'; END IF;
  checks:=checks+1;

  z := public.ordax_refresh_product_artifact_read_v1(d,r,a,new_token,
    pg_catalog.clock_timestamp()+interval '10 minutes');
  IF z->>'error' IS DISTINCT FROM 'artifact_not_found'
  THEN RAISE EXCEPTION 'nonexistent Product token refresh permitted'; END IF;
  checks:=checks+1;

  IF EXISTS(SELECT 1 FROM private.ordax_product_artifacts WHERE artifact_id=a)
    OR EXISTS(SELECT 1 FROM private.ordax_product_artifact_uploads WHERE artifact_id=a)
  THEN RAISE EXCEPTION 'Product lease-denial created data'; END IF;
  checks:=checks+1;

  z := public.ordax_delete_artifact_record_v1(a,'wrong/key');
  IF z->>'deleted' IS DISTINCT FROM 'false'
  THEN RAISE EXCEPTION 'wrong storage path deleted artifact'; END IF;
  checks:=checks+1;

  z := public.ordax_delete_artifact_record_v1(a,key);
  IF z->>'deleted' IS DISTINCT FROM 'true'
  THEN RAISE EXCEPTION 'correct artifact was not deleted'; END IF;
  checks:=checks+1;

  z := public.ordax_delete_artifact_upload_v1(a,j,d,'postflight-no-r2');
  IF z->>'deleted' IS DISTINCT FROM 'true'
  THEN RAISE EXCEPTION 'correct upload was not deleted'; END IF;
  checks:=checks+1;

  IF EXISTS(SELECT 1 FROM private.ordax_artifact_records WHERE artifact_id=a)
    OR EXISTS(SELECT 1 FROM private.ordax_artifact_upload_sessions WHERE artifact_id=a)
  THEN RAISE EXCEPTION 'synthetic artifact cleanup failed'; END IF;
  checks:=checks+1;

  RAISE NOTICE 'ORDAX_ARTIFACT_SQL_POSTFLIGHT_PASS % checks; rollback required',checks;
END;
$postflight$;
SELECT 'artifact metadata postflight complete; ROLLBACK follows' AS test_status;
ROLLBACK;
