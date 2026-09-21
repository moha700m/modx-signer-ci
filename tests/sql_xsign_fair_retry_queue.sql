-- Verification fixture for the queue migration. Run this file against a
-- disposable database only; every fixture is rolled back before exit.
BEGIN;

DO $verify$
DECLARE
  c integer;
BEGIN
  SELECT count(*) INTO c
  FROM information_schema.columns
  WHERE table_schema = 'public' AND table_name = 'xsign_jobs'
    AND column_name IN ('next_attempt_at', 'last_attempt_at', 'attempt_count');
  IF c <> 3 THEN RAISE EXCEPTION 'retry columns are missing'; END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.xsign_jobs'::regclass
      AND conname = 'xsign_jobs_attempt_count_nonnegative'
  ) THEN RAISE EXCEPTION 'attempt_count check is missing'; END IF;
END
$verify$;

-- Sentinel rows are older than production rows and use only valid table values.
-- They exercise FIFO, cooldown, attempt accounting, and terminal requeue.
INSERT INTO public.xsign_jobs(
  id, order_id, udid, device_name, filename, size_bytes, source_url,
  callback_url, signing_token, status, status_message, created_at,
  next_attempt_at, attempt_count
) VALUES
  ('00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000011', repeat('A', 40), 'fixture-a', 'a.ipa', 1,
   'https://example.invalid/source/a', 'https://example.invalid/callback/a', repeat('a', 64), 'awaiting_worker', 'fixture', '1970-01-01', now(), 0),
  ('00000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-000000000012', repeat('B', 40), 'fixture-b', 'b.ipa', 1,
   'https://example.invalid/source/b', 'https://example.invalid/callback/b', repeat('b', 64), 'awaiting_worker', 'fixture', '1971-01-01', now() + interval '15 minutes', 0);

DO $claim$
DECLARE r jsonb; id uuid; attempts integer; last_attempt timestamptz;
BEGIN
  SELECT public.xsign_claim_job('sql-fixture') INTO r;
  id := (r->'job'->>'id')::uuid;
  IF id <> '00000000-0000-4000-8000-000000000001' THEN RAISE EXCEPTION 'claim was not FIFO'; END IF;
  SELECT j.attempt_count, j.last_attempt_at INTO attempts, last_attempt
  FROM public.xsign_jobs AS j WHERE j.id = id;
  IF attempts <> 1 OR last_attempt IS NULL THEN RAISE EXCEPTION 'claim accounting failed'; END IF;
  PERFORM public.xsign_job_defer(id, 'fixture cooldown');
  IF (SELECT status FROM public.xsign_jobs WHERE xsign_jobs.id = id) <> 'awaiting_worker'
     OR (SELECT next_attempt_at FROM public.xsign_jobs WHERE xsign_jobs.id = id) <= now()
  THEN RAISE EXCEPTION 'defer cooldown failed'; END IF;
END
$claim$;

-- Re-enqueueing a terminal fixture resets retry metadata. This is deliberately
-- the only enqueue assertion; no live customer order is touched.
UPDATE public.xsign_jobs
SET status = 'failed', attempt_count = 7, last_attempt_at = now(), next_attempt_at = now() + interval '1 hour'
WHERE id = '00000000-0000-4000-8000-000000000002';
SELECT public.xsign_portal_enqueue(
  '00000000-0000-4000-8000-000000000012', repeat('B', 40), 'fixture-b', 'b.ipa', 1,
  'https://example.invalid/source/b', 'https://example.invalid/callback/b', repeat('b', 64)
);
DO $enqueue$
BEGIN
  IF (SELECT status FROM public.xsign_jobs WHERE id = '00000000-0000-4000-8000-000000000002') <> 'awaiting_worker'
     OR (SELECT attempt_count FROM public.xsign_jobs WHERE id = '00000000-0000-4000-8000-000000000002') <> 0
     OR (SELECT last_attempt_at FROM public.xsign_jobs WHERE id = '00000000-0000-4000-8000-000000000002') IS NOT NULL
  THEN RAISE EXCEPTION 'terminal enqueue did not reset retry metadata'; END IF;
END
$enqueue$;

ROLLBACK;
