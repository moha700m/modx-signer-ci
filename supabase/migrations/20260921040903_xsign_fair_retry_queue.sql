-- Fair queue retry metadata.  The worker uses this migration to release a
-- device that Apple is still processing, allowing later jobs to make progress.
ALTER TABLE public.xsign_jobs
  ADD COLUMN IF NOT EXISTS next_attempt_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS last_attempt_at timestamptz,
  ADD COLUMN IF NOT EXISTS attempt_count integer NOT NULL DEFAULT 0;

DO $constraint$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.xsign_jobs'::regclass
      AND conname = 'xsign_jobs_attempt_count_nonnegative'
  ) THEN
    ALTER TABLE public.xsign_jobs
      ADD CONSTRAINT xsign_jobs_attempt_count_nonnegative CHECK (attempt_count >= 0);
  END IF;
END
$constraint$;

CREATE INDEX IF NOT EXISTS xsign_jobs_awaiting_due_idx
  ON public.xsign_jobs (next_attempt_at ASC, created_at ASC)
  WHERE status = 'awaiting_worker';

CREATE OR REPLACE FUNCTION public.xsign_claim_job(p_worker_id text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE r public.xsign_jobs;
BEGIN
  SELECT * INTO r
  FROM public.xsign_jobs
  WHERE status = 'awaiting_worker'
    AND next_attempt_at <= now()
  ORDER BY created_at ASC
  FOR UPDATE SKIP LOCKED
  LIMIT 1;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('job', null);
  END IF;

  UPDATE public.xsign_jobs
  SET status = 'claimed',
      status_message = 'تم استلام الطلب بواسطة عامل التوقيع',
      started_at = now(),
      claimed_by = left(coalesce(p_worker_id, 'github-macos'), 80),
      attempt_count = coalesce(attempt_count, 0) + 1,
      last_attempt_at = now(),
      next_attempt_at = now()
  WHERE id = r.id
  RETURNING * INTO r;

  RETURN jsonb_build_object('job', jsonb_build_object(
    'id', r.id, 'filename', r.filename, 'size', r.size_bytes, 'chunkCount', 0,
    'deviceName', r.device_name, 'udid', r.udid, 'createdAt', r.created_at,
    'sourceUrl', r.source_url, 'callbackUrl', r.callback_url, 'signingToken', r.signing_token
  ));
END
$function$;

CREATE OR REPLACE FUNCTION public.xsign_job_defer(p_id uuid, p_message text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
BEGIN
  UPDATE public.xsign_jobs
  SET status = 'awaiting_worker',
      status_message = left(coalesce(p_message, 'بانتظار إعادة المحاولة'), 240),
      started_at = null,
      claimed_by = null,
      failure_reason = null,
      next_attempt_at = now() + interval '15 minutes'
  WHERE id = p_id
    AND status IN ('claimed', 'registering_device', 'creating_profile', 'signing', 'verifying', 'uploading_result');

  IF NOT FOUND THEN
    RAISE EXCEPTION 'job not found or not deferrable';
  END IF;
  RETURN jsonb_build_object('ok', true, 'status', 'awaiting_worker');
END
$function$;

CREATE OR REPLACE FUNCTION public.xsign_portal_enqueue(
  p_order_id uuid, p_udid text, p_device_name text, p_filename text, p_size bigint,
  p_source_url text, p_callback_url text, p_signing_token text
)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE r public.xsign_jobs;
BEGIN
  SELECT * INTO r FROM public.xsign_jobs
  WHERE order_id = p_order_id
    AND status IN ('awaiting_worker', 'claimed', 'registering_device', 'creating_profile', 'signing', 'verifying', 'uploading_result')
  ORDER BY created_at DESC LIMIT 1;
  IF FOUND THEN
    RETURN jsonb_build_object('jobId', r.id, 'status', r.status);
  END IF;

  SELECT * INTO r FROM public.xsign_jobs
  WHERE order_id = p_order_id
  ORDER BY created_at DESC LIMIT 1;
  IF FOUND THEN
    UPDATE public.xsign_jobs
    SET udid = p_udid,
        device_name = p_device_name,
        filename = p_filename,
        size_bytes = p_size,
        source_url = p_source_url,
        callback_url = p_callback_url,
        signing_token = p_signing_token,
        status = 'awaiting_worker',
        status_message = 'بانتظار عامل التوقيع',
        started_at = null,
        completed_at = null,
        output_filename = null,
        expiration_date = null,
        failure_reason = null,
        claimed_by = null,
        next_attempt_at = now(),
        last_attempt_at = null,
        attempt_count = 0
    WHERE id = r.id
    RETURNING * INTO r;
    RETURN jsonb_build_object('jobId', r.id, 'status', r.status);
  END IF;

  INSERT INTO public.xsign_jobs(
    order_id, udid, device_name, filename, size_bytes, source_url,
    callback_url, signing_token, status, status_message
  ) VALUES (
    p_order_id, p_udid, p_device_name, p_filename, p_size, p_source_url,
    p_callback_url, p_signing_token, 'awaiting_worker', 'بانتظار عامل التوقيع'
  ) RETURNING * INTO r;
  RETURN jsonb_build_object('jobId', r.id, 'status', r.status);
END
$function$;

REVOKE EXECUTE ON FUNCTION public.xsign_claim_job(text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.xsign_job_defer(uuid, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.xsign_portal_enqueue(uuid, text, text, text, bigint, text, text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.xsign_claim_job(text) TO service_role;
GRANT EXECUTE ON FUNCTION public.xsign_job_defer(uuid, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.xsign_portal_enqueue(uuid, text, text, text, bigint, text, text, text) TO service_role;
