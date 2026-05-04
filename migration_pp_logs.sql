-- ════════════════════════════════════════════════════════════════
-- Migration: Tabel pp_logs untuk audit log Pre-Project requests
-- Jalankan ini di Supabase SQL Editor sebelum deploy index.html baru
-- ════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS pp_logs (
  id BIGSERIAL PRIMARY KEY,
  request_id TEXT NOT NULL REFERENCES pp_requests(id) ON DELETE CASCADE,
  action TEXT NOT NULL,                 -- 'Buat Request', 'Edit Request', 'Upload Dokumen', 'Hapus Dokumen', 'Update Status'
  detail TEXT,                          -- detail perubahan (contoh: 'Customer: "A" → "B"')
  user_id TEXT REFERENCES app_users(id),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pp_logs_request ON pp_logs(request_id);
CREATE INDEX IF NOT EXISTS idx_pp_logs_created ON pp_logs(created_at DESC);

-- Disable RLS (sesuai pola tabel lain di sistem)
ALTER TABLE pp_logs DISABLE ROW LEVEL SECURITY;
