# Talent Forge

Talent Forge is a small student learning app with account signup, login, five timed skill challenges, and saved results.

## Run the project

1. Install Node.js 18 or newer.
2. In this project folder, run `npm start`.
3. Open <http://localhost:3000>.

The server creates a local session-signing secret in `.env` when one is not present. If Supabase is not configured, student accounts and challenge results are stored locally in `data/db.json`.

## Connect Supabase

1. Open the Supabase project and choose **SQL Editor → New query**.
2. Paste and run the full contents of `schema.sql`. This is safe to run on an existing setup: it creates missing tables and adds `students.password_hash` when needed.
3. In this folder, copy `.env.example` to `.env` and set `SUPABASE_URL` and `SUPABASE_SECRET_KEY` from the Supabase project API settings. Use a server-side secret key; keep `.env` private and never add the key to browser code.
4. Restart the app with `npm start` and open <http://localhost:3000/api/health>. A working hosted setup returns `{"status":"ok","database":"supabase"}`.

Signup and login need the `password_hash` column. If the app reports that the column is missing, run this migration in the Supabase SQL Editor:

```sql
alter table public.students add column if not exists password_hash text;
```

Refresh the app after running the migration. Passwords are stored as salted hashes; results are associated with the signed-in student using an HTTP-only session cookie. The Supabase secret key stays on the server.

## Database tables

- `public.students` stores each student's USN, profile details, and password hash.
- `public.challenge_results` stores each completed skill, score, duration, checklist, answer, and timestamp.

The server writes to Supabase when configured, otherwise it uses `data/db.json`. Existing local JSON records are not automatically copied to Supabase.
