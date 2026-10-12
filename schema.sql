-- Run this once in the Supabase SQL Editor for the project.
create table if not exists public.students (
  usn text primary key check (usn ~ '^[A-Z0-9]{6,15}$'),
  name text not null,
  department text not null,
  semester smallint not null check (semester between 1 and 8),
  section text not null,
  created_at timestamptz not null default now()
);

-- Store a one-way password hash for student account login.
alter table public.students add column if not exists password_hash text;

create table if not exists public.challenge_results (
  id bigint generated always as identity primary key,
  usn text not null references public.students(usn) on delete cascade,
  skill text not null check (skill in ('deploy', 'api', 'ai', 'chatbot', 'grade')),
  score smallint not null check (score between 0 and 100),
  duration_seconds smallint not null check (duration_seconds between 0 and 900),
  checks jsonb not null default '[]'::jsonb,
  answer text not null default '',
  created_at timestamptz not null default now()
);

create index if not exists challenge_results_usn_created_at_idx
  on public.challenge_results (usn, created_at desc);

-- Keep tables unavailable to browser roles. The server uses a secret key only.
alter table public.students enable row level security;
alter table public.challenge_results enable row level security;
grant all on table public.students, public.challenge_results to service_role;
grant usage, select on sequence public.challenge_results_id_seq to service_role;
