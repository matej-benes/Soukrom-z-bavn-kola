-- Supabase schema pro MojeSkola
-- Spust v Supabase: SQL Editor -> New query -> vloz a Run
-- Staci JEDNA tabulka (klic-hodnota), zadne slozite migrace.

create table if not exists public.school_store (
  key text primary key,
  value jsonb not null,
  updated_at timestamptz default now()
);

-- Pro demo povolime cteni i zapis pres anon klic.
-- POZOR: na ostrou skolu pak nastav prisnejsi RLS (jen pro prihlasene role).
alter table public.school_store enable row level security;

drop policy if exists "public read" on public.school_store;
create policy "public read" on public.school_store
  for select using (true);

drop policy if exists "public write" on public.school_store;
create policy "public write" on public.school_store
  for all using (true) with check (true);
