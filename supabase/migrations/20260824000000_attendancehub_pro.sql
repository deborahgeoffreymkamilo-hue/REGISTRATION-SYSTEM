-- AttendanceHub Pro: profiles, roles, attendees, attendance, and protected uploads
create type public.app_role as enum ('admin', 'supervisor', 'worker');

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default '',
  role public.app_role not null default 'worker',
  avatar_path text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.attendees (
  id uuid primary key default gen_random_uuid(),
  full_name text not null,
  email text,
  phone text,
  gender text check (gender in ('female','male','other','prefer_not_to_say')),
  date_of_birth date,
  address text,
  country text,
  city text,
  organization text,
  department text,
  position text,
  national_id_number text,
  profile_photo_path text,
  id_document_path text,
  notes text,
  status text not null default 'active' check (status in ('active','inactive')),
  created_by uuid references public.profiles(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (email),
  unique (phone)
);

create table public.attendance_records (
  id uuid primary key default gen_random_uuid(),
  attendee_id uuid not null references public.attendees(id) on delete cascade,
  attendance_date date not null default current_date,
  check_in_at timestamptz not null default now(),
  check_out_at timestamptz,
  method text not null default 'manual' check (method in ('manual','qr','import')),
  recorded_by uuid references public.profiles(id),
  notes text,
  created_at timestamptz not null default now(),
  unique (attendee_id, attendance_date)
);

create index attendees_name_idx on public.attendees using gin (to_tsvector('simple', full_name));
create index attendance_date_idx on public.attendance_records (attendance_date desc);

create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path = public as $$
begin insert into public.profiles (id, full_name, role) values (new.id, coalesce(new.raw_user_meta_data->>'full_name', ''), 'worker'); return new; end;
$$;
create trigger on_auth_user_created after insert on auth.users for each row execute procedure public.handle_new_user();

create or replace function public.is_staff() returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role in ('admin','supervisor','worker'));
$$;
create or replace function public.is_manager() returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role in ('admin','supervisor'));
$$;

alter table public.profiles enable row level security;
alter table public.attendees enable row level security;
alter table public.attendance_records enable row level security;
create policy "Profiles readable by staff" on public.profiles for select to authenticated using (public.is_staff());
create policy "Users update own profile" on public.profiles for update to authenticated using (id = auth.uid()) with check (id = auth.uid());
create policy "Staff read attendees" on public.attendees for select to authenticated using (public.is_staff());
create policy "Staff create attendees" on public.attendees for insert to authenticated with check (public.is_staff() and created_by = auth.uid());
create policy "Managers update attendees" on public.attendees for update to authenticated using (public.is_manager()) with check (public.is_manager());
create policy "Admins delete attendees" on public.attendees for delete to authenticated using ((select role from public.profiles where id = auth.uid()) = 'admin');
create policy "Staff read attendance" on public.attendance_records for select to authenticated using (public.is_staff());
create policy "Staff check in attendees" on public.attendance_records for insert to authenticated with check (public.is_staff() and recorded_by = auth.uid());
create policy "Managers amend attendance" on public.attendance_records for update to authenticated using (public.is_manager()) with check (public.is_manager());

insert into storage.buckets (id, name, public) values ('attendee-files', 'attendee-files', false) on conflict (id) do nothing;
create policy "Staff upload attendee files" on storage.objects for insert to authenticated with check (bucket_id = 'attendee-files' and public.is_staff());
create policy "Staff view attendee files" on storage.objects for select to authenticated using (bucket_id = 'attendee-files' and public.is_staff());
create policy "Managers remove attendee files" on storage.objects for delete to authenticated using (bucket_id = 'attendee-files' and public.is_manager());