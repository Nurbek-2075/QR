-- Выполните этот файл в Supabase SQL Editor перед публикацией сайта.
create extension if not exists pgcrypto;

create table if not exists public.allowed_admins (
  email text primary key,
  is_main boolean not null default false,
  created_at timestamptz not null default now()
);
create table if not exists public.participants (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  email text not null unique,
  code text unique not null,
  created_at timestamptz not null default now()
);
-- Совместимость со старой версией таблицы, где были только имя и личный код.
alter table public.participants add column if not exists email text;
alter table public.participants add column if not exists code text;
alter table public.participants add column if not exists owner_email text;
-- Заполнить владельца старых записей главным администратором, только если он настроен.
update public.participants
set owner_email = (
  select email from public.allowed_admins
  where is_main
  order by created_at
  limit 1
)
where owner_email is null or btrim(owner_email) = '';
-- Перед добавлением UNIQUE проверьте дубли email без учёта регистра:
-- select lower(email), count(*) from public.participants
-- where email is not null group by lower(email) having count(*) > 1;
create table if not exists public.qr_tokens (
  token text primary key,
  admin_email text not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);
create table if not exists public.checkins (
  id uuid primary key default gen_random_uuid(),
  participant_id uuid not null references public.participants(id) on delete cascade,
  day date not null,
  created_at timestamptz not null default now(),
  admin_email text,
  status text not null default 'present',
  unique(participant_id, day)
);
alter table public.checkins add column if not exists status text not null default 'present';

alter table public.allowed_admins enable row level security;
alter table public.participants enable row level security;
alter table public.qr_tokens enable row level security;
alter table public.checkins enable row level security;

create or replace function public.is_admin() returns boolean language sql stable security definer set search_path = public as $$
  select exists(select 1 from public.allowed_admins where lower(email)=lower(auth.jwt()->>'email'));
$$;
create or replace function public.is_main_admin() returns boolean language sql stable security definer set search_path = public as $$
  select exists(select 1 from public.allowed_admins where lower(email)=lower(auth.jwt()->>'email') and is_main);
$$;

create or replace function public.is_login_allowed(p_login text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists(
    select 1 from public.participants where lower(email)=lower(p_login||'@attendance.local')
  ) or exists(
    select 1 from public.allowed_admins where lower(email)=lower(p_login||'@attendance.local')
  );
$$;

create or replace function public.is_participant_login_allowed(p_login text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists(
    select 1 from public.participants where lower(email)=lower(p_login||'@attendance.local')
  );
$$;

create or replace function public.is_admin_login_allowed(p_login text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists(
    select 1 from public.allowed_admins where lower(email)=lower(p_login||'@attendance.local')
  );
$$;

revoke all on function public.is_login_allowed(text) from public;
revoke all on function public.is_participant_login_allowed(text) from public;
revoke all on function public.is_admin_login_allowed(text) from public;
grant execute on function public.is_login_allowed(text) to anon, authenticated;
grant execute on function public.is_participant_login_allowed(text) to anon, authenticated;
grant execute on function public.is_admin_login_allowed(text) to anon, authenticated;

drop policy if exists admins_read on public.allowed_admins;
create policy admins_read on public.allowed_admins for select to authenticated using (public.is_admin());
drop policy if exists admins_main_insert on public.allowed_admins;
create policy admins_main_insert on public.allowed_admins for insert to authenticated with check (public.is_main_admin());
drop policy if exists admins_main_delete on public.allowed_admins;
create policy admins_main_delete on public.allowed_admins for delete to authenticated using (public.is_main_admin() and not is_main);

drop policy if exists participants_admin_all on public.participants;
create policy participants_admin_all on public.participants for all to authenticated
  using (public.is_admin() and (public.is_main_admin() or lower(owner_email)=lower(auth.jwt()->>'email')))
  with check (public.is_admin() and (public.is_main_admin() or lower(owner_email)=lower(auth.jwt()->>'email')));
drop policy if exists participants_self_read on public.participants;
create policy participants_self_read on public.participants for select to authenticated using (lower(email)=lower(auth.jwt()->>'email'));

drop policy if exists qr_admin_all on public.qr_tokens;
create policy qr_admin_all on public.qr_tokens for all to authenticated using (public.is_admin()) with check (public.is_admin());
drop policy if exists checkins_admin_all on public.checkins;
create policy checkins_admin_all on public.checkins for all to authenticated
  using (public.is_admin() and exists(select 1 from public.participants p where p.id=participant_id and (public.is_main_admin() or lower(p.owner_email)=lower(auth.jwt()->>'email'))))
  with check (public.is_admin() and exists(select 1 from public.participants p where p.id=participant_id and (public.is_main_admin() or lower(p.owner_email)=lower(auth.jwt()->>'email'))));
drop policy if exists checkins_self_read on public.checkins;
create policy checkins_self_read on public.checkins for select to authenticated using (exists(select 1 from public.participants p where p.id=participant_id and lower(p.email)=lower(auth.jwt()->>'email')));

create or replace function public.check_in_for_user(p_token text) returns text language plpgsql security definer set search_path = public as $$
declare p public.participants; t public.qr_tokens; already boolean;
begin
  select * into t from public.qr_tokens where token=p_token and expires_at > now();
  if t is null then return 'bad_token'; end if;
  select * into p from public.participants where lower(email)=lower(auth.jwt()->>'email');
  if p is null then return 'not_participant'; end if;
  select exists(select 1 from public.checkins where participant_id=p.id and day=current_date) into already;
  if already then return 'already:'||p.name; end if;
  insert into public.checkins(participant_id,day,admin_email) values(p.id,current_date,t.admin_email);
  return 'ok:'||p.name;
end; $$;

-- Возвращает только агрегированный процент текущего участника.
create or replace function public.participant_attendance_rate() returns integer
language sql stable security definer set search_path = public as $$
  select coalesce(round(100.0 * count(distinct c.day) filter (where c.participant_id=p.id)
    / nullif(count(distinct c.day),0))::integer,0)
  from public.participants p
  left join public.checkins c on c.day >= p.created_at::date
  where lower(p.email)=lower(auth.jwt()->>'email')
  group by p.id;
$$;
revoke all on function public.participant_attendance_rate() from public;
grant execute on function public.participant_attendance_rate() to authenticated;

-- После создания первого аккаунта администратора выполните, заменив почту:
-- insert into public.allowed_admins(email,is_main) values ('admin@example.com', true);
-- Для Supabase сначала создайте аккаунт в Authentication -> Users -> Add user
-- с включённым Auto confirm и надёжным паролем, затем добавьте доступ:
-- insert into public.allowed_admins(email,is_main) values ('developer@attendance.local', true);
