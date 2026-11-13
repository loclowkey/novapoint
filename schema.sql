-- Run this file in Supabase SQL Editor.
create extension if not exists pgcrypto;
create table if not exists public.profiles(id uuid primary key references auth.users(id) on delete cascade,email text,display_name text not null default 'Thành viên',role text not null default 'member' check(role in('member','admin')),points bigint not null default 0 check(points>=0),created_at timestamptz default now());
create table if not exists public.tasks(id uuid primary key default gen_random_uuid(),title text not null,description text default '',reward_points integer not null check(reward_points>0),proof_instructions text default 'Gửi link minh chứng, không gửi mật khẩu/OTP.',active boolean default true,created_by uuid references profiles(id),created_at timestamptz default now());
create table if not exists public.task_submissions(id uuid primary key default gen_random_uuid(),task_id uuid not null references tasks(id),user_id uuid not null references profiles(id),proof_url text not null,status text not null default 'pending' check(status in('pending','approved','rejected')),reviewed_by uuid references profiles(id),reviewed_at timestamptz,created_at timestamptz default now());
create table if not exists public.rewards(id uuid primary key default gen_random_uuid(),title text not null,description text default '',category text not null check(category in('Thẻ game','Liên Quân','Free Fire')),cost_points integer not null check(cost_points>0),stock integer not null default 0 check(stock>=0),active boolean default true,created_by uuid references profiles(id),created_at timestamptz default now());
create table if not exists public.redemptions(id uuid primary key default gen_random_uuid(),reward_id uuid not null references rewards(id),user_id uuid not null references profiles(id),status text not null default 'pending' check(status in('pending','approved','rejected')),reviewed_by uuid references profiles(id),reviewed_at timestamptz,created_at timestamptz default now());
create table if not exists public.point_transactions(id uuid primary key default gen_random_uuid(),user_id uuid not null references profiles(id),amount bigint not null check(amount<>0),description text not null,related_submission uuid references task_submissions(id),related_redemption uuid references redemptions(id),created_at timestamptz default now());
create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path=public as $$ begin insert into profiles(id,email,display_name) values(new.id,new.email,coalesce(new.raw_user_meta_data->>'display_name','Thành viên')) on conflict do nothing; return new; end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute procedure public.handle_new_user();
create or replace function public.is_admin() returns boolean language sql stable security definer set search_path=public as $$ select exists(select 1 from profiles where id=auth.uid() and role='admin') $$;
create or replace function public.review_task_submission(submission_id uuid,decision text) returns void language plpgsql security definer set search_path=public as $$
declare s task_submissions%rowtype;t tasks%rowtype;begin
if not is_admin() then raise exception 'Không có quyền quản trị';end if;
if decision not in('approve','reject') then raise exception 'Quyết định không hợp lệ';end if;
select * into s from task_submissions where id=submission_id for update;
if not found or s.status<>'pending' then raise exception 'Yêu cầu đã xử lý';end if;
select * into t from tasks where id=s.task_id;
if decision='approve' then update task_submissions set status='approved',reviewed_by=auth.uid(),reviewed_at=now() where id=s.id;update profiles set points=points+t.reward_points where id=s.user_id;insert into point_transactions(user_id,amount,description,related_submission) values(s.user_id,t.reward_points,'Hoàn thành nhiệm vụ: '||t.title,s.id);
else update task_submissions set status='rejected',reviewed_by=auth.uid(),reviewed_at=now() where id=s.id;end if;end $$;
create or replace function public.review_redemption(redemption_id uuid,decision text) returns void language plpgsql security definer set search_path=public as $$
declare r redemptions%rowtype;g rewards%rowtype;bal bigint;begin
if not is_admin() then raise exception 'Không có quyền quản trị';end if;
if decision not in('approve','reject') then raise exception 'Quyết định không hợp lệ';end if;
select * into r from redemptions where id=redemption_id for update;
if not found or r.status<>'pending' then raise exception 'Yêu cầu đã xử lý';end if;
select * into g from rewards where id=r.reward_id for update;select points into bal from profiles where id=r.user_id for update;
if decision='approve' then if g.stock<1 then raise exception 'Hết tồn kho';end if;if bal<g.cost_points then raise exception 'Không đủ điểm';end if;
update profiles set points=points-g.cost_points where id=r.user_id;update rewards set stock=stock-1 where id=g.id;
insert into point_transactions(user_id,amount,description,related_redemption) values(r.user_id,-g.cost_points,'Đổi quà: '||g.title,r.id);
update redemptions set status='approved',reviewed_by=auth.uid(),reviewed_at=now() where id=r.id;
else update redemptions set status='rejected',reviewed_by=auth.uid(),reviewed_at=now() where id=r.id;end if;end $$;
alter table profiles enable row level security;alter table tasks enable row level security;alter table task_submissions enable row level security;alter table rewards enable row level security;alter table redemptions enable row level security;alter table point_transactions enable row level security;
create policy "profile own or admin" on profiles for select to authenticated using(id=auth.uid() or is_admin());
create policy "active tasks" on tasks for select to authenticated using(active or is_admin());
create policy "admin create tasks" on tasks for insert to authenticated with check(is_admin() and created_by=auth.uid());
create policy "admin update tasks" on tasks for update to authenticated using(is_admin()) with check(is_admin());
create policy "own submissions" on task_submissions for insert to authenticated with check(user_id=auth.uid() and status='pending');
create policy "read submissions" on task_submissions for select to authenticated using(user_id=auth.uid() or is_admin());
create policy "active rewards" on rewards for select to authenticated using(active or is_admin());
create policy "admin create rewards" on rewards for insert to authenticated with check(is_admin() and created_by=auth.uid());
create policy "admin update rewards" on rewards for update to authenticated using(is_admin()) with check(is_admin());
create policy "own redemption insert" on redemptions for insert to authenticated with check(user_id=auth.uid() and status='pending');
create policy "read redemptions" on redemptions for select to authenticated using(user_id=auth.uid() or is_admin());
create policy "read own ledger" on point_transactions for select to authenticated using(user_id=auth.uid() or is_admin());
revoke all on function review_task_submission(uuid,text) from public;revoke all on function review_redemption(uuid,text) from public;grant execute on function review_task_submission(uuid,text) to authenticated;grant execute on function review_redemption(uuid,text) to authenticated;grant execute on function is_admin() to authenticated;
-- After signing up, manually promote your own account:
-- update public.profiles set role='admin' where email='YOUR_EMAIL';
