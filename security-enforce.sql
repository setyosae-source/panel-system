-- Activate only after the updated frontend is live. Restore metadata is private.
create table if not exists private.panel_security_restore (
  table_name text primary key,
  rls_enabled boolean not null,
  policies jsonb not null,
  grants jsonb not null
);
revoke all on private.panel_security_restore from public,anon,authenticated;
alter table private.panel_security_restore enable row level security;

create table if not exists private.panel_data_audit (
  id bigint generated always as identity primary key,
  occurred_at timestamptz not null default now(),
  table_name text not null,
  operation text not null,
  actor_id text,
  actor_username text,
  before_row jsonb,
  after_row jsonb
);
revoke all on private.panel_data_audit from public,anon,authenticated;
alter table private.panel_data_audit enable row level security;
create or replace function private.panel_audit_change()
returns trigger language plpgsql security definer set search_path = '' as $$
declare actor jsonb:=private.panel_actor(); old_data jsonb; new_data jsonb;
begin
  if TG_OP<>'INSERT' then old_data:=to_jsonb(OLD)-'password_hash'-'password'; end if;
  if TG_OP<>'DELETE' then new_data:=to_jsonb(NEW)-'password_hash'-'password'; end if;
  insert into private.panel_data_audit(table_name,operation,actor_id,actor_username,before_row,after_row)
    values(TG_TABLE_NAME,TG_OP,actor->>'id',coalesce(actor->>'username',current_setting('request.jwt.claim.role',true),'backend'),old_data,new_data);
  return null;
end $$;
revoke all on function private.panel_audit_change() from public;

do $protect$
declare t record; p record; predicate text;
begin
for t in
  select c.relname,c.relrowsecurity from pg_class c join pg_namespace n on n.oid=c.relnamespace
  where n.nspname='public' and c.relkind='r' and c.relname not like 'pv_%'
    and (not c.relrowsecurity or c.relname in ('app_users','product_units','misc_jobs','requests','docs_customer','docs_result','po_log') or c.relname like '\_old\_%' escape '\')
loop
  insert into private.panel_security_restore(table_name,rls_enabled,policies,grants)
  values(t.relname,t.relrowsecurity,
    coalesce((select jsonb_agg(to_jsonb(x)) from pg_policies x where x.schemaname='public' and x.tablename=t.relname),'[]'::jsonb),
    coalesce((select jsonb_agg(to_jsonb(x)) from information_schema.role_table_grants x where x.table_schema='public' and x.table_name=t.relname and x.grantee in ('PUBLIC','anon','authenticated')),'[]'::jsonb))
  on conflict do nothing;
  for p in select policyname from pg_policies where schemaname='public' and tablename=t.relname loop
    execute format('drop policy %I on public.%I',p.policyname,t.relname);
  end loop;
  execute format('alter table public.%I enable row level security',t.relname);
  -- Archived tables have no frontend references and no client access.
  if t.relname like '\_old\_%' escape '\' then
    execute format('revoke all on public.%I from public,anon,authenticated',t.relname);
    continue;
  end if;
  execute format('grant select,insert,update,delete on public.%I to anon,authenticated',t.relname);
  predicate:='(select private.panel_actor()) is not null';
  execute format('create policy secure_project_member_read on public.%I for select to anon,authenticated using (%s)',t.relname,predicate);
  if t.relname='app_users' then predicate:='(select private.panel_actor()->>''role'') in (''owner'',''admin'')'; end if;
  execute format('create policy secure_project_member_insert on public.%I for insert to anon,authenticated with check (%s)',t.relname,predicate);
  execute format('create policy secure_project_member_update on public.%I for update to anon,authenticated using (%s) with check (%s)',t.relname,predicate,predicate);
  execute format('create policy secure_project_member_delete on public.%I for delete to anon,authenticated using (%s)',t.relname,predicate);
  execute format('drop trigger if exists panel_verified_actor_audit on public.%I',t.relname);
  execute format('create trigger panel_verified_actor_audit after insert or update or delete on public.%I for each row execute function private.panel_audit_change()',t.relname);
end loop;
end $protect$;

-- SELECT * cannot return a reusable credential. Safe directory fields remain available to staff.
revoke select on public.app_users from public,anon,authenticated;
grant select(id,username,full_name,role,permissions,is_active,last_login,created_at,phone_wa) on public.app_users to anon,authenticated;
create policy published_general_documents on public.general_downloads for select to anon,authenticated using(is_active=true);

-- Signup metadata is supplied by the user and cannot grant administrative roles.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles(id,full_name,role)
  values(NEW.id,coalesce(NEW.raw_user_meta_data->>'full_name',NEW.email),'engineering');
  return NEW;
end $$;
