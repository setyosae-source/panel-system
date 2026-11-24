-- Emergency restore of the access metadata captured immediately before enforcement.
-- Run only on the panel-system database. Business rows are not changed.
do $restore$
declare t record; p record; g record; command text; role_list text;
begin
for t in select * from private.panel_security_restore loop
  for p in select policyname from pg_policies where schemaname='public' and tablename=t.table_name loop
    execute format('drop policy %I on public.%I',p.policyname,t.table_name);
  end loop;
  for p in select * from jsonb_to_recordset(t.policies) as x(policyname text,permissive text,roles text[],cmd text,qual text,with_check text) loop
    select string_agg(quote_ident(role_name),',') into role_list from unnest(p.roles) role_name;
    command:=format('create policy %I on public.%I as %s for %s to %s',p.policyname,t.table_name,p.permissive,p.cmd,role_list);
    if p.qual is not null then command:=command||' using ('||p.qual||')'; end if;
    if p.with_check is not null then command:=command||' with check ('||p.with_check||')'; end if;
    execute command;
  end loop;
  execute format('alter table public.%I %s row level security',t.table_name,case when t.rls_enabled then 'enable' else 'disable' end);
  execute format('revoke all on public.%I from public,anon,authenticated',t.table_name);
  for g in select * from jsonb_to_recordset(t.grants) as x(grantee text,privilege_type text,is_grantable text) loop
    execute format('grant %s on public.%I to %s%s',g.privilege_type,t.table_name,case when g.grantee='PUBLIC' then 'PUBLIC' else quote_ident(g.grantee) end,case when g.is_grantable='YES' then ' with grant option' else '' end);
  end loop;
  execute format('drop trigger if exists panel_verified_actor_audit on public.%I',t.table_name);
end loop;
end $restore$;
