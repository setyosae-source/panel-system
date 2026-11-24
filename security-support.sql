-- Additive support. Existing application access is not changed in this phase.
create schema if not exists private;
create table if not exists private.panel_secure_sessions (
  token_hash text primary key,
  user_id text not null references public.app_users(id) on delete cascade,
  credential_fingerprint text not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);
create index if not exists panel_secure_sessions_expiry on private.panel_secure_sessions(expires_at);
create table if not exists private.panel_login_attempts (
  username text primary key,
  failures integer not null default 0,
  window_start timestamptz not null default now()
);
revoke all on private.panel_secure_sessions, private.panel_login_attempts from public, anon, authenticated;
alter table private.panel_secure_sessions enable row level security;
alter table private.panel_login_attempts enable row level security;

create or replace function private.panel_actor()
returns jsonb language sql stable security definer set search_path = '' as $$
  select to_jsonb(u) - 'password_hash'
  from private.panel_secure_sessions s join public.app_users u on u.id=s.user_id
  where s.token_hash=encode(extensions.digest(coalesce(current_setting('request.headers',true),'{}')::jsonb->>'x-panel-session','sha256'),'hex')
    and s.expires_at>now() and u.is_active
    and s.credential_fingerprint=encode(extensions.digest(u.password_hash,'sha256'),'hex')
  limit 1
$$;
revoke all on function private.panel_actor() from public;
grant usage on schema private to anon, authenticated;
grant execute on function private.panel_actor() to anon, authenticated;

create or replace function public.panel_secure_login(p_username text,p_password text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare u public.app_users; v_token text; a private.panel_login_attempts; v_name text:=lower(trim(p_username));
begin
  if length(coalesce(p_username,''))>128 or length(coalesce(p_password,''))>1024 or coalesce(p_password,'')='' then
    return jsonb_build_object('ok',false,'error','Username atau password salah');
  end if;
  insert into private.panel_login_attempts(username) values(v_name) on conflict do nothing;
  select * into a from private.panel_login_attempts where username=v_name for update;
  if a.window_start<now()-interval '15 minutes' then
    update private.panel_login_attempts set failures=0,window_start=now() where username=v_name;
    a.failures:=0;
  end if;
  if a.failures>=30 then return jsonb_build_object('ok',false,'error','Terlalu banyak percobaan. Coba kembali dalam 15 menit.'); end if;
  select * into u from public.app_users where lower(username)=v_name and is_active
    and password_hash=encode(extensions.digest(p_password,'sha256'),'hex') limit 1;
  if not found then
    update private.panel_login_attempts set failures=failures+1 where username=v_name;
    return jsonb_build_object('ok',false,'error','Username atau password salah');
  end if;
  delete from private.panel_login_attempts where username=v_name;
  delete from private.panel_secure_sessions where expires_at<=now();
  v_token:=encode(extensions.gen_random_bytes(32),'hex');
  insert into private.panel_secure_sessions(token_hash,user_id,credential_fingerprint,expires_at)
    values(encode(extensions.digest(v_token,'sha256'),'hex'),u.id,encode(extensions.digest(u.password_hash,'sha256'),'hex'),now()+interval '12 hours');
  update public.app_users set last_login=now() where id=u.id;
  return jsonb_build_object('ok',true,'token',v_token,'user',to_jsonb(u)-'password_hash','expires_at',now()+interval '12 hours');
end $$;
revoke all on function public.panel_secure_login(text,text) from public;
grant execute on function public.panel_secure_login(text,text) to anon,authenticated;

create or replace function public.panel_session_user()
returns jsonb language sql stable security definer set search_path = '' as $$ select private.panel_actor() $$;
revoke all on function public.panel_session_user() from public;
grant execute on function public.panel_session_user() to anon,authenticated;

create or replace function public.panel_secure_logout()
returns void language sql security definer set search_path = '' as $$
  delete from private.panel_secure_sessions
  where token_hash=encode(extensions.digest(coalesce(current_setting('request.headers',true),'{}')::jsonb->>'x-panel-session','sha256'),'hex')
$$;
revoke all on function public.panel_secure_logout() from public;
grant execute on function public.panel_secure_logout() to anon,authenticated;

-- Public product pages get only one exact serial and the fields they display.
create or replace function public.panel_public_product(p_serial text)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare i public.po_items; unit_json jsonb; item_json jsonb; po_json jsonb; serial text:=upper(trim(p_serial));
begin
  if coalesce(length(serial),0)<3 or length(serial)>128 then return null; end if;
  select jsonb_build_object('serial_number',pu.serial_number,'po_item_id',pu.po_item_id) into unit_json
    from public.product_units pu where upper(pu.serial_number)=serial limit 1;
  select * into i from public.po_items where id=(unit_json->>'po_item_id')::uuid;
  if i.id is null then
    select * into i from public.po_items pi
      where exists(select 1 from unnest(string_to_array(pi.serial_number,',')) s where upper(trim(s))=serial) limit 1;
  end if;
  if i.id is null then return null; end if;
  select jsonb_build_object('no_po',p.no_po,'no_project',p.no_project,'customer_name',p.customer_name,'download_files',p.download_files)
    into po_json from public.purchase_orders p where p.id=i.po_id;
  item_json:=jsonb_build_object('category',i.category,'model_name',i.model_name,'serial_number',serial,'serial_generated_at',i.serial_generated_at,
    'item_specs',coalesce((select jsonb_agg(to_jsonb(s)-'id'-'item_id'-'updated_at') from public.item_specs s where s.item_id=i.id),'[]'::jsonb),
    'item_detail_specs',coalesce((select jsonb_agg(to_jsonb(s)-'id'-'item_id'-'created_at'-'updated_at') from public.item_detail_specs s where s.item_id=i.id),'[]'::jsonb),
    'purchase_orders',po_json);
  return jsonb_build_object('item',item_json,'unit',unit_json-'po_item_id');
end $$;
revoke all on function public.panel_public_product(text) from public;
grant execute on function public.panel_public_product(text) to anon,authenticated;
