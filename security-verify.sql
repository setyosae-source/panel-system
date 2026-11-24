do $verify$
declare
  test_id text:='security-test-'||gen_random_uuid()::text;
  test_name text:='security-test-'||gen_random_uuid()::text;
  test_password text:=encode(extensions.gen_random_bytes(24),'hex');
  login_result jsonb; v_token text; n bigint; m bigint; v_serial text; v_product jsonb; table_record record;
begin
  insert into public.app_users(id,username,full_name,password_hash,role,is_active)
    values(test_id,test_name,'Temporary verification',encode(extensions.digest(test_password,'sha256'),'hex'),'owner',true);
  perform set_config('request.headers','{}',true);
  set local role anon;
  if private.panel_actor() is not null then raise exception 'Anonymous actor accepted'; end if;
  select count(*) into n from public.purchase_orders;
  if n<>0 then raise exception 'Anonymous PO data exposed'; end if;
  begin
    perform password_hash from public.app_users limit 1;
    raise exception 'Password hash was readable';
  exception when insufficient_privilege then null;
  end;
  login_result:=public.panel_secure_login(test_name,'wrong-password');
  if login_result->>'ok'<>'false' then raise exception 'Wrong password accepted'; end if;
  login_result:=public.panel_secure_login(test_name,test_password);
  if login_result->>'ok'<>'true' then raise exception 'Valid login rejected'; end if;
  if login_result->'user' ? 'password_hash' then raise exception 'Login leaked hash'; end if;
  v_token:=login_result->>'token';
  perform set_config('request.headers',jsonb_build_object('x-panel-session',v_token)::text,true);
  if public.panel_session_user()->>'id' is distinct from test_id then raise exception 'Session did not restore'; end if;
  reset role;
  for table_record in select table_name from private.panel_security_restore where table_name<>'app_users' and table_name not like '\_old\_%' escape '\' loop
    execute format('select count(*) from public.%I',table_record.table_name) into n;
    set local role anon;
    execute format('select count(*) from public.%I',table_record.table_name) into m;
    reset role;
    if n<>m then raise exception 'Staff access changed for %',table_record.table_name; end if;
  end loop;
  set local role anon;
  update public.app_users set full_name='Verified admin write' where id=test_id;
  reset role;
  if not exists(select 1 from private.panel_data_audit where actor_id=test_id and table_name='app_users' and operation='UPDATE') then
    raise exception 'Verified audit actor missing';
  end if;
  update public.app_users set role='teknisi' where id=test_id;
  set local role anon;
  update public.app_users set role='owner' where id=test_id;
  get diagnostics n=row_count;
  if n<>0 then raise exception 'Ordinary staff could escalate role'; end if;
  perform public.panel_secure_logout();
  if public.panel_session_user() is not null then raise exception 'Logout token still accepted'; end if;
  reset role;
  select trim(split_part(serial_number,',',1)) into v_serial from public.po_items where serial_number is not null limit 1;
  if v_serial is not null then
    set local role anon;
    v_product:=public.panel_public_product(v_serial);
    if v_product->'item' is null then raise exception 'Existing public product unavailable'; end if;
    if v_product->'item' ? 'qty' or v_product->'item'->'purchase_orders' ? 'total_value' then raise exception 'Public product leaked private fields'; end if;
    reset role;
  end if;
end $verify$;
