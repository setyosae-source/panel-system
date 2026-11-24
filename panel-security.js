(function (global) {
  'use strict';
  const origin = 'https://sswslwddemackxrrbpre.supabase.co';
  const tokenKey = 'sae_secure_session_v1';
  const userKey = 'sae_secure_user_v1';
  const nativeFetch = global.fetch.bind(global);
  let apiHeaders = null;
  const token = () => localStorage.getItem(tokenKey) || '';
  function clear() {
    localStorage.removeItem(tokenKey);
    localStorage.removeItem(userKey);
    sessionStorage.removeItem('panelUser');
  }
  global.fetch = function (input, init) {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url, location.href);
    if (url.origin !== origin) return nativeFetch(input, init);
    const options = Object.assign({}, init);
    const headers = new Headers(input instanceof Request ? input.headers : undefined);
    new Headers(options.headers).forEach((value, key) => headers.set(key, value));
    if (token()) headers.set('x-panel-session', token());
    if (headers.has('apikey')) apiHeaders = new Headers(headers);
    options.headers = headers;
    return nativeFetch(input, options);
  };
  async function login(sb, username, password) {
    const {data, error} = await sb.rpc('panel_secure_login', {p_username: username, p_password: password});
    if (error || !data?.ok) throw new Error(data?.error || error?.message || 'Login gagal');
    localStorage.setItem(tokenKey, data.token);
    localStorage.setItem(userKey, JSON.stringify(data.user));
    sessionStorage.setItem('panelUser', JSON.stringify(data.user));
    return data.user;
  }
  async function resume(sb) {
    if (!token()) { clear(); return null; }
    const {data, error} = await sb.rpc('panel_session_user');
    if (error) throw new Error(error.message);
    if (!data?.id) { clear(); return null; }
    sessionStorage.setItem('panelUser', JSON.stringify(data));
    localStorage.setItem(userKey, JSON.stringify(data));
    return data;
  }
  async function logout() {
    const headers = apiHeaders && new Headers(apiHeaders);
    if (headers) {
      headers.set('x-panel-session', token());
      headers.set('Content-Type', 'application/json');
    }
    clear();
    if (headers) {
      try { await nativeFetch(origin + '/rest/v1/rpc/panel_secure_logout', {method: 'POST', headers, body: '{}'}); } catch (_) {}
    }
  }
  // New tabs inherit only a cached display identity. Database access always checks the server token.
  if (token() && !sessionStorage.getItem('panelUser')) {
    const cached = localStorage.getItem(userKey);
    if (cached) sessionStorage.setItem('panelUser', cached);
  }
  global.PanelSecurity = {login, resume, logout, clear, hasSession: () => !!token()};
})(window);
