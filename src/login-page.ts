import { cookie, BROWSER_COOKIE, SESSION_TTL_SECONDS } from './auth.ts';
import { htmlResponse, noStoreHeaders } from './utils.ts';

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]!);
}

export function loginPage(options: {
  email: string;
  transaction: string;
  binding: string;
  redirectUri: string;
  remembered: boolean;
  error?: string;
  status?: number;
}): Response {
  const email = escapeHtml(options.email);
  const headers = noStoreHeaders({
    // Chromium also checks form-action on POST redirects. Permit the already
    // validated callback origin so a successful login can return to Google.
    'Content-Security-Policy': `default-src 'none'; style-src 'unsafe-inline'; form-action 'self' ${new URL(options.redirectUri).origin}; frame-ancestors 'none'; base-uri 'none'`,
    // no-referrer makes Chromium send Origin: null for native form POSTs.
    // same-origin preserves the CSRF origin check without leaking the request
    // query to the external Google callback.
    'Referrer-Policy': 'same-origin',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
  });
  headers.append('Set-Cookie', cookie(BROWSER_COOKIE, options.binding, SESSION_TTL_SECONDS));

  return htmlResponse(`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>登录 · ZeroAuth</title>
  <style>
    :root { color-scheme: light dark; font-family: ui-sans-serif, system-ui, -apple-system, "Microsoft YaHei", "PingFang SC", sans-serif;
      --bg: #f3f6fb; --card: #fff; --ink: #17243a; --muted: #5c6980; --border: #d6deea; --accent: #2859d4; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100svh; display: grid; place-items: center; padding: 24px;
      background: radial-gradient(ellipse at top, #dce7fc, transparent 65%), var(--bg); color: var(--ink); }
    main { width: 100%; max-width: 420px; padding: 36px; background: var(--card); border: 1px solid var(--border);
      border-radius: 24px; box-shadow: 0 20px 60px #17243a0c; }
    .mark { width: 40px; height: 40px; border-radius: 12px; display: grid; place-items: center;
      background: var(--accent); color: white; font-weight: 700; }
    h1 { font-size: 26px; margin: 22px 0 8px; letter-spacing: -.7px; }
    p { color: var(--muted); line-height: 1.6; margin: 0 0 20px; }
    .email { display: block; width: 100%; border-radius: 10px; background: var(--bg);
      padding: 12px; font: inherit; font-weight: 600; margin-bottom: 24px; overflow-wrap: anywhere; }
    label { display: block; font-size: 14px; font-weight: 600; margin-bottom: 8px; }
    input[type=password] { width: 100%; padding: 13px; border: 1px solid var(--border); border-radius: 10px;
      font: inherit; background: var(--card); color: var(--ink); }
    input:focus-visible, button:focus-visible { outline: 3px solid #7399f5; outline-offset: 3px; }
    button { width: 100%; min-height: 48px; margin-top: 20px; border: 0; border-radius: 10px;
      padding: 12px; background: var(--accent); color: white; font: inherit; font-weight: 600; cursor: pointer; }
    button:hover { filter: brightness(1.08); }
    .secondary { background: transparent; color: var(--muted); font-size: 14px; margin-top: 8px; }
    .note { font-size: 13px; margin: 20px 0 0; }
    .error { color: #c53737; margin: 12px 0 0; font-size: 14px; }
    @media (max-width: 480px) { main { padding: 28px 24px; } }
    @media (prefers-color-scheme: dark) { :root { --bg: #101827; --card: #192336; --ink: #ecf1fb;
      --muted: #aab7cd; --border: #344159; --accent: #396be2; }
      body { background: radial-gradient(ellipse at top, #21355b, transparent 65%), var(--bg); }
      .error { color: #ff9696; } }
  </style>
</head>
<body>
  <main>
    <div class="mark" aria-hidden="true">Z</div>
    <h1>ZeroAuth</h1>
    <p>${options.remembered ? '此浏览器已验证，请确认本次登录账号。' : '使用统一密码，登录你的 Google 账号。'}</p>
    <span class="email">${email}</span>
    <form method="post" action="/authorize">
      <input type="hidden" name="transaction" value="${escapeHtml(options.transaction)}">
      <input type="text" name="username" value="${email}" autocomplete="username" hidden>
      ${options.remembered ? '' : `<label for="password">统一登录密码</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required autofocus
        ${options.error ? 'aria-invalid="true" aria-describedby="login-error"' : ''}>`}
      ${options.error ? `<p class="error" id="login-error" role="alert">${escapeHtml(options.error)}</p>` : ''}
      <button type="submit" name="action" value="login">${options.remembered ? '确认登录' : '登录'}</button>
      ${options.remembered ? '<button class="secondary" type="submit" name="action" value="forget">忘记此浏览器，重新输入密码</button>' : ''}
    </form>
    <p class="note">${options.remembered ? '确认后将返回 Google。' : '验证后，此浏览器记住 30 天。其他账号登录时只需确认邮箱。'}</p>
  </main>
</body>
</html>`, { headers, status: options.status ?? 200 });
}
