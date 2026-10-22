import { htmlResponse } from '../utils.ts';

export function handleChangePassword(): Response {
  return htmlResponse(
    `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>ZeroAuth Change Password</title>
    <style>
      :root {
        color-scheme: light;
        --bg: #f2efe8;
        --ink: #1f1b16;
        --accent: #0f766e;
        --card: #fffaf0;
      }
      body {
        margin: 0;
        font-family: "IBM Plex Sans", ui-sans-serif, system-ui, sans-serif;
        background:
          radial-gradient(circle at top left, rgba(15, 118, 110, 0.12), transparent 35%),
          linear-gradient(135deg, #f8f5ee, #ece6db);
        color: var(--ink);
      }
      main {
        max-width: 720px;
        margin: 8vh auto;
        padding: 2rem;
      }
      .card {
        background: var(--card);
        border: 1px solid rgba(31, 27, 22, 0.08);
        border-radius: 24px;
        padding: 2rem;
        box-shadow: 0 16px 50px rgba(31, 27, 22, 0.08);
      }
      h1 {
        margin-top: 0;
        font-size: clamp(2rem, 4vw, 3rem);
        line-height: 1;
      }
      p {
        font-size: 1.05rem;
        line-height: 1.6;
      }
      code {
        background: rgba(15, 118, 110, 0.08);
        padding: 0.15rem 0.35rem;
        border-radius: 6px;
      }
    </style>
  </head>
  <body>
    <main>
      <section class="card">
        <h1>ZeroAuth 密码管理</h1>
        <p>
          所有账号共用一个登录密码。此页面不提供在线修改或找回密码功能，请联系此服务的管理者。
        </p>
        <p>
          管理者可在本地终端运行 <code>npx wrangler secret put ZEROAUTH_PASSWORD</code> 更新统一密码。
        </p>
        <p>
          更新密码后，旧的浏览器登录凭据失效，下次登录需要输入新密码。已建立的 Google 登录会话不会被退出。
        </p>
      </section>
    </main>
  </body>
</html>`,
    { status: 200 },
  );
}
