# ZeroAuth

运行在 Cloudflare Workers 上的轻量 OpenID Connect Provider，用一个统一密码登录自己管理的 Google Workspace / Cloud Identity 账号。

首次登录输入统一密码；同一浏览器在 **30 天内** 登录其他账号时，显示本次目标邮箱，点击“确认登录”即可。没有用户数据库、注册、MFA 或外部认证服务，也没有新增依赖。

## 登录行为与存储

1. Google 将包含 `login_hint` 的请求发到 `GET /authorize`。
2. ZeroAuth 校验 Client ID、Redirect URI、openid scope、邮箱域名及 PKCE 等参数。
3. 首次显示邮箱与密码框；已有有效 Cookie 时显示邮箱与确认按钮。GET 不签发授权码。
4. 表单以 `POST /authorize` 提交。服务端验证签名表单、浏览器绑定、请求来源，以及密码或已有登录 Cookie，之后才创建授权码。
5. Google 在 `/token` 兑换授权码，获得对应邮箱的 RS256 ID Token。

**登录认证无状态**：登录表单使用有效期 10 分钟的签名数据，Cookie 使用有效期 30 天的签名数据，均不写 KV。Cookie 只代表浏览器已验证统一密码，不绑定某个邮箱。每次登录身份以本次经过验证的 `login_hint` 为准。

**保留原项目的 `ZEROAUTH_CODES` KV**：只存短期授权码，兑换时删除。没有新增 KV namespace 或登录事务记录。原有 KV 的 get/delete 流程不提供跨区域并发兑换的原子性保证。

- 登录 Cookie 使用 `HttpOnly; Secure; SameSite=Lax; Path=/` 和 `__Host-` 前缀。
- Cookie 固定有效 30 天；点击确认不延长有效期。浏览器清理 Cookie 后需重新输入密码。
- 签名密钥由已有 Client Secret 与统一密码通过 HMAC 派生，不需要额外的 Session Secret；前端不包含密码或密码哈希。
- 更新 `ZEROAUTH_PASSWORD` 或 Client Secret 会使旧 Cookie 和未完成表单失效。已经签发的 token、授权码和 Google 会话不会因此被撤销。
- 确认页可点击“忘记此浏览器，重新输入密码”，清除此浏览器的认证 Cookie；这不会退出 Google 或撤销复制到其他设备的 Cookie。
- `prompt=login`、`max_age=0` 或超过 `max_age` 要求重新输入密码。`prompt=none` 返回 `login_required` 或 `interaction_required`，不会跳过确认。
- 已移除 `ZEROAUTH_ALLOW_ANY_LOGIN_HINT` 的放行逻辑；即使旧环境仍有此变量，也无法跳过认证。
- 域名白名单精确匹配，不自动允许子域名。知道统一密码或持有有效 Cookie 的人可登录白名单域名内任意目标邮箱；本项目不查询 Google 用户目录。账号须事先存在于 Google，不能使用本服务注册账号。

## 本地开发

需要 Node.js **22.18+**（也支持 24/26）及 npm。

```bash
npm ci
cp .dev.vars.example .dev.vars
node scripts/generate-jwk.mjs
```

编辑 `.dev.vars`，填写自己生成的 RSA `privateJwk`（压缩为单行 JSON）、`kid`、统一密码、随机 Client Secret 和允许域名。模板只有占位符，不包含可部署的私钥或密码；`.dev.vars` 已被 Git 忽略。不要将真实凭据写回模板或提交到仓库。

本地使用 `ZEROAUTH_ISSUER=https://localhost:8787`，然后运行：

```bash
npm run dev -- --local --local-protocol https --port 8787
```

在浏览器打开 `https://localhost:8787/healthz`，按浏览器提示信任本地开发证书。HTTPS 用于测试 Secure Cookie 和同源 POST；不要为了本地测试删除这些保护。

手工测试授权页时，可访问（示例配置允许 `example.com` 及此回调地址）：

```text
https://localhost:8787/authorize?client_id=zeroauth-local-client&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code&scope=openid%20email&login_hint=user01%40example.com&state=local-test
```

`client.example` 仅用于观察重定向，不是真正可兑换授权码的 Google 回调。Google 联调必须使用公开 HTTPS Worker 地址以及 Google 管理后台给出的真实 Redirect URI。

## Cloudflare Workers 部署

### 1. 安装、检查并登录 Cloudflare

```bash
npm ci
npm run typecheck
npm test
npx wrangler login
cp wrangler.toml wrangler.production.toml
```

仓库中的 `wrangler.toml` 仅为通用模板。所有真实域名、账号 ID、KV ID、Client ID 和 Google 回调地址只填入本机的 `wrangler.production.toml`；此文件已被 Git 忽略，不要提交或粘贴到公开 Issue、日志中。`npm run deploy` 会自动选择此私有配置文件。以后如使用 GitHub Actions，应通过仓库或 Environment Secrets 注入真实配置，避免在工作流及构建日志中输出。

### 2. 配置原有授权码 KV

更新现有部署时，可以继续使用原来的 `ZEROAUTH_CODES` namespace。新账号部署时创建自己的 namespace：

```bash
npx wrangler kv namespace create ZEROAUTH_CODES --config wrangler.production.toml
npx wrangler kv namespace create ZEROAUTH_CODES --preview --config wrangler.production.toml
```

把两次返回的 ID 分别填入 `wrangler.production.toml` 中已有的 `[[kv_namespaces]]` 的 `id` 和 `preview_id`。仓库模板中的全零 ID 是占位符，必须替换。保持 `binding = "ZEROAUTH_CODES"`。

### 3. 配置本机生产参数

运行 `node scripts/generate-jwk.mjs` 生成独有的 RSA 私钥和 `kid`。不要使用历史版本示例中的公开私钥。

在 `wrangler.production.toml` 添加以下 `[vars]`，修改示例值：

```toml
[vars]
ZEROAUTH_CLIENT_ID = "zeroauth-google-sso"
ZEROAUTH_KID = "你的生成结果中的-kid"
ZEROAUTH_ISSUER = "https://zeroauth.你的子域.workers.dev"
ZEROAUTH_ALLOWED_EMAIL_DOMAINS = "example.com,second.example"
ZEROAUTH_ALLOWED_REDIRECT_URIS = ""
ZEROAUTH_AUTH_CODE_TTL_SECONDS = "60"
ZEROAUTH_TOKEN_TTL_SECONDS = "3600"
```

- Issuer 必须是 Worker 的公开 HTTPS 地址，与稍后填入 Google 的值完全相同，包括末尾斜杠。建议使用根地址且不加末尾斜杠。
- 域名填写 Google 用户**主邮箱**使用的真实域名，多个域名用逗号分隔。不要填写 `@`、URL 或 `*`。
- 首次可暂时留空 Redirect URI。此时任何授权请求都被拒绝，但配齐 Secrets 后 discovery 和 JWKS 可供 Google 校验。
- `.dev.vars` 只用于本地开发，不会自动作为线上 Secrets 上传。
- 使用自定义域名时，在此私有文件添加 `routes = [{ pattern = "auth.example.com", custom_domain = true }]`（放在 `[vars]` 和 `[[kv_namespaces]]` 之前），将 Issuer 设置为同一 HTTPS 域名，并按需设置 `workers_dev = false`。域名须位于当前 Cloudflare 账号管理的活动区域。

### 4. 创建 Worker 并设置 Secrets

首次部署以创建 Worker 并获取实际 URL：

```bash
npm run deploy
```

尚未配置 Secrets 时接口会返回配置错误。核对部署输出的 URL，如有不同，更新 `ZEROAUTH_ISSUER`。然后交互式设置三个 Secrets：

```bash
npx wrangler secret put ZEROAUTH_PASSWORD --config wrangler.production.toml
npx wrangler secret put ZEROAUTH_CLIENT_SECRET --config wrangler.production.toml
npx wrangler secret put ZEROAUTH_PRIVATE_JWK --config wrangler.production.toml
npm run deploy
```

依次输入统一登录密码、密码管理器生成的长随机 Client Secret、生成结果中的 `privateJwk` 单行 JSON。不要把整个含 `kid` 和 `privateJwk` 的外层对象当作 JWK。Client Secret 稍后还需要填入 Google 管理后台。

Cloudflare 的 `secret put` 会更新并立即部署 Worker 配置；本地开发凭据和生产凭据应分别管理。密码不应放在 `[vars]`、源码、前端或版本库中。

### 5. 检查公开端点

将以下示例主机替换为实际 Worker 地址：

```bash
curl https://zeroauth.你的子域.workers.dev/healthz
curl https://zeroauth.你的子域.workers.dev/.well-known/openid-configuration
curl https://zeroauth.你的子域.workers.dev/jwks.json
```

确认 discovery 中的 `issuer` 与你的配置完全一致，端点指向公开 Worker，JWKS 中有自己的 `kid`、RSA 公钥及 `alg=RS256`。

## Google Workspace / Cloud Identity 自定义 OIDC SSO

Google 的接入要求是 Authorization Code Flow，且 ID Token 的 `email` 必须匹配用户的 Google 主邮箱。ZeroAuth 保留这两项行为。

1. 用管理员账号进入 Google Admin：**安全性 → 身份验证 → 使用第三方 IdP 的单点登录**（Security → Authentication → SSO with third party IdP）。
2. 在第三方 SSO 配置文件中选择 **添加 OIDC 配置文件 / Add OIDC profile**，创建自定义 OIDC 配置，命名为 ZeroAuth。不要选择 Microsoft Entra 的预置配置。
3. 填写：

   | Google 字段 | ZeroAuth 配置 |
   | --- | --- |
   | Client ID | `ZEROAUTH_CLIENT_ID`，如 `zeroauth-google-sso` |
   | Client secret | 保存到 Cloudflare 的 `ZEROAUTH_CLIENT_SECRET` |
   | Issuer URL | `ZEROAUTH_ISSUER`，完全一致 |
   | Change password URL（如界面要求） | `https://你的Worker主机/change-password` |

4. 保存后，在新 OIDC 配置的设置页复制 Google 显示的 **Redirect URI**。
5. 将该 URI 原样填入本机 `wrangler.production.toml` 的 `ZEROAUTH_ALLOWED_REDIRECT_URIS`，再运行 `npm run deploy`。不需要自己猜测 Google 回调地址，也不需要在 Google Cloud Console 创建用于“使用 Google 登录”的 OAuth 客户端。
6. 回到 Google Admin，在 **管理 SSO 配置文件分配** 中，把新建的配置分配给需要使用 SSO 的组织单位（OU）或群组，保存。仅创建配置而不分配，用户不会走 ZeroAuth。
7. 使用普通 Google 用户做联调。Google 的新 SSO 配置不支持超级管理员通过该配置进行 SSO；超级管理员保留直接使用 Google 凭据登录管理后台的路径。
8. 在同一浏览器中启动 `user01@example.com` 的 Google 登录，确认跳到 ZeroAuth、目标邮箱正确，输入统一密码后返回 Google；再启动 `user02@example.com` 的登录，确认只需点“确认登录”且最终进入 user02。
9. 确认错误密码无法登录；清除 ZeroAuth Cookie 或使用一个全新浏览器上下文后需要重新输入密码。Google 已经登录的账号可能直接复用 Google 自身会话，只有发起新 SSO 请求时才会到 ZeroAuth。

### 多个 Google 组织

每个组织分别创建和分配自定义 OIDC 配置。最简单的方式是各组织填写同一个 ZeroAuth Issuer、Client ID 和 Client Secret，把所有真实回调 URI 加入同一个精确白名单，例如：

```toml
ZEROAUTH_ALLOWED_REDIRECT_URIS = "https://accounts.google.com/组织一的真实回调,https://accounts.google.com/组织二的真实回调"
ZEROAUTH_ALLOWED_EMAIL_DOMAINS = "example.com,second.example"
```

以上回调只是格式示意，应从每个组织的 Google Admin 原样复制。也支持 JSON 数组格式的回调白名单。本项目沿用单 Client ID / Secret 配置，不引入多客户端管理系统。

## 环境变量

| 变量 | 必填 | 用途 |
| --- | --- | --- |
| `ZEROAUTH_PASSWORD` | 是，Secret | 所有邮箱共用的密码 |
| `ZEROAUTH_ALLOWED_EMAIL_DOMAINS` | 是 | 逗号分隔的精确域名白名单；为空时拒绝启动 |
| `ZEROAUTH_CLIENT_ID` | 是 | 原有的单一 OAuth Client ID |
| `ZEROAUTH_CLIENT_SECRET` | 是，Secret | Google token 兑换客户端认证；同时参与派生浏览器签名密钥 |
| `ZEROAUTH_PRIVATE_JWK` | 是，Secret | RSA 私钥 JWK，JSON 字符串，RS256 |
| `ZEROAUTH_KID` | 是 | RSA 签名密钥标识 |
| `ZEROAUTH_ISSUER` | 是 | 公开 HTTPS Issuer，必须与 Google 配置完全一致 |
| `ZEROAUTH_ALLOWED_REDIRECT_URIS` | 否 | 逗号分隔或 JSON 数组格式的回调白名单；为空则拒绝全部授权 |
| `ZEROAUTH_AUTH_CODE_TTL_SECONDS` | 否 | 授权码有效期，默认 60 秒；Workers KV 要求至少 60 秒 |
| `ZEROAUTH_TOKEN_TTL_SECONDS` | 否 | Access Token / ID Token 有效期，默认 3600 秒 |
| `ZEROAUTH_CODES` | 是，KV binding | 沿用现有授权码存储 |

缺少统一密码或合法域名白名单会返回配置错误，不会回退到无认证模式。没有新增 Session Secret 或数据库配置。

## 保留的接口与 OIDC 行为

- `GET /.well-known/openid-configuration`
- `GET /jwks.json`
- `GET /authorize`：校验请求，显示密码页或确认页
- `POST /authorize`：校验认证，成功后创建授权码
- `POST /token`：原有授权码兑换、Client Secret Basic/Post、PKCE plain/S256
- `GET /userinfo`：校验 ZeroAuth JWT Access Token
- `GET /healthz`
- `GET /change-password`：说明由管理者通过 Secret 修改统一密码

保留 `state`、`nonce`、PKCE、RS256、邮箱小写规范化、`email_verified` 与原有 `sub = SHA-256(规范化邮箱)`。Cookie 复用时 `auth_time` 保留最近一次密码认证时间。不会签发 Refresh Token。

本项目适用于全部账号都由同一个人控制、共享密码符合预期的场景。没有实现分布式密码尝试限速或按用户权限管理；请使用长且独有的统一密码。

## 验证

```bash
npm run typecheck
npm test
npm run deploy -- --dry-run
```

测试覆盖正确/错误密码、直接请求无法绕过、多个邮箱共用密码、记住浏览器后确认登录、Cookie/表单篡改、CSRF、过期、密码更新、域名限制，以及原有 token 兑换、PKCE、nonce、state、userinfo、JWKS 和 RS256 签名验证。自动测试使用本地模拟 KV；真实 Cloudflare 部署与 Google 登录仍需按上面的步骤进行联调。

## 官方参考

- [Google Cloud Identity：自定义 OIDC SSO 与配置分配](https://support.google.com/cloudidentity/answer/12032922?hl=en)
- [Google：超级管理员 SSO 的限制](https://support.google.com/a/answer/6341409?hl=en)
- [Cloudflare Workers Secrets](https://developers.cloudflare.com/workers/configuration/secrets/)
- [Cloudflare Workers KV 的一致性](https://developers.cloudflare.com/kv/concepts/how-kv-works/)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
