# grok-rs

面向 Claude Code 的 Grok OAuth 多账号网关。Rust 控制面提供管理 UI、账号操作和流式反向代理；镜像内的 Grok 执行器负责 OAuth、协议转换、Token 刷新及账号调度。

## 启动

```bash
API_KEY=sk-your-api-key \
ADMIN_PASSWORD=your-admin-password \
GROK_MANAGEMENT_KEY=your-internal-key \
docker compose up -d --build
```

也可以直接使用 GitHub Actions 自动构建的多架构镜像：

```bash
docker pull ghcr.io/yunyang906/grok-rs:latest
```

打开 `http://localhost:8991`，使用 `ADMIN_PASSWORD` 登录后台后添加一个或多个 xAI 账号。登录成功后服务端会签发 HttpOnly 会话 Cookie，管理员密码不会保存在浏览器。登录凭据保存在 `/data/auth`，生产部署必须挂载持久卷到 `/data`。

> 本地 HTTP 测试需要设置 `COOKIE_SECURE=false`；Zeabur 等公网 HTTPS 部署保持默认的 `true`。

Claude Code 配置：

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "http://127.0.0.1:8991",
    "ANTHROPIC_AUTH_TOKEN": "sk-your-api-key",
    "ANTHROPIC_DEFAULT_OPUS_MODEL": "claude-opus-4-5-20251101"
  },
  "model": "claude-opus-4-5-20251101"
}
```

## Zeabur

- 使用本仓库 Dockerfile 部署。
- 服务端口设为 `8991`。
- 挂载 Volume 到 `/data`。
- 设置 `API_KEY`、`ADMIN_PASSWORD`、`GROK_MANAGEMENT_KEY` 三个不同的强随机值，均至少 12 个字符。
- `COOKIE_SECURE` 设置为 `true`，只允许浏览器通过 HTTPS 发送后台会话。

### 公网安全

- 后台账号接口必须先通过管理员密码登录。
- 会话 Cookie 使用 `HttpOnly`、`SameSite=Strict` 和 `Secure`。
- 同一来源十分钟内连续失败五次会临时禁止继续登录。
- 后台页面不会返回 access token 或 refresh token。
- 内部 Grok 引擎仅监听容器内的 `127.0.0.1:8318`。
- 不要公开 `/data`，也不要把任何真实凭据提交到 Git。

## 说明

当前 MVP 使用开源 CLIProxyAPI 作为镜像内 Grok 协议执行器（MIT License），Rust 层负责产品化控制面。后续可以逐步将 OAuth 和 Responses 转换模块原生移植到 Rust，而不改变外部 API 和数据目录。
