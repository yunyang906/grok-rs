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

后台的“用户与 API Keys”页面可以签发独立访问 Key。每个 Key 支持首次调用后开始计算有效期、复制、停用和删除；主 `API_KEY` 始终保留为管理员自用密钥。用户 Key 保存在 `/data/api_keys.json`，不会写入日志。

首页会按主 Key 和每个用户 Key 汇总成功请求数、输入 Token、输出 Token、缓存 Token、调用模型和最近使用时间。普通 JSON 响应和 SSE 流式响应均直接读取 Anthropic `usage` 字段，统计结果持久化到 `/data/api_key_usage.json`。历史请求不会被追溯补录，升级后的新请求才开始统计。

首页和账号池还会分别显示每个 Grok OAuth 订阅账号的真实额度，包括订阅档位、已用/剩余百分比、额度周期、重置时间和额外用量状态。数据由服务端使用账号凭据请求 Grok CLI Billing 接口，成功结果缓存 5 分钟；access token 和 refresh token 始终不会返回浏览器。

“调度设置”页面可以热更新账号选择策略、会话粘滞时长和失败重试次数，并为每个 OAuth 账号设置 `-100` 至 `100` 的优先级。优先级数值越高越先使用；同一最高优先级内再使用 `round-robin`（均衡轮询）或 `fill-first`（优先用满）策略。账号不可用或进入冷却时会自动故障切换。

> 本地 HTTP 测试需要设置 `COOKIE_SECURE=false`；Zeabur 等公网 HTTPS 部署保持默认的 `true`。

Claude Code 配置：

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "http://127.0.0.1:8991",
    "ANTHROPIC_AUTH_TOKEN": "sk-your-api-key",
    "ANTHROPIC_DEFAULT_OPUS_MODEL": "grok-4.5"
  },
  "model": "grok-4.5"
}
```

服务不会创建 Claude 模型别名，也不会把模型名称映射为其他值。客户端应直接使用 `/v1/models` 返回的实际 Grok 模型名称，例如 `grok-4.5`。

为其他使用者配置 Claude Code 时，把 `ANTHROPIC_AUTH_TOKEN` 换成后台签发的用户 Key 即可；所有用户仍使用同一个公网 `ANTHROPIC_BASE_URL`。

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
