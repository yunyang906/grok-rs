# grok-rs

面向 Claude Code 的 Grok OAuth 多账号网关。Rust 控制面提供管理 UI、账号操作和流式反向代理；镜像内的 Grok 执行器负责 OAuth、协议转换、Token 刷新及账号调度。

## 启动

```bash
API_KEY=sk-your-api-key \
ADMIN_API_KEY=your-admin-key \
GROK_MANAGEMENT_KEY=your-internal-key \
docker compose up -d --build
```

打开 `http://localhost:8991`，输入 `ADMIN_API_KEY` 后添加一个或多个 xAI 账号。登录凭据保存在 `/data/auth`，生产部署必须挂载持久卷到 `/data`。

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
- 设置 `API_KEY`、`ADMIN_API_KEY`、`GROK_MANAGEMENT_KEY` 三个不同的强随机值。

## 说明

当前 MVP 使用开源 CLIProxyAPI 作为镜像内 Grok 协议执行器（MIT License），Rust 层负责产品化控制面。后续可以逐步将 OAuth 和 Responses 转换模块原生移植到 Rust，而不改变外部 API 和数据目录。

