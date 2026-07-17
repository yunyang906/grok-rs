use std::{
    collections::HashMap,
    env,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Path as AxumPath, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{any, delete, get, patch, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::{process::Child, sync::Mutex, time::sleep};
use tower_http::trace::TraceLayer;

const INDEX_HTML: &str = include_str!("../static/index.html");
const SESSION_COOKIE: &str = "grok_admin_session";
const SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const LOGIN_WINDOW: Duration = Duration::from_secs(10 * 60);
const MAX_LOGIN_FAILURES: usize = 5;

#[derive(Clone)]
struct AppState {
    client: Client,
    engine_url: String,
    management_key: String,
    admin_password_hash: [u8; 32],
    cookie_secure: bool,
    sessions: Arc<Mutex<HashMap<String, Instant>>>,
    login_failures: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>,
    child: Arc<Mutex<Option<Child>>>,
}

#[derive(Deserialize)]
struct LoginStatusQuery {
    state: String,
}

#[derive(Deserialize)]
struct AccountStatus {
    disabled: bool,
}

#[derive(Deserialize)]
struct AdminLoginRequest {
    password: String,
}

#[derive(Serialize)]
struct AuthStatus {
    authenticated: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "grok_rs=info,tower_http=info".into()),
        )
        .init();

    let bind = env::var("BIND").unwrap_or_else(|_| "0.0.0.0:8991".to_string());
    let engine_url =
        env::var("GROK_ENGINE_URL").unwrap_or_else(|_| "http://127.0.0.1:8318".to_string());
    let management_key = required_secret("GROK_MANAGEMENT_KEY")?;
    let admin_password = required_secret("ADMIN_PASSWORD")?;
    let cookie_secure = env::var("COOKIE_SECURE")
        .map(|value| value != "false" && value != "0")
        .unwrap_or(true);

    let child = start_engine_if_configured(&management_key).await?;
    let state = AppState {
        client: Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .build()?,
        engine_url,
        management_key,
        admin_password_hash: Sha256::digest(admin_password.as_bytes()).into(),
        cookie_secure,
        sessions: Arc::new(Mutex::new(HashMap::new())),
        login_failures: Arc::new(Mutex::new(HashMap::new())),
        child: Arc::new(Mutex::new(child)),
    };

    wait_for_engine(&state).await?;

    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/api/auth/session", get(auth_session))
        .route("/api/auth/login", post(admin_login))
        .route("/api/auth/logout", post(admin_logout))
        .route("/api/admin/accounts", get(list_accounts))
        .route("/api/admin/accounts/{name}", delete(delete_account))
        .route(
            "/api/admin/accounts/{name}/status",
            patch(set_account_status),
        )
        .route("/api/admin/login", post(start_login))
        .route("/api/admin/login/status", get(login_status))
        .route("/v1/{*path}", any(proxy_v1))
        .route("/cc/{*path}", any(proxy_cc))
        .layer(middleware::from_fn(security_headers))
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    let addr: SocketAddr = bind.parse().context("invalid BIND address")?;
    tracing::info!(%addr, "grok-rs listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(state))
    .await?;
    Ok(())
}

fn required_secret(name: &str) -> Result<String> {
    let value = env::var(name).with_context(|| format!("{name} is required"))?;
    if value.trim().len() < 12 {
        anyhow::bail!("{name} must contain at least 12 characters");
    }
    Ok(value)
}

async fn start_engine_if_configured(management_key: &str) -> Result<Option<Child>> {
    let bin = env::var("GROK_ENGINE_BIN").unwrap_or_default();
    if bin.is_empty() {
        tracing::info!("GROK_ENGINE_BIN is unset; using an externally managed engine");
        return Ok(None);
    }

    let config_path = PathBuf::from(
        env::var("GROK_ENGINE_CONFIG").unwrap_or_else(|_| "/data/engine.yaml".to_string()),
    );
    ensure_engine_config(&config_path, management_key).await?;

    let child = tokio::process::Command::new(&bin)
        .arg("-config")
        .arg(&config_path)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to start Grok engine: {bin}"))?;
    tracing::info!(pid = child.id(), "Grok engine started");
    Ok(Some(child))
}

async fn ensure_engine_config(path: &Path, management_key: &str) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let public_key = required_secret("API_KEY")?;
    let auth_dir = env::var("GROK_AUTH_DIR").unwrap_or_else(|_| "/data/auth".to_string());
    let config = format!(
        r#"host: "127.0.0.1"
port: 8318
auth-dir: "{auth_dir}"
api-keys:
  - "{public_key}"
remote-management:
  allow-remote: false
  secret-key: "{management_key}"
  disable-control-panel: true
debug: false
logging-to-file: false
usage-statistics-enabled: false
request-retry: 2
oauth-model-alias:
  xai:
    - name: "grok-4.5"
      alias: "claude-opus-4-5-20251101"
      fork: true
      force-mapping: true
"#
    );
    tokio::fs::write(path, config).await?;
    Ok(())
}

async fn wait_for_engine(state: &AppState) -> Result<()> {
    for _ in 0..60 {
        if state
            .client
            .get(format!("{}/", state.engine_url))
            .send()
            .await
            .is_ok()
        {
            return Ok(());
        }
        sleep(Duration::from_millis(500)).await;
    }
    anyhow::bail!("Grok engine did not become ready at {}", state.engine_url)
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let engine = state
        .client
        .get(format!("{}/", state.engine_url))
        .send()
        .await
        .is_ok();
    let managed = state.child.lock().await.is_some();
    (
        StatusCode::OK,
        axum::Json(json!({"ok": engine, "engine_managed": managed})),
    )
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_string())
}

async fn authorize_admin(headers: &HeaderMap, state: &AppState) -> Result<(), StatusCode> {
    let token = cookie_value(headers, SESSION_COOKIE).ok_or(StatusCode::UNAUTHORIZED)?;
    let now = Instant::now();
    let mut sessions = state.sessions.lock().await;
    sessions.retain(|_, expires_at| *expires_at > now);
    match sessions.get_mut(&token) {
        Some(expires_at) => {
            *expires_at = now + SESSION_TTL;
            Ok(())
        }
        None => Err(StatusCode::UNAUTHORIZED),
    }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({"error": "请先登录管理后台"})),
    )
        .into_response()
}

async fn auth_session(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    axum::Json(AuthStatus {
        authenticated: authorize_admin(&headers, &state).await.is_ok(),
    })
}

async fn admin_login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    axum::Json(payload): axum::Json<AdminLoginRequest>,
) -> Response {
    let now = Instant::now();
    {
        let mut failures = state.login_failures.lock().await;
        let attempts = failures.entry(peer.ip()).or_default();
        attempts.retain(|attempt| now.duration_since(*attempt) < LOGIN_WINDOW);
        if attempts.len() >= MAX_LOGIN_FAILURES {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                axum::Json(json!({"error": "登录失败次数过多，请十分钟后再试"})),
            )
                .into_response();
        }
    }

    let supplied: [u8; 32] = Sha256::digest(payload.password.as_bytes()).into();
    if !bool::from(supplied.ct_eq(&state.admin_password_hash)) {
        state
            .login_failures
            .lock()
            .await
            .entry(peer.ip())
            .or_default()
            .push(now);
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "管理员密码错误"})),
        )
            .into_response();
    }
    state.login_failures.lock().await.remove(&peer.ip());

    let mut random = [0u8; 32];
    rand::rng().fill_bytes(&mut random);
    let token = URL_SAFE_NO_PAD.encode(random);
    state
        .sessions
        .lock()
        .await
        .insert(token.clone(), now + SESSION_TTL);
    let secure = if state.cookie_secure { "; Secure" } else { "" };
    let cookie = format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
        SESSION_TTL.as_secs(),
        secure
    );
    let mut response = axum::Json(json!({"ok": true})).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("valid session cookie"),
    );
    response
}

async fn admin_logout(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(token) = cookie_value(&headers, SESSION_COOKIE) {
        state.sessions.lock().await.remove(&token);
    }
    let secure = if state.cookie_secure { "; Secure" } else { "" };
    let cookie = format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}");
    let mut response = axum::Json(json!({"ok": true})).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("valid logout cookie"),
    );
    response
}

async fn management_request(
    state: &AppState,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Response {
    let mut request = state
        .client
        .request(method, format!("{}{path}", state.engine_url))
        .bearer_auth(&state.management_key);
    if let Some(body) = body {
        request = request.json(&body);
    }
    match request.send().await {
        Ok(response) => relay_response(response),
        Err(error) => (
            StatusCode::BAD_GATEWAY,
            axum::Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn list_accounts(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if authorize_admin(&headers, &state).await.is_err() {
        return unauthorized();
    }
    management_request(&state, Method::GET, "/v0/management/auth-files", None).await
}

async fn start_login(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if authorize_admin(&headers, &state).await.is_err() {
        return unauthorized();
    }
    management_request(&state, Method::GET, "/v0/management/xai-auth-url", None).await
}

async fn login_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<LoginStatusQuery>,
) -> Response {
    if authorize_admin(&headers, &state).await.is_err() {
        return unauthorized();
    }
    let path = format!(
        "/v0/management/get-auth-status?state={}",
        urlencoding::encode(&query.state)
    );
    management_request(&state, Method::GET, &path, None).await
}

async fn delete_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> Response {
    if authorize_admin(&headers, &state).await.is_err() {
        return unauthorized();
    }
    let path = format!(
        "/v0/management/auth-files?name={}",
        urlencoding::encode(&name)
    );
    management_request(&state, Method::DELETE, &path, None).await
}

async fn set_account_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
    axum::Json(payload): axum::Json<AccountStatus>,
) -> Response {
    if authorize_admin(&headers, &state).await.is_err() {
        return unauthorized();
    }
    management_request(
        &state,
        Method::PATCH,
        "/v0/management/auth-files/status",
        Some(json!({"name": name, "disabled": payload.disabled})),
    )
    .await
}

async fn proxy_v1(State(state): State<AppState>, request: Request) -> Response {
    proxy_request(state, request).await
}

async fn proxy_cc(State(state): State<AppState>, request: Request) -> Response {
    proxy_request(state, request).await
}

async fn proxy_request(state: AppState, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let suffix = parts
        .uri
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or("/");
    let target = format!("{}{}", state.engine_url, suffix);
    let bytes = match axum::body::to_bytes(body, 64 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            return (StatusCode::BAD_REQUEST, error.to_string()).into_response();
        }
    };
    let mut upstream = state.client.request(parts.method, target).body(bytes);
    for (name, value) in &parts.headers {
        if name.as_str().eq_ignore_ascii_case("host") {
            continue;
        }
        upstream = upstream.header(name, value);
    }
    match upstream.send().await {
        Ok(response) => relay_response(response),
        Err(error) => (StatusCode::BAD_GATEWAY, error.to_string()).into_response(),
    }
}

fn relay_response(upstream: reqwest::Response) -> Response {
    let status = upstream.status();
    let headers = upstream.headers().clone();
    let stream = upstream.bytes_stream();
    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = status;
    for (name, value) in &headers {
        if name.as_str().eq_ignore_ascii_case("content-length")
            || name.as_str().eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        response.headers_mut().insert(name, value.clone());
    }
    response
}

async fn shutdown_signal(state: AppState) {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! { _ = ctrl_c => {}, _ = terminate => {} }
    if let Some(child) = state.child.lock().await.as_mut() {
        let _ = child.kill().await;
    }
}
