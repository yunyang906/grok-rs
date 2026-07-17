use std::{
    collections::HashMap,
    env,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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
use futures_util::StreamExt;
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
    public_api_key: String,
    issued_keys: Arc<Mutex<Vec<IssuedApiKey>>>,
    issued_keys_path: PathBuf,
    usage: Arc<Mutex<Vec<KeyUsage>>>,
    usage_path: PathBuf,
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

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IssuedApiKey {
    id: u64,
    key: String,
    name: String,
    enabled: bool,
    created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    duration_days: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    activated_at: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateIssuedKeyRequest {
    name: String,
    duration_days: Option<f64>,
}

#[derive(Deserialize)]
struct UpdateIssuedKeyRequest {
    name: Option<String>,
    enabled: Option<bool>,
}

#[derive(Clone)]
struct ApiIdentity {
    key_id: u64,
    key_name: String,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyUsage {
    api_key_id: u64,
    api_key_name: String,
    request_count: u64,
    input_tokens: u64,
    output_tokens: u64,
    cache_creation_input_tokens: u64,
    cache_read_input_tokens: u64,
    last_used_at: u64,
    #[serde(default)]
    by_model: HashMap<String, ModelUsage>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ModelUsage {
    request_count: u64,
    input_tokens: u64,
    output_tokens: u64,
}

#[derive(Default, Debug, PartialEq)]
struct UsageDelta {
    input_tokens: u64,
    output_tokens: u64,
    cache_creation_input_tokens: u64,
    cache_read_input_tokens: u64,
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
    let public_api_key = required_secret("API_KEY")?;
    let admin_password = required_secret("ADMIN_PASSWORD")?;
    let cookie_secure = env::var("COOKIE_SECURE")
        .map(|value| value != "false" && value != "0")
        .unwrap_or(true);

    let issued_keys_path = PathBuf::from(
        env::var("API_KEYS_FILE").unwrap_or_else(|_| "/data/api_keys.json".to_string()),
    );
    let usage_path = PathBuf::from(
        env::var("API_KEY_USAGE_FILE").unwrap_or_else(|_| "/data/api_key_usage.json".to_string()),
    );
    let issued_keys = load_issued_keys(&issued_keys_path).await?;
    let usage = load_usage(&usage_path).await?;
    let child = start_engine_if_configured(&management_key, &public_api_key).await?;
    let state = AppState {
        client: Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .build()?,
        engine_url,
        management_key,
        public_api_key,
        issued_keys: Arc::new(Mutex::new(issued_keys)),
        issued_keys_path,
        usage: Arc::new(Mutex::new(usage)),
        usage_path,
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
        .route(
            "/api/admin/api-keys",
            get(list_issued_keys).post(create_issued_key),
        )
        .route(
            "/api/admin/api-keys/{id}",
            patch(update_issued_key).delete(delete_issued_key),
        )
        .route("/api/admin/usage", get(list_usage))
        .route("/api/admin/usage/{id}", delete(reset_usage))
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

async fn start_engine_if_configured(
    management_key: &str,
    public_api_key: &str,
) -> Result<Option<Child>> {
    let bin = env::var("GROK_ENGINE_BIN").unwrap_or_default();
    if bin.is_empty() {
        tracing::info!("GROK_ENGINE_BIN is unset; using an externally managed engine");
        return Ok(None);
    }

    let config_path = PathBuf::from(
        env::var("GROK_ENGINE_CONFIG").unwrap_or_else(|_| "/data/engine.yaml".to_string()),
    );
    ensure_engine_config(&config_path, management_key, public_api_key).await?;

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

async fn ensure_engine_config(
    path: &Path,
    management_key: &str,
    public_api_key: &str,
) -> Result<()> {
    if path.exists() {
        let existing = tokio::fs::read_to_string(path).await?;
        let migrated = remove_top_level_yaml_section(&existing, "oauth-model-alias");
        if migrated != existing {
            tokio::fs::write(path, migrated).await?;
            tracing::info!(
                path = %path.display(),
                "removed legacy model aliases; upstream model names are now used directly"
            );
        }
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let auth_dir = env::var("GROK_AUTH_DIR").unwrap_or_else(|_| "/data/auth".to_string());
    let config = format!(
        r#"host: "127.0.0.1"
port: 8318
auth-dir: "{auth_dir}"
api-keys:
  - "{public_api_key}"
remote-management:
  allow-remote: false
  secret-key: "{management_key}"
  disable-control-panel: true
debug: false
logging-to-file: false
usage-statistics-enabled: false
request-retry: 2
"#
    );
    tokio::fs::write(path, config).await?;
    Ok(())
}

async fn load_issued_keys(path: &Path) -> Result<Vec<IssuedApiKey>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = tokio::fs::read_to_string(path).await?;
    if content.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(&content).context("invalid issued API key file")
}

async fn save_issued_keys(path: &Path, keys: &[IssuedApiKey]) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let temporary = path.with_extension("json.tmp");
    tokio::fs::write(&temporary, serde_json::to_vec_pretty(keys)?).await?;
    tokio::fs::rename(temporary, path).await?;
    Ok(())
}

async fn load_usage(path: &Path) -> Result<Vec<KeyUsage>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = tokio::fs::read_to_string(path).await?;
    if content.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(&content).context("invalid API key usage file")
}

async fn save_usage(path: &Path, usage: &[KeyUsage]) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let temporary = path.with_extension("json.tmp");
    tokio::fs::write(&temporary, serde_json::to_vec_pretty(usage)?).await?;
    tokio::fs::rename(temporary, path).await?;
    Ok(())
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn generate_issued_key() -> String {
    let mut bytes = [0_u8; 24];
    rand::rng().fill_bytes(&mut bytes);
    format!("sk-{}", URL_SAFE_NO_PAD.encode(bytes))
}

fn remove_top_level_yaml_section(input: &str, section: &str) -> String {
    let section_header = format!("{section}:");
    let mut skipping = false;
    let mut kept = Vec::new();

    for line in input.lines() {
        let trimmed = line.trim();
        let is_top_level =
            !line.starts_with([' ', '\t']) && !trimmed.is_empty() && !trimmed.starts_with('#');

        if !skipping && is_top_level && trimmed == section_header {
            skipping = true;
            continue;
        }
        if skipping && is_top_level {
            skipping = false;
        }
        if !skipping {
            kept.push(line);
        }
    }

    let mut result = kept.join("\n");
    if input.ends_with('\n') && !result.ends_with('\n') {
        result.push('\n');
    }
    result
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

async fn list_issued_keys(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if authorize_admin(&headers, &state).await.is_err() {
        return unauthorized();
    }
    axum::Json(state.issued_keys.lock().await.clone()).into_response()
}

async fn create_issued_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(payload): axum::Json<CreateIssuedKeyRequest>,
) -> Response {
    if authorize_admin(&headers, &state).await.is_err() {
        return unauthorized();
    }
    let name = payload.name.trim();
    if name.is_empty() || name.chars().count() > 80 {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "用户名称必须为 1–80 个字符"})),
        )
            .into_response();
    }
    if payload
        .duration_days
        .is_some_and(|days| !days.is_finite() || days <= 0.0 || days > 3650.0)
    {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "有效期必须大于 0 且不超过 3650 天"})),
        )
            .into_response();
    }

    let mut keys = state.issued_keys.lock().await;
    let issued = IssuedApiKey {
        id: keys.iter().map(|key| key.id).max().unwrap_or(0) + 1,
        key: generate_issued_key(),
        name: name.to_string(),
        enabled: true,
        created_at: unix_seconds(),
        expires_at: None,
        duration_days: payload.duration_days,
        activated_at: None,
    };
    keys.push(issued.clone());
    if let Err(error) = save_issued_keys(&state.issued_keys_path, &keys).await {
        keys.pop();
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": error.to_string()})),
        )
            .into_response();
    }
    (StatusCode::CREATED, axum::Json(issued)).into_response()
}

async fn update_issued_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<u64>,
    axum::Json(payload): axum::Json<UpdateIssuedKeyRequest>,
) -> Response {
    if authorize_admin(&headers, &state).await.is_err() {
        return unauthorized();
    }
    if payload.name.as_ref().is_some_and(|name| {
        let length = name.trim().chars().count();
        length == 0 || length > 80
    }) {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "用户名称必须为 1–80 个字符"})),
        )
            .into_response();
    }

    let mut keys = state.issued_keys.lock().await;
    let Some(index) = keys.iter().position(|key| key.id == id) else {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "API Key 不存在"})),
        )
            .into_response();
    };
    let previous = keys[index].clone();
    if let Some(name) = payload.name {
        keys[index].name = name.trim().to_string();
    }
    if let Some(enabled) = payload.enabled {
        keys[index].enabled = enabled;
    }
    let updated = keys[index].clone();
    if let Err(error) = save_issued_keys(&state.issued_keys_path, &keys).await {
        keys[index] = previous;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": error.to_string()})),
        )
            .into_response();
    }
    axum::Json(updated).into_response()
}

async fn delete_issued_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<u64>,
) -> Response {
    if authorize_admin(&headers, &state).await.is_err() {
        return unauthorized();
    }
    let mut keys = state.issued_keys.lock().await;
    let Some(index) = keys.iter().position(|key| key.id == id) else {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "API Key 不存在"})),
        )
            .into_response();
    };
    let removed = keys.remove(index);
    if let Err(error) = save_issued_keys(&state.issued_keys_path, &keys).await {
        keys.insert(index, removed);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": error.to_string()})),
        )
            .into_response();
    }
    axum::Json(json!({"ok": true})).into_response()
}

async fn list_usage(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if authorize_admin(&headers, &state).await.is_err() {
        return unauthorized();
    }
    axum::Json(state.usage.lock().await.clone()).into_response()
}

async fn reset_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<u64>,
) -> Response {
    if authorize_admin(&headers, &state).await.is_err() {
        return unauthorized();
    }
    let mut usage = state.usage.lock().await;
    let previous = usage.clone();
    usage.retain(|item| item.api_key_id != id);
    if let Err(error) = save_usage(&state.usage_path, &usage).await {
        *usage = previous;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": error.to_string()})),
        )
            .into_response();
    }
    axum::Json(json!({"ok": true})).into_response()
}

fn request_api_key(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
    {
        return Some(value.trim().to_string());
    }
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|value| value.trim().to_string())
}

async fn authorize_api_request(
    state: &AppState,
    headers: &HeaderMap,
) -> std::result::Result<ApiIdentity, (StatusCode, &'static str)> {
    let supplied = request_api_key(headers).ok_or((StatusCode::UNAUTHORIZED, "Missing API key"))?;
    if bool::from(supplied.as_bytes().ct_eq(state.public_api_key.as_bytes())) {
        return Ok(ApiIdentity {
            key_id: 0,
            key_name: "主 API Key".to_string(),
        });
    }

    let mut keys = state.issued_keys.lock().await;
    let Some(index) = keys
        .iter()
        .position(|key| bool::from(supplied.as_bytes().ct_eq(key.key.as_bytes())))
    else {
        return Err((StatusCode::UNAUTHORIZED, "Invalid API key"));
    };
    if !keys[index].enabled {
        return Err((StatusCode::FORBIDDEN, "API key is disabled"));
    }
    let now = unix_seconds();
    if keys[index].expires_at.is_some_and(|expires| expires <= now) {
        return Err((StatusCode::FORBIDDEN, "API key has expired"));
    }
    if keys[index].duration_days.is_some() && keys[index].activated_at.is_none() {
        let lifetime = (keys[index].duration_days.unwrap() * 86_400.0).round() as u64;
        keys[index].activated_at = Some(now);
        keys[index].expires_at = Some(now.saturating_add(lifetime));
        if let Err(error) = save_issued_keys(&state.issued_keys_path, &keys).await {
            tracing::error!(%error, id = keys[index].id, "failed to persist API key activation");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to activate API key",
            ));
        }
    }
    Ok(ApiIdentity {
        key_id: keys[index].id,
        key_name: keys[index].name.clone(),
    })
}

fn api_auth_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        axum::Json(json!({
            "type": "error",
            "error": {"type": "authentication_error", "message": message}
        })),
    )
        .into_response()
}

async fn proxy_v1(State(state): State<AppState>, request: Request) -> Response {
    proxy_request(state, request).await
}

async fn proxy_cc(State(state): State<AppState>, request: Request) -> Response {
    proxy_request(state, request).await
}

async fn proxy_request(state: AppState, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let identity = match authorize_api_request(&state, &parts.headers).await {
        Ok(identity) => identity,
        Err((status, message)) => return api_auth_error(status, message),
    };
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
    let model = serde_json::from_slice::<Value>(&bytes)
        .ok()
        .and_then(|value| value.get("model")?.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string());
    let mut upstream = state.client.request(parts.method, target).body(bytes);
    for (name, value) in &parts.headers {
        if name.as_str().eq_ignore_ascii_case("host")
            || name.as_str().eq_ignore_ascii_case("x-api-key")
            || name.as_str().eq_ignore_ascii_case("authorization")
        {
            continue;
        }
        upstream = upstream.header(name, value);
    }
    upstream = upstream
        .header("x-api-key", &state.public_api_key)
        .bearer_auth(&state.public_api_key);
    match upstream.send().await {
        Ok(response) => relay_response_with_usage(response, state, identity, model),
        Err(error) => (StatusCode::BAD_GATEWAY, error.to_string()).into_response(),
    }
}

fn usage_number(usage: &Value, primary: &str, compatible: &str) -> u64 {
    usage
        .get(primary)
        .or_else(|| usage.get(compatible))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

fn merge_usage_value(delta: &mut UsageDelta, value: &Value) -> bool {
    let usage = value
        .get("usage")
        .or_else(|| value.pointer("/message/usage"));
    let Some(usage) = usage else {
        return false;
    };
    delta.input_tokens =
        delta
            .input_tokens
            .max(usage_number(usage, "input_tokens", "prompt_tokens"));
    delta.output_tokens =
        delta
            .output_tokens
            .max(usage_number(usage, "output_tokens", "completion_tokens"));
    delta.cache_creation_input_tokens = delta.cache_creation_input_tokens.max(
        usage
            .get("cache_creation_input_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    );
    delta.cache_read_input_tokens = delta.cache_read_input_tokens.max(
        usage
            .get("cache_read_input_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    );
    true
}

fn extract_usage_delta(body: &[u8]) -> Option<UsageDelta> {
    let mut delta = UsageDelta::default();
    if let Ok(value) = serde_json::from_slice::<Value>(body) {
        return merge_usage_value(&mut delta, &value).then_some(delta);
    }

    let mut found = false;
    for line in String::from_utf8_lossy(body).lines() {
        let Some(data) = line.strip_prefix("data:") else {
            continue;
        };
        let data = data.trim();
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(data) {
            found |= merge_usage_value(&mut delta, &value);
        }
    }
    found.then_some(delta)
}

async fn record_usage(
    state: &AppState,
    identity: &ApiIdentity,
    model: &str,
    delta: UsageDelta,
) -> Result<()> {
    let mut usage = state.usage.lock().await;
    let index = match usage
        .iter()
        .position(|item| item.api_key_id == identity.key_id)
    {
        Some(index) => index,
        None => {
            usage.push(KeyUsage {
                api_key_id: identity.key_id,
                api_key_name: identity.key_name.clone(),
                ..KeyUsage::default()
            });
            usage.len() - 1
        }
    };
    let item = &mut usage[index];
    item.api_key_name = identity.key_name.clone();
    item.request_count += 1;
    item.input_tokens += delta.input_tokens;
    item.output_tokens += delta.output_tokens;
    item.cache_creation_input_tokens += delta.cache_creation_input_tokens;
    item.cache_read_input_tokens += delta.cache_read_input_tokens;
    item.last_used_at = unix_seconds();
    let model_usage = item.by_model.entry(model.to_string()).or_default();
    model_usage.request_count += 1;
    model_usage.input_tokens += delta.input_tokens;
    model_usage.output_tokens += delta.output_tokens;
    save_usage(&state.usage_path, &usage).await
}

fn relay_response_with_usage(
    upstream: reqwest::Response,
    state: AppState,
    identity: ApiIdentity,
    model: String,
) -> Response {
    const CAPTURE_LIMIT: usize = 16 * 1024 * 1024;
    let status = upstream.status();
    let headers = upstream.headers().clone();
    let observed = async_stream::stream! {
        let mut stream = upstream.bytes_stream();
        let mut captured = Vec::new();
        while let Some(result) = stream.next().await {
            if let Ok(bytes) = &result
                && captured.len() < CAPTURE_LIMIT
            {
                let remaining = CAPTURE_LIMIT - captured.len();
                captured.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
            }
            yield result;
        }
        if status.is_success()
            && let Some(delta) = extract_usage_delta(&captured)
            && let Err(error) = record_usage(&state, &identity, &model, delta).await
        {
            tracing::error!(%error, key_id = identity.key_id, "failed to persist API key usage");
        }
    };
    let mut response = Response::new(Body::from_stream(observed));
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

#[cfg(test)]
mod tests {
    use super::{UsageDelta, extract_usage_delta, remove_top_level_yaml_section};

    #[test]
    fn removes_model_alias_without_removing_following_settings() {
        let config = concat!(
            "host: 127.0.0.1\n",
            "oauth-model-alias:\n",
            "  xai:\n",
            "    - name: grok-4.5\n",
            "      alias: claude-opus-4-5\n",
            "request-retry: 2\n",
        );

        assert_eq!(
            remove_top_level_yaml_section(config, "oauth-model-alias"),
            "host: 127.0.0.1\nrequest-retry: 2\n"
        );
    }

    #[test]
    fn extracts_anthropic_json_usage() {
        let body = br#"{"usage":{"input_tokens":120,"output_tokens":45,"cache_creation_input_tokens":10,"cache_read_input_tokens":30}}"#;
        assert_eq!(
            extract_usage_delta(body),
            Some(UsageDelta {
                input_tokens: 120,
                output_tokens: 45,
                cache_creation_input_tokens: 10,
                cache_read_input_tokens: 30,
            })
        );
    }

    #[test]
    fn extracts_anthropic_sse_usage() {
        let body = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":90,\"output_tokens\":1,\"cache_read_input_tokens\":20}}}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":32}}\n\n",
        );
        assert_eq!(
            extract_usage_delta(body.as_bytes()),
            Some(UsageDelta {
                input_tokens: 90,
                output_tokens: 32,
                cache_creation_input_tokens: 0,
                cache_read_input_tokens: 20,
            })
        );
    }
}
