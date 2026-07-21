use std::{
    collections::{HashMap, VecDeque},
    env,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
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
const ACCOUNT_QUOTA_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

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
    request_events: Arc<Mutex<Vec<RequestEvent>>>,
    request_events_path: PathBuf,
    request_event_limit: usize,
    next_request_event_id: Arc<AtomicU64>,
    request_events_dirty: Arc<AtomicU32>,
    request_events_flush_lock: Arc<Mutex<()>>,
    notification_settings: Arc<Mutex<NotificationSettings>>,
    notification_settings_path: PathBuf,
    last_notification_at: Arc<Mutex<Option<Instant>>>,
    traffic_policy: Arc<Mutex<TrafficPolicy>>,
    traffic_policy_path: PathBuf,
    traffic_runtime: Arc<TrafficRuntime>,
    auth_dir: PathBuf,
    account_quota_cache: Arc<Mutex<HashMap<String, CachedAccountQuota>>>,
    admin_password_hash: [u8; 32],
    cookie_secure: bool,
    sessions: Arc<Mutex<HashMap<String, Instant>>>,
    login_failures: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>,
    child: Arc<Mutex<Option<Child>>>,
    started_at: Instant,
}

#[derive(Clone)]
struct CachedAccountQuota {
    fetched_at: Instant,
    quota: AccountQuota,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountQuota {
    name: String,
    email: String,
    subscription_tier: Option<String>,
    used_percent: Option<f64>,
    remaining_percent: Option<f64>,
    period_type: Option<String>,
    period_start: Option<String>,
    period_end: Option<String>,
    on_demand_cap: Option<i64>,
    on_demand_used: Option<i64>,
    fetched_at: u64,
    error: Option<String>,
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
struct AccountPriority {
    priority: i32,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RoutingSettings {
    strategy: String,
    session_affinity: bool,
    session_affinity_ttl: String,
    request_retry: u8,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrafficPolicy {
    enabled: bool,
    max_concurrent_requests: u32,
    requests_per_minute_per_key: u32,
}

impl Default for TrafficPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            max_concurrent_requests: 8,
            requests_per_minute_per_key: 60,
        }
    }
}

#[derive(Default)]
struct TrafficRuntime {
    active: Arc<AtomicU32>,
    recent_by_key: Mutex<HashMap<u64, VecDeque<Instant>>>,
}

struct TrafficLease {
    active: Arc<AtomicU32>,
    counted: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RealtimeTrafficMetrics {
    window_seconds: u64,
    rpm: u32,
    active_requests: u32,
    protection_enabled: bool,
    rpm_limit_per_key: u32,
    users: Vec<UserRpm>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserRpm {
    api_key_id: u64,
    api_key_name: String,
    rpm: u32,
    rpm_limit: Option<u32>,
    utilization_percent: Option<f64>,
}

impl Drop for TrafficLease {
    fn drop(&mut self) {
        if self.counted {
            self.active.fetch_sub(1, Ordering::AcqRel);
        }
    }
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

struct RequestObservation {
    id: u64,
    started: Instant,
    identity: ApiIdentity,
    model: String,
    session_id: String,
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

#[derive(Clone, Copy, Default, Debug, PartialEq)]
struct UsageDelta {
    input_tokens: u64,
    output_tokens: u64,
    cache_creation_input_tokens: u64,
    cache_read_input_tokens: u64,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestEvent {
    id: u64,
    timestamp: u64,
    duration_ms: u64,
    api_key_id: u64,
    api_key_name: String,
    model: String,
    status: u16,
    input_tokens: u64,
    output_tokens: u64,
    cached_tokens: u64,
    session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NotificationSettings {
    enabled: bool,
    webhook_url: String,
    error_rate_threshold: u32,
    quota_remaining_threshold: u32,
    notify_on_auth_failure: bool,
    notify_on_rate_limit: bool,
}

impl Default for NotificationSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            webhook_url: String::new(),
            error_rate_threshold: 10,
            quota_remaining_threshold: 20,
            notify_on_auth_failure: true,
            notify_on_rate_limit: true,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackupBundle {
    version: u32,
    exported_at: u64,
    issued_keys: Vec<IssuedApiKey>,
    usage: Vec<KeyUsage>,
    traffic_policy: TrafficPolicy,
    notification_settings: NotificationSettings,
    request_events: Vec<RequestEvent>,
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
    let traffic_policy_path = PathBuf::from(
        env::var("TRAFFIC_POLICY_FILE").unwrap_or_else(|_| "/data/traffic_policy.json".to_string()),
    );
    let request_events_path = PathBuf::from(
        env::var("REQUEST_EVENTS_FILE").unwrap_or_else(|_| "/data/request_events.json".to_string()),
    );
    let notification_settings_path = PathBuf::from(
        env::var("NOTIFICATION_SETTINGS_FILE")
            .unwrap_or_else(|_| "/data/notification_settings.json".to_string()),
    );
    let request_event_limit = env::var("REQUEST_EVENT_LIMIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(5_000)
        .clamp(100, 100_000);
    let issued_keys = load_issued_keys(&issued_keys_path).await?;
    let usage = load_usage(&usage_path).await?;
    let traffic_policy = load_traffic_policy(&traffic_policy_path).await?;
    let mut request_events =
        load_json_or_default::<Vec<RequestEvent>>(&request_events_path).await?;
    if request_events.len() > request_event_limit {
        let excess = request_events.len() - request_event_limit;
        request_events.drain(..excess);
    }
    let next_request_event_id = request_events
        .iter()
        .map(|event| event.id)
        .max()
        .unwrap_or(0)
        + 1;
    let notification_settings =
        load_json_or_default::<NotificationSettings>(&notification_settings_path).await?;
    let auth_dir =
        PathBuf::from(env::var("GROK_AUTH_DIR").unwrap_or_else(|_| "/data/auth".to_string()));
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
        request_events: Arc::new(Mutex::new(request_events)),
        request_events_path,
        request_event_limit,
        next_request_event_id: Arc::new(AtomicU64::new(next_request_event_id)),
        request_events_dirty: Arc::new(AtomicU32::new(0)),
        request_events_flush_lock: Arc::new(Mutex::new(())),
        notification_settings: Arc::new(Mutex::new(notification_settings)),
        notification_settings_path,
        last_notification_at: Arc::new(Mutex::new(None)),
        traffic_policy: Arc::new(Mutex::new(traffic_policy)),
        traffic_policy_path,
        traffic_runtime: Arc::new(TrafficRuntime::default()),
        auth_dir,
        account_quota_cache: Arc::new(Mutex::new(HashMap::new())),
        admin_password_hash: Sha256::digest(admin_password.as_bytes()).into(),
        cookie_secure,
        sessions: Arc::new(Mutex::new(HashMap::new())),
        login_failures: Arc::new(Mutex::new(HashMap::new())),
        child: Arc::new(Mutex::new(child)),
        started_at: Instant::now(),
    };

    wait_for_engine(&state).await?;
    tokio::spawn(request_event_flush_loop(state.clone()));

    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/api/auth/session", get(auth_session))
        .route("/api/auth/login", post(admin_login))
        .route("/api/auth/logout", post(admin_logout))
        .route("/api/admin/accounts", get(list_accounts))
        .route("/api/admin/account-quotas", get(list_account_quotas))
        .route("/api/admin/accounts/{name}", delete(delete_account))
        .route(
            "/api/admin/accounts/{name}/status",
            patch(set_account_status),
        )
        .route(
            "/api/admin/accounts/{name}/priority",
            patch(set_account_priority),
        )
        .route(
            "/api/admin/settings/routing",
            get(get_routing_settings).patch(update_routing_settings),
        )
        .route(
            "/api/admin/settings/traffic",
            get(get_traffic_policy).patch(update_traffic_policy),
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
        .route("/api/admin/realtime", get(realtime_traffic_metrics))
        .route(
            "/api/admin/request-events",
            get(list_request_events).delete(clear_request_events),
        )
        .route(
            "/api/admin/settings/notifications",
            get(get_notification_settings).patch(update_notification_settings),
        )
        .route("/api/admin/backup", get(export_backup).post(restore_backup))
        .route("/api/admin/system-info", get(system_info))
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

async fn load_json_or_default<T>(path: &Path) -> Result<T>
where
    T: for<'de> Deserialize<'de> + Default,
{
    if !path.exists() {
        return Ok(T::default());
    }
    let content = tokio::fs::read_to_string(path).await?;
    if content.trim().is_empty() {
        return Ok(T::default());
    }
    serde_json::from_str(&content).with_context(|| format!("invalid JSON file: {}", path.display()))
}

async fn save_json<T: Serialize + ?Sized>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let temporary = path.with_extension("json.tmp");
    tokio::fs::write(&temporary, serde_json::to_vec_pretty(value)?).await?;
    tokio::fs::rename(temporary, path).await?;
    Ok(())
}

async fn flush_request_events(state: &AppState) -> Result<()> {
    if state.request_events_dirty.swap(0, Ordering::AcqRel) == 0 {
        return Ok(());
    }
    let _flush_guard = state.request_events_flush_lock.lock().await;
    let snapshot = state.request_events.lock().await.clone();
    if let Err(error) = save_json(&state.request_events_path, &snapshot).await {
        state.request_events_dirty.fetch_add(1, Ordering::AcqRel);
        return Err(error);
    }
    Ok(())
}

async fn request_event_flush_loop(state: AppState) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    loop {
        interval.tick().await;
        if let Err(error) = flush_request_events(&state).await {
            tracing::warn!(%error, "failed to flush request event batch");
        }
    }
}

async fn load_traffic_policy(path: &Path) -> Result<TrafficPolicy> {
    if !path.exists() {
        return Ok(TrafficPolicy::default());
    }
    let content = tokio::fs::read_to_string(path).await?;
    if content.trim().is_empty() {
        return Ok(TrafficPolicy::default());
    }
    serde_json::from_str(&content).context("invalid traffic policy file")
}

async fn save_traffic_policy(path: &Path, policy: &TrafficPolicy) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let temporary = path.with_extension("json.tmp");
    tokio::fs::write(&temporary, serde_json::to_vec_pretty(policy)?).await?;
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

async fn get_routing_settings(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if authorize_admin(&headers, &state).await.is_err() {
        return unauthorized();
    }
    let response = match state
        .client
        .get(format!("{}/v0/management/config", state.engine_url))
        .bearer_auth(&state.management_key)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(json!({"error": error.to_string()})),
            )
                .into_response();
        }
    };
    if !response.status().is_success() {
        return relay_response(response);
    }
    match response.json::<Value>().await {
        Ok(config) => axum::Json(routing_settings_from_config(&config)).into_response(),
        Err(error) => (
            StatusCode::BAD_GATEWAY,
            axum::Json(json!({"error": format!("解析引擎配置失败: {error}")})),
        )
            .into_response(),
    }
}

async fn update_routing_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(payload): axum::Json<RoutingSettings>,
) -> Response {
    if authorize_admin(&headers, &state).await.is_err() {
        return unauthorized();
    }
    if let Err(message) = validate_routing_settings(&payload) {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": message})),
        )
            .into_response();
    }

    let config_response = match state
        .client
        .get(format!("{}/v0/management/config.yaml", state.engine_url))
        .bearer_auth(&state.management_key)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(json!({"error": error.to_string()})),
            )
                .into_response();
        }
    };
    if !config_response.status().is_success() {
        return relay_response(config_response);
    }
    let current = match config_response.text().await {
        Ok(current) => current,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(json!({"error": format!("读取引擎配置失败: {error}")})),
            )
                .into_response();
        }
    };
    let updated = apply_routing_settings_to_yaml(&current, &payload);
    let response = match state
        .client
        .put(format!("{}/v0/management/config.yaml", state.engine_url))
        .bearer_auth(&state.management_key)
        .header(header::CONTENT_TYPE, "application/yaml")
        .body(updated)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(json!({"error": error.to_string()})),
            )
                .into_response();
        }
    };
    if !response.status().is_success() {
        return relay_response(response);
    }
    axum::Json(payload).into_response()
}

fn routing_settings_from_config(config: &Value) -> RoutingSettings {
    let strategy = config
        .pointer("/routing/strategy")
        .and_then(Value::as_str)
        .filter(|value| *value == "fill-first")
        .unwrap_or("round-robin")
        .to_string();
    let session_affinity = config
        .pointer("/routing/session-affinity")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let session_affinity_ttl = config
        .pointer("/routing/session-affinity-ttl")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("1h")
        .to_string();
    let request_retry = config
        .get("request-retry")
        .and_then(Value::as_u64)
        .unwrap_or(2)
        .min(10) as u8;
    RoutingSettings {
        strategy,
        session_affinity,
        session_affinity_ttl,
        request_retry,
    }
}

fn validate_routing_settings(settings: &RoutingSettings) -> std::result::Result<(), &'static str> {
    if settings.strategy != "round-robin" && settings.strategy != "fill-first" {
        return Err("不支持的调度模式");
    }
    if !matches!(
        settings.session_affinity_ttl.as_str(),
        "30m" | "1h" | "2h" | "6h" | "12h" | "24h"
    ) {
        return Err("不支持的会话粘滞时长");
    }
    if settings.request_retry > 10 {
        return Err("重试次数不能超过 10");
    }
    Ok(())
}

fn remove_top_level_yaml_key(input: &str, key: &str) -> String {
    let mut skipping = false;
    let mut kept = Vec::new();
    for line in input.lines() {
        let trimmed = line.trim();
        let top_level =
            !line.starts_with([' ', '\t']) && !trimmed.is_empty() && !trimmed.starts_with('#');
        if top_level {
            let line_key = trimmed.split_once(':').map(|(key, _)| key.trim());
            if line_key == Some(key) {
                skipping = true;
                continue;
            }
            if skipping {
                skipping = false;
            }
        }
        if !skipping {
            kept.push(line);
        }
    }
    let mut result = kept.join("\n");
    if !result.is_empty() && !result.ends_with('\n') {
        result.push('\n');
    }
    result
}

fn apply_routing_settings_to_yaml(input: &str, settings: &RoutingSettings) -> String {
    let without_routing = remove_top_level_yaml_key(input, "routing");
    let mut output = remove_top_level_yaml_key(&without_routing, "request-retry");
    output.push_str(&format!(
        "request-retry: {}\nrouting:\n  strategy: {}\n  session-affinity: {}\n  session-affinity-ttl: \"{}\"\n",
        settings.request_retry,
        settings.strategy,
        settings.session_affinity,
        settings.session_affinity_ttl
    ));
    output
}

async fn get_traffic_policy(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if authorize_admin(&headers, &state).await.is_err() {
        return unauthorized();
    }
    axum::Json(state.traffic_policy.lock().await.clone()).into_response()
}

async fn update_traffic_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(payload): axum::Json<TrafficPolicy>,
) -> Response {
    if authorize_admin(&headers, &state).await.is_err() {
        return unauthorized();
    }
    if let Err(message) = validate_traffic_policy(&payload) {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": message})),
        )
            .into_response();
    }
    let mut policy = state.traffic_policy.lock().await;
    let previous = policy.clone();
    *policy = payload.clone();
    if let Err(error) = save_traffic_policy(&state.traffic_policy_path, &policy).await {
        *policy = previous;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": error.to_string()})),
        )
            .into_response();
    }
    axum::Json(payload).into_response()
}

fn validate_traffic_policy(policy: &TrafficPolicy) -> std::result::Result<(), &'static str> {
    if !(1..=100).contains(&policy.max_concurrent_requests) {
        return Err("全局并发必须在 1 到 100 之间");
    }
    if !(1..=10_000).contains(&policy.requests_per_minute_per_key) {
        return Err("每个 Key 的 RPM 必须在 1 到 10000 之间");
    }
    Ok(())
}

async fn list_account_quotas(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if authorize_admin(&headers, &state).await.is_err() {
        return unauthorized();
    }

    let mut entries = match tokio::fs::read_dir(&state.auth_dir).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return axum::Json(Vec::<AccountQuota>::new()).into_response();
        }
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": format!("读取账号凭据目录失败: {error}")})),
            )
                .into_response();
        }
    };

    let mut credentials = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let Ok(bytes) = tokio::fs::read(&path).await else {
            continue;
        };
        let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        if value.get("type").and_then(Value::as_str) != Some("xai") {
            continue;
        }
        let Some(access_token) = value
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|token| !token.trim().is_empty())
        else {
            continue;
        };
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("unknown.json")
            .to_string();
        let email = value
            .get("email")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        credentials.push((name, email, access_token.to_string()));
    }

    let now = Instant::now();
    let cached = state.account_quota_cache.lock().await.clone();
    let mut quotas = Vec::with_capacity(credentials.len());
    for (name, email, access_token) in credentials {
        if let Some(item) = cached.get(&name)
            && now.duration_since(item.fetched_at) < ACCOUNT_QUOTA_CACHE_TTL
        {
            quotas.push(item.quota.clone());
            continue;
        }
        let quota = fetch_account_quota(&state.client, name.clone(), email, &access_token).await;
        if quota.error.is_none() {
            state.account_quota_cache.lock().await.insert(
                name,
                CachedAccountQuota {
                    fetched_at: Instant::now(),
                    quota: quota.clone(),
                },
            );
        }
        quotas.push(quota);
    }
    quotas.sort_by(|a, b| a.email.cmp(&b.email).then_with(|| a.name.cmp(&b.name)));
    maybe_send_quota_notification(&state, &quotas).await;
    axum::Json(quotas).into_response()
}

async fn maybe_send_quota_notification(state: &AppState, quotas: &[AccountQuota]) {
    let settings = state.notification_settings.lock().await.clone();
    if !settings.enabled || settings.webhook_url.is_empty() {
        return;
    }
    let Some(quota) = quotas.iter().find(|quota| {
        quota
            .remaining_percent
            .is_some_and(|remaining| remaining <= settings.quota_remaining_threshold as f64)
    }) else {
        return;
    };
    let now = Instant::now();
    let mut last = state.last_notification_at.lock().await;
    if last.is_some_and(|previous| now.duration_since(previous) < Duration::from_secs(300)) {
        return;
    }
    *last = Some(now);
    drop(last);
    let payload = json!({
        "source": "grok-rs",
        "event": "quota_low",
        "account": quota.email,
        "remainingPercent": quota.remaining_percent,
        "threshold": settings.quota_remaining_threshold
    });
    if let Err(error) = state
        .client
        .post(&settings.webhook_url)
        .json(&payload)
        .send()
        .await
    {
        tracing::warn!(%error, "failed to deliver quota webhook");
    }
}

async fn fetch_account_quota(
    client: &Client,
    name: String,
    email: String,
    access_token: &str,
) -> AccountQuota {
    let request = |path: &'static str| {
        client
            .get(format!("https://cli-chat-proxy.grok.com/v1/{path}"))
            .bearer_auth(access_token)
            .header("X-XAI-Token-Auth", "xai-grok-cli")
            .header("User-Agent", "xai-grok-workspace/0.2.102")
            .header(header::ACCEPT, "application/json")
    };
    let (billing_result, settings_result) = tokio::join!(
        request("billing?format=credits").send(),
        request("settings").send()
    );

    let mut quota = AccountQuota {
        name,
        email,
        subscription_tier: None,
        used_percent: None,
        remaining_percent: None,
        period_type: None,
        period_start: None,
        period_end: None,
        on_demand_cap: None,
        on_demand_used: None,
        fetched_at: unix_seconds(),
        error: None,
    };

    match billing_result {
        Ok(response) if response.status().is_success() => match response.json::<Value>().await {
            Ok(value) => apply_billing_value(&mut quota, &value),
            Err(error) => quota.error = Some(format!("额度响应解析失败: {error}")),
        },
        Ok(response) => quota.error = Some(format!("额度接口返回 HTTP {}", response.status())),
        Err(error) => quota.error = Some(format!("额度接口请求失败: {error}")),
    }
    if let Ok(response) = settings_result
        && response.status().is_success()
        && let Ok(value) = response.json::<Value>().await
    {
        quota.subscription_tier = value
            .get("subscription_tier_display")
            .and_then(Value::as_str)
            .map(str::to_string);
    }
    quota
}

fn cent_value(value: &Value, pointer: &str) -> Option<i64> {
    value.pointer(pointer)?.get("val")?.as_i64()
}

fn apply_billing_value(quota: &mut AccountQuota, value: &Value) {
    let config = value.get("config").unwrap_or(value);
    quota.used_percent = config
        .get("creditUsagePercent")
        .and_then(Value::as_f64)
        .map(|value| value.clamp(0.0, 100.0));
    quota.remaining_percent = quota.used_percent.map(|value| 100.0 - value);
    quota.period_type = config
        .pointer("/currentPeriod/type")
        .and_then(Value::as_str)
        .map(str::to_string);
    quota.period_start = config
        .pointer("/currentPeriod/start")
        .or_else(|| config.get("billingPeriodStart"))
        .and_then(Value::as_str)
        .map(str::to_string);
    quota.period_end = config
        .pointer("/currentPeriod/end")
        .or_else(|| config.get("billingPeriodEnd"))
        .and_then(Value::as_str)
        .map(str::to_string);
    quota.on_demand_cap = cent_value(config, "/onDemandCap");
    quota.on_demand_used = cent_value(config, "/onDemandUsed");
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

async fn set_account_priority(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
    axum::Json(payload): axum::Json<AccountPriority>,
) -> Response {
    if authorize_admin(&headers, &state).await.is_err() {
        return unauthorized();
    }
    if !(-100..=100).contains(&payload.priority) {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "优先级必须在 -100 到 100 之间"})),
        )
            .into_response();
    }
    management_request(
        &state,
        Method::PATCH,
        "/v0/management/auth-files/fields",
        Some(json!({"name": name, "priority": payload.priority})),
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

async fn realtime_traffic_metrics(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if authorize_admin(&headers, &state).await.is_err() {
        return unauthorized();
    }

    let policy = state.traffic_policy.lock().await.clone();
    let issued_keys = state.issued_keys.lock().await.clone();
    let now = Instant::now();
    let mut recent_by_key = state.traffic_runtime.recent_by_key.lock().await;
    for requests in recent_by_key.values_mut() {
        requests.retain(|timestamp| now.duration_since(*timestamp) < Duration::from_secs(60));
    }
    recent_by_key.retain(|_, requests| !requests.is_empty());

    let mut names = HashMap::from([(0_u64, "主 API Key".to_string())]);
    for key in issued_keys {
        names.insert(key.id, key.name);
    }
    for key_id in recent_by_key.keys() {
        names
            .entry(*key_id)
            .or_insert_with(|| format!("已删除 Key #{key_id:03}"));
    }

    let rpm_limit = policy.enabled.then_some(policy.requests_per_minute_per_key);
    let mut users = names
        .into_iter()
        .map(|(api_key_id, api_key_name)| {
            let rpm = recent_by_key
                .get(&api_key_id)
                .map_or(0, |requests| requests.len() as u32);
            UserRpm {
                api_key_id,
                api_key_name,
                rpm,
                rpm_limit,
                utilization_percent: rpm_limit.map(|limit| {
                    if limit == 0 {
                        0.0
                    } else {
                        rpm as f64 / limit as f64 * 100.0
                    }
                }),
            }
        })
        .collect::<Vec<_>>();
    users.sort_by(|left, right| {
        right
            .rpm
            .cmp(&left.rpm)
            .then_with(|| left.api_key_id.cmp(&right.api_key_id))
    });
    let rpm = users.iter().map(|user| user.rpm).sum();

    axum::Json(RealtimeTrafficMetrics {
        window_seconds: 60,
        rpm,
        active_requests: state.traffic_runtime.active.load(Ordering::Acquire),
        protection_enabled: policy.enabled,
        rpm_limit_per_key: policy.requests_per_minute_per_key,
        users,
    })
    .into_response()
}

async fn list_request_events(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if authorize_admin(&headers, &state).await.is_err() {
        return unauthorized();
    }
    let events = state.request_events.lock().await;
    let start = events.len().saturating_sub(2_000);
    axum::Json(events[start..].to_vec()).into_response()
}

async fn clear_request_events(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if authorize_admin(&headers, &state).await.is_err() {
        return unauthorized();
    }
    let _flush_guard = state.request_events_flush_lock.lock().await;
    let mut events = state.request_events.lock().await;
    events.clear();
    if let Err(error) = save_json(&state.request_events_path, &*events).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": error.to_string()})),
        )
            .into_response();
    }
    state.request_events_dirty.store(0, Ordering::Release);
    axum::Json(json!({"ok": true})).into_response()
}

async fn get_notification_settings(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if authorize_admin(&headers, &state).await.is_err() {
        return unauthorized();
    }
    axum::Json(state.notification_settings.lock().await.clone()).into_response()
}

async fn update_notification_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(settings): axum::Json<NotificationSettings>,
) -> Response {
    if authorize_admin(&headers, &state).await.is_err() {
        return unauthorized();
    }
    if settings.error_rate_threshold > 100 || settings.quota_remaining_threshold > 100 {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "通知阈值必须在 0–100 之间"})),
        )
            .into_response();
    }
    if !settings.webhook_url.is_empty() && !settings.webhook_url.starts_with("https://") {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "公网部署仅允许 HTTPS Webhook 地址"})),
        )
            .into_response();
    }
    let mut current = state.notification_settings.lock().await;
    if let Err(error) = save_json(&state.notification_settings_path, &settings).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": error.to_string()})),
        )
            .into_response();
    }
    *current = settings.clone();
    axum::Json(settings).into_response()
}

async fn export_backup(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if authorize_admin(&headers, &state).await.is_err() {
        return unauthorized();
    }
    let bundle = BackupBundle {
        version: 1,
        exported_at: unix_seconds(),
        issued_keys: state.issued_keys.lock().await.clone(),
        usage: state.usage.lock().await.clone(),
        traffic_policy: state.traffic_policy.lock().await.clone(),
        notification_settings: state.notification_settings.lock().await.clone(),
        request_events: state.request_events.lock().await.clone(),
    };
    let mut response = axum::Json(bundle).into_response();
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"grok-rs-backup.json\""),
    );
    response
}

async fn restore_backup(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(bundle): axum::Json<BackupBundle>,
) -> Response {
    if authorize_admin(&headers, &state).await.is_err() {
        return unauthorized();
    }
    if bundle.version != 1 || bundle.request_events.len() > state.request_event_limit {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "备份版本无效或请求记录超过当前存储上限"})),
        )
            .into_response();
    }
    if let Err(message) = validate_traffic_policy(&bundle.traffic_policy) {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": message})),
        )
            .into_response();
    }
    if let Err(error) = save_issued_keys(&state.issued_keys_path, &bundle.issued_keys).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": error.to_string()})),
        )
            .into_response();
    }
    if let Err(error) = save_usage(&state.usage_path, &bundle.usage).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": error.to_string()})),
        )
            .into_response();
    }
    if let Err(error) = save_json(&state.traffic_policy_path, &bundle.traffic_policy).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": error.to_string()})),
        )
            .into_response();
    }
    if let Err(error) = save_json(
        &state.notification_settings_path,
        &bundle.notification_settings,
    )
    .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": error.to_string()})),
        )
            .into_response();
    }
    let next_event_id = bundle
        .request_events
        .iter()
        .map(|event| event.id)
        .max()
        .unwrap_or(0)
        + 1;
    {
        let _flush_guard = state.request_events_flush_lock.lock().await;
        let mut current_events = state.request_events.lock().await;
        *current_events = bundle.request_events.clone();
        if let Err(error) = save_json(&state.request_events_path, &*current_events).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": error.to_string()})),
            )
                .into_response();
        }
        state.request_events_dirty.store(0, Ordering::Release);
    }
    *state.issued_keys.lock().await = bundle.issued_keys;
    *state.usage.lock().await = bundle.usage;
    *state.traffic_policy.lock().await = bundle.traffic_policy;
    *state.notification_settings.lock().await = bundle.notification_settings;
    state
        .next_request_event_id
        .store(next_event_id, Ordering::Release);
    axum::Json(json!({"ok": true})).into_response()
}

async fn system_info(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if authorize_admin(&headers, &state).await.is_err() {
        return unauthorized();
    }
    let engine_reachable = state
        .client
        .get(format!("{}/", state.engine_url))
        .send()
        .await
        .is_ok();
    let mut account_files = 0_u64;
    if let Ok(mut entries) = tokio::fs::read_dir(&state.auth_dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if entry
                .path()
                .extension()
                .is_some_and(|value| value == "json")
            {
                account_files += 1;
            }
        }
    }
    axum::Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "uptimeSeconds": state.started_at.elapsed().as_secs(),
        "engineReachable": engine_reachable,
        "engineManaged": state.child.lock().await.is_some(),
        "activeRequests": state.traffic_runtime.active.load(Ordering::Acquire),
        "issuedKeys": state.issued_keys.lock().await.len(),
        "requestEvents": state.request_events.lock().await.len(),
        "requestEventLimit": state.request_event_limit,
        "accountFiles": account_files,
        "dataPaths": {
            "usage": state.usage_path.display().to_string(),
            "events": state.request_events_path.display().to_string(),
            "auth": state.auth_dir.display().to_string()
        }
    }))
    .into_response()
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

fn traffic_limit_error(message: &str) -> Response {
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        axum::Json(json!({
            "type": "error",
            "error": {"type": "rate_limit_error", "message": message}
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
    response
}

async fn acquire_traffic_lease(
    state: &AppState,
    key_id: u64,
) -> std::result::Result<TrafficLease, Response> {
    let policy = state.traffic_policy.lock().await.clone();
    if policy.enabled {
        loop {
            let active = state.traffic_runtime.active.load(Ordering::Acquire);
            if active >= policy.max_concurrent_requests {
                return Err(traffic_limit_error("服务并发已达到安全上限，请稍后重试"));
            }
            if state
                .traffic_runtime
                .active
                .compare_exchange(active, active + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }
    } else {
        state.traffic_runtime.active.fetch_add(1, Ordering::AcqRel);
    }
    let lease = TrafficLease {
        active: state.traffic_runtime.active.clone(),
        counted: true,
    };

    let now = Instant::now();
    let mut recent_by_key = state.traffic_runtime.recent_by_key.lock().await;
    let recent = recent_by_key.entry(key_id).or_default();
    recent.retain(|timestamp| now.duration_since(*timestamp) < Duration::from_secs(60));
    if policy.enabled && recent.len() >= policy.requests_per_minute_per_key as usize {
        return Err(traffic_limit_error("当前 API Key 请求过于频繁，请稍后重试"));
    }
    recent.push_back(now);
    if recent_by_key.len() > 4096 {
        for requests in recent_by_key.values_mut() {
            requests.retain(|timestamp| now.duration_since(*timestamp) < Duration::from_secs(60));
        }
        recent_by_key.retain(|_, requests| !requests.is_empty());
    }
    drop(recent_by_key);
    Ok(lease)
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
    let traffic_lease = match acquire_traffic_lease(&state, identity.key_id).await {
        Ok(lease) => lease,
        Err(response) => return response,
    };
    let request_started = Instant::now();
    let request_event_id = state.next_request_event_id.fetch_add(1, Ordering::AcqRel);
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
    let body = inject_prompt_cache_key(&bytes, &parts.headers, identity.key_id);
    let parsed_body = serde_json::from_slice::<Value>(&body).ok();
    let model = parsed_body
        .as_ref()
        .and_then(|value| value.get("model")?.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string());
    let session_id = parsed_body
        .as_ref()
        .and_then(|value| value.get("prompt_cache_key")?.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("key-{}", identity.key_id));
    let observation = RequestObservation {
        id: request_event_id,
        started: request_started,
        identity,
        model,
        session_id,
    };
    let mut upstream = state.client.request(parts.method, target).body(body);
    for (name, value) in &parts.headers {
        if name.as_str().eq_ignore_ascii_case("host")
            || name.as_str().eq_ignore_ascii_case("x-api-key")
            || name.as_str().eq_ignore_ascii_case("authorization")
            || name.as_str().eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        upstream = upstream.header(name, value);
    }
    upstream = upstream
        .header("x-api-key", &state.public_api_key)
        .bearer_auth(&state.public_api_key);
    match upstream.send().await {
        Ok(response) => relay_response_with_usage(response, state, observation, traffic_lease),
        Err(error) => {
            let message = error.to_string();
            if let Err(record_error) = record_request_event(
                &state,
                observation.id,
                &observation.identity,
                &observation.model,
                &observation.session_id,
                StatusCode::BAD_GATEWAY.as_u16(),
                observation.started,
                UsageDelta::default(),
                Some(message.clone()),
            )
            .await
            {
                tracing::error!(%record_error, "failed to persist failed request event");
            }
            (StatusCode::BAD_GATEWAY, message).into_response()
        }
    }
}

fn inject_prompt_cache_key(body: &[u8], headers: &HeaderMap, key_id: u64) -> Vec<u8> {
    let Ok(mut value) = serde_json::from_slice::<Value>(body) else {
        return body.to_vec();
    };
    if !value.is_object() {
        return body.to_vec();
    }

    let header_hint = [
        "x-grok-conv-id",
        "prompt-cache-key",
        "session-id",
        "session_id",
        "x-session-id",
        "x-claude-session-id",
    ]
    .iter()
    .find_map(|name| {
        headers
            .get(*name)
            .and_then(|entry| entry.to_str().ok())
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
    });
    let body_hint = value
        .get("prompt_cache_key")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .or_else(|| {
            value
                .pointer("/metadata/user_id")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
        });
    let stable_source = header_hint
        .or(body_hint)
        .map(str::to_owned)
        .unwrap_or_else(|| {
            serde_json::to_string(&json!({
                "model": value.get("model"),
                "system": value.get("system"),
                "tools": value.get("tools"),
                "first_message": value
                    .get("messages")
                    .and_then(Value::as_array)
                    .and_then(|messages| messages.first()),
            }))
            .unwrap_or_default()
        });
    let digest = Sha256::digest(format!("{key_id}\0{stable_source}").as_bytes());
    value["prompt_cache_key"] =
        Value::String(format!("cc_{}", URL_SAFE_NO_PAD.encode(&digest[..18])));
    force_high_grok_reasoning(&mut value);
    serde_json::to_vec(&value).unwrap_or_else(|_| body.to_vec())
}

fn force_high_grok_reasoning(value: &mut Value) {
    let is_grok_45 = value
        .get("model")
        .and_then(Value::as_str)
        .is_some_and(|model| model == "grok-4.5" || model.starts_with("grok-4.5-"));
    if !is_grok_45 {
        return;
    }

    value["thinking"] = json!({"type": "adaptive"});
    if !value.get("output_config").is_some_and(Value::is_object) {
        value["output_config"] = json!({});
    }
    value["output_config"]["effort"] = Value::String("high".to_string());
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
            .or_else(|| {
                usage
                    .pointer("/input_tokens_details/cached_tokens")
                    .and_then(Value::as_u64)
            })
            .or_else(|| {
                usage
                    .pointer("/prompt_tokens_details/cached_tokens")
                    .and_then(Value::as_u64)
            })
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

fn extract_error_message(body: &[u8]) -> Option<String> {
    if let Ok(value) = serde_json::from_slice::<Value>(body) {
        for pointer in ["/error/message", "/message", "/error"] {
            if let Some(message) = value.pointer(pointer).and_then(Value::as_str) {
                return Some(message.chars().take(500).collect());
            }
        }
    }
    let text = String::from_utf8_lossy(body).trim().to_string();
    (!text.is_empty()).then(|| text.chars().take(500).collect())
}

#[allow(clippy::too_many_arguments)]
async fn record_request_event(
    state: &AppState,
    id: u64,
    identity: &ApiIdentity,
    model: &str,
    session_id: &str,
    status: u16,
    started: Instant,
    delta: UsageDelta,
    error: Option<String>,
) -> Result<()> {
    let mut events = state.request_events.lock().await;
    let event = RequestEvent {
        id,
        timestamp: unix_seconds(),
        duration_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
        api_key_id: identity.key_id,
        api_key_name: identity.key_name.clone(),
        model: model.to_string(),
        status,
        input_tokens: delta.input_tokens,
        output_tokens: delta.output_tokens,
        cached_tokens: delta.cache_creation_input_tokens + delta.cache_read_input_tokens,
        session_id: session_id.to_string(),
        error,
    };
    events.push(event.clone());
    if events.len() > state.request_event_limit {
        let excess = events.len() - state.request_event_limit;
        events.drain(..excess);
    }
    let cutoff = unix_seconds().saturating_sub(3600);
    let recent = events
        .iter()
        .filter(|entry| entry.timestamp >= cutoff)
        .collect::<Vec<_>>();
    let recent_error_rate = if recent.is_empty() {
        0.0
    } else {
        recent.iter().filter(|entry| entry.status >= 400).count() as f64 / recent.len() as f64
            * 100.0
    };
    drop(events);
    state.request_events_dirty.fetch_add(1, Ordering::Relaxed);
    maybe_send_notification(state, &event, recent_error_rate).await;
    Ok(())
}

async fn maybe_send_notification(state: &AppState, event: &RequestEvent, error_rate: f64) {
    let settings = state.notification_settings.lock().await.clone();
    if !settings.enabled || settings.webhook_url.is_empty() || event.status < 400 {
        return;
    }
    let should_notify = (settings.notify_on_auth_failure
        && (event.status == 401 || event.status == 403))
        || (settings.notify_on_rate_limit && event.status == 429)
        || error_rate >= settings.error_rate_threshold as f64;
    if !should_notify {
        return;
    }
    let now = Instant::now();
    let mut last = state.last_notification_at.lock().await;
    if last.is_some_and(|previous| now.duration_since(previous) < Duration::from_secs(300)) {
        return;
    }
    *last = Some(now);
    drop(last);
    let payload = json!({
        "source": "grok-rs",
        "event": "request_error",
        "status": event.status,
        "user": event.api_key_name,
        "model": event.model,
        "errorRateLastHour": error_rate,
        "message": event.error
    });
    if let Err(error) = state
        .client
        .post(&settings.webhook_url)
        .json(&payload)
        .send()
        .await
    {
        tracing::warn!(%error, "failed to deliver notification webhook");
    }
}

fn relay_response_with_usage(
    upstream: reqwest::Response,
    state: AppState,
    observation: RequestObservation,
    traffic_lease: TrafficLease,
) -> Response {
    const CAPTURE_LIMIT: usize = 16 * 1024 * 1024;
    let status = upstream.status();
    let headers = upstream.headers().clone();
    let observed = async_stream::stream! {
        let _traffic_lease = traffic_lease;
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
        let delta = extract_usage_delta(&captured).unwrap_or_default();
        if status.is_success() && let Err(error) = record_usage(&state, &observation.identity, &observation.model, delta).await {
            tracing::error!(%error, key_id = observation.identity.key_id, "failed to persist API key usage");
        }
        let error_message = (!status.is_success()).then(|| extract_error_message(&captured)).flatten();
        if let Err(error) = record_request_event(
            &state,
            observation.id,
            &observation.identity,
            &observation.model,
            &observation.session_id,
            status.as_u16(),
            observation.started,
            delta,
            error_message,
        ).await {
            tracing::error!(%error, key_id = observation.identity.key_id, "failed to persist request event");
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
    if let Err(error) = flush_request_events(&state).await {
        tracing::warn!(%error, "failed to flush request events during shutdown");
    }
    if let Some(child) = state.child.lock().await.as_mut() {
        let _ = child.kill().await;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AccountQuota, RoutingSettings, TrafficPolicy, UsageDelta, apply_billing_value,
        apply_routing_settings_to_yaml, extract_error_message, extract_usage_delta,
        inject_prompt_cache_key, remove_top_level_yaml_section, routing_settings_from_config,
        validate_traffic_policy,
    };
    use axum::http::HeaderMap;
    use serde_json::json;

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

    #[test]
    fn injects_stable_isolated_prompt_cache_keys() {
        let first = br#"{"model":"grok-4.5","system":"stable","messages":[{"role":"user","content":"hello"}]}"#;
        let second = br#"{"model":"grok-4.5","system":"stable","messages":[{"role":"user","content":"hello"},{"role":"assistant","content":"hi"},{"role":"user","content":"next"}]}"#;
        let headers = HeaderMap::new();
        let first: serde_json::Value =
            serde_json::from_slice(&inject_prompt_cache_key(first, &headers, 7)).unwrap();
        let second: serde_json::Value =
            serde_json::from_slice(&inject_prompt_cache_key(second, &headers, 7)).unwrap();
        let other_user: serde_json::Value = serde_json::from_slice(&inject_prompt_cache_key(
            first.to_string().as_bytes(),
            &headers,
            8,
        ))
        .unwrap();

        assert_eq!(first["prompt_cache_key"], second["prompt_cache_key"]);
        assert_ne!(first["prompt_cache_key"], other_user["prompt_cache_key"]);
    }

    #[test]
    fn forces_grok_45_to_high_reasoning() {
        let headers = HeaderMap::new();
        let body = br#"{"model":"grok-4.5","thinking":{"type":"adaptive"},"output_config":{"effort":"low"},"messages":[{"role":"user","content":"hello"}]}"#;
        let prepared: serde_json::Value =
            serde_json::from_slice(&inject_prompt_cache_key(body, &headers, 7)).unwrap();

        assert_eq!(prepared["thinking"]["type"], "adaptive");
        assert_eq!(prepared["output_config"]["effort"], "high");
    }

    #[test]
    fn extracts_xai_cached_token_usage() {
        let body = br#"{"usage":{"input_tokens":120,"output_tokens":45,"input_tokens_details":{"cached_tokens":80}}}"#;
        assert_eq!(
            extract_usage_delta(body),
            Some(UsageDelta {
                input_tokens: 120,
                output_tokens: 45,
                cache_creation_input_tokens: 0,
                cache_read_input_tokens: 80,
            })
        );
    }

    #[test]
    fn parses_grok_weekly_account_quota() {
        let mut quota = AccountQuota {
            name: "xai-test.json".to_string(),
            email: "test@example.com".to_string(),
            subscription_tier: None,
            used_percent: None,
            remaining_percent: None,
            period_type: None,
            period_start: None,
            period_end: None,
            on_demand_cap: None,
            on_demand_used: None,
            fetched_at: 0,
            error: None,
        };
        apply_billing_value(
            &mut quota,
            &json!({"config": {
                "creditUsagePercent": 51.0,
                "currentPeriod": {
                    "type": "USAGE_PERIOD_TYPE_WEEKLY",
                    "start": "2026-07-15T05:30:28Z",
                    "end": "2026-07-22T05:30:28Z"
                },
                "onDemandCap": {"val": 250000},
                "onDemandUsed": {"val": 1200}
            }}),
        );

        assert_eq!(quota.used_percent, Some(51.0));
        assert_eq!(quota.remaining_percent, Some(49.0));
        assert_eq!(
            quota.period_type.as_deref(),
            Some("USAGE_PERIOD_TYPE_WEEKLY")
        );
        assert_eq!(quota.on_demand_cap, Some(250000));
        assert_eq!(quota.on_demand_used, Some(1200));
    }

    #[test]
    fn replaces_routing_yaml_without_touching_secrets() {
        let config = concat!(
            "api-keys:\n",
            "  - secret-key\n",
            "request-retry: 2\n",
            "routing:\n",
            "  strategy: fill-first\n",
            "  session-affinity: false\n",
            "debug: false\n",
        );
        let updated = apply_routing_settings_to_yaml(
            config,
            &RoutingSettings {
                strategy: "round-robin".to_string(),
                session_affinity: true,
                session_affinity_ttl: "2h".to_string(),
                request_retry: 3,
            },
        );

        assert!(updated.contains("  - secret-key\n"));
        assert!(updated.contains("debug: false\n"));
        assert!(updated.contains("request-retry: 3\n"));
        assert!(updated.contains("  strategy: round-robin\n"));
        assert!(updated.contains("  session-affinity: true\n"));
        assert!(updated.contains("  session-affinity-ttl: \"2h\"\n"));
        assert_eq!(updated.matches("routing:").count(), 1);
    }

    #[test]
    fn reads_routing_defaults_and_values() {
        let defaults = routing_settings_from_config(&json!({}));
        assert_eq!(defaults.strategy, "round-robin");
        assert!(!defaults.session_affinity);
        assert_eq!(defaults.session_affinity_ttl, "1h");
        assert_eq!(defaults.request_retry, 2);

        let configured = routing_settings_from_config(&json!({
            "request-retry": 4,
            "routing": {
                "strategy": "fill-first",
                "session-affinity": true,
                "session-affinity-ttl": "6h"
            }
        }));
        assert_eq!(configured.strategy, "fill-first");
        assert!(configured.session_affinity);
        assert_eq!(configured.session_affinity_ttl, "6h");
        assert_eq!(configured.request_retry, 4);
    }

    #[test]
    fn validates_safe_traffic_policy_ranges() {
        assert!(validate_traffic_policy(&TrafficPolicy::default()).is_ok());
        assert!(
            validate_traffic_policy(&TrafficPolicy {
                enabled: true,
                max_concurrent_requests: 0,
                requests_per_minute_per_key: 60,
            })
            .is_err()
        );
        assert!(
            validate_traffic_policy(&TrafficPolicy {
                enabled: true,
                max_concurrent_requests: 8,
                requests_per_minute_per_key: 10_001,
            })
            .is_err()
        );
    }

    #[test]
    fn extracts_and_limits_upstream_error_messages() {
        let body = br#"{"error":{"message":"quota exceeded"}}"#;
        assert_eq!(
            extract_error_message(body).as_deref(),
            Some("quota exceeded")
        );

        let long = vec![b'x'; 800];
        assert_eq!(extract_error_message(&long).unwrap().chars().count(), 500);
    }
}
