# INTEGRATION_NOTES — worker API + task events (routes/worker.rs, services/)

Ceci documente l'API consommée/produite par les fichiers livrés par l'agent
« worker API » : `src/error.rs`, `src/services/{mod,task_events}.rs`,
`src/routes/{mod,worker}.rs`. Les signatures ci-dessous sont celles **réellement
utilisées** dans mon code — toute la couche `models`/`security`/`db` ayant
depuis atterri avec exactement ces signatures, la compilation est alignée.

## Endpoints couverts (préfixe `/api/worker`, portage de `hub/app/api/routes/worker.py`)

| Route | Handler Python | Comportement porté |
|---|---|---|
| `POST /api/worker/enroll` | `enroll` | token d'enrollment → `models::enrollment::create_vm_on_enroll` (consommation du token + VM atomiques) ; secret worker généré (`security::generate_secret`) et stocké haché (`security::hash_secret`) ; 201 `{worker_id, worker_secret, state}` ; auto-approve → tasks `status`+`metrics` best-effort + `notify_queue_on_commit` |
| `POST /api/worker/heartbeat` | `heartbeat` | maj `last_heartbeat_at`/`worker_version`/`ip_address`, reprise OFFLINE→ACTIVE, réponse `{target_worker_version, exec_mode, allowed_release_domains}` ; auto-update (settings `auto_update_enabled` + version ≠ target + pas d'update en vol) via `models::task::{has_inflight_update, create_update_task}` + wake |
| `GET /api/worker/tasks/next?wait=N` | `next_task` | long-poll event-driven : subscribe AVANT le 1er claim, claim transactionnel (`FOR UPDATE SKIP LOCKED`), park sur le wake par vm_id avec timeout restant, cap 25 s (`MAX_WAIT_SECONDS`), null à l'expiration |
| `POST /api/worker/tasks/{id}/result` | `submit_result` | `models::task::submit_result` (troncature `max_output_bytes`, idempotent sur état terminal, 404 si tâche absente/autre VM) → `notify(task_id)` ; re-queue (status `pending` dans le résultat) → `notify_queue_on_commit(vm_id)` ; 204 |

Enforcements : `_enforce_tls` (400 « TLS is required for worker communication »,
`X-Forwarded-Proto` sinon scheme), auth worker (`X-Worker-Id`/`X-Worker-Secret`,
`verify_secret` constant-time même si la VM n'existe pas, 401/403), caps de
corps, rate limit minimal sur `/enroll`. Voir « écarts assumés » plus bas.

## Signatures requises (consommées telles quelles)

```rust
// crate::db
pub type PgPool = sqlx::PgPool;                 // (sqlx::PgPool utilisé directement)
pub enum DbError { Sqlx(sqlx::Error), Migrate(...), NotFound, Conflict(String), Invalid(String) }
pub fn pool_options(max_connections: u32) -> PgPoolOptions;   // tests (connect_lazy)

// crate::config::Config  (champs utilisés)
//   require_tls, trust_forwarded_for, max_body_bytes, max_output_bytes,
//   default_task_timeout_seconds, rate_limit_exec_per_minute,
//   target_worker_version, secret_hash_key, jwt_secret, mfa_encryption_key

// crate::security
pub struct SecurityConfig;
impl SecurityConfig {
    pub fn new(mfa_encryption_key: &str, jwt_secret: &str, secret_hash_key: &str) -> Self;
    pub fn hash_secret(&self, secret: &str) -> String;
    pub fn verify_secret(&self, secret: &str, expected_hash: Option<&str>) -> bool;
}
pub use secret::{generate_secret, hash_secret, verify_secret}; // hash_secret(key, secret)

// crate::models::enums — VMState, ExecMode, WorkerArch, TaskType, TaskStatus
//   (serde lowercase + as_str() + TaskStatus::is_terminal())

// crate::models::vm
pub struct VM { id, name, arch, state, exec_mode, worker_secret_hash, ... }
pub struct VmPatch { worker_version: Option<String>, ip_address: Option<String>, ... }
pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<VM>, DbError>;
pub async fn update_heartbeat(pool: &PgPool, id: Uuid, at: DateTime<Utc>) -> Result<Option<VM>, DbError>;
pub async fn update(pool: &PgPool, id: Uuid, patch: VmPatch) -> Result<Option<VM>, DbError>;
pub async fn set_state(pool: &PgPool, id: Uuid, state: VMState) -> Result<Option<VM>, DbError>;

// crate::models::task
pub struct Task { id, vm_id, task_type, action_name, payload, status, ... }
pub struct ActionTaskNew { vm_id, action_name, params: Value, timeout_seconds: i64, created_by, idempotency_key }
pub struct UpdateTaskNew { vm_id, target_version, urls: Value /* SSRF-validated */, created_by }
pub struct SubmitResult { task_id, vm_id, status, exit_code, stdout, stderr, error, output_cap_bytes: usize }
pub async fn claim_next_task(pool: &PgPool, vm_id: Uuid) -> Result<Option<Task>, DbError>;
pub async fn submit_result(pool: &PgPool, res: SubmitResult) -> Result<Option<Task>, DbError>;
pub async fn has_inflight_update(pool: &PgPool, vm_id: Uuid) -> Result<bool, DbError>;
pub async fn create_action_task(pool: &PgPool, new: ActionTaskNew) -> Result<Task, DbError>;
pub async fn create_update_task(pool: &PgPool, new: UpdateTaskNew) -> Result<Task, DbError>;

// crate::models::enrollment
pub struct EnrollVmParams { name, hostname, ip_address, arch, os_info, worker_version, worker_secret_hash }
pub struct EnrollOutcome { token: EnrollmentToken, vm: VM }
pub async fn create_vm_on_enroll(pool: &PgPool, token_hash: &str, params: EnrollVmParams)
    -> Result<EnrollOutcome, DbError>;   // Err(DbError::Invalid("invalid or expired enrollment token")) → 401

// crate::models::setting
pub struct Setting { target_worker_version, target_release_repo, auto_update_enabled, ... }
impl Setting { pub fn allowed_release_domains_vec(&self) -> Vec<String>; }
pub async fn get_settings_row(pool: &PgPool) -> Result<Option<Setting>, DbError>;
```

Toutes ces signatures existent telles quelles dans `src/models/*`,
`src/security/*`, `src/db.rs`, `src/config.rs` — rien à réaligner côté données.

## `services::task_events` — ce que les autres couches doivent utiliser

Bus d'événements in-process (portage de `core/task_events.py`) :

- `TaskEvents::notify(task_id)` — **après** le COMMIT du résultat (côté route
  `submit_result` c'est fait).
- `TaskEvents::notify_queue(vm_id)` / `notify_queue_on_commit(vm_id)` — à
  appeler **après** le COMMIT réussi de la transaction qui crée la tâche
  (création, re-queue de `sweep_timeouts`). La discipline « wake au commit » de
  la version SQLAlchemy (`after_commit`/`after_rollback`) est rendue par
  l'ordre d'appel, ou par `defer_queue_wakes()` → `PendingQueueWakes` avec
  `commit()` (feu) / `rollback()` ou drop (discard) pour les créations
  groupées.
- `broadcast_queue()` — fallback sans vm ciblée.
- `subscribe_queue(vm_id) -> QueueWaiter` / `subscribe_task(task_id) -> TaskWaiter`
  (unsubscribe RAII au drop), `wait(timeout)`, `clear()`.
- `wait_for_terminal(task_id, timeout)` (attend un wake) et
  `wait_for_terminal_checked(task_id, timeout, load, is_terminal)` (boucle
  Python `services/tasks.wait_for_terminal` : subscribe avant la 1re lecture,
  relecture à chaque wake, rend la dernière observation).

**Pour le sweep (`sweep_timeouts`, à porter plus tard)** : après le COMMIT,
`notify(task_id)` pour chaque `dead_letter` et
`notify_queue_on_commit(vm_id)` pour chaque re-queue — exactement la fin de
`sweep_timeouts` en Python.

## Branchements restants (hors scope de cet agent, à câbler par l'assemblage)

1. `audit.record(...)` dans `/enroll` — remplacé provisoirement par
   `tracing::info!(target: "huginn.hub.audit", event_type="enroll", ...)` avec
   le même détail `{name, arch, auto_approved}`. Remplacer par
   `crate::models::audit` + la couche hash-chain quand le module audit route
   existe.
2. `events.publish({"type": "tasks"})` après un submit de résultat (hint SSE
   dashboard, `core/events.py`) — pub/sub à porter dans `core::events` (hors
   fichiers de cette tâche). À ajouter à la fin de `submit_task_result`.
3. `notifications.notify(row, "vm_recovered" | "task_failure", ...)` — webhook
   best-effort (`services/notifications.py`), non porté (toujours best-effort
   en Python). À câbler dans `heartbeat` (recovered) et `submit_task_result`
   (status ∈ failed/timeout/dead_letter).
4. `versioning.build_release_urls` — porté en privé dans `routes/worker.rs`
   (`build_release_urls`, validation SSRF des hôtes + formes repo/version) car
   `models::task::UpdateTaskNew` attend l'objet d'URLs déjà validé et aucun
   module `services::versioning` n'existait. **À déplacer** vers un futur
   `services::versioning` (partagé avec les routes d'exécution) ; mon
   `auto_queue_update` appellera alors cette fonction.
5. Validation `ACTION_CATALOG` / `validate_action` de
   `services/tasks.create_action_task` : non refaite ici (les deux actions
   créées par `/enroll` sont des noms fixes `status`/`metrics`). Si la couche
   service des tâches atterrit, c'est elle qui valide.
6. Rate limit : `RateLimiter` (fenêtre fixe 60 s, portage de
   `core/ratelimit.py`) vit dans `routes/worker.rs` — à mutualiser dans un futur
   `core::ratelimit` avec `rate_limit_exec`.

## Écarts assumés (vs la référence Python)

1. **TLS sur tous les endpoints worker** : `worker.py` n'appelle
   `_enforce_tls` que dans `/enroll` ; je l'applique aux 4 endpoints (strictement
   plus fort, même erreur 400) car tous transportent le secret worker.
2. **Rate limit `/enroll`** (429 « rate limit exceeded; slow down », par IP
   client, budget `rate_limit_exec_per_minute`) : la référence n'en a aucun sur
   les routes worker ; demandé par la mission (« rate limit minimal »).
3. **Validation schéma → 422** (`{"detail": "..."}`) comme FastAPI, mais la
   référence renvoie des tableaux pydantic `detail: [{loc, msg, type}]` ; le
   format de détail est simplifié à une chaîne. Corps trop gros → 413
   `{"detail": "request body too large"}` (identique).
4. **Caps de corps** : cap global `max_output_bytes*2+65536` (middleware de
   `main.py`) posé sur le routeur ; cap 64 KB (`max_body_bytes`,
   `deps.enforce_body_size`) sur `/enroll`, `/heartbeat`, `/tasks/next` (corps
   minuscules) MAIS PAS sur `/result`, dont les champs font légitimement
   jusqu'à 2 Mio (caps schéma 2 097 152 chars/champ conservés, troncature
   ensuite à `max_output_bytes`) — un cap global 64 KB sur `/result` casserait
   les sorties normales.
5. **Ordre validation/auth** : validation de la forme (JSON, tailles de champs,
   UUID de path) avant l'auth worker, comme la validation pydantic de FastAPI ;
   la référence résout dépendances et corps dans un ordre non spécifié.
6. **Commit** : la session SQLAlchemy est committée en fin de requête (ou au
   milieu du long-poll) ; en Rust chaque fonction `models::*` ouvre/clost sa
   propre transaction. Le long-poll n'a donc pas de `session.commit()`
   intermédiaire (le snapshot est déjà droppé), et les wakes sont émises après
   le commit de l'appel de création (discipline `notify_queue_on_commit`).
7. `wait=NaN`/négatif est clampé à `[0, 25]` (la Python bouclerait
   indéfiniment sur NaN) ; message de validation légèrement différent des
   pydantic (ex. « name must be at most 255 characters »).

## Tests

- `services::task_events` (16 tests) : wake ciblé par vm, broadcast, timeout
  propre, pas de wake perdu (subscribe avant wait), coalescence (« pas de
  double distribution » : un wake = un round de claim), clear, drop = cleanup,
  `PendingQueueWakes` feu au commit / discard au rollback, sémantique de
  `wait_for_terminal*`.
- `routes::worker` (24 tests) : machine à états du long-poll (claim immédiat,
  wake→re-claim, timeout, cap, wait=0, deux long-polls concurrents → une seule
  tâche distribuée), `_enforce_tls`, `client_ip`, cap de corps, rate limiter,
  validations schéma, URLs de release (modes GitHub/self-hosté + SSRF), et
  tests de routes axum (`tower::ServiceExt::oneshot`) sur les chemins pré-DB :
  400 TLS, 401 (creds manquants / id invalide), 413, 422, 429.
- `src/error.rs` (4 tests) : mapping des codes + corps `{"detail": ...}`.

`cargo test` : 105 tests verts (crate entier). `cargo clippy -- -D warnings` :
uniquement des issues dans les fichiers d'autres agents encore en vol au moment
de l'écriture (voir rapport) — mes fichiers sont propres.
