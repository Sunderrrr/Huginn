//! Shared enumerations, mirroring `app/models/enums.py`.
//!
//! The `sqlx::Type` derives map each variant to its exact PostgreSQL enum
//! label (see the `CREATE TYPE ... AS ENUM` statements in
//! `migrations/0001_baseline.sql`), and serde serializes each variant to the
//! same label so JSON payloads match the Python/FastAPI schemas.

use serde::{Deserialize, Serialize};

/// `user_role`: admin, operator, readonly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    Operator,
    #[default]
    Readonly,
}

impl UserRole {
    pub fn as_str(self) -> &'static str {
        match self {
            UserRole::Admin => "admin",
            UserRole::Operator => "operator",
            UserRole::Readonly => "readonly",
        }
    }

    pub fn is_admin(self) -> bool {
        matches!(self, UserRole::Admin)
    }
}

/// `worker_arch`: amd64, arm64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "worker_arch", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum WorkerArch {
    Amd64,
    Arm64,
}

impl WorkerArch {
    pub fn as_str(self) -> &'static str {
        match self {
            WorkerArch::Amd64 => "amd64",
            WorkerArch::Arm64 => "arm64",
        }
    }
}

/// `vm_state`: pending, active, offline, revoked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "vm_state", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum VMState {
    #[default]
    Pending,
    Active,
    Offline,
    Revoked,
}

impl VMState {
    pub fn as_str(self) -> &'static str {
        match self {
            VMState::Pending => "pending",
            VMState::Active => "active",
            VMState::Offline => "offline",
            VMState::Revoked => "revoked",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, VMState::Active)
    }
}

/// `exec_mode`: whitelist, custom, unrestricted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "exec_mode", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ExecMode {
    /// Built-in whitelist actions only.
    #[default]
    Whitelist,
    /// Built-in actions + admin-defined custom commands (no shell).
    Custom,
    /// Free shell.
    Unrestricted,
}

impl ExecMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ExecMode::Whitelist => "whitelist",
            ExecMode::Custom => "custom",
            ExecMode::Unrestricted => "unrestricted",
        }
    }
}

/// `task_type`: action, command, update, uninstall.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "task_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum TaskType {
    Action,
    Command,
    Update,
    Uninstall,
}

impl TaskType {
    pub fn as_str(self) -> &'static str {
        match self {
            TaskType::Action => "action",
            TaskType::Command => "command",
            TaskType::Update => "update",
            TaskType::Uninstall => "uninstall",
        }
    }
}

/// `task_status`: pending, dispatched, running, succeeded, failed, timeout,
/// dead_letter, cancelled.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "task_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    #[default]
    Pending,
    Dispatched,
    Running,
    Succeeded,
    Failed,
    Timeout,
    DeadLetter,
    Cancelled,
}

impl TaskStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            TaskStatus::Pending => "pending",
            TaskStatus::Dispatched => "dispatched",
            TaskStatus::Running => "running",
            TaskStatus::Succeeded => "succeeded",
            TaskStatus::Failed => "failed",
            TaskStatus::Timeout => "timeout",
            TaskStatus::DeadLetter => "dead_letter",
            TaskStatus::Cancelled => "cancelled",
        }
    }

    /// Terminal states are final: `submit_result` is a no-op once one is reached.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            TaskStatus::Succeeded
                | TaskStatus::Failed
                | TaskStatus::Timeout
                | TaskStatus::DeadLetter
                | TaskStatus::Cancelled
        )
    }
}

/// `actor_type`: user, agent, system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "actor_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ActorType {
    User,
    Agent,
    System,
}

impl ActorType {
    pub fn as_str(self) -> &'static str {
        match self {
            ActorType::User => "user",
            ActorType::Agent => "agent",
            ActorType::System => "system",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The serde labels must be exactly the PostgreSQL enum labels.
    #[test]
    fn serde_labels_match_db_labels() {
        assert_eq!(
            serde_json::to_string(&UserRole::Readonly).unwrap(),
            "\"readonly\""
        );
        assert_eq!(
            serde_json::to_string(&UserRole::Admin).unwrap(),
            "\"admin\""
        );
        assert_eq!(
            serde_json::to_string(&WorkerArch::Amd64).unwrap(),
            "\"amd64\""
        );
        assert_eq!(
            serde_json::to_string(&VMState::Revoked).unwrap(),
            "\"revoked\""
        );
        assert_eq!(
            serde_json::to_string(&ExecMode::Unrestricted).unwrap(),
            "\"unrestricted\""
        );
        assert_eq!(
            serde_json::to_string(&TaskType::Uninstall).unwrap(),
            "\"uninstall\""
        );
        assert_eq!(
            serde_json::to_string(&TaskStatus::DeadLetter).unwrap(),
            "\"dead_letter\""
        );
        assert_eq!(
            serde_json::to_string(&TaskStatus::Pending).unwrap(),
            "\"pending\""
        );
        assert_eq!(
            serde_json::to_string(&ActorType::Agent).unwrap(),
            "\"agent\""
        );

        let all = [
            (TaskStatus::Pending.as_str(), "pending"),
            (TaskStatus::Dispatched.as_str(), "dispatched"),
            (TaskStatus::Running.as_str(), "running"),
            (TaskStatus::Succeeded.as_str(), "succeeded"),
            (TaskStatus::Failed.as_str(), "failed"),
            (TaskStatus::Timeout.as_str(), "timeout"),
            (TaskStatus::DeadLetter.as_str(), "dead_letter"),
            (TaskStatus::Cancelled.as_str(), "cancelled"),
        ];
        for (got, want) in all {
            assert_eq!(got, want);
        }
    }

    #[test]
    fn deserialization_matches_python_values() {
        assert!(serde_json::from_str::<UserRole>("\"viewer\"").is_err());
        assert_eq!(
            serde_json::from_str::<UserRole>("\"readonly\"").unwrap(),
            UserRole::Readonly
        );
        assert_eq!(
            serde_json::from_str::<TaskStatus>("\"dead_letter\"").unwrap(),
            TaskStatus::DeadLetter
        );
    }

    #[test]
    fn terminal_states_match_python() {
        assert!(TaskStatus::Succeeded.is_terminal());
        assert!(TaskStatus::Failed.is_terminal());
        assert!(TaskStatus::Timeout.is_terminal());
        assert!(TaskStatus::DeadLetter.is_terminal());
        assert!(TaskStatus::Cancelled.is_terminal());
        assert!(!TaskStatus::Pending.is_terminal());
        assert!(!TaskStatus::Dispatched.is_terminal());
        assert!(!TaskStatus::Running.is_terminal());
    }

    #[test]
    fn defaults_match_python_model_defaults() {
        assert_eq!(UserRole::default(), UserRole::Readonly);
        assert_eq!(VMState::default(), VMState::Pending);
        assert_eq!(ExecMode::default(), ExecMode::Whitelist);
        assert_eq!(TaskStatus::default(), TaskStatus::Pending);
    }
}
