//! The settings keys Engineering syncs: their kinds, defaults and allowed values, the keys that
//! never sync, and how the field name of a set element or a keybinding is derived.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The two sets: one field per element, so an add on one machine and a removal on another merge.
pub const SET_LISTS: [&str; 2] = ["favorite_models", "hidden_models"];
/// The field-name prefix of a keybinding rule.
pub const KEYBINDING_PREFIX: &str = "keybinding";
/// A bare name that no plain field may take: the lists and keybindings are made of derived fields.
pub const RESERVED: [&str; 4] = [
    "favorite_models",
    "hidden_models",
    "keybinding",
    "keybindings",
];

/// Settings that never leave the device. Some hold paths, provider connections or secrets, or only
/// make sense on one machine. The last four (`default_permission_mode`, `default_project_scripts`,
/// `enable_agent_browser_access`, `enable_agent_device_access`) widen what agents may do or run
/// commands, and the last seven (the default model, fallback and text-generation model, effort,
/// thread environment, engine and model options) raise what a run costs or what it may reach. The
/// rule: a setting that raises cost or widens what an agent may do never syncs, and when it is
/// unclear the stricter reading wins. A peer must not be able to loosen another machine, so each
/// is chosen on that machine. The crate refuses all of them in both directions.
pub const NOT_SYNCED: [&str; 26] = [
    "environment_icon",
    "keep_awake_during_runs",
    "background_activity_profile",
    "add_project_base_directory",
    "provider_instances",
    "custom_models",
    "observability",
    "storage_cleanup",
    "worktree_cleanup",
    "app_update_mode",
    "automatic_git_fetch_minutes",
    "provider_health_refresh_minutes",
    "prefer_saved_login",
    "disabled_engines",
    "default_theme_set_at",
    "default_permission_mode",
    "default_project_scripts",
    "enable_agent_browser_access",
    "enable_agent_device_access",
    "default_model",
    "fallback_model",
    "text_generation_model",
    "default_effort",
    "default_thread_env_mode",
    "default_engine",
    "default_model_options",
];

/// What a plain field holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Any text.
    Text,
    /// One of these.
    Enum(&'static [&'static str]),
    /// One of these, or a theme id: 1 to 64 of `a-z 0-9 _ . : -`.
    EnumOrThemeId(&'static [&'static str]),
    Bool,
    /// A finite number above 0, up to 10.
    Number,
    /// A list of text, replaced whole by the last writer.
    Order,
}

/// A plain field the crate knows, and the value it reads as when nobody has set it.
#[derive(Clone, Copy, Debug)]
pub struct Spec {
    pub key: &'static str,
    pub kind: Kind,
    default: Initial,
}

#[derive(Clone, Copy, Debug)]
enum Initial {
    Text(&'static str),
    Bool(bool),
    Number(f64),
    EmptyList,
}

impl Spec {
    pub fn default_value(&self) -> Value {
        match self.default {
            Initial::Text(text) => json!(text),
            Initial::Bool(value) => json!(value),
            Initial::Number(value) if value.fract() == 0.0 => json!(value as i64),
            Initial::Number(value) => json!(value),
            Initial::EmptyList => json!([]),
        }
    }
}

const THEMES: &[&str] = &["system", "light", "dark"];
const APPEARANCE: &[&str] = &["system", "light", "dark"];

macro_rules! spec {
    ($key:literal, $kind:expr, $default:expr) => {
        Spec {
            key: $key,
            kind: $kind,
            default: $default,
        }
    };
}

/// Every plain field, in one place.
pub const SPECS: &[Spec] = &[
    spec!(
        "default_theme",
        Kind::EnumOrThemeId(THEMES),
        Initial::Text("system")
    ),
    spec!("branch_name_prefix", Kind::Text, Initial::Text("feat")),
    spec!("branch_name_instructions", Kind::Text, Initial::Text("")),
    spec!(
        "response_streaming_mode",
        Kind::Enum(&["paragraph", "turn"]),
        Initial::Text("paragraph")
    ),
    spec!(
        "branch_naming_mode",
        Kind::Enum(&["static", "semantic", "custom"]),
        Initial::Text("static")
    ),
    spec!(
        "quit_confirmation",
        Kind::Enum(&["direct", "hold", "double_press"]),
        Initial::Text("direct")
    ),
    spec!(
        "preview_appearance",
        Kind::Enum(APPEARANCE),
        Initial::Text("system")
    ),
    spec!("auto_thread_titles", Kind::Bool, Initial::Bool(true)),
    spec!("open_web_links_in_app", Kind::Bool, Initial::Bool(false)),
    spec!("preview_zoom", Kind::Number, Initial::Number(1.0)),
    spec!("model_order", Kind::Order, Initial::EmptyList),
];

/// The spec of a plain field, if this version knows it.
pub fn spec(key: &str) -> Option<&'static Spec> {
    SPECS.iter().find(|spec| spec.key == key)
}

/// Whether `text` can be a theme id.
pub fn is_theme_id(text: &str) -> bool {
    (1..=64).contains(&text.len())
        && text.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | ':' | '-')
        })
}

/// The first 16 characters of the lower-case, unpadded base32 (RFC 4648) of SHA-256 of `input`:
/// 80 bits, which is the 10 first bytes of the digest. Raw ids and key chords contain `-`, `/`,
/// capitals and can be long, so a field name never carries them.
pub fn derive(input: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let digest = Sha256::digest(input);
    let mut bits = 0u32;
    let mut held = 0;
    let mut out = String::with_capacity(16);
    for byte in &digest[..10] {
        bits = (bits << 8) | u32::from(*byte);
        held += 8;
        while held >= 5 {
            held -= 5;
            out.push(char::from(ALPHABET[((bits >> held) & 31) as usize]));
        }
        bits &= (1 << held) - 1;
    }
    out
}

/// The field of element `id` in `list`: `<list>.<derived>`. The id itself is the field's value.
pub fn element_field(list: &str, id: &str) -> String {
    format!("{list}.{}", derive(id.as_bytes()))
}

/// The field of a keybinding rule: `keybinding.<derived from key + NUL + when>`. A rule with no
/// `when` hashes the empty text, and a `when` may not be empty, so the two never collide.
pub fn keybinding_field(key: &str, when: Option<&str>) -> String {
    format!(
        "{KEYBINDING_PREFIX}.{}",
        derive(format!("{key}\0{}", when.unwrap_or("")).as_bytes())
    )
}

/// What a field name is for.
#[derive(Clone, Copy, Debug)]
pub enum Class {
    /// An element of one of [`SET_LISTS`].
    Element(&'static str),
    /// A keybinding rule.
    Keybinding,
    /// A plain field: known (`Some`) or from a newer version (`None`).
    Plain(Option<&'static Spec>),
}

fn is_derived(text: &str) -> bool {
    text.len() == 16
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}

/// The class of `name`, or `None` when it is not a name this crate allows (a reserved name, or a
/// reserved prefix with a part that is not a derivation). Run the key rule first.
pub fn classify(name: &str) -> Option<Class> {
    if RESERVED.contains(&name) {
        return None;
    }
    for list in SET_LISTS {
        if let Some(rest) = name.strip_prefix(list).and_then(|r| r.strip_prefix('.')) {
            return is_derived(rest).then_some(Class::Element(list));
        }
    }
    if let Some(rest) = name
        .strip_prefix(KEYBINDING_PREFIX)
        .and_then(|r| r.strip_prefix('.'))
    {
        return is_derived(rest).then_some(Class::Keybinding);
    }
    Some(Class::Plain(spec(name)))
}
