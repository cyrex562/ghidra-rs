//! Port of `ghidra.program.database.data.DataTypeSettingsDB`.
//!
//! Default [`Settings`] handler for those datatypes managed by an associated
//! `DataTypeManagerDB`. In Java this is a thin per-instance object: nearly every method delegates
//! straight to package-private helper methods on the owning `DataTypeManagerDB`
//! (`getSetting`/`updateSettingsRecord`/`clearSetting`/`clearAllSettings`/`getSettingsNames`/
//! `getSuggestedValues`), which in turn wrap a `SettingsDBAdapter` (the actual settings table) and
//! a `SettingsCache<Long>` (an LRU front for it).
//!
//! # Why this doesn't depend on `DataTypeManagerDb`
//!
//! Three classes ported earlier ([`TypedefDb`](super::typedef_db::TypedefDb),
//! [`DataTypeComponentDb`](super::data_type_component_db), and
//! [`UnionDb`](super::union_db)) each independently hit and documented the same gap: this class
//! didn't exist, so their `get_default_settings` falls back to the referenced type's own defaults
//! rather than a persisted local override. Their module docs also note the obvious next
//! candidate for delegation -- `DataTypeManagerDB`'s package-private settings helpers -- but
//! [`DataTypeManagerDb`](super::data_type_manager_db::DataTypeManagerDb) (the trait cut-point
//! standing in for that class in this crate) does not declare any of them; only the *notification*
//! hook, [`data_type_settings_changed`](super::data_type_manager_db::DataTypeManagerDb::data_type_settings_changed),
//! exists there today.
//!
//! Rather than add unported surface to `DataTypeManagerDb` (out of scope for this change -- see
//! the module docs of the three files above for the shape a future retrofit should take), this
//! port depends directly on the two pieces that already exist as real, DB-backed, already-tested
//! building blocks:
//!
//! - [`SettingsDBAdapter`] (a trait; [`SettingsDBAdapterV1`](super::settings_db_adapter_v1::SettingsDBAdapterV1)
//!   is a real, concrete, on-disk-table-backed implementation) for the settings table itself.
//! - [`SettingsCache`] for the LRU front, exactly mirroring `DataTypeManagerDB`'s own
//!   `settingsCache` field.
//!
//! This makes [`DataTypeSettingsDB`] a **real, DB-backed** `Settings` implementation today -- not
//! an in-memory stand-in -- as long as its caller hands it the *same* shared
//! `Arc<Mutex<dyn SettingsDBAdapter + Send>>`/`Arc<Mutex<SettingsCache<i64>>>` pair that the owning
//! manager uses for every other datatype's settings (matching Java's single manager-wide
//! `settingsAdapter`/`settingsCache` fields). A future session wiring this into `TypedefDb`/
//! `UnionDb`/`DataTypeComponentDb` needs `DataTypeManagerDb` to expose accessors for that shared
//! pair (e.g. `fn settings_adapter(&self) -> Arc<Mutex<dyn SettingsDBAdapter + Send>>` and
//! `fn settings_cache(&self) -> Arc<Mutex<SettingsCache<i64>>>`) -- the notification half of the
//! wiring (`dataMgr.dataTypeSettingsChanged(dataType)`) needs no new surface, since
//! `data_type_settings_changed` already exists; see [`DataTypeSettingsDB::set_on_settings_changed`].
//!
//! # Deliberate simplifications
//!
//! - **`settingsChanged()` -> injectable callback, not a `DataTypeManagerDb` call.** Java's
//!   `settingsChanged()` calls `dataMgr.dataTypeSettingsChanged(dataType)` directly. Since this
//!   port holds no manager/datatype reference (see above), [`DataTypeSettingsDB::new`] instead
//!   accepts (via [`set_on_settings_changed`](DataTypeSettingsDB::set_on_settings_changed)) an
//!   optional `FnMut()` invoked at exactly the same call sites Java's `settingsChanged()` is
//!   invoked from. A composing caller wires this to `dataMgr.data_type_settings_changed(dt)`.
//! - **`getSuggestedValues` drops the manager-level `previouslyUsedSettingsValuesMap` cache.**
//!   Java's real `DataTypeManagerDB.getSuggestedValues` caches the once-computed
//!   `generateSuggestions` set per storage key across *every* datatype in the manager (an
//!   optimization, not a correctness requirement -- the cache is explicitly invalidated with a
//!   "last-minute additions are not cached" comment even in Java). This port recomputes the same
//!   set fresh on every call from the real settings table
//!   ([`SettingsDBAdapter::add_all_values`]) plus the settings definition's own preferred values,
//!   which is always correct, just not memoized manager-wide -- the same dropped-cache tradeoff
//!   `TypedefDb`'s module docs make for `settingsDef`.
//! - **`settingsDefinition.addPreferredValues(this, set)` passes `None`, not the manager.** Java
//!   passes the owning `DataTypeManagerDB` itself as the "settings owner" a definition may query
//!   for extra preferred values; with no manager reference held here, `None` is passed instead.
//!   [`StringSettingsDefinition::add_preferred_values`] already treats an unsupported settings
//!   owner as a no-op (returns `false`), so this is a silent, faithful degradation rather than a
//!   crash.
//! - **`getDefaultSettings()` returns a freshly-built forwarding handle, not the stored object.**
//!   Java simply returns the shared `defaultSettings` field reference. Rust's `Settings` trait has
//!   no `clone_box`, so the stored default settings are held as `Arc<dyn Settings + Send + Sync>`
//!   and [`get_default_settings`](Settings::get_default_settings) hands back a
//!   [`DefaultSettingsHandle`] wrapping a cheap `Arc` clone. Its getters forward to the shared
//!   instance; its setters are no-ops (an `Arc<dyn Settings>` cannot yield the `&mut` access the
//!   `Settings` trait's setters require) -- the same shared-ownership-vs-`&mut` tradeoff
//!   `DataDB`'s own `Settings` impl documents in `data_component.rs`.
//! - **`Msg.warn(SettingsImpl.class, ...)` / `Msg.warn(this, ...)` -> string originators.** Java
//!   logs immutable-setting and disallowed-setting warnings under the (slightly misleading, but
//!   faithfully reproduced) `SettingsImpl` class name and under `this` respectively; this port
//!   uses the literal strings `"SettingsImpl"` and `"DataTypeSettingsDB"` as the
//!   [`Msg::warn`](crate::util::Msg::warn) originator in the same two call sites.
//! - **IO errors log-and-degrade rather than propagate.** Every `SettingsDBAdapter` call in Java
//!   is wrapped in `try { ... } catch (IOException e) { errHandler.dbError(e); }`, falling through
//!   to the same default the exception path would have produced (`null`/`false`/empty). This port
//!   has no injected `errHandler`, so it logs via `Msg::warn_with_error` and returns that same
//!   default -- observably identical for callers, just without a way to plug in a different error
//!   handler.

use std::any::Any;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::docking::settings::string_settings_definition::StringSettingsDefinition;
use crate::framework::db::Field;
use crate::program::database::data::setting_db::{SettingDB, SettingValue};
use crate::program::database::data::settings_cache::SettingsCache;
use crate::program::database::data::settings_db_adapter::SettingsDBAdapter;
use crate::util::Msg;

/// A found settings record's decoded value columns, mirroring what a live [`SettingDB`] would
/// report via `get_long_value`/`get_string_value`. Kept separate from `Option<SettingValue>` (see
/// [`DataTypeSettingsDB::fetch_setting`]) so callers can distinguish "no persisted setting exists
/// at all" (falls through to `defaultSettings`, matching Java) from "a persisted setting exists
/// but doesn't hold this particular value kind" (does *not* fall through -- Java's `getLong`/
/// `getString`/`getValue` all return whatever the found `SettingDB` reports, `null` included, the
/// moment `dataMgr.getSetting` returns non-null).
struct FoundSetting {
    long_value: Option<i64>,
    string_value: Option<String>,
}

/// A thin, freshly-constructed forwarding wrapper around a shared default-`Settings` reference.
///
/// See the module docs' note on `getDefaultSettings()` for why this exists instead of returning
/// the stored value directly.
struct DefaultSettingsHandle(Arc<dyn Settings + Send + Sync>);

impl Settings for DefaultSettingsHandle {
    fn is_immutable_settings(&self) -> bool {
        self.0.is_immutable_settings()
    }

    fn is_change_allowed(&self, settings_definition: &dyn SettingsDefinition) -> bool {
        self.0.is_change_allowed(settings_definition)
    }

    fn get_suggested_values(
        &self,
        settings_definition: &dyn StringSettingsDefinition,
    ) -> Vec<String> {
        self.0.get_suggested_values(settings_definition)
    }

    fn get_long(&self, name: &str) -> Option<i64> {
        self.0.get_long(name)
    }

    fn get_string(&self, name: &str) -> Option<String> {
        self.0.get_string(name)
    }

    fn get_value(&self, name: &str) -> Option<Box<dyn Any>> {
        self.0.get_value(name)
    }

    fn set_long(&mut self, name: &str, value: i64) {
        // TODO(port): `Arc<dyn Settings>` cannot yield `&mut`; see module docs.
        let _ = (name, value);
    }

    fn set_string(&mut self, name: &str, value: &str) {
        let _ = (name, value);
    }

    fn set_value(&mut self, name: &str, value: Box<dyn Any>) {
        let _ = (name, value);
    }

    fn clear_setting(&mut self, name: &str) {
        let _ = name;
    }

    fn clear_all_settings(&mut self) {}

    fn get_names(&self) -> Vec<String> {
        self.0.get_names()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn get_default_settings(&self) -> Option<Box<dyn Settings>> {
        self.0.get_default_settings()
    }
}

/// Default [`Settings`] handler for those datatypes managed by an associated DB-backed data type
/// manager.
///
/// Port of `ghidra.program.database.data.DataTypeSettingsDB`. See the module docs for the
/// dependency and behavioral simplifications this port makes.
pub struct DataTypeSettingsDB {
    adapter: Arc<Mutex<dyn SettingsDBAdapter + Send>>,
    cache: Arc<Mutex<SettingsCache<i64>>>,
    data_type_id: i64,

    locked: AtomicBool,
    allowed_setting_predicate: Mutex<Option<Box<dyn Fn(&str) -> bool + Send>>>,
    default_settings: Mutex<Option<Arc<dyn Settings + Send + Sync>>>,
    on_settings_changed: Mutex<Option<Box<dyn FnMut() + Send>>>,
}

impl DataTypeSettingsDB {
    /// Constructor for settings storage manager.
    ///
    /// `adapter`/`cache` should be the same shared pair every `DataTypeSettingsDB` constructed
    /// for datatypes owned by the same manager uses, mirroring Java's single manager-wide
    /// `settingsAdapter`/`settingsCache` fields (see the module docs). `data_type_id` is the
    /// resolved datatype ID this instance stores settings for. `is_program_based_manager` mirrors
    /// Java's `dataMgr instanceof ProgramBasedDataTypeManager` constructor check: initial state is
    /// locked (immutable) unless the owning manager is program-based.
    pub fn new(
        adapter: Arc<Mutex<dyn SettingsDBAdapter + Send>>,
        cache: Arc<Mutex<SettingsCache<i64>>>,
        data_type_id: i64,
        is_program_based_manager: bool,
    ) -> Self {
        DataTypeSettingsDB {
            adapter,
            cache,
            data_type_id,
            locked: AtomicBool::new(!is_program_based_manager),
            allowed_setting_predicate: Mutex::new(None),
            default_settings: Mutex::new(None),
            on_settings_changed: Mutex::new(None),
        }
    }

    /// Change the current settings lock. Attempts to modify locked settings will be ignored with
    /// a logged error. This is done to write-protect settings at the public API level.
    ///
    /// Returns the previous lock state.
    pub fn set_lock(&self, lock: bool) -> bool {
        self.locked.swap(lock, Ordering::SeqCst)
    }

    /// Set predicate for settings modification.
    pub fn set_allowed_setting_predicate(
        &self,
        allowed_setting_predicate: Option<Box<dyn Fn(&str) -> bool + Send>>,
    ) {
        *self.allowed_setting_predicate.lock().unwrap() = allowed_setting_predicate;
    }

    /// Set the underlying default settings for this settings object.
    pub fn set_default_settings(&self, settings: Option<Arc<dyn Settings + Send + Sync>>) {
        *self.default_settings.lock().unwrap() = settings;
    }

    /// Set the callback invoked whenever a settings change is actually persisted (a value was
    /// set, cleared, or all settings were cleared). Stands in for Java's `settingsChanged()`
    /// calling `dataMgr.dataTypeSettingsChanged(dataType)`; see the module docs.
    pub fn set_on_settings_changed(&self, callback: Option<Box<dyn FnMut() + Send>>) {
        *self.on_settings_changed.lock().unwrap() = callback;
    }

    /// Check for immutable settings and log error if modification not permitted.
    ///
    /// `setting_type` is a description like `"long"`/`"string"` or `None`; `name` is the setting
    /// name or `None` (clearing all settings).
    fn check_setting(&self, setting_type: Option<&str>, name: Option<&str>) -> bool {
        if !self.check_immutable_setting(setting_type, name) {
            return false;
        }
        if let Some(n) = name {
            let predicate = self.allowed_setting_predicate.lock().unwrap();
            if let Some(predicate) = predicate.as_ref() {
                if !predicate(n) {
                    Msg::warn("DataTypeSettingsDB", &format!("Ignored disallowed setting '{n}'"));
                    return false;
                }
            }
        }
        true
    }

    /// Check for immutable settings and log error if modification not permitted. Does not check
    /// for other setting restrictions.
    fn check_immutable_setting(&self, setting_type: Option<&str>, name: Option<&str>) -> bool {
        if self.locked.load(Ordering::SeqCst) {
            let type_str = setting_type.map(|t| format!("{t} ")).unwrap_or_default();
            let name_str = match name {
                Some(n) => format!(": {n}"),
                None => "s".to_string(),
            };
            Msg::warn(
                "SettingsImpl",
                &format!(
                    "Ignored invalid attempt to modify immutable {type_str}component setting{name_str}"
                ),
            );
            return false;
        }
        true
    }

    fn settings_changed(&self) {
        // NOTE: Merge currently only supports TypeDefDB default settings changes which correspond
        // to TypeDefSettingsDefinition established by the base datatype and does not consider
        // DataTypeComponent default settings changes or other setting types (mirroring the Java
        // comment on `DataTypeSettingsDB.settingsChanged()`).
        if let Some(callback) = self.on_settings_changed.lock().unwrap().as_mut() {
            callback();
        }
    }

    /// Look up a persisted setting record by name, consulting the shared cache first and falling
    /// back to the adapter (populating the cache on a hit), mirroring
    /// `DataTypeManagerDB.getSetting(long, String)`. Returns `None` if no record exists at all
    /// (distinct from a record existing with an empty/wrong-kind value -- see [`FoundSetting`]).
    fn fetch_setting(&self, name: &str) -> Option<FoundSetting> {
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(setting) = cache.get(self.data_type_id, name) {
                return Some(FoundSetting {
                    long_value: setting.get_long_value(),
                    string_value: setting.get_string_value().map(str::to_string),
                });
            }
        }

        let record = {
            let adapter = self.adapter.lock().unwrap();
            adapter.get_settings_record_by_name(self.data_type_id, name)
        };
        match record {
            Ok(Some(rec)) => {
                let setting_name = {
                    let adapter = self.adapter.lock().unwrap();
                    match adapter.get_setting_name(&rec) {
                        Ok(n) => n,
                        Err(e) => {
                            Msg::warn_with_error(
                                "DataTypeSettingsDB",
                                &format!("Failed to resolve setting name for '{name}'"),
                                &e,
                            );
                            name.to_string()
                        }
                    }
                };
                let setting = SettingDB::new(rec, setting_name);
                let found = FoundSetting {
                    long_value: setting.get_long_value(),
                    string_value: setting.get_string_value().map(str::to_string),
                };
                self.cache.lock().unwrap().put(self.data_type_id, name, setting);
                Some(found)
            }
            Ok(None) => None,
            Err(e) => {
                Msg::warn_with_error(
                    "DataTypeSettingsDB",
                    &format!("Failed to read setting '{name}'"),
                    &e,
                );
                None
            }
        }
    }

    /// Persist a settings record and, if it changed, refresh the cache and fire
    /// [`settings_changed`](Self::settings_changed). Shared by `set_long`/`set_string`, mirroring
    /// `DataTypeManagerDB.updateSettingsRecord(long, String, String, long)`.
    fn update_setting(&self, name: &str, str_value: Option<&str>, long_value: i64) {
        let updated = {
            let mut adapter = self.adapter.lock().unwrap();
            adapter.update_settings_record_by_name(self.data_type_id, name, str_value, long_value)
        };
        match updated {
            Ok(Some(rec)) => {
                let setting_name = {
                    let adapter = self.adapter.lock().unwrap();
                    match adapter.get_setting_name(&rec) {
                        Ok(n) => n,
                        Err(e) => {
                            Msg::warn_with_error(
                                "DataTypeSettingsDB",
                                &format!("Failed to resolve setting name for '{name}'"),
                                &e,
                            );
                            name.to_string()
                        }
                    }
                };
                let setting = SettingDB::new(rec, setting_name);
                self.cache.lock().unwrap().put(self.data_type_id, name, setting);
                self.settings_changed();
            }
            Ok(None) => {
                // No-op: value already matched what's stored (mirrors
                // `SettingsDBAdapterV1.updateSettingsRecord` returning `null` for an unchanged
                // value), so `DataTypeManagerDB.updateSettingsRecord` returns `false` and
                // `settingsChanged()` is not invoked.
            }
            Err(e) => {
                Msg::warn_with_error(
                    "DataTypeSettingsDB",
                    &format!("Failed to update setting '{name}'"),
                    &e,
                );
            }
        }
    }
}

impl Settings for DataTypeSettingsDB {
    fn is_immutable_settings(&self) -> bool {
        self.locked.load(Ordering::SeqCst)
    }

    fn is_change_allowed(&self, settings_definition: &dyn SettingsDefinition) -> bool {
        if self.locked.load(Ordering::SeqCst) {
            return false;
        }
        let predicate = self.allowed_setting_predicate.lock().unwrap();
        if let Some(predicate) = predicate.as_ref() {
            if !predicate(&settings_definition.get_storage_key()) {
                return false;
            }
        }
        true
    }

    fn get_suggested_values(
        &self,
        settings_definition: &dyn StringSettingsDefinition,
    ) -> Vec<String> {
        if !settings_definition.supports_suggested_values() {
            return Vec::new();
        }
        let storage_key = settings_definition.get_storage_key();
        let mut set: HashSet<String> = HashSet::new();
        {
            let adapter = self.adapter.lock().unwrap();
            if let Err(e) = adapter.add_all_values(&storage_key, &mut set) {
                Msg::warn_with_error(
                    "DataTypeSettingsDB",
                    &format!("Failed to collect suggested values for '{storage_key}'"),
                    &e,
                );
            }
        }
        settings_definition.add_preferred_values(None, &mut set);
        if set.is_empty() {
            return Vec::new();
        }
        let mut values: Vec<String> = set.into_iter().collect();
        values.sort();
        values
    }

    fn get_long(&self, name: &str) -> Option<i64> {
        if let Some(found) = self.fetch_setting(name) {
            return found.long_value;
        }
        let defaults = self.default_settings.lock().unwrap();
        defaults.as_ref().and_then(|d| d.get_long(name))
    }

    fn get_string(&self, name: &str) -> Option<String> {
        if let Some(found) = self.fetch_setting(name) {
            return found.string_value;
        }
        let defaults = self.default_settings.lock().unwrap();
        defaults.as_ref().and_then(|d| d.get_string(name))
    }

    fn get_value(&self, name: &str) -> Option<Box<dyn Any>> {
        if let Some(found) = self.fetch_setting(name) {
            if let Some(s) = found.string_value {
                return Some(Box::new(s));
            }
            if let Some(l) = found.long_value {
                return Some(Box::new(l));
            }
            return None;
        }
        let defaults = self.default_settings.lock().unwrap();
        defaults.as_ref().and_then(|d| d.get_value(name))
    }

    fn set_long(&mut self, name: &str, value: i64) {
        if self.check_setting(Some("long"), Some(name)) {
            self.update_setting(name, None, value);
        }
    }

    fn set_string(&mut self, name: &str, value: &str) {
        if self.check_setting(Some("string"), Some(name)) {
            self.update_setting(name, Some(value), -1);
        }
    }

    fn set_value(&mut self, name: &str, value: Box<dyn Any>) {
        if let Some(l) = value.downcast_ref::<i64>() {
            self.set_long(name, *l);
        } else if let Some(s) = value.downcast_ref::<String>() {
            let s = s.clone();
            self.set_string(name, &s);
        } else {
            // Java throws IllegalArgumentException here; the `Settings` trait's `set_value` has
            // no `Result` to propagate a checked failure through, so this logs and no-ops
            // instead, matching the "ignored, logged" shape every other rejected-write path in
            // this class already uses.
            Msg::warn(
                "DataTypeSettingsDB",
                &format!("Value is not a known settings type: {name}"),
            );
        }
    }

    fn clear_setting(&mut self, name: &str) {
        if !self.check_immutable_setting(None, Some(name)) {
            return;
        }
        self.cache.lock().unwrap().remove(self.data_type_id, name);
        let removed = {
            let mut adapter = self.adapter.lock().unwrap();
            adapter.remove_settings_record_by_name(self.data_type_id, name)
        };
        match removed {
            Ok(true) => self.settings_changed(),
            Ok(false) => {}
            Err(e) => {
                Msg::warn_with_error(
                    "DataTypeSettingsDB",
                    &format!("Failed to clear setting '{name}'"),
                    &e,
                );
            }
        }
    }

    fn clear_all_settings(&mut self) {
        if !self.check_immutable_setting(None, None) {
            return;
        }

        let keys = {
            let adapter = self.adapter.lock().unwrap();
            adapter.get_settings_keys(self.data_type_id)
        };
        let keys = match keys {
            Ok(keys) => keys,
            Err(e) => {
                Msg::warn_with_error(
                    "DataTypeSettingsDB",
                    &"Failed to enumerate settings keys",
                    &e,
                );
                return;
            }
        };

        let mut changed = false;
        for key in keys {
            let Field::Long(Some(settings_id)) = key else {
                continue;
            };
            let rec = {
                let adapter = self.adapter.lock().unwrap();
                adapter.get_settings_record(settings_id)
            };
            let rec = match rec {
                Ok(Some(rec)) => rec,
                Ok(None) => continue,
                Err(e) => {
                    Msg::warn_with_error(
                        "DataTypeSettingsDB",
                        &"Failed to read settings record",
                        &e,
                    );
                    continue;
                }
            };
            let name = {
                let adapter = self.adapter.lock().unwrap();
                adapter.get_setting_name(&rec)
            };
            let name = match name {
                Ok(name) => name,
                Err(e) => {
                    Msg::warn_with_error(
                        "DataTypeSettingsDB",
                        &"Failed to resolve setting name",
                        &e,
                    );
                    continue;
                }
            };
            {
                let mut adapter = self.adapter.lock().unwrap();
                if let Err(e) = adapter.remove_settings_record(settings_id) {
                    Msg::warn_with_error(
                        "DataTypeSettingsDB",
                        &format!("Failed to remove setting '{name}'"),
                        &e,
                    );
                    continue;
                }
            }
            self.cache.lock().unwrap().remove(self.data_type_id, &name);
            changed = true;
        }

        if changed {
            self.settings_changed();
        }
    }

    fn get_names(&self) -> Vec<String> {
        let adapter = self.adapter.lock().unwrap();
        match adapter.get_settings_names(self.data_type_id) {
            Ok(names) => names,
            Err(e) => {
                Msg::warn_with_error("DataTypeSettingsDB", &"Failed to read setting names", &e);
                Vec::new()
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.get_names().is_empty()
    }

    fn get_default_settings(&self) -> Option<Box<dyn Settings>> {
        self.default_settings
            .lock()
            .unwrap()
            .clone()
            .map(|arc| Box::new(DefaultSettingsHandle(arc)) as Box<dyn Settings>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::DBHandle;
    use crate::program::database::data::settings_db_adapter_v1::SettingsDBAdapterV1;
    use std::sync::atomic::AtomicUsize;

    fn new_settings(data_type_id: i64, is_program_based_manager: bool) -> DataTypeSettingsDB {
        let mut handle = DBHandle::new().unwrap();
        let adapter = SettingsDBAdapterV1::new("Settings", &mut handle, true).unwrap();
        let adapter: Arc<Mutex<dyn SettingsDBAdapter + Send>> = Arc::new(Mutex::new(adapter));
        let cache = Arc::new(Mutex::new(SettingsCache::new(200)));
        DataTypeSettingsDB::new(adapter, cache, data_type_id, is_program_based_manager)
    }

    struct MockStringSettingsDefinition {
        storage_key: String,
        supports_suggestions: bool,
        extra: Option<String>,
    }

    impl SettingsDefinition for MockStringSettingsDefinition {
        fn get_storage_key(&self) -> String {
            self.storage_key.clone()
        }
    }

    impl StringSettingsDefinition for MockStringSettingsDefinition {
        fn get_value(&self, settings: &dyn Settings) -> Option<String> {
            settings.get_string(&self.storage_key)
        }

        fn set_value(&self, settings: &mut dyn Settings, value: &str) {
            settings.set_string(&self.storage_key, value);
        }

        fn supports_suggested_values(&self) -> bool {
            self.supports_suggestions
        }

        fn add_preferred_values(
            &self,
            _settings_owner: Option<&dyn Any>,
            set: &mut HashSet<String>,
        ) -> bool {
            if let Some(extra) = &self.extra {
                set.insert(extra.clone());
                true
            } else {
                false
            }
        }
    }

    #[test]
    fn set_and_get_long_round_trips() {
        let mut settings = new_settings(1, true);
        assert_eq!(settings.get_long("count"), None);

        settings.set_long("count", 42);
        assert_eq!(settings.get_long("count"), Some(42));
        assert!(!settings.is_empty());
    }

    #[test]
    fn set_and_get_string_round_trips() {
        let mut settings = new_settings(1, true);
        assert_eq!(settings.get_string("format"), None);

        settings.set_string("format", "hex");
        assert_eq!(settings.get_string("format"), Some("hex".to_string()));
    }

    #[test]
    fn get_value_returns_string_or_long_boxed() {
        let mut settings = new_settings(1, true);
        settings.set_string("format", "hex");
        let value = settings.get_value("format").expect("value should exist");
        assert_eq!(value.downcast_ref::<String>(), Some(&"hex".to_string()));

        settings.set_long("count", 7);
        let value = settings.get_value("count").expect("value should exist");
        assert_eq!(value.downcast_ref::<i64>(), Some(&7));
    }

    #[test]
    fn set_value_dispatches_by_boxed_type() {
        let mut settings = new_settings(1, true);
        settings.set_value("count", Box::new(9_i64));
        assert_eq!(settings.get_long("count"), Some(9));

        settings.set_value("format", Box::new("hex".to_string()));
        assert_eq!(settings.get_string("format"), Some("hex".to_string()));
    }

    #[test]
    fn set_value_unknown_type_is_ignored() {
        let mut settings = new_settings(1, true);
        settings.set_value("bogus", Box::new(3.14_f64));
        assert!(settings.get_value("bogus").is_none());
        assert!(settings.is_empty());
    }

    #[test]
    fn default_settings_used_only_when_no_override_persisted() {
        struct FixedDefaults;
        impl Settings for FixedDefaults {
            fn get_long(&self, _name: &str) -> Option<i64> {
                Some(100)
            }
            fn get_string(&self, _name: &str) -> Option<String> {
                Some("default".to_string())
            }
        }

        let mut settings = new_settings(1, true);
        settings.set_default_settings(Some(Arc::new(FixedDefaults)));

        // No override yet -> falls through to defaults.
        assert_eq!(settings.get_long("count"), Some(100));
        assert_eq!(settings.get_string("format"), Some("default".to_string()));

        // A persisted override of one kind of value on "format" means lookups for "format" no
        // longer consult defaults at all, matching Java's `getLong`/`getString` returning
        // whatever the found `SettingDB` reports (even `null`) once `dataMgr.getSetting` returns
        // non-null, rather than falling through further.
        settings.set_string("format", "hex");
        assert_eq!(settings.get_string("format"), Some("hex".to_string()));
        assert_eq!(settings.get_long("format"), None);

        // "count" still has no persisted override, so it still falls through.
        assert_eq!(settings.get_long("count"), Some(100));
    }

    #[test]
    fn get_default_settings_forwards_reads() {
        struct FixedDefaults;
        impl Settings for FixedDefaults {
            fn get_long(&self, _name: &str) -> Option<i64> {
                Some(55)
            }
        }

        let settings = new_settings(1, true);
        settings.set_default_settings(Some(Arc::new(FixedDefaults)));

        let handle = settings.get_default_settings().expect("defaults should be set");
        assert_eq!(handle.get_long("anything"), Some(55));
    }

    #[test]
    fn clear_setting_removes_single_value() {
        let mut settings = new_settings(1, true);
        settings.set_long("a", 1);
        settings.set_long("b", 2);

        settings.clear_setting("a");
        assert_eq!(settings.get_long("a"), None);
        assert_eq!(settings.get_long("b"), Some(2));
    }

    #[test]
    fn clear_all_settings_removes_everything() {
        let mut settings = new_settings(1, true);
        settings.set_long("a", 1);
        settings.set_string("b", "x");
        assert!(!settings.is_empty());

        settings.clear_all_settings();
        assert!(settings.is_empty());
        assert_eq!(settings.get_names(), Vec::<String>::new());
    }

    #[test]
    fn locked_settings_reject_writes() {
        let mut settings = new_settings(1, false); // non-program-based -> starts locked
        assert!(settings.is_immutable_settings());

        settings.set_long("count", 5);
        assert_eq!(settings.get_long("count"), None);

        let was_locked = settings.set_lock(false);
        assert!(was_locked);
        assert!(!settings.is_immutable_settings());

        settings.set_long("count", 5);
        assert_eq!(settings.get_long("count"), Some(5));
    }

    #[test]
    fn program_based_manager_starts_unlocked() {
        let settings = new_settings(1, true);
        assert!(!settings.is_immutable_settings());
    }

    #[test]
    fn allowed_setting_predicate_blocks_disallowed_names() {
        let mut settings = new_settings(1, true);
        settings.set_allowed_setting_predicate(Some(Box::new(|name: &str| name == "ok")));

        settings.set_long("blocked", 1);
        assert_eq!(settings.get_long("blocked"), None);

        settings.set_long("ok", 2);
        assert_eq!(settings.get_long("ok"), Some(2));
    }

    #[test]
    fn is_change_allowed_reflects_lock_and_predicate() {
        struct Def(&'static str);
        impl SettingsDefinition for Def {
            fn get_storage_key(&self) -> String {
                self.0.to_string()
            }
        }

        let settings = new_settings(1, false);
        assert!(!settings.is_change_allowed(&Def("x"))); // locked

        settings.set_lock(false);
        assert!(settings.is_change_allowed(&Def("x")));

        settings.set_allowed_setting_predicate(Some(Box::new(|name: &str| name == "x")));
        assert!(settings.is_change_allowed(&Def("x")));
        assert!(!settings.is_change_allowed(&Def("y")));
    }

    #[test]
    fn settings_changed_callback_fires_only_on_real_changes() {
        let mut settings = new_settings(1, true);
        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = count.clone();
        settings.set_on_settings_changed(Some(Box::new(move || {
            count_clone.fetch_add(1, Ordering::SeqCst);
        })));

        settings.set_long("count", 1);
        assert_eq!(count.load(Ordering::SeqCst), 1);

        // Setting the same value again is a no-op at the adapter level (matches
        // `SettingsDBAdapterV1.updateSettingsRecord` returning null for an unchanged value), so
        // the callback should not fire a second time.
        settings.set_long("count", 1);
        assert_eq!(count.load(Ordering::SeqCst), 1);

        settings.set_long("count", 2);
        assert_eq!(count.load(Ordering::SeqCst), 2);

        settings.clear_setting("count");
        assert_eq!(count.load(Ordering::SeqCst), 3);

        settings.set_long("count", 3);
        settings.clear_all_settings();
        assert_eq!(count.load(Ordering::SeqCst), 5);

        // Clearing again with nothing left to clear should not fire.
        settings.clear_all_settings();
        assert_eq!(count.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn get_suggested_values_respects_support_flag_and_includes_stored_and_preferred_values() {
        let mut settings = new_settings(1, true);
        let unsupported = MockStringSettingsDefinition {
            storage_key: "fmt".to_string(),
            supports_suggestions: false,
            extra: None,
        };
        assert_eq!(settings.get_suggested_values(&unsupported), Vec::<String>::new());

        // Store some previously-used values for the "fmt" storage key on this datatype.
        settings.set_string("fmt", "hex");

        let supported = MockStringSettingsDefinition {
            storage_key: "fmt".to_string(),
            supports_suggestions: true,
            extra: Some("preferred".to_string()),
        };
        let mut values = settings.get_suggested_values(&supported);
        values.sort();
        assert_eq!(values, vec!["hex".to_string(), "preferred".to_string()]);
    }

    #[test]
    fn distinct_data_type_ids_have_independent_settings() {
        let mut handle = DBHandle::new().unwrap();
        let adapter = SettingsDBAdapterV1::new("Settings", &mut handle, true).unwrap();
        let adapter: Arc<Mutex<dyn SettingsDBAdapter + Send>> = Arc::new(Mutex::new(adapter));
        let cache = Arc::new(Mutex::new(SettingsCache::new(200)));

        let mut a = DataTypeSettingsDB::new(adapter.clone(), cache.clone(), 1, true);
        let mut b = DataTypeSettingsDB::new(adapter, cache, 2, true);

        a.set_long("count", 1);
        b.set_long("count", 2);

        assert_eq!(a.get_long("count"), Some(1));
        assert_eq!(b.get_long("count"), Some(2));

        a.clear_all_settings();
        assert_eq!(a.get_long("count"), None);
        assert_eq!(b.get_long("count"), Some(2));
    }

    #[test]
    fn cache_hit_path_returns_same_value_as_first_read() {
        let mut settings = new_settings(1, true);
        settings.set_string("format", "hex");

        // First read populates from the adapter (already cached by `update_setting`); second read
        // exercises the cache-hit branch of `fetch_setting`.
        assert_eq!(settings.get_string("format"), Some("hex".to_string()));
        assert_eq!(settings.get_string("format"), Some("hex".to_string()));
    }
}
