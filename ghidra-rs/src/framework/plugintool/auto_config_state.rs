//! Port of `ghidra.framework.plugintool.AutoConfigState`.
//!
//! The Java type is a namespace interface bundling: a small `ConfigFieldCodec<T>` type-class
//! interface, one implementation per primitive/array/JDK type, and a reflection-driven
//! `ConfigStateField`/`ClassHandler`/`wireHandler` trio that discovers `@AutoConfigStateField`
//! -annotated fields on an arbitrary class (via `MethodHandle`s obtained through a caller-supplied
//! `Lookup`) and (de)serializes them automatically. It was selected as a dependency-cycle
//! cut-point, so `ConfigFieldCodec<T>` -- the piece every referencing site actually depends on --
//! is ported here as an object-safe trait (`Box<dyn ConfigFieldCodec<T>>`), with one concrete,
//! zero-sized codec type per Java nested codec class.
//!
//! `ConfigStateField`'s `MethodHandle`-based per-field get/set, its `CODECS_BY_TYPE`
//! /`CODECS_BY_SPEC` reflective registries (`getCodecByType`, `getCodecBySpec`, `putState`,
//! `getState`), and `ClassHandler`/`wireHandler`'s reflective gathering of annotated fields have
//! no Rust equivalent -- there is no runtime reflection over struct fields or annotations here.
//! In their place, [`ClassStateHandler<T>`] ports `ClassHandler`'s two *public* instance methods
//! (`writeConfigState`/`readConfigState`) as an object-safe trait; concrete state-bearing types
//! implement it by hand (typically by calling each field's codec directly), rather than having an
//! implementation derived by scanning annotated fields at runtime.

use std::path::{Path, PathBuf};

use crate::framework::seam_stubs::{AsyncReferenceLike, SaveState};

/// Codec for reading/writing a single field's value to/from a [`SaveState`].
///
/// Mirrors `AutoConfigState.ConfigFieldCodec<T>`. Object-safe once `T` is concrete, so
/// implementations can be stored as `Box<dyn ConfigFieldCodec<T>>`.
///
/// `write` takes `value` by non-optional reference because the Java field this codec ultimately
/// serializes is asserted non-null just before `write` is invoked (`ConfigStateField.save`:
/// `assert val != null;`); `read` returns `Option<T>` because `ConfigStateField.load` explicitly
/// treats a `null` result as "leave the current value alone".
pub trait ConfigFieldCodec<T> {
    /// Reads the value stored under `name`, mirroring `ConfigFieldCodec.read`. `current` is the
    /// field's present value, consulted by codecs (e.g. the path- and async-based ones) that need
    /// a fallback or an object to mutate in place rather than simply replacing wholesale.
    fn read(&self, state: &dyn SaveState, name: &str, current: Option<&T>) -> Option<T>;

    /// Writes `value` under `name`, mirroring `ConfigFieldCodec.write`.
    fn write(&self, state: &mut dyn SaveState, name: &str, value: &T);
}

/// Mirrors `AutoConfigState.BooleanConfigFieldCodec`.
#[derive(Debug, Clone, Copy, Default)]
pub struct BooleanConfigFieldCodec;

impl ConfigFieldCodec<bool> for BooleanConfigFieldCodec {
    fn read(&self, state: &dyn SaveState, name: &str, _current: Option<&bool>) -> Option<bool> {
        Some(state.get_boolean(name, false))
    }

    fn write(&self, state: &mut dyn SaveState, name: &str, value: &bool) {
        state.put_boolean(name, *value);
    }
}

/// Mirrors `AutoConfigState.ByteConfigFieldCodec`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ByteConfigFieldCodec;

impl ConfigFieldCodec<i8> for ByteConfigFieldCodec {
    fn read(&self, state: &dyn SaveState, name: &str, _current: Option<&i8>) -> Option<i8> {
        Some(state.get_byte(name, 0))
    }

    fn write(&self, state: &mut dyn SaveState, name: &str, value: &i8) {
        state.put_byte(name, *value);
    }
}

/// Mirrors `AutoConfigState.ShortConfigFieldCodec`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ShortConfigFieldCodec;

impl ConfigFieldCodec<i16> for ShortConfigFieldCodec {
    fn read(&self, state: &dyn SaveState, name: &str, _current: Option<&i16>) -> Option<i16> {
        Some(state.get_short(name, 0))
    }

    fn write(&self, state: &mut dyn SaveState, name: &str, value: &i16) {
        state.put_short(name, *value);
    }
}

/// Mirrors `AutoConfigState.IntConfigFieldCodec`.
#[derive(Debug, Clone, Copy, Default)]
pub struct IntConfigFieldCodec;

impl ConfigFieldCodec<i32> for IntConfigFieldCodec {
    fn read(&self, state: &dyn SaveState, name: &str, _current: Option<&i32>) -> Option<i32> {
        Some(state.get_int(name, 0))
    }

    fn write(&self, state: &mut dyn SaveState, name: &str, value: &i32) {
        state.put_int(name, *value);
    }
}

/// Mirrors `AutoConfigState.LongConfigFieldCodec`.
#[derive(Debug, Clone, Copy, Default)]
pub struct LongConfigFieldCodec;

impl ConfigFieldCodec<i64> for LongConfigFieldCodec {
    fn read(&self, state: &dyn SaveState, name: &str, _current: Option<&i64>) -> Option<i64> {
        Some(state.get_long(name, 0))
    }

    fn write(&self, state: &mut dyn SaveState, name: &str, value: &i64) {
        state.put_long(name, *value);
    }
}

/// Mirrors `AutoConfigState.FloatConfigFieldCodec`.
#[derive(Debug, Clone, Copy, Default)]
pub struct FloatConfigFieldCodec;

impl ConfigFieldCodec<f32> for FloatConfigFieldCodec {
    fn read(&self, state: &dyn SaveState, name: &str, _current: Option<&f32>) -> Option<f32> {
        Some(state.get_float(name, 0.0))
    }

    fn write(&self, state: &mut dyn SaveState, name: &str, value: &f32) {
        state.put_float(name, *value);
    }
}

/// Mirrors `AutoConfigState.DoubleConfigFieldCodec`.
#[derive(Debug, Clone, Copy, Default)]
pub struct DoubleConfigFieldCodec;

impl ConfigFieldCodec<f64> for DoubleConfigFieldCodec {
    fn read(&self, state: &dyn SaveState, name: &str, _current: Option<&f64>) -> Option<f64> {
        Some(state.get_double(name, 0.0))
    }

    fn write(&self, state: &mut dyn SaveState, name: &str, value: &f64) {
        state.put_double(name, *value);
    }
}

/// Mirrors `AutoConfigState.StringConfigFieldCodec`.
#[derive(Debug, Clone, Copy, Default)]
pub struct StringConfigFieldCodec;

impl ConfigFieldCodec<String> for StringConfigFieldCodec {
    fn read(&self, state: &dyn SaveState, name: &str, _current: Option<&String>) -> Option<String> {
        state.get_string(name, None)
    }

    fn write(&self, state: &mut dyn SaveState, name: &str, value: &String) {
        state.put_string(name, Some(value.as_str()));
    }
}

/// Mirrors `AutoConfigState.BooleanArrayConfigFieldCodec`.
#[derive(Debug, Clone, Copy, Default)]
pub struct BooleanArrayConfigFieldCodec;

impl ConfigFieldCodec<Vec<bool>> for BooleanArrayConfigFieldCodec {
    fn read(
        &self,
        state: &dyn SaveState,
        name: &str,
        _current: Option<&Vec<bool>>,
    ) -> Option<Vec<bool>> {
        state.get_booleans(name, None)
    }

    fn write(&self, state: &mut dyn SaveState, name: &str, value: &Vec<bool>) {
        state.put_booleans(name, Some(value.as_slice()));
    }
}

/// Mirrors `AutoConfigState.ByteArrayConfigFieldCodec`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ByteArrayConfigFieldCodec;

impl ConfigFieldCodec<Vec<u8>> for ByteArrayConfigFieldCodec {
    fn read(
        &self,
        state: &dyn SaveState,
        name: &str,
        _current: Option<&Vec<u8>>,
    ) -> Option<Vec<u8>> {
        state.get_bytes(name, None)
    }

    fn write(&self, state: &mut dyn SaveState, name: &str, value: &Vec<u8>) {
        state.put_bytes(name, Some(value.as_slice()));
    }
}

/// Mirrors `AutoConfigState.ShortArrayConfigFieldCodec`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ShortArrayConfigFieldCodec;

impl ConfigFieldCodec<Vec<i16>> for ShortArrayConfigFieldCodec {
    fn read(
        &self,
        state: &dyn SaveState,
        name: &str,
        _current: Option<&Vec<i16>>,
    ) -> Option<Vec<i16>> {
        state.get_shorts(name, None)
    }

    fn write(&self, state: &mut dyn SaveState, name: &str, value: &Vec<i16>) {
        state.put_shorts(name, Some(value.as_slice()));
    }
}

/// Mirrors `AutoConfigState.IntArrayConfigFieldCodec`.
#[derive(Debug, Clone, Copy, Default)]
pub struct IntArrayConfigFieldCodec;

impl ConfigFieldCodec<Vec<i32>> for IntArrayConfigFieldCodec {
    fn read(
        &self,
        state: &dyn SaveState,
        name: &str,
        _current: Option<&Vec<i32>>,
    ) -> Option<Vec<i32>> {
        state.get_ints(name, None)
    }

    fn write(&self, state: &mut dyn SaveState, name: &str, value: &Vec<i32>) {
        state.put_ints(name, Some(value.as_slice()));
    }
}

/// Mirrors `AutoConfigState.LongArrayConfigFieldCodec`.
#[derive(Debug, Clone, Copy, Default)]
pub struct LongArrayConfigFieldCodec;

impl ConfigFieldCodec<Vec<i64>> for LongArrayConfigFieldCodec {
    fn read(
        &self,
        state: &dyn SaveState,
        name: &str,
        _current: Option<&Vec<i64>>,
    ) -> Option<Vec<i64>> {
        state.get_longs(name, None)
    }

    fn write(&self, state: &mut dyn SaveState, name: &str, value: &Vec<i64>) {
        state.put_longs(name, Some(value.as_slice()));
    }
}

/// Mirrors `AutoConfigState.FloatArrayConfigFieldCodec`.
#[derive(Debug, Clone, Copy, Default)]
pub struct FloatArrayConfigFieldCodec;

impl ConfigFieldCodec<Vec<f32>> for FloatArrayConfigFieldCodec {
    fn read(
        &self,
        state: &dyn SaveState,
        name: &str,
        _current: Option<&Vec<f32>>,
    ) -> Option<Vec<f32>> {
        state.get_floats(name, None)
    }

    fn write(&self, state: &mut dyn SaveState, name: &str, value: &Vec<f32>) {
        state.put_floats(name, Some(value.as_slice()));
    }
}

/// Mirrors `AutoConfigState.DoubleArrayConfigFieldCodec`.
#[derive(Debug, Clone, Copy, Default)]
pub struct DoubleArrayConfigFieldCodec;

impl ConfigFieldCodec<Vec<f64>> for DoubleArrayConfigFieldCodec {
    fn read(
        &self,
        state: &dyn SaveState,
        name: &str,
        _current: Option<&Vec<f64>>,
    ) -> Option<Vec<f64>> {
        state.get_doubles(name, None)
    }

    fn write(&self, state: &mut dyn SaveState, name: &str, value: &Vec<f64>) {
        state.put_doubles(name, Some(value.as_slice()));
    }
}

/// Mirrors `AutoConfigState.StringArrayConfigFieldCodec`.
#[derive(Debug, Clone, Copy, Default)]
pub struct StringArrayConfigFieldCodec;

impl ConfigFieldCodec<Vec<String>> for StringArrayConfigFieldCodec {
    fn read(
        &self,
        state: &dyn SaveState,
        name: &str,
        _current: Option<&Vec<String>>,
    ) -> Option<Vec<String>> {
        state.get_strings(name, None)
    }

    fn write(&self, state: &mut dyn SaveState, name: &str, value: &Vec<String>) {
        state.put_strings(name, Some(value.as_slice()));
    }
}

/// Mirrors `AutoConfigState.BigIntegerConfigFieldCodec`.
///
/// The crate has no arbitrary-precision integer type yet, so this codec operates directly on the
/// same big-endian two's-complement byte encoding `java.math.BigInteger`'s `toByteArray()`/
/// `BigInteger(byte[])` constructor use; a future `BigInteger` port can wrap this representation.
#[derive(Debug, Clone, Copy, Default)]
pub struct BigIntegerConfigFieldCodec;

impl ConfigFieldCodec<Vec<u8>> for BigIntegerConfigFieldCodec {
    fn read(
        &self,
        state: &dyn SaveState,
        name: &str,
        _current: Option<&Vec<u8>>,
    ) -> Option<Vec<u8>> {
        state.get_bytes(name, Some(&[0]))
    }

    fn write(&self, state: &mut dyn SaveState, name: &str, value: &Vec<u8>) {
        state.put_bytes(name, Some(value.as_slice()));
    }
}

/// Mirrors `AutoConfigState.FileConfigFieldCodec`. `java.io.File` has no direct Rust counterpart,
/// so `T` is [`PathBuf`], the same as [`PathConfigFieldCodec`]; the two remain distinct codec
/// types (delegating to [`SaveState::get_file`]/[`SaveState::put_file`] rather than the
/// string-based accessors) to mirror the two distinct Java classes.
#[derive(Debug, Clone, Copy, Default)]
pub struct FileConfigFieldCodec;

impl ConfigFieldCodec<PathBuf> for FileConfigFieldCodec {
    fn read(&self, state: &dyn SaveState, name: &str, current: Option<&PathBuf>) -> Option<PathBuf> {
        match current {
            Some(c) => state.get_file(name, Some(c.as_path())),
            None => state.get_file(name, None),
        }
    }

    fn write(&self, state: &mut dyn SaveState, name: &str, value: &PathBuf) {
        state.put_file(name, Some(value.as_path()));
    }
}

/// Mirrors `AutoConfigState.PathConfigFieldCodec`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PathConfigFieldCodec;

impl ConfigFieldCodec<PathBuf> for PathConfigFieldCodec {
    fn read(&self, state: &dyn SaveState, name: &str, current: Option<&PathBuf>) -> Option<PathBuf> {
        let default = current.map(|c| c.to_string_lossy().into_owned());
        state.get_string(name, default.as_deref()).map(PathBuf::from)
    }

    fn write(&self, state: &mut dyn SaveState, name: &str, value: &PathBuf) {
        state.put_string(name, Some(&value.to_string_lossy()));
    }
}

/// Mirrors `AutoConfigState.PathIsDir`, a `Path` known (by convention, not enforcement) to
/// identify a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathIsDir(pub PathBuf);

impl PathIsDir {
    /// Constructs a `PathIsDir` from a string path, mirroring `PathIsDir.fromString`.
    pub fn from_string(s: &str) -> Self {
        PathIsDir(PathBuf::from(s))
    }
}

impl std::fmt::Display for PathIsDir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

/// Mirrors `AutoConfigState.PathIsDirConfigFieldCodec`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PathIsDirConfigFieldCodec;

impl ConfigFieldCodec<PathIsDir> for PathIsDirConfigFieldCodec {
    fn read(
        &self,
        state: &dyn SaveState,
        name: &str,
        current: Option<&PathIsDir>,
    ) -> Option<PathIsDir> {
        let current_path = current.map(|c| &c.0);
        PathConfigFieldCodec.read(state, name, current_path).map(PathIsDir)
    }

    fn write(&self, state: &mut dyn SaveState, name: &str, value: &PathIsDir) {
        PathConfigFieldCodec.write(state, name, &value.0);
    }
}

/// Mirrors `AutoConfigState.PathIsFile`, a `Path` known (by convention, not enforcement) to
/// identify a regular file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathIsFile(pub PathBuf);

impl PathIsFile {
    /// Constructs a `PathIsFile` from a string path, mirroring `PathIsFile.fromString`.
    pub fn from_string(s: &str) -> Self {
        PathIsFile(PathBuf::from(s))
    }
}

impl std::fmt::Display for PathIsFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

/// Mirrors `AutoConfigState.PathIsFileConfigFieldCodec`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PathIsFileConfigFieldCodec;

impl ConfigFieldCodec<PathIsFile> for PathIsFileConfigFieldCodec {
    fn read(
        &self,
        state: &dyn SaveState,
        name: &str,
        current: Option<&PathIsFile>,
    ) -> Option<PathIsFile> {
        let current_path = current.map(|c| &c.0);
        PathConfigFieldCodec.read(state, name, current_path).map(PathIsFile)
    }

    fn write(&self, state: &mut dyn SaveState, name: &str, value: &PathIsFile) {
        PathConfigFieldCodec.write(state, name, &value.0);
    }
}

/// Adapts a Rust enum-like type to [`EnumConfigFieldCodec`], replacing the Java codec's use of
/// reflection (`Enum.valueOf`/`Enum.name()` looked up via the field's runtime `Class`) with an
/// explicit, hand-implemented name mapping.
pub trait EnumLike: Sized {
    /// The constant's name, mirroring `Enum.name()`.
    fn enum_name(&self) -> &str;

    /// Resolves a constant by name, mirroring `Enum.valueOf(Class, String)`; `None` if `name`
    /// does not name a constant.
    fn from_enum_name(name: &str) -> Option<Self>;
}

/// Mirrors `AutoConfigState.EnumConfigFieldCodec`. Unlike its Java counterpart -- a single
/// non-generic class handling every enum type via the raw `Enum<?>` type and runtime reflection
/// -- this is a blanket implementation over any [`EnumLike`] `T`, since Rust generics need the
/// name/value mapping spelled out per type rather than discovered reflectively.
#[derive(Debug, Clone, Copy, Default)]
pub struct EnumConfigFieldCodec;

impl<T: EnumLike> ConfigFieldCodec<T> for EnumConfigFieldCodec {
    fn read(&self, state: &dyn SaveState, name: &str, _current: Option<&T>) -> Option<T> {
        state.get_enum_name(name).and_then(|n| T::from_enum_name(&n))
    }

    fn write(&self, state: &mut dyn SaveState, name: &str, value: &T) {
        state.put_enum_name(name, Some(value.enum_name()));
    }
}

/// Mirrors `AutoConfigState.GenericAsyncConfigFieldCodec<T>`.
///
/// Java's version mutates the field's existing `AsyncReference` in place (`current.set(...)`)
/// and returns that same reference back to the caller, so `ConfigStateField.load`'s
/// `val == current` identity check skips re-invoking the (no-op) setter. This port has no
/// analogous reflective setter step to skip (see the module-level docs on [`ClassStateHandler`]),
/// so `read` instead always returns `None` after applying the mutation directly through
/// [`AsyncReferenceLike::set`] -- signaling "no replacement value; any update already happened
/// in place" to callers, rather than handing back an owned copy of a value it only borrowed.
pub struct GenericAsyncConfigFieldCodec<T> {
    codec: Box<dyn ConfigFieldCodec<T>>,
}

impl<T> GenericAsyncConfigFieldCodec<T> {
    /// Wraps an inner codec for `T`, mirroring `GenericAsyncConfigFieldCodec(ConfigFieldCodec<T>)`.
    pub fn new(codec: Box<dyn ConfigFieldCodec<T>>) -> Self {
        Self { codec }
    }
}

impl<T> ConfigFieldCodec<Box<dyn AsyncReferenceLike<T>>> for GenericAsyncConfigFieldCodec<T> {
    fn read(
        &self,
        state: &dyn SaveState,
        name: &str,
        current: Option<&Box<dyn AsyncReferenceLike<T>>>,
    ) -> Option<Box<dyn AsyncReferenceLike<T>>> {
        let current_ref = current
            .expect("GenericAsyncConfigFieldCodec requires an existing AsyncReference to update in place");
        let existing = current_ref.get();
        if let Some(value) = self.codec.read(state, name, Some(&existing)) {
            current_ref.set(value);
        }
        None
    }

    fn write(&self, state: &mut dyn SaveState, name: &str, value: &Box<dyn AsyncReferenceLike<T>>) {
        self.codec.write(state, name, &value.get());
    }
}

/// Mirrors `AutoConfigState.BooleanAsyncConfigFieldCodec`.
pub struct BooleanAsyncConfigFieldCodec {
    inner: GenericAsyncConfigFieldCodec<bool>,
}

impl BooleanAsyncConfigFieldCodec {
    /// Creates a new codec, mirroring `new BooleanAsyncConfigFieldCodec()`.
    pub fn new() -> Self {
        Self { inner: GenericAsyncConfigFieldCodec::new(Box::new(BooleanConfigFieldCodec)) }
    }
}

impl Default for BooleanAsyncConfigFieldCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigFieldCodec<Box<dyn AsyncReferenceLike<bool>>> for BooleanAsyncConfigFieldCodec {
    fn read(
        &self,
        state: &dyn SaveState,
        name: &str,
        current: Option<&Box<dyn AsyncReferenceLike<bool>>>,
    ) -> Option<Box<dyn AsyncReferenceLike<bool>>> {
        self.inner.read(state, name, current)
    }

    fn write(&self, state: &mut dyn SaveState, name: &str, value: &Box<dyn AsyncReferenceLike<bool>>) {
        self.inner.write(state, name, value)
    }
}

/// Mirrors the two public instance methods of `AutoConfigState.ClassHandler<T>`
/// (`writeConfigState`/`readConfigState`); see the module-level docs for why the reflective
/// field-discovery half of `ClassHandler` (and `wireHandler`, which builds one via reflection)
/// has no port here. Object-safe, so handlers can be stored as `Box<dyn ClassStateHandler<T>>`.
pub trait ClassStateHandler<T> {
    /// Writes every handled field of `from` into `into`, mirroring `ClassHandler.writeConfigState`.
    fn write_config_state(&self, from: &T, into: &mut dyn SaveState);

    /// Reads every handled field of `into` from `from`, mirroring `ClassHandler.readConfigState`.
    fn read_config_state(&self, into: &mut T, from: &dyn SaveState);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MockSaveState {
        strings: HashMap<String, String>,
        bools: HashMap<String, bool>,
        ints: HashMap<String, i32>,
        byte_arrays: HashMap<String, Vec<u8>>,
    }

    impl SaveState for MockSaveState {
        fn has_value(&self, name: &str) -> bool {
            self.strings.contains_key(name)
                || self.bools.contains_key(name)
                || self.ints.contains_key(name)
                || self.byte_arrays.contains_key(name)
        }

        fn get_boolean(&self, name: &str, default_value: bool) -> bool {
            self.bools.get(name).copied().unwrap_or(default_value)
        }
        fn put_boolean(&mut self, name: &str, value: bool) {
            self.bools.insert(name.to_string(), value);
        }

        fn get_byte(&self, _name: &str, default_value: i8) -> i8 {
            default_value
        }
        fn put_byte(&mut self, _name: &str, _value: i8) {}

        fn get_short(&self, _name: &str, default_value: i16) -> i16 {
            default_value
        }
        fn put_short(&mut self, _name: &str, _value: i16) {}

        fn get_int(&self, name: &str, default_value: i32) -> i32 {
            self.ints.get(name).copied().unwrap_or(default_value)
        }
        fn put_int(&mut self, name: &str, value: i32) {
            self.ints.insert(name.to_string(), value);
        }

        fn get_long(&self, _name: &str, default_value: i64) -> i64 {
            default_value
        }
        fn put_long(&mut self, _name: &str, _value: i64) {}

        fn get_float(&self, _name: &str, default_value: f32) -> f32 {
            default_value
        }
        fn put_float(&mut self, _name: &str, _value: f32) {}

        fn get_double(&self, _name: &str, default_value: f64) -> f64 {
            default_value
        }
        fn put_double(&mut self, _name: &str, _value: f64) {}

        fn get_string(&self, name: &str, default_value: Option<&str>) -> Option<String> {
            self.strings
                .get(name)
                .cloned()
                .or_else(|| default_value.map(|s| s.to_string()))
        }
        fn put_string(&mut self, name: &str, value: Option<&str>) {
            match value {
                Some(v) => {
                    self.strings.insert(name.to_string(), v.to_string());
                }
                None => {
                    self.strings.remove(name);
                }
            }
        }

        fn get_booleans(&self, _name: &str, default_value: Option<&[bool]>) -> Option<Vec<bool>> {
            default_value.map(|v| v.to_vec())
        }
        fn put_booleans(&mut self, _name: &str, _value: Option<&[bool]>) {}

        fn get_bytes(&self, name: &str, default_value: Option<&[u8]>) -> Option<Vec<u8>> {
            self.byte_arrays
                .get(name)
                .cloned()
                .or_else(|| default_value.map(|v| v.to_vec()))
        }
        fn put_bytes(&mut self, name: &str, value: Option<&[u8]>) {
            match value {
                Some(v) => {
                    self.byte_arrays.insert(name.to_string(), v.to_vec());
                }
                None => {
                    self.byte_arrays.remove(name);
                }
            }
        }

        fn get_shorts(&self, _name: &str, default_value: Option<&[i16]>) -> Option<Vec<i16>> {
            default_value.map(|v| v.to_vec())
        }
        fn put_shorts(&mut self, _name: &str, _value: Option<&[i16]>) {}

        fn get_ints(&self, _name: &str, default_value: Option<&[i32]>) -> Option<Vec<i32>> {
            default_value.map(|v| v.to_vec())
        }
        fn put_ints(&mut self, _name: &str, _value: Option<&[i32]>) {}

        fn get_longs(&self, _name: &str, default_value: Option<&[i64]>) -> Option<Vec<i64>> {
            default_value.map(|v| v.to_vec())
        }
        fn put_longs(&mut self, _name: &str, _value: Option<&[i64]>) {}

        fn get_floats(&self, _name: &str, default_value: Option<&[f32]>) -> Option<Vec<f32>> {
            default_value.map(|v| v.to_vec())
        }
        fn put_floats(&mut self, _name: &str, _value: Option<&[f32]>) {}

        fn get_doubles(&self, _name: &str, default_value: Option<&[f64]>) -> Option<Vec<f64>> {
            default_value.map(|v| v.to_vec())
        }
        fn put_doubles(&mut self, _name: &str, _value: Option<&[f64]>) {}

        fn get_strings(&self, _name: &str, default_value: Option<&[String]>) -> Option<Vec<String>> {
            default_value.map(|v| v.to_vec())
        }
        fn put_strings(&mut self, _name: &str, _value: Option<&[String]>) {}

        fn get_file(&self, name: &str, default_value: Option<&Path>) -> Option<PathBuf> {
            self.strings
                .get(name)
                .map(PathBuf::from)
                .or_else(|| default_value.map(|p| p.to_path_buf()))
        }
        fn put_file(&mut self, name: &str, value: Option<&Path>) {
            match value {
                Some(v) => {
                    self.strings.insert(name.to_string(), v.to_string_lossy().into_owned());
                }
                None => {
                    self.strings.remove(name);
                }
            }
        }

        fn get_enum_name(&self, name: &str) -> Option<String> {
            self.strings.get(name).cloned()
        }
        fn put_enum_name(&mut self, name: &str, value: Option<&str>) {
            self.put_string(name, value);
        }
    }

    #[test]
    fn boolean_codec_round_trips_through_trait_object() {
        let codec: Box<dyn ConfigFieldCodec<bool>> = Box::new(BooleanConfigFieldCodec);
        let mut state = MockSaveState::default();

        assert_eq!(codec.read(&state, "flag", None), Some(false));

        codec.write(&mut state, "flag", &true);
        assert_eq!(codec.read(&state, "flag", None), Some(true));
    }

    #[test]
    fn path_is_dir_codec_round_trips() {
        let codec = PathIsDirConfigFieldCodec;
        let mut state = MockSaveState::default();
        let value = PathIsDir::from_string("/tmp/some/dir");

        codec.write(&mut state, "workdir", &value);
        let read_back = codec.read(&state, "workdir", None);
        assert_eq!(read_back, Some(value));
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Mode {
        Fast,
        Slow,
    }

    impl EnumLike for Mode {
        fn enum_name(&self) -> &str {
            match self {
                Mode::Fast => "Fast",
                Mode::Slow => "Slow",
            }
        }

        fn from_enum_name(name: &str) -> Option<Self> {
            match name {
                "Fast" => Some(Mode::Fast),
                "Slow" => Some(Mode::Slow),
                _ => None,
            }
        }
    }

    #[test]
    fn enum_codec_round_trips_through_trait_object() {
        let codec: Box<dyn ConfigFieldCodec<Mode>> = Box::new(EnumConfigFieldCodec);
        let mut state = MockSaveState::default();

        assert_eq!(codec.read(&state, "mode", None), None);

        codec.write(&mut state, "mode", &Mode::Slow);
        assert_eq!(codec.read(&state, "mode", None), Some(Mode::Slow));
    }

    struct MockAsyncReference(RefCell<i32>);

    impl AsyncReferenceLike<i32> for MockAsyncReference {
        fn get(&self) -> i32 {
            *self.0.borrow()
        }

        fn set(&self, value: i32) {
            *self.0.borrow_mut() = value;
        }
    }

    #[test]
    fn generic_async_codec_mutates_reference_in_place() {
        let codec: Box<dyn ConfigFieldCodec<Box<dyn AsyncReferenceLike<i32>>>> =
            Box::new(GenericAsyncConfigFieldCodec::new(Box::new(IntConfigFieldCodec)));
        let mut state = MockSaveState::default();
        state.put_int("counter", 42);

        let current: Box<dyn AsyncReferenceLike<i32>> = Box::new(MockAsyncReference(RefCell::new(0)));
        let result = codec.read(&state, "counter", Some(&current));

        assert!(result.is_none());
        assert_eq!(current.get(), 42);
    }

    struct Widget {
        name: String,
        count: i32,
    }

    struct WidgetStateHandler;

    impl ClassStateHandler<Widget> for WidgetStateHandler {
        fn write_config_state(&self, from: &Widget, into: &mut dyn SaveState) {
            StringConfigFieldCodec.write(into, "name", &from.name);
            IntConfigFieldCodec.write(into, "count", &from.count);
        }

        fn read_config_state(&self, into: &mut Widget, from: &dyn SaveState) {
            if let Some(name) = StringConfigFieldCodec.read(from, "name", Some(&into.name)) {
                into.name = name;
            }
            if let Some(count) = IntConfigFieldCodec.read(from, "count", Some(&into.count)) {
                into.count = count;
            }
        }
    }

    #[test]
    fn class_state_handler_round_trips_through_trait_object() {
        let handler: Box<dyn ClassStateHandler<Widget>> = Box::new(WidgetStateHandler);
        let mut state = MockSaveState::default();
        let original = Widget { name: "gizmo".to_string(), count: 7 };

        handler.write_config_state(&original, &mut state);

        let mut restored = Widget { name: String::new(), count: 0 };
        handler.read_config_state(&mut restored, &state);

        assert_eq!(restored.name, "gizmo");
        assert_eq!(restored.count, 7);
    }
}
