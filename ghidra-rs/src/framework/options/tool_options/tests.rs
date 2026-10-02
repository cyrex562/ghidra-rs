//! Ported from `ghidra.framework.options.OptionsTest` (Features/Base test).

use std::any::Any;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use super::*;
use crate::framework::options::custom_option::register_custom_option_class;
use crate::framework::options::g_properties::GProperties;
use crate::framework::options::option::{minus_years, HelpRef};
use crate::framework::seam_stubs::{HelpLocation, OptionsVetoException};

fn options() -> ToolOptions {
    ToolOptions::new("Test")
}

fn save_and_restore(options: &ToolOptions) -> ToolOptions {
    let root = options.get_xml_root(false);
    // Round-trip through text as the tool file does.
    let parsed = Element::parse_str(&root.output_string()).unwrap();
    ToolOptions::from_xml(&parsed)
}

struct TestColor;
impl Color for TestColor {}

struct TestHelp;
impl HelpLocation for TestHelp {}

fn fruit(name: &str) -> EnumOptionValue {
    EnumOptionValue { class_name: "test.FRUIT".to_string(), name: name.to_string() }
}

#[derive(Default)]
struct MyCustomOption(i32);
impl fmt::Display for MyCustomOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MyCustomOption[value={}]", self.0)
    }
}
impl CustomOption for MyCustomOption {
    fn read_state(&mut self, properties: &GProperties) {
        self.0 = properties.get_int("VALUE", 0);
    }
    fn write_state(&self, properties: &mut GProperties) {
        properties.put_int("VALUE", self.0);
    }
    fn java_class_name(&self) -> &'static str {
        "test.MyCustomOption"
    }
}

#[test]
fn getting_default_when_no_options_exist() {
    assert_eq!(options().get_int("Foo", 5), Ok(5));
}

#[test]
fn get_name() {
    assert_eq!(options().get_name(), "Test");
}

#[test]
fn getting_value_when_already_set() {
    let o = options();
    o.set_int("Foo", 32).unwrap();
    assert_eq!(o.get_int("Foo", 5), Ok(32));
}

#[test]
fn defaults_not_saved() {
    let o = options();
    o.register_option("Foo", Some(OptionValue::Int(5)), None, "foo").unwrap();
    assert!(o.contains("Foo"));
    assert_eq!(o.get_int("Foo", 0), Ok(5));
    let o = save_and_restore(&o);
    assert!(!o.contains("Foo"));
}

#[test]
fn mixing_types_for_same_name_is_illegal_state() {
    let o = options();
    o.set_int("Foo", 5).unwrap();
    assert!(matches!(o.get_string("Foo", Some("Default")), Err(OptionsError::IllegalState(_))));
    assert!(matches!(o.set_string("Foo", Some("x")), Err(OptionsError::IllegalState(_))));
}

#[test]
fn save_primitive_options() {
    let o = options();
    o.set_int("Int", 32).unwrap();
    o.set_long("Long", 5_000_000_000).unwrap();
    o.set_float("Float", 5.3).unwrap();
    o.set_double("Double", 5.3).unwrap();
    o.set_boolean("Bool", true).unwrap();
    o.set_string("Str", Some("Hey")).unwrap();
    o.set_byte_array("BYTES", Some(&[1, 2, 3])).unwrap();
    let o = save_and_restore(&o);
    assert_eq!(o.get_int("Int", 5), Ok(32));
    assert_eq!(o.get_long("Long", 5), Ok(5_000_000_000));
    assert_eq!(o.get_float("Float", 0.0), Ok(5.3));
    assert_eq!(o.get_double("Double", 0.0), Ok(5.3));
    assert_eq!(o.get_boolean("Bool", false), Ok(true));
    assert_eq!(o.get_string("Str", Some("Default")), Ok(Some("Hey".to_string())));
    assert_eq!(o.get_byte_array("BYTES", None), Ok(Some(vec![1, 2, 3])));
}

#[test]
fn save_file_and_date_options() {
    let o = options();
    let file = std::path::absolute(PathBuf::from("/Users/foo")).unwrap();
    o.set_file("Foo", Some(file.clone())).unwrap();
    let date = UNIX_EPOCH + Duration::from_millis(1_700_000_000_123);
    o.set_date("Date", Some(date)).unwrap();
    let o = save_and_restore(&o);
    assert_eq!(o.get_file("Foo", Some(PathBuf::from("/"))), Ok(Some(file)));
    assert_eq!(o.get_date("Date", None), Ok(Some(date)));
}

#[test]
fn save_enum_option() {
    let o = options();
    o.set_enum("SNACK", Some(fruit("Orange"))).unwrap();
    assert_eq!(o.get_enum("SNACK", None), Ok(Some(fruit("Orange"))));
    let o = save_and_restore(&o);
    assert_eq!(o.get_enum("SNACK", None), Ok(Some(fruit("Orange"))));
}

#[test]
fn save_custom_option() {
    register_custom_option_class("test.MyCustomOption", || Box::new(MyCustomOption(0)));
    let o = options();
    o.set_custom_option("Foo", Some(Arc::new(MyCustomOption(3)))).unwrap();
    let o = save_and_restore(&o);
    let value = o.get_custom_option("Foo", None).unwrap().unwrap();
    assert_eq!(value.to_string(), "MyCustomOption[value=3]");
}

#[test]
fn cleared_wrapped_value_round_trips() {
    let o = options();
    let file = std::path::absolute(PathBuf::from("/tmp-not-used/a")).unwrap();
    o.register_option("F", Some(OptionValue::File(file)), None, "file").unwrap();
    o.set_file("F", None).unwrap();
    let o = save_and_restore(&o);
    assert!(o.contains("F"));
    assert_eq!(o.get_type("F"), Ok(OptionType::FileType));
    assert_eq!(o.find_option("F").unwrap().current_value().is_none(), true);
}

#[test]
fn copy() {
    let o = options();
    o.set_int("Foo", 3).unwrap();
    o.get_long("LONG", 10).unwrap();
    o.register_option("Bar", Some(OptionValue::Boolean(true)), None, "foo").unwrap();
    let copy = o.copy();
    assert!(copy.contains("Foo"));
    assert!(copy.contains("LONG"));
    assert!(copy.contains("Bar"));
    assert_eq!(copy.get_int("Foo", 3), Ok(3));
    assert!(o == copy);
}

#[test]
fn has_non_default_values() {
    let o = options();
    let non_default =
        |o: &ToolOptions| o.get_option_names().iter().any(|n| !o.is_default_value(n).unwrap());
    assert!(!non_default(&o));
    o.get_long("LONG", 10).unwrap();
    assert!(!non_default(&o));
    o.set_long("LONG", 3).unwrap();
    assert!(non_default(&o));
}

/// `OptionsChangeListenerForTestVeto`: the second listener called vetoes.
struct VetoListener {
    counter: Arc<Mutex<i32>>,
    call_count: i32,
    value: Option<i32>,
}

struct Veto;
impl OptionsVetoException for Veto {}

impl OptionsChangeListener for VetoListener {
    fn options_changed(
        &mut self,
        _options: &dyn crate::framework::seam_stubs::ToolOptions,
        _option_name: &str,
        _old_value: Option<&dyn Any>,
        new_value: Option<&dyn Any>,
    ) -> Result<(), Box<dyn OptionsVetoException>> {
        if self.call_count < 0 {
            let mut c = self.counter.lock().unwrap();
            *c += 1;
            self.call_count = *c;
        }
        if self.call_count > 1 {
            return Err(Box::new(Veto));
        }
        self.value = match new_value.and_then(|v| v.downcast_ref::<OptionValue>()) {
            Some(OptionValue::Int(i)) => Some(*i),
            _ => None,
        };
        Ok(())
    }
}

#[test]
fn veto_rolls_back_and_renotifies() {
    let o = options();
    o.set_int("VALUE", 1).unwrap();
    let counter = Arc::new(Mutex::new(0));
    let l1 = Arc::new(Mutex::new(VetoListener { counter: counter.clone(), call_count: -1, value: None }));
    let l2 = Arc::new(Mutex::new(VetoListener { counter, call_count: -1, value: None }));
    let s1: SharedOptionsListener = l1.clone();
    let s2: SharedOptionsListener = l2.clone();
    o.add_options_change_listener(&s1);
    o.add_options_change_listener(&s2);

    assert_eq!(o.set_int("VALUE", 2), Err(OptionsError::Vetoed));
    assert_eq!(o.get_int("VALUE", 1), Ok(1));
    // The first listener saw the change, then the revert back to the old value.
    let first = l1.lock().unwrap();
    assert_eq!(first.call_count, 1);
    assert_eq!(first.value, Some(1));
    assert_eq!(l2.lock().unwrap().value, None);
}

struct Recorder(Vec<(String, Option<i32>, Option<i32>)>);
impl OptionsChangeListener for Recorder {
    fn options_changed(
        &mut self,
        options: &dyn crate::framework::seam_stubs::ToolOptions,
        option_name: &str,
        old_value: Option<&dyn Any>,
        new_value: Option<&dyn Any>,
    ) -> Result<(), Box<dyn OptionsVetoException>> {
        let int = |v: Option<&dyn Any>| match v.and_then(|v| v.downcast_ref::<OptionValue>()) {
            Some(OptionValue::Int(i)) => Some(*i),
            _ => None,
        };
        // The new value is already visible through the options while notifying.
        assert_eq!(options.get_option(option_name), int(new_value).map(|i| i.to_string()));
        self.0.push((option_name.to_string(), int(old_value), int(new_value)));
        Ok(())
    }
}

#[test]
fn listeners_are_notified_and_held_weakly() {
    let o = options();
    o.register_option("Foo", Some(OptionValue::Int(10)), None, "foo").unwrap();
    let rec = Arc::new(Mutex::new(Recorder(Vec::new())));
    let shared: SharedOptionsListener = rec.clone();
    o.add_options_change_listener(&shared);
    o.set_int("Foo", 2).unwrap();
    o.restore_default_value("Foo").unwrap();
    o.restore_default_value("Foo").unwrap(); // already default: no notification
    assert_eq!(
        rec.lock().unwrap().0,
        vec![("Foo".to_string(), Some(10), Some(2)), ("Foo".to_string(), Some(2), Some(10))]
    );
    o.remove_options_change_listener(&shared);
    o.set_int("Foo", 3).unwrap();
    assert_eq!(rec.lock().unwrap().0.len(), 2);

    // Dropped listeners are no longer notified (WeakSet).
    let o2 = options();
    {
        let temp: SharedOptionsListener = Arc::new(Mutex::new(Recorder(Vec::new())));
        o2.add_options_change_listener(&temp);
    }
    o2.set_int("Foo", 1).unwrap();
}

#[test]
fn remove() {
    let o = options();
    o.set_int("COLOR", 1).unwrap();
    assert!(o.contains("COLOR"));
    o.remove_option("COLOR");
    assert!(!o.contains("COLOR"));
}

#[test]
fn get_option_names_sorted() {
    let o = options();
    o.set_color("COLOR", Some(Arc::new(TestColor))).unwrap();
    o.set_int("INT", 3).unwrap();
    assert_eq!(o.get_option_names(), vec!["COLOR".to_string(), "INT".to_string()]);
}

#[test]
fn default_value_and_restore() {
    let o = options();
    let red: Arc<dyn Color + Send + Sync> = Arc::new(TestColor);
    let blue: Arc<dyn Color + Send + Sync> = Arc::new(TestColor);
    o.register_option("Foo", Some(OptionValue::Color(red.clone())), None, "foo").unwrap();
    o.set_color("Foo", Some(blue.clone())).unwrap();
    assert!(Arc::ptr_eq(&o.get_color("Foo", None).unwrap().unwrap(), &blue));
    match o.get_default_value("Foo").unwrap() {
        Some(OptionValue::Color(c)) => assert!(Arc::ptr_eq(&c, &red)),
        other => panic!("unexpected default {other:?}"),
    }
    o.restore_default_value("Foo").unwrap();
    assert!(Arc::ptr_eq(&o.get_color("Foo", None).unwrap().unwrap(), &red));
}

#[test]
fn registered_editor_id_and_help_location() {
    let o = options();
    o.register_option_with_type(
        "color",
        OptionType::ColorType,
        Some(OptionValue::Color(Arc::new(TestColor))),
        None,
        Some("foo"),
        Some("my.editor".to_string()),
    )
    .unwrap();
    assert_eq!(o.get_registered_editor_id("color"), Ok(Some("my.editor".to_string())));

    let help: HelpRef = Arc::new(TestHelp);
    o.register_option("Foo", Some(OptionValue::Int(3)), Some(help.clone()), "foo").unwrap();
    assert!(Arc::ptr_eq(&o.get_help_location("Foo").unwrap().unwrap(), &help));
}

#[test]
fn options_help_and_editor_per_category() {
    let o = options();
    assert!(o.get_category_help_location("").is_none());
    let help: HelpRef = Arc::new(TestHelp);
    o.set_category_help_location("", Some(help.clone()));
    assert!(o.get_category_help_location("").is_some());
    assert!(o.get_category_help_location("SUB").is_none());
    o.set_category_help_location("SUB", Some(help));
    assert!(o.get_category_help_location("SUB").is_some());

    o.register_options_editor("", "root.editor");
    o.register_options_editor("SUB", "sub.editor");
    assert_eq!(o.get_options_editor(""), Some("root.editor".to_string()));
    assert_eq!(o.get_options_editor("SUB"), Some("sub.editor".to_string()));
}

#[test]
fn illegal_names() {
    let o = options();
    for bad in ["a..b", ".a", "a."] {
        assert!(matches!(o.set_int(bad, 3), Err(OptionsError::IllegalArgument(_))), "{bad}");
    }
    // Consecutive delimiters inside quotes are allowed.
    assert!(o.set_int("a.\"x..y\"", 3).is_ok());
}

#[test]
fn is_default_value() {
    let o = options();
    assert_eq!(o.is_default_value("Foo"), Ok(true));
    o.get_int("Foo", 2).unwrap();
    assert_eq!(o.is_default_value("Foo"), Ok(true));
    o.set_int("Foo", 3).unwrap();
    assert_eq!(o.is_default_value("Foo"), Ok(false));
}

#[test]
fn is_registered() {
    let o = options();
    assert!(!o.is_registered("Foo"));
    o.set_int("Foo", 3).unwrap();
    assert!(o.is_registered("Foo"));

    assert!(!o.is_registered("Bar"));
    o.get_int("Bar", 10).unwrap();
    assert!(!o.is_registered("Bar"));

    assert!(!o.is_registered("aaa"));
    o.register_option("aaa", Some(OptionValue::Int(3)), None, "foo").unwrap();
    assert!(o.is_registered("aaa"));
}

#[test]
fn restore_defaults() {
    let o = options();
    o.register_option("Foo", Some(OptionValue::Int(10)), None, "foo").unwrap();
    o.set_int("Foo", 2).unwrap();
    o.register_option("Bar", Some(OptionValue::Int(100)), None, "foo").unwrap();
    o.set_int("Bar", 1).unwrap();
    o.restore_default_values().unwrap();
    assert_eq!(o.get_int("Foo", 0), Ok(10));
    assert_eq!(o.get_int("Bar", 0), Ok(100));
}

#[test]
fn description_first_register_wins() {
    let o = options();
    assert_eq!(o.get_description("Foo"), Ok("Unregistered Option".to_string()));
    o.register_option("Foo", Some(OptionValue::Int(5)), None, "Hey").unwrap();
    assert_eq!(o.get_description("Foo"), Ok("Hey".to_string()));
    o.set_int("Foo", 3).unwrap();
    assert_eq!(o.get_description("Foo"), Ok("Hey".to_string()));
    o.register_option("Foo", Some(OptionValue::Int(7)), None, "There").unwrap();
    assert_eq!(o.get_description("Foo"), Ok("Hey".to_string()));
}

#[test]
fn is_empty() {
    let o = options();
    assert!(o.get_option_names().is_empty());
    o.set_int("Foo", 3).unwrap();
    assert!(!o.get_option_names().is_empty());
}

#[test]
fn remove_unused_options() {
    // Java testRemoveUnusedOptions: options last registered over a year ago are removed after
    // a save/restore cycle; recently registered ones stay.
    let o = options();
    o.register_option("Old", Some(OptionValue::Int(1)), None, "old").unwrap();
    o.set_int("Old", 2).unwrap();
    o.register_option("New", Some(OptionValue::Int(1)), None, "new").unwrap();
    o.set_int("New", 2).unwrap();
    let mut old = o.find_option("Old").unwrap();
    old.set_last_registered_day(Some(minus_years(today_epoch_day(), 2)));
    o.registry().insert_option(old);

    let o = save_and_restore(&o);
    assert!(o.contains("Old"));
    o.remove_unused_options();
    assert!(!o.contains("Old"));
    assert!(o.contains("New"));
}

#[test]
fn copy_options() {
    let o = options();
    o.set_int("INT", 3).unwrap();
    let o2 = ToolOptions::new("aaa");
    o2.copy_options(&o).unwrap();
    assert_eq!(o2.get_int("INT", 0), Ok(3));
}

#[test]
fn sub_option_categories() {
    let o = options();
    o.set_int("Z", 1).unwrap();
    o.set_int("A.B", 2).unwrap();
    o.set_int("A.D.E", 3).unwrap();
    o.set_int("B.F", 4).unwrap();

    assert_eq!(o.child_categories(""), vec!["A".to_string(), "B".to_string()]);
    assert_eq!(o.option_names_in_category("A"), vec!["B".to_string(), "D.E".to_string()]);
    assert_eq!(o.child_categories("A"), vec!["D".to_string()]);
    assert_eq!(o.option_names_in_category("A.D"), vec!["E".to_string()]);
    assert_eq!(o.get_int("A.D.E", 0), Ok(3));
}

#[test]
fn leaf_option_names() {
    let o = options();
    o.set_int("aaa", 5).unwrap();
    o.set_int("bbb", 6).unwrap();
    o.set_int("ccc.ddd", 10).unwrap();
    assert_eq!(o.leaf_option_names(""), vec!["aaa".to_string(), "bbb".to_string()]);

    o.set_int("foo.aaa", 5).unwrap();
    o.set_int("foo.bbb", 6).unwrap();
    o.set_int("foo.ccc.ddd", 10).unwrap();
    assert_eq!(o.leaf_option_names("foo"), vec!["aaa".to_string(), "bbb".to_string()]);
}

#[test]
fn get_id() {
    let o = options();
    assert_eq!(o.get_id("foo.aaa"), "Test.foo.aaa");
    assert_eq!(ToolOptions::new("").get_id("x"), "x");
}

#[test]
fn value_and_default_as_string() {
    let o = options();
    o.set_int("foo", 5).unwrap();
    assert_eq!(o.get_value_as_string("foo"), Ok(Some("5".to_string())));
    assert_eq!(o.get_value_as_string("bar"), Ok(None));

    o.register_option("dflt", Some(OptionValue::Int(7)), None, "foo").unwrap();
    o.set_int("dflt", 5).unwrap();
    assert_eq!(o.get_default_value_as_string("dflt"), Ok(Some("7".to_string())));
    assert_eq!(o.get_default_value_as_string("bar"), Ok(None));
}

#[test]
fn registering_with_null_value_or_no_type_fails() {
    let o = options();
    assert!(matches!(o.register_option("Foo", None, None, "foo"), Err(OptionsError::IllegalArgument(_))));
    assert!(matches!(
        o.register_option_with_type("Foo", OptionType::NoType, None, None, Some("foo"), None),
        Err(OptionsError::IllegalArgument(_))
    ));
    // A default value that does not match the declared type.
    assert!(matches!(
        o.register_option_with_type(
            "Foo",
            OptionType::IntType,
            Some(OptionValue::String("x".into())),
            None,
            Some("foo"),
            None
        ),
        Err(OptionsError::IllegalState(_))
    ));
}

#[test]
fn null_values() {
    let o = options();
    o.set_color("Bar", Some(Arc::new(TestColor))).unwrap();
    o.set_color("Bar", None).unwrap();
    assert!(o.get_color("Bar", None).unwrap().is_none());

    // With no default, a null value uses the passed-in default.
    let blue: Arc<dyn Color + Send + Sync> = Arc::new(TestColor);
    assert!(Arc::ptr_eq(&o.get_color("Bar", Some(blue.clone())).unwrap().unwrap(), &blue));

    // putObject(null) is only allowed for nullable types.
    o.set_int("Int", 1).unwrap();
    assert!(matches!(o.put_object("Int", None), Err(OptionsError::IllegalArgument(_))));
    o.set_string("Str", Some("s")).unwrap();
    assert!(o.put_object("Str", None).is_ok());
    assert_eq!(o.get_string("Str", None), Ok(None));
}

#[test]
fn get_type() {
    let o = options();
    o.set_int("fool", 5).unwrap();
    assert_eq!(o.get_type("fool"), Ok(OptionType::IntType));
    assert_eq!(o.get_type("bar"), Ok(OptionType::NoType));
    assert!(!o.contains("bar"));
}

#[test]
fn key_strokes_are_stored_as_action_triggers() {
    use crate::util::awt::key_stroke::{vk, CTRL_DOWN_MASK};
    let o = options();
    let ks = KeyStroke::new(vk::G, CTRL_DOWN_MASK);
    o.register_option_with_type(
        "Action",
        OptionType::KeystrokeType,
        Some(OptionValue::KeyStroke(ks)),
        None,
        Some("an action"),
        None,
    )
    .unwrap();
    assert_eq!(o.get_type("Action"), Ok(OptionType::ActionTrigger));
    assert_eq!(o.get_key_stroke("Action", None), Ok(Some(ks)));
    o.set_key_stroke("Action", None).unwrap();
    assert_eq!(o.get_key_stroke("Action", None), Ok(None));
}

#[test]
fn register_options_from_old_options() {
    let old = options();
    old.register_option("Foo", Some(OptionValue::Int(5)), None, "desc").unwrap();
    old.get_int("Unreg", 1).unwrap();
    let new = ToolOptions::new("Test");
    new.register_options(&old).unwrap();
    assert!(new.is_registered("Foo"));
    assert_eq!(new.get_description("Foo"), Ok("desc".to_string()));
    assert!(!new.contains("Unreg"));
}

#[test]
fn xml_format_matches_java() {
    let o = options();
    o.set_int("Foo", 32).unwrap();
    let root = o.get_xml_root(false);
    assert_eq!(root.get_name(), "CATEGORY");
    assert_eq!(root.get_attribute_value("NAME"), Some("Test"));
    let state = root.get_children().first().unwrap();
    assert_eq!(state.get_attribute_value("NAME"), Some("Foo"));
    assert_eq!(state.get_attribute_value("TYPE"), Some("int"));
    assert_eq!(state.get_attribute_value("VALUE"), Some("32"));
    assert_eq!(
        state.get_attribute_value("LAST_REGISTERED"),
        Some(format_iso_date(today_epoch_day()).as_str())
    );
}

#[test]
fn alias() {
    // Java testAlias / testAliasAcrossSubOptions.
    let o = options();
    let other = ToolOptions::new("Other");
    other.set_int("Foo", 1).unwrap();
    other.set_int("sub.Bar", 7).unwrap();
    o.create_alias("MyFoo", &other.shared_registry(), "Foo");
    o.create_alias("MyBar", &other.shared_registry(), "sub.Bar");
    assert!(o.is_alias("MyFoo"));
    assert!(o.contains("MyFoo"));
    assert_eq!(o.get_option_names(), vec!["MyBar".to_string(), "MyFoo".to_string()]);
    assert_eq!(o.get_int("MyFoo", 0), Ok(1));
    assert_eq!(o.get_int("MyBar", 0), Ok(7));
    o.set_int("MyFoo", 5).unwrap();
    assert_eq!(other.get_int("Foo", 0), Ok(5));
    o.remove_option("MyFoo");
    assert!(!o.is_alias("MyFoo"));
}

#[test]
fn dispose_drops_listeners() {
    let o = options();
    let rec = Arc::new(Mutex::new(Recorder(Vec::new())));
    let shared: SharedOptionsListener = rec.clone();
    o.add_options_change_listener(&shared);
    o.dispose();
    o.set_int("Foo", 1).unwrap();
    assert!(rec.lock().unwrap().0.is_empty());
    // validate_options never fails; it only logs in development mode.
    o.validate_options();
}

#[test]
fn take_listeners_moves_them() {
    let old = options();
    let rec = Arc::new(Mutex::new(Recorder(Vec::new())));
    let shared: SharedOptionsListener = rec.clone();
    old.add_options_change_listener(&shared);
    let new = options();
    new.take_listeners(&old);
    old.set_int("Foo", 1).unwrap();
    assert!(rec.lock().unwrap().0.is_empty());
    new.set_int("Foo", 2).unwrap();
    assert_eq!(rec.lock().unwrap().0.len(), 1);
}
