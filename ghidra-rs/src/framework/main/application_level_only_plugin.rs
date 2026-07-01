use super::ApplicationLevelPlugin;

/// Marker trait to indicate this plugin is application-level tools only (see
/// [`ApplicationLevelPlugin`]).
pub trait ApplicationLevelOnlyPlugin: ApplicationLevelPlugin {}

#[cfg(test)]
mod tests {
	use super::*;

	struct ConcreteApplicationLevelOnlyPlugin;

	impl ApplicationLevelPlugin for ConcreteApplicationLevelOnlyPlugin {}
	impl ApplicationLevelOnlyPlugin for ConcreteApplicationLevelOnlyPlugin {}

	fn requires_application_level_only<T: ApplicationLevelOnlyPlugin>(_: &T) {}

	#[test]
	fn concrete_type_satisfies_marker_trait() {
		let plugin = ConcreteApplicationLevelOnlyPlugin;
		requires_application_level_only(&plugin);
	}

	#[test]
	fn trait_is_object_safe() {
		let plugin = ConcreteApplicationLevelOnlyPlugin;
		let _boxed: Box<dyn ApplicationLevelOnlyPlugin> = Box::new(plugin);
	}

	#[test]
	fn trait_extends_application_level_plugin() {
		fn generic_level<T: ApplicationLevelPlugin>(_: &T) {}
		let plugin = ConcreteApplicationLevelOnlyPlugin;
		generic_level(&plugin);
	}
}
