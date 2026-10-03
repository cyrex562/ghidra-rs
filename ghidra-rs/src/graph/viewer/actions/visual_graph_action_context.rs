/// Action context for visual graphs.
///
/// Port of `ghidra.graph.viewer.actions.VisualGraphActionContext`. Java implementors are the
/// graph viewers' docking action contexts, which mix this interface in; it carries no docking
/// dependency of its own.
pub trait VisualGraphActionContext {
    /// Returns true if actions that manipulate the satellite viewer should be enabled for this
    /// context.
    ///
    /// These actions should be available generically; implementors may override to return
    /// false.
    fn should_show_satellite_actions(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DefaultContext;
    impl VisualGraphActionContext for DefaultContext {}

    struct NoSatelliteContext;
    impl VisualGraphActionContext for NoSatelliteContext {
        fn should_show_satellite_actions(&self) -> bool {
            false
        }
    }

    fn shows(ctx: &impl VisualGraphActionContext) -> bool {
        ctx.should_show_satellite_actions()
    }

    #[test]
    fn satellite_actions_default_to_enabled() {
        assert!(shows(&DefaultContext));
    }

    #[test]
    fn implementors_may_disable_satellite_actions() {
        assert!(!shows(&NoSatelliteContext));
        let ctxs: Vec<Box<dyn VisualGraphActionContext>> =
            vec![Box::new(DefaultContext), Box::new(NoSatelliteContext)];
        let shown: Vec<bool> = ctxs.iter().map(|c| c.should_show_satellite_actions()).collect();
        assert_eq!(shown, [true, false]);
    }
}
