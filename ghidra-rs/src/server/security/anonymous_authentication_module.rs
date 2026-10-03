//! Port of `ghidra.server.security.AnonymousAuthenticationModule`.

use crate::framework::remote::AnonymousCallback;
use crate::framework::seam_stubs::AuthCallback;
use crate::server::security::authentication_module::get_first_callback_of_type;

/// Helper for composing anonymous-login support into an `AuthenticationModule`.
///
/// Port of `ghidra.server.security.AnonymousAuthenticationModule`. Java declares no `implements`
/// clause -- this is not itself an `AuthenticationModule`; concrete authentication modules
/// (password file, PKI, Kerberos/Active Directory, SSH key, or JAAS-based) compose an instance of
/// this helper to add and detect the anonymous-login [`AnonymousCallback`] alongside their own
/// primary authentication callbacks.
#[derive(Debug, Default, Clone, Copy)]
pub struct AnonymousAuthenticationModule;

impl AnonymousAuthenticationModule {
    /// Appends an [`AnonymousCallback`] onto the given primary authentication callbacks.
    ///
    /// Port of `Callback[] addAuthenticationCallbacks(Callback[] primaryAuthCallbacks)`. A `None`
    /// `primary_auth_callbacks` mirrors Java's null-tolerant `if (primaryAuthCallbacks != null)`
    /// guard around the `addAll`.
    pub fn add_authentication_callbacks(
        &self,
        primary_auth_callbacks: Option<Vec<Box<dyn AuthCallback>>>,
    ) -> Vec<Box<dyn AuthCallback>> {
        let mut list = primary_auth_callbacks.unwrap_or_default();
        list.push(Box::new(AnonymousCallback::new()));
        list
    }

    /// Returns whether anonymous access was requested via an [`AnonymousCallback`] present amongst
    /// the given callbacks.
    ///
    /// Port of `boolean anonymousAccessRequested(Callback[] callbacks)`.
    pub fn anonymous_access_requested(&self, callbacks: &[Box<dyn AuthCallback>]) -> bool {
        get_first_callback_of_type::<AnonymousCallback>(callbacks)
            .is_some_and(AnonymousCallback::anonymous_access_requested)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_authentication_callbacks_appends_anonymous_to_an_empty_primary_list() {
        let module = AnonymousAuthenticationModule;
        let result = module.add_authentication_callbacks(Some(vec![]));
        assert_eq!(result.len(), 1);
        assert!(get_first_callback_of_type::<AnonymousCallback>(&result).is_some());
    }

    #[test]
    fn add_authentication_callbacks_preserves_primary_callbacks_and_their_order() {
        use crate::server::security::authentication_module::{NameCallback, PasswordCallback};

        let module = AnonymousAuthenticationModule;
        let primary: Vec<Box<dyn AuthCallback>> = vec![
            Box::new(NameCallback { prompt: "User ID:".to_string(), name: None }),
            Box::new(PasswordCallback { prompt: "Password:".to_string(), echo_on: false, password: None }),
        ];

        let result = module.add_authentication_callbacks(Some(primary));
        assert_eq!(result.len(), 3);
        assert!(get_first_callback_of_type::<NameCallback>(&result).is_some());
        assert!(get_first_callback_of_type::<PasswordCallback>(&result).is_some());
        assert!(get_first_callback_of_type::<AnonymousCallback>(&result).is_some());
    }

    #[test]
    fn add_authentication_callbacks_with_no_primary_callbacks_yields_just_anonymous() {
        let module = AnonymousAuthenticationModule;
        let result = module.add_authentication_callbacks(None);
        assert_eq!(result.len(), 1);
        assert!(get_first_callback_of_type::<AnonymousCallback>(&result).is_some());
    }

    #[test]
    fn anonymous_access_requested_true_when_callback_present_and_set() {
        let module = AnonymousAuthenticationModule;
        let mut anon = AnonymousCallback::new();
        anon.set_anonymous_access_requested(true);
        let callbacks: Vec<Box<dyn AuthCallback>> = vec![Box::new(anon)];

        assert!(module.anonymous_access_requested(&callbacks));
    }

    #[test]
    fn anonymous_access_requested_false_when_callback_present_but_unset() {
        let module = AnonymousAuthenticationModule;
        let callbacks: Vec<Box<dyn AuthCallback>> = vec![Box::new(AnonymousCallback::new())];

        assert!(!module.anonymous_access_requested(&callbacks));
    }

    #[test]
    fn anonymous_access_requested_false_when_no_anonymous_callback_present() {
        let module = AnonymousAuthenticationModule;
        let callbacks: Vec<Box<dyn AuthCallback>> = vec![];

        assert!(!module.anonymous_access_requested(&callbacks));
    }

    #[test]
    fn round_trip_through_add_then_check() {
        let module = AnonymousAuthenticationModule;
        let callbacks = module.add_authentication_callbacks(None);

        // Freshly added anonymous callbacks default to "not requested", matching
        // `AnonymousCallback`'s own default.
        assert!(!module.anonymous_access_requested(&callbacks));
    }
}
