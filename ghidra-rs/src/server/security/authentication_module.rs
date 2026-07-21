use std::any::Any;

use thiserror::Error;

use crate::framework::remote::GhidraPrincipal;
use crate::framework::seam_stubs::AuthCallback;
use crate::server::seam_stubs::UserManagerLike;

/// Prompt text for a username callback.
pub const USERNAME_CALLBACK_PROMPT: &str = "User ID";

/// Prompt text for a password callback.
pub const PASSWORD_CALLBACK_PROMPT: &str = "Password";

/// Combines the checked exceptions declared on `AuthenticationModule.authenticate`, which is
/// declared `throws LoginException` (with `FailedLoginException` as a distinguished subclass).
#[derive(Error, Debug)]
pub enum LoginError {
    /// Mirrors a plain `LoginException`: an unrecoverable error occurred during login and the
    /// client should not retry authentication.
    #[error("{0}")]
    Login(String),
    /// Mirrors `FailedLoginException`: authentication was unsuccessful and the client may retry.
    #[error("{0}")]
    FailedLogin(String),
}

/// Standard username-prompting callback, mirroring `javax.security.auth.callback.NameCallback`
/// as used by [`create_simple_name_password_callbacks`].
pub struct NameCallback {
    /// Prompt text presented to the user.
    pub prompt: String,
    /// The name entered by the user, filled in by the caller before authentication.
    pub name: Option<String>,
}

impl AuthCallback for NameCallback {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Standard password-prompting callback, mirroring
/// `javax.security.auth.callback.PasswordCallback` as used by
/// [`create_simple_name_password_callbacks`].
pub struct PasswordCallback {
    /// Prompt text presented to the user.
    pub prompt: String,
    /// Whether the entered password should be echoed back to the user.
    pub echo_on: bool,
    /// The password entered by the user, filled in by the caller before authentication.
    pub password: Option<Vec<u8>>,
}

impl AuthCallback for PasswordCallback {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Performs authentication of a Ghidra Server user via some means (e.g., password file, PKI,
/// Kerberos/Active Directory, SSH key, or JAAS login module).
///
/// Mirrors `ghidra.server.security.AuthenticationModule`. Concrete authentication mechanisms
/// (not yet ported) implement this trait; the Ghidra Server login handler drives it by first
/// consulting [`get_authentication_callbacks`](AuthenticationModule::get_authentication_callbacks)
/// to determine what to prompt the user for, then invoking
/// [`authenticate`](AuthenticationModule::authenticate) once those callbacks have been satisfied.
///
/// `ghidra.server.UserManager` is not yet ported; it is represented here by the
/// [`UserManagerLike`](crate::server::seam_stubs::UserManagerLike) placeholder. Java's
/// `javax.security.auth.Subject` is represented by the extracted [`GhidraPrincipal`] slice,
/// consistent with [`GhidraPrincipal::get_ghidra_principal`], and
/// `javax.security.auth.callback.Callback` by the
/// [`AuthCallback`](crate::framework::seam_stubs::AuthCallback) placeholder already used for
/// this purpose by [`GhidraServerHandle`](crate::framework::remote::GhidraServerHandle).
pub trait AuthenticationModule {
    /// Complete the authentication process.
    ///
    /// Note to `AuthenticationModule` implementors:
    /// - The authentication callback objects are not guaranteed to be the same instances as
    ///   those returned by [`get_authentication_callbacks`](Self::get_authentication_callbacks)
    ///   (they may have been cloned or duplicated or copied in some manner).
    /// - The authentication callback slice may contain callback instances other than the ones
    ///   this module specified in its `get_authentication_callbacks`.
    ///
    /// `user_mgr` is the Ghidra server user manager. `subject_principals` is the unauthenticated
    /// user ID (must be used if a name callback is not provided/allowed). `callbacks` are the
    /// authentication callbacks, already satisfied by the caller.
    ///
    /// Returns the authenticated user ID (may come from the callbacks). Returns
    /// [`LoginError::Login`] if an unrecoverable error occurred during login (the client should
    /// not retry), or [`LoginError::FailedLogin`] if authentication was unsuccessful (the client
    /// may retry).
    fn authenticate(
        &self,
        user_mgr: &dyn UserManagerLike,
        subject_principals: Option<&[GhidraPrincipal]>,
        callbacks: &[Box<dyn AuthCallback>],
    ) -> Result<String, LoginError>;

    /// Returns authentication callbacks needed to authenticate a user.
    fn get_authentication_callbacks(&self) -> Vec<Box<dyn AuthCallback>>;

    /// Allows this `AuthenticationModule` to deny default anonymous login steps.
    ///
    /// Returns true if a separate anonymous-login callback is allowed and may be added to the
    /// callbacks returned by [`get_authentication_callbacks`](Self::get_authentication_callbacks).
    fn anonymous_callbacks_allowed(&self) -> bool;

    /// Returns true if a name callback is allowed.
    fn is_name_callback_allowed(&self) -> bool;
}

/// Creates a standard pair of name and password callback instances.
///
/// `allow_user_to_specify_name`: if false, a name callback is not added to the results.
pub fn create_simple_name_password_callbacks(
    allow_user_to_specify_name: bool,
) -> Vec<Box<dyn AuthCallback>> {
    let pass_cb = Box::new(PasswordCallback {
        prompt: format!("{PASSWORD_CALLBACK_PROMPT}:"),
        echo_on: false,
        password: None,
    });
    if allow_user_to_specify_name {
        let name_cb = Box::new(NameCallback {
            prompt: format!("{USERNAME_CALLBACK_PROMPT}:"),
            name: None,
        });
        vec![name_cb, pass_cb]
    } else {
        vec![pass_cb]
    }
}

/// Find the first callback of a specific type in the slice and returns it.
///
/// Mirrors `AuthenticationModule.getFirstCallbackOfType`, which matches by exact runtime class;
/// [`Any::downcast_ref`] provides the same exact-type semantics.
pub fn get_first_callback_of_type<T: AuthCallback + 'static>(
    callbacks: &[Box<dyn AuthCallback>],
) -> Option<&T> {
    callbacks.iter().find_map(|cb| cb.as_any().downcast_ref::<T>())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockUserManager;
    impl UserManagerLike for MockUserManager {}

    /// Authenticates against a fixed username/password pair pulled out of the callback slice by
    /// type, exercising both static helpers and proving `AuthenticationModule` is object-safe.
    struct FixedCredentialsModule {
        expected_user: &'static str,
        expected_password: &'static [u8],
    }

    impl AuthenticationModule for FixedCredentialsModule {
        fn authenticate(
            &self,
            _user_mgr: &dyn UserManagerLike,
            subject_principals: Option<&[GhidraPrincipal]>,
            callbacks: &[Box<dyn AuthCallback>],
        ) -> Result<String, LoginError> {
            let username = match get_first_callback_of_type::<NameCallback>(callbacks) {
                Some(cb) => cb.name.clone().ok_or_else(|| {
                    LoginError::Login("name callback not filled in".to_string())
                })?,
                None => GhidraPrincipal::get_ghidra_principal(subject_principals)
                    .ok_or_else(|| LoginError::Login("no user identity available".to_string()))?
                    .name()
                    .to_string(),
            };

            let password = get_first_callback_of_type::<PasswordCallback>(callbacks)
                .and_then(|cb| cb.password.as_ref())
                .ok_or_else(|| LoginError::FailedLogin("password not provided".to_string()))?;

            if username != self.expected_user || password != self.expected_password {
                return Err(LoginError::FailedLogin("bad credentials".to_string()));
            }
            Ok(username)
        }

        fn get_authentication_callbacks(&self) -> Vec<Box<dyn AuthCallback>> {
            create_simple_name_password_callbacks(true)
        }

        fn anonymous_callbacks_allowed(&self) -> bool {
            false
        }

        fn is_name_callback_allowed(&self) -> bool {
            true
        }
    }

    #[test]
    fn test_create_simple_name_password_callbacks_with_name() {
        let callbacks = create_simple_name_password_callbacks(true);
        assert_eq!(callbacks.len(), 2);
        assert!(get_first_callback_of_type::<NameCallback>(&callbacks).is_some());
        assert!(get_first_callback_of_type::<PasswordCallback>(&callbacks).is_some());
    }

    #[test]
    fn test_create_simple_name_password_callbacks_without_name() {
        let callbacks = create_simple_name_password_callbacks(false);
        assert_eq!(callbacks.len(), 1);
        assert!(get_first_callback_of_type::<NameCallback>(&callbacks).is_none());
        assert!(get_first_callback_of_type::<PasswordCallback>(&callbacks).is_some());
    }

    #[test]
    fn test_get_first_callback_of_type_returns_none_when_absent() {
        let callbacks: Vec<Box<dyn AuthCallback>> = vec![];
        assert!(get_first_callback_of_type::<NameCallback>(&callbacks).is_none());
    }

    fn filled_in_callbacks(name: &str, password: &[u8]) -> Vec<Box<dyn AuthCallback>> {
        vec![
            Box::new(NameCallback {
                prompt: format!("{USERNAME_CALLBACK_PROMPT}:"),
                name: Some(name.to_string()),
            }),
            Box::new(PasswordCallback {
                prompt: format!("{PASSWORD_CALLBACK_PROMPT}:"),
                echo_on: false,
                password: Some(password.to_vec()),
            }),
        ]
    }

    #[test]
    fn test_object_safety_and_successful_authentication() {
        let module: Box<dyn AuthenticationModule> = Box::new(FixedCredentialsModule {
            expected_user: "alice",
            expected_password: b"hunter2",
        });
        let user_mgr = MockUserManager;

        let callbacks = filled_in_callbacks("alice", b"hunter2");
        let result = module.authenticate(&user_mgr, None, &callbacks);
        assert_eq!(result.unwrap(), "alice");
    }

    #[test]
    fn test_failed_login_is_retryable_distinct_from_login_error() {
        let module: Box<dyn AuthenticationModule> = Box::new(FixedCredentialsModule {
            expected_user: "alice",
            expected_password: b"hunter2",
        });
        let user_mgr = MockUserManager;

        let callbacks = filled_in_callbacks("alice", b"wrong");
        let result = module.authenticate(&user_mgr, None, &callbacks);
        assert!(matches!(result, Err(LoginError::FailedLogin(_))));

        // With no name callback present, the username must fall back to the subject's
        // principal; only the password is missing here.
        let principals = vec![GhidraPrincipal::new("alice")];
        let no_password_result = module.authenticate(&user_mgr, Some(&principals), &[]);
        assert!(matches!(no_password_result, Err(LoginError::FailedLogin(_))));
    }
}
