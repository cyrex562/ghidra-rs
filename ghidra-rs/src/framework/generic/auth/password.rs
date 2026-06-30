use std::hash::{Hash, Hasher};

/// Wrapper for a password held as a sequence of characters.
///
/// Dropping or calling [`close`](Password::close) overwrites the characters with `'\0'`
/// and releases the allocation, matching the Java `Closeable` contract.
pub struct Password {
    password: Option<Vec<char>>,
}

impl Password {
    /// Creates a new [`Password`] using a copy of the given characters.
    pub fn copy_of(password: &[char]) -> Self {
        Self {
            password: Some(password.to_vec()),
        }
    }

    /// Creates a new [`Password`] by taking ownership of the given character vector.
    ///
    /// The vector will be zeroed when the instance is dropped or [`close`](Self::close)
    /// is called.
    pub fn wrap(password: Vec<char>) -> Self {
        Self {
            password: Some(password),
        }
    }

    /// Zeroes the password characters and releases the allocation.
    pub fn close(&mut self) {
        if let Some(ref mut chars) = self.password {
            for c in chars.iter_mut() {
                *c = '\0';
            }
        }
        self.password = None;
    }

    /// Returns a reference to the current password characters, or `None` if already closed.
    pub fn get_password_chars(&self) -> Option<&[char]> {
        self.password.as_deref()
    }
}

impl Clone for Password {
    fn clone(&self) -> Self {
        Self {
            password: self.password.clone(),
        }
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        self.close();
    }
}

impl PartialEq for Password {
    fn eq(&self, other: &Self) -> bool {
        self.password == other.password
    }
}

impl Eq for Password {}

impl Hash for Password {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.password.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn hash_of(p: &Password) -> u64 {
        let mut h = DefaultHasher::new();
        p.hash(&mut h);
        h.finish()
    }

    #[test]
    fn copy_of_makes_independent_copy() {
        let chars: Vec<char> = "secret".chars().collect();
        let p = Password::copy_of(&chars);
        // original chars unchanged; password holds its own copy
        assert_eq!(p.get_password_chars().unwrap(), chars.as_slice());
    }

    #[test]
    fn wrap_takes_ownership() {
        let chars: Vec<char> = "secret".chars().collect();
        let p = Password::wrap(chars.clone());
        assert_eq!(p.get_password_chars().unwrap(), chars.as_slice());
    }

    #[test]
    fn clone_produces_equal_independent_password() {
        let p1 = Password::copy_of(&"abc".chars().collect::<Vec<_>>());
        let p2 = p1.clone();
        assert_eq!(p1, p2);
    }

    #[test]
    fn close_zeroes_chars_and_makes_none() {
        let chars: Vec<char> = "secret".chars().collect();
        let mut p = Password::copy_of(&chars);
        p.close();
        assert!(p.get_password_chars().is_none());
    }

    #[test]
    fn close_idempotent() {
        let mut p = Password::copy_of(&"x".chars().collect::<Vec<_>>());
        p.close();
        p.close(); // second call must not panic
        assert!(p.get_password_chars().is_none());
    }

    #[test]
    fn equality_same_content() {
        let a = Password::copy_of(&"pw".chars().collect::<Vec<_>>());
        let b = Password::copy_of(&"pw".chars().collect::<Vec<_>>());
        assert_eq!(a, b);
    }

    #[test]
    fn equality_different_content() {
        let a = Password::copy_of(&"pw1".chars().collect::<Vec<_>>());
        let b = Password::copy_of(&"pw2".chars().collect::<Vec<_>>());
        assert_ne!(a, b);
    }

    #[test]
    fn equal_passwords_have_equal_hashes() {
        let a = Password::copy_of(&"hello".chars().collect::<Vec<_>>());
        let b = Password::copy_of(&"hello".chars().collect::<Vec<_>>());
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn empty_password() {
        let p = Password::copy_of(&[]);
        assert_eq!(p.get_password_chars().unwrap(), &[] as &[char]);
    }

    #[test]
    fn reflexive_equality() {
        let p = Password::copy_of(&"pw".chars().collect::<Vec<_>>());
        assert_eq!(p, p);
    }
}
