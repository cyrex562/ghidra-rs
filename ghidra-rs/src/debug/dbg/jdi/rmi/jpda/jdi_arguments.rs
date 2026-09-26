use std::collections::HashMap;

use crate::pty::shell_utils;

/// Determines the mode in which JDI will connect to the target JVM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Attach to a running JVM on a specific host and port.
    AttachPort,
    /// Attach to a running JVM by process ID.
    AttachPid,
    /// Launch a new JVM process.
    Launch,
}

/// Configures JDI connection arguments based on an environment map.
///
/// Determines the connection mode from environment variables and provides methods
/// to access and configure the connection parameters. This mirrors the Java class
/// `ghidra.dbg.jdi.rmi.jpda.JdiArguments`, adapting it for Rust by using String
/// maps instead of Java's JDI-specific types.
pub struct JdiArguments {
    env: HashMap<String, String>,
    mode: Mode,
}

impl JdiArguments {
    /// Creates a new `JdiArguments` with the given environment map.
    ///
    /// The mode is automatically determined based on the presence of specific
    /// environment variables:
    /// - If `OPT_PORT` is present, mode is `AttachPort`
    /// - If `OPT_PID` is present, mode is `AttachPid`
    /// - Otherwise, mode is `Launch`
    pub fn new(env: HashMap<String, String>) -> Self {
        let env = env.clone();
        let mode = Self::compute_mode(&env);
        JdiArguments { env, mode }
    }

    /// Determines the launch mode based on environment variables.
    fn compute_mode(env: &HashMap<String, String>) -> Mode {
        if env.contains_key("OPT_PORT") {
            Mode::AttachPort
        } else if env.contains_key("OPT_PID") {
            Mode::AttachPid
        } else {
            Mode::Launch
        }
    }

    /// Returns the determined connection mode.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Returns the environment map.
    pub fn env(&self) -> &HashMap<String, String> {
        &self.env
    }

    /// Populates a configuration map with the appropriate arguments for the current mode.
    ///
    /// This mirrors the Java method `putArguments(Map<String, Argument> args)`,
    /// adapted to use a `HashMap<String, String>` instead of JDI's `Argument` type.
    pub fn put_arguments(&self, args: &mut HashMap<String, String>) {
        match self.mode {
            Mode::AttachPort => {
                if let Some(host) = self.env.get("OPT_HOST") {
                    args.insert("hostname".to_string(), host.clone());
                }
                if let Some(port) = self.env.get("OPT_PORT") {
                    args.insert("port".to_string(), port.clone());
                }
                if let Some(timeout) = self.env.get("OPT_TIMEOUT") {
                    args.insert("timeout".to_string(), timeout.clone());
                }
            }
            Mode::AttachPid => {
                if let Some(pid) = self.env.get("OPT_PID") {
                    args.insert("pid".to_string(), pid.clone());
                }
                if let Some(timeout) = self.env.get("OPT_TIMEOUT") {
                    args.insert("timeout".to_string(), timeout.clone());
                }
            }
            Mode::Launch => {
                if let Some(target_class) = self.env.get("OPT_TARGET_CLASS") {
                    args.insert("main".to_string(), target_class.clone());
                }
                if let Some(suspend) = self.env.get("OPT_SUSPEND") {
                    args.insert("suspend".to_string(), suspend.clone());
                }
                if let Some(include) = self.env.get("OPT_INCLUDE") {
                    args.insert("includevirtualthreads".to_string(), include.clone());
                }
                if let Some(cp) = self.env.get("OPT_TARGET_CLASSPATH") {
                    if !cp.is_empty() && cp.trim() != "" {
                        let options = format!("-cp {}", shell_utils::generate_argument(cp));
                        args.insert("options".to_string(), options);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_mode_attach_port() {
        let mut env = HashMap::new();
        env.insert("OPT_PORT".to_string(), "5005".to_string());
        let args = JdiArguments::new(env);
        assert_eq!(args.mode(), Mode::AttachPort);
    }

    #[test]
    fn compute_mode_attach_pid() {
        let mut env = HashMap::new();
        env.insert("OPT_PID".to_string(), "12345".to_string());
        let args = JdiArguments::new(env);
        assert_eq!(args.mode(), Mode::AttachPid);
    }

    #[test]
    fn compute_mode_launch() {
        let env = HashMap::new();
        let args = JdiArguments::new(env);
        assert_eq!(args.mode(), Mode::Launch);
    }

    #[test]
    fn compute_mode_port_takes_precedence() {
        let mut env = HashMap::new();
        env.insert("OPT_PORT".to_string(), "5005".to_string());
        env.insert("OPT_PID".to_string(), "12345".to_string());
        let args = JdiArguments::new(env);
        assert_eq!(args.mode(), Mode::AttachPort);
    }

    #[test]
    fn put_arguments_attach_port() {
        let mut env = HashMap::new();
        env.insert("OPT_HOST".to_string(), "localhost".to_string());
        env.insert("OPT_PORT".to_string(), "5005".to_string());
        env.insert("OPT_TIMEOUT".to_string(), "30000".to_string());
        let args = JdiArguments::new(env);

        let mut config = HashMap::new();
        args.put_arguments(&mut config);

        assert_eq!(config.get("hostname"), Some(&"localhost".to_string()));
        assert_eq!(config.get("port"), Some(&"5005".to_string()));
        assert_eq!(config.get("timeout"), Some(&"30000".to_string()));
    }

    #[test]
    fn put_arguments_attach_pid() {
        let mut env = HashMap::new();
        env.insert("OPT_PID".to_string(), "12345".to_string());
        env.insert("OPT_TIMEOUT".to_string(), "30000".to_string());
        let args = JdiArguments::new(env);

        let mut config = HashMap::new();
        args.put_arguments(&mut config);

        assert_eq!(config.get("pid"), Some(&"12345".to_string()));
        assert_eq!(config.get("timeout"), Some(&"30000".to_string()));
    }

    #[test]
    fn put_arguments_launch_basic() {
        let mut env = HashMap::new();
        env.insert("OPT_TARGET_CLASS".to_string(), "com.example.Main".to_string());
        let args = JdiArguments::new(env);

        let mut config = HashMap::new();
        args.put_arguments(&mut config);

        assert_eq!(config.get("main"), Some(&"com.example.Main".to_string()));
    }

    #[test]
    fn put_arguments_launch_with_suspend() {
        let mut env = HashMap::new();
        env.insert("OPT_TARGET_CLASS".to_string(), "com.example.Main".to_string());
        env.insert("OPT_SUSPEND".to_string(), "true".to_string());
        let args = JdiArguments::new(env);

        let mut config = HashMap::new();
        args.put_arguments(&mut config);

        assert_eq!(config.get("main"), Some(&"com.example.Main".to_string()));
        assert_eq!(config.get("suspend"), Some(&"true".to_string()));
    }

    #[test]
    fn put_arguments_launch_with_virtual_threads() {
        let mut env = HashMap::new();
        env.insert("OPT_TARGET_CLASS".to_string(), "com.example.Main".to_string());
        env.insert("OPT_INCLUDE".to_string(), "true".to_string());
        let args = JdiArguments::new(env);

        let mut config = HashMap::new();
        args.put_arguments(&mut config);

        assert_eq!(config.get("main"), Some(&"com.example.Main".to_string()));
        assert_eq!(config.get("includevirtualthreads"), Some(&"true".to_string()));
    }

    #[test]
    fn put_arguments_launch_with_classpath() {
        let mut env = HashMap::new();
        env.insert("OPT_TARGET_CLASS".to_string(), "com.example.Main".to_string());
        env.insert("OPT_TARGET_CLASSPATH".to_string(), "/path/to/lib.jar:/path/with spaces/lib.jar".to_string());
        let args = JdiArguments::new(env);

        let mut config = HashMap::new();
        args.put_arguments(&mut config);

        assert_eq!(config.get("main"), Some(&"com.example.Main".to_string()));
        let options = config.get("options").unwrap();
        assert!(options.starts_with("-cp "));
    }

    #[test]
    fn put_arguments_launch_empty_classpath_ignored() {
        let mut env = HashMap::new();
        env.insert("OPT_TARGET_CLASS".to_string(), "com.example.Main".to_string());
        env.insert("OPT_TARGET_CLASSPATH".to_string(), "".to_string());
        let args = JdiArguments::new(env);

        let mut config = HashMap::new();
        args.put_arguments(&mut config);

        assert_eq!(config.get("main"), Some(&"com.example.Main".to_string()));
        assert!(!config.contains_key("options"));
    }

    #[test]
    fn env_method_returns_reference() {
        let mut env = HashMap::new();
        env.insert("OPT_PORT".to_string(), "5005".to_string());
        let args = JdiArguments::new(env);

        assert_eq!(args.env().get("OPT_PORT"), Some(&"5005".to_string()));
    }

    #[test]
    fn mode_enum_equality() {
        assert_eq!(Mode::AttachPort, Mode::AttachPort);
        assert_ne!(Mode::AttachPort, Mode::AttachPid);
        assert_ne!(Mode::AttachPort, Mode::Launch);
        assert_ne!(Mode::AttachPid, Mode::Launch);
    }

    #[test]
    fn mode_enum_is_copy() {
        let m1 = Mode::AttachPort;
        let m2 = m1;
        assert_eq!(m1, m2);
    }
}
