use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use regex::Regex;

/// Number of positional arguments before the list of input files: base input
/// path, base output path, package name, and grammar name.
const NUMBER_PARAMS: usize = 4;

/// Build-time tool that scans Sleigh grammar source files for uppercase token
/// identifiers and emits an ANTLR lexer grammar (`<name>.g`) assigning each
/// token a numeric literal.
///
/// Mirrors `ghidra.sleigh.grammar.TokenExtractor`.
pub struct TokenExtractor;

impl TokenExtractor {
    /// Runs the extractor exactly like the Java `main` method.
    ///
    /// `args` layout: `[base_in_path, base_out_path, package, name, in_file...]`.
    /// Input files are resolved relative to `base_in_path`; the generated
    /// grammar is written to `base_out_path/<name>.g`.
    pub fn run(args: &[String]) -> io::Result<()> {
        let base_in_path = Path::new(&args[0]);
        let base_out_path = Path::new(&args[1]);
        let packedge = &args[2];
        let name = &args[3];
        let output_file = base_out_path.join(format!("{}.g", name));
        let in_files: Vec<PathBuf> = args[NUMBER_PARAMS..]
            .iter()
            .map(|f| base_in_path.join(f))
            .collect();

        let set = Self::extract(&in_files)?;
        Self::write(packedge, name, &output_file, &set)
    }

    /// Writes the lexer grammar header and one token declaration per entry in
    /// `set` to `output_file`, creating parent directories as needed.
    fn write(
        packedge: &str,
        name: &str,
        output_file: &Path,
        set: &HashSet<String>,
    ) -> io::Result<()> {
        if let Some(parent) = output_file.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }
        println!("writing tokens to: {}", output_file.display());

        let mut out = File::create(output_file)?;
        writeln!(out, "lexer grammar {};", name)?;
        if !packedge.trim().is_empty() {
            writeln!(out, "@lexer::header{{")?;
            writeln!(out, "package {};", packedge)?;
            writeln!(out, "}}")?;
        }
        let mut ii: u32 = 4;
        for s in set {
            writeln!(out, "{}: '{:04}';", s, ii)?;
            ii += 1;
        }
        Ok(())
    }

    fn match_pattern(re: &Regex, line: &str, set: &mut HashSet<String>) {
        if let Some(caps) = re.captures(line) {
            set.insert(caps[1].to_string());
        }
    }

    /// Scans `in_files` line by line, collecting the distinct uppercase token
    /// names declared, terminated, assigned, or defined on each line.
    pub fn extract(in_files: &[PathBuf]) -> io::Result<HashSet<String>> {
        let p1 = Regex::new(r"^\s*([A-Z_][A-Z_0-9]*)\s*$").unwrap();
        let p2 = Regex::new(r"^\s*([A-Z_][A-Z_0-9]*)\s*;").unwrap();
        let p3 = Regex::new(r"^\s*([A-Z_][A-Z_0-9]*)\s*=").unwrap();
        let p4 = Regex::new(r"^\s*([A-Z_][A-Z_0-9]*)\s*:").unwrap();

        let mut result = HashSet::new();
        for path in in_files {
            println!("extracting tokens from: {}", path.display());
            let file = File::open(path)?;
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let line = line?;
                Self::match_pattern(&p1, &line, &mut result);
                Self::match_pattern(&p2, &line, &mut result);
                Self::match_pattern(&p3, &line, &mut result);
                Self::match_pattern(&p4, &line, &mut result);
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as IoRead;

    fn write_temp_file(dir: &Path, name: &str, contents: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, contents).unwrap();
        path
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("token_extractor_test_{}", tag));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn extract_matches_bare_identifier_line() {
        let dir = temp_dir("bare");
        let file = write_temp_file(&dir, "in.txt", "  FOO_BAR  \n");
        let set = TokenExtractor::extract(&[file]).unwrap();
        assert_eq!(set, HashSet::from(["FOO_BAR".to_string()]));
    }

    #[test]
    fn extract_matches_identifier_before_semicolon() {
        let dir = temp_dir("semi");
        let file = write_temp_file(&dir, "in.txt", "TOKEN;\n");
        let set = TokenExtractor::extract(&[file]).unwrap();
        assert_eq!(set, HashSet::from(["TOKEN".to_string()]));
    }

    #[test]
    fn extract_matches_identifier_before_equals() {
        let dir = temp_dir("eq");
        let file = write_temp_file(&dir, "in.txt", "TOKEN = 5\n");
        let set = TokenExtractor::extract(&[file]).unwrap();
        assert_eq!(set, HashSet::from(["TOKEN".to_string()]));
    }

    #[test]
    fn extract_matches_identifier_before_colon() {
        let dir = temp_dir("colon");
        let file = write_temp_file(&dir, "in.txt", "TOKEN: '0004';\n");
        let set = TokenExtractor::extract(&[file]).unwrap();
        assert_eq!(set, HashSet::from(["TOKEN".to_string()]));
    }

    #[test]
    fn extract_ignores_lowercase_identifiers() {
        let dir = temp_dir("lower");
        let file = write_temp_file(&dir, "in.txt", "not_a_token\n");
        let set = TokenExtractor::extract(&[file]).unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn extract_collects_across_multiple_files_and_dedups() {
        let dir = temp_dir("multi");
        let f1 = write_temp_file(&dir, "a.txt", "ALPHA;\nBETA = 1\n");
        let f2 = write_temp_file(&dir, "b.txt", "ALPHA\nGAMMA:\n");
        let set = TokenExtractor::extract(&[f1, f2]).unwrap();
        assert_eq!(
            set,
            HashSet::from([
                "ALPHA".to_string(),
                "BETA".to_string(),
                "GAMMA".to_string(),
            ])
        );
    }

    #[test]
    fn extract_missing_file_errors() {
        let dir = temp_dir("missing");
        let missing = dir.join("does_not_exist.txt");
        let err = TokenExtractor::extract(&[missing]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn write_emits_header_and_numbered_tokens() {
        let dir = temp_dir("write_basic");
        let out_file = dir.join("MyGrammar.g");
        let set = HashSet::from(["ONE".to_string()]);
        TokenExtractor::write("", "MyGrammar", &out_file, &set).unwrap();

        let mut contents = String::new();
        File::open(&out_file)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        assert_eq!(contents, "lexer grammar MyGrammar;\nONE: '0004';\n");
    }

    #[test]
    fn write_emits_package_header_when_present() {
        let dir = temp_dir("write_pkg");
        let out_file = dir.join("Pkg.g");
        let set = HashSet::new();
        TokenExtractor::write("ghidra.sleigh.grammar", "Pkg", &out_file, &set).unwrap();

        let mut contents = String::new();
        File::open(&out_file)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        assert_eq!(
            contents,
            "lexer grammar Pkg;\n@lexer::header{\npackage ghidra.sleigh.grammar;\n}\n"
        );
    }

    #[test]
    fn write_skips_package_header_when_blank() {
        let dir = temp_dir("write_blank_pkg");
        let out_file = dir.join("Blank.g");
        let set = HashSet::new();
        TokenExtractor::write("   ", "Blank", &out_file, &set).unwrap();

        let mut contents = String::new();
        File::open(&out_file)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        assert_eq!(contents, "lexer grammar Blank;\n");
    }

    #[test]
    fn write_creates_missing_parent_directories() {
        let dir = temp_dir("write_mkdirs");
        let out_file = dir.join("nested").join("dir").join("Out.g");
        let set = HashSet::new();
        TokenExtractor::write("", "Out", &out_file, &set).unwrap();
        assert!(out_file.exists());
    }

    #[test]
    fn write_numbers_tokens_starting_at_four() {
        let dir = temp_dir("write_numbering");
        let out_file = dir.join("Num.g");
        let set = HashSet::from(["ONLY".to_string()]);
        TokenExtractor::write("", "Num", &out_file, &set).unwrap();

        let mut contents = String::new();
        File::open(&out_file)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        assert!(contents.contains("ONLY: '0004';"));
    }

    #[test]
    fn run_extracts_and_writes_end_to_end() {
        let dir = temp_dir("run_e2e");
        let in_dir = dir.join("in");
        let out_dir = dir.join("out");
        fs::create_dir_all(&in_dir).unwrap();
        write_temp_file(&in_dir, "grammar.sleigh", "ALPHA;\nBETA = 1\n");

        let args = vec![
            in_dir.to_string_lossy().to_string(),
            out_dir.to_string_lossy().to_string(),
            String::new(),
            "Generated".to_string(),
            "grammar.sleigh".to_string(),
        ];
        TokenExtractor::run(&args).unwrap();

        let out_file = out_dir.join("Generated.g");
        let mut contents = String::new();
        File::open(&out_file)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        assert!(contents.starts_with("lexer grammar Generated;\n"));
        assert!(contents.contains("ALPHA:"));
        assert!(contents.contains("BETA:"));
    }
}
