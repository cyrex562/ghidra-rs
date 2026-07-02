use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use once_cell::sync::Lazy;

/// Maps ASCII codes for non-printable characters to their `[SHORT]` code and
/// human-readable description, e.g. `0 -> ("[NUL]", "null")`.
static ASCII_NUM_TO_DESCRIPTION: Lazy<HashMap<i32, (&'static str, &'static str)>> =
    Lazy::new(|| {
        let mut map = HashMap::new();
        map.insert(0, ("[NUL]", "null"));
        map.insert(1, ("[SOH]", "start of header"));
        map.insert(2, ("[STX]", "start of text"));
        map.insert(3, ("[ETX]", "end of text"));
        map.insert(4, ("[EOT]", "end of transmission"));
        map.insert(5, ("[ENQ]", "enquiry"));
        map.insert(6, ("[ACK]", "acknowledgement"));
        map.insert(7, ("[BEL]", "bell"));
        map.insert(8, ("[BS]", "backspace"));
        map.insert(9, ("[HT]", "horizontal tab"));
        map.insert(10, ("[LF]", "line feed"));
        map.insert(11, ("[VT]", "vertical tab"));
        map.insert(12, ("[FF]", "form feed"));
        map.insert(13, ("[CR]", "carriage return"));
        map.insert(14, ("[SO]", "shift out"));
        map.insert(15, ("[SI]", "shift in"));
        map.insert(16, ("[DLE]", "data link escape"));
        map.insert(17, ("[DC1]", "device control 1"));
        map.insert(18, ("[DC2]", "device control 2"));
        map.insert(19, ("[DC3]", "device control 3"));
        map.insert(20, ("[DC4]", "device control 4"));
        map.insert(21, ("[NAK]", "negative acknowledge"));
        map.insert(22, ("[SYN]", "synchronous idle"));
        map.insert(23, ("[ETB]", "end of transmission block"));
        map.insert(24, ("[CAN]", "cancel"));
        map.insert(25, ("[EM]", "end of medium"));
        map.insert(26, ("[SUB]", "substitute"));
        map.insert(27, ("[ESC]", "escape"));
        map.insert(28, ("[FS]", "file separator"));
        map.insert(29, ("[GS]", "group separator"));
        map.insert(30, ("[RS]", "record separator"));
        map.insert(31, ("[US]", "unit separator"));
        map.insert(32, ("[SP]", "space"));
        map.insert(127, ("[DEL]", "delete"));
        map
    });

/// Text representations for ASCII codes 0-127: the literal character for
/// printable codes (33-126), and the `[SHORT]` code from
/// [`ASCII_NUM_TO_DESCRIPTION`] otherwise.
static TEXT_REPS: Lazy<Vec<String>> = Lazy::new(|| {
    (0..128)
        .map(|i| {
            if (33..=126).contains(&i) {
                (i as u8 as char).to_string()
            } else {
                ASCII_NUM_TO_DESCRIPTION
                    .get(&i)
                    .map(|(short, _)| short.to_string())
                    .unwrap_or_default()
            }
        })
        .collect()
});

/// Holds trigram frequency counts used to model ASCII strings for detection
/// and validation purposes.
pub struct StringModel {
    ascii_trigram_storage: Vec<Vec<Vec<i32>>>,
    begin_string_trigram_storage: Vec<Vec<i32>>,
    end_string_trigram_storage: Vec<Vec<i32>>,
    total_num_trigrams: i64,
}

impl StringModel {
    /// Creates a new `StringModel` from precomputed trigram counts.
    pub fn new(
        ascii_trigrams: Vec<Vec<Vec<i32>>>,
        begin_trigram: Vec<Vec<i32>>,
        end_trigram: Vec<Vec<i32>>,
        num_trigrams: i64,
    ) -> Self {
        StringModel {
            ascii_trigram_storage: ascii_trigrams,
            begin_string_trigram_storage: begin_trigram,
            end_string_trigram_storage: end_trigram,
            total_num_trigrams: num_trigrams,
        }
    }

    /// Replaces the trigram counts held by this model.
    pub fn set_trigram_counts(
        &mut self,
        ascii_trigrams: Vec<Vec<Vec<i32>>>,
        begin_trigram: Vec<Vec<i32>>,
        end_trigram: Vec<Vec<i32>>,
        num_trigrams: i64,
    ) {
        self.ascii_trigram_storage = ascii_trigrams;
        self.begin_string_trigram_storage = begin_trigram;
        self.end_string_trigram_storage = end_trigram;
        self.total_num_trigrams = num_trigrams;
    }

    /// Returns the full ASCII trigram counts.
    pub fn get_trigram_counts(&self) -> &Vec<Vec<Vec<i32>>> {
        &self.ascii_trigram_storage
    }

    /// Returns the trigram counts for string beginnings.
    pub fn get_begin_trigram_counts(&self) -> &Vec<Vec<i32>> {
        &self.begin_string_trigram_storage
    }

    /// Returns the trigram counts for string endings.
    pub fn get_end_trigram_counts(&self) -> &Vec<Vec<i32>> {
        &self.end_string_trigram_storage
    }

    /// Returns the total number of trigrams recorded by this model.
    pub fn get_total_num_trigrams(&self) -> i64 {
        self.total_num_trigrams
    }

    /// Writes this model's trigram counts to a file named `trigram_filename`
    /// inside `output_path`, in the tab-separated format expected by the
    /// string model trainer/reader.
    pub fn write_trigram_model_file(
        &self,
        trigram_filename: &str,
        training_files: &[String],
        model_type: &str,
        output_path: &Path,
    ) -> io::Result<()> {
        let output_file = output_path.join(trigram_filename);

        // Store information about "special" characters that will need to be clarified
        // in comments
        let mut comments_needed: HashSet<i32> = HashSet::new();

        for (i, plane) in self.ascii_trigram_storage.iter().enumerate() {
            for (j, row) in plane.iter().enumerate() {
                for (k, &count) in row.iter().enumerate() {
                    if count > 0 {
                        if ASCII_NUM_TO_DESCRIPTION.contains_key(&(i as i32)) {
                            comments_needed.insert(i as i32);
                        }
                        if ASCII_NUM_TO_DESCRIPTION.contains_key(&(j as i32)) {
                            comments_needed.insert(j as i32);
                        }
                        if ASCII_NUM_TO_DESCRIPTION.contains_key(&(k as i32)) {
                            comments_needed.insert(k as i32);
                        }
                    }
                }
            }
        }

        let file = File::create(&output_file)?;
        let mut out = BufWriter::new(file);

        writeln!(out, "# Model Type: {}", model_type)?;

        for tr_file in training_files {
            writeln!(out, "# Training file: {}", tr_file)?;
        }

        writeln!(out, "# [^] denotes beginning of string")?;
        writeln!(out, "# [$] denotes end of string")?;

        for ascii_num in &comments_needed {
            let (short, description) = ASCII_NUM_TO_DESCRIPTION[ascii_num];
            writeln!(out, "# {} denotes {}", short, description)?;
        }
        writeln!(out)?;

        for (i, plane) in self.ascii_trigram_storage.iter().enumerate() {
            for (j, row) in plane.iter().enumerate() {
                for (k, &count) in row.iter().enumerate() {
                    if count > 0 {
                        writeln!(
                            out,
                            "{}\t{}\t{}\t{}",
                            TEXT_REPS[i], TEXT_REPS[j], TEXT_REPS[k], count
                        )?;
                    }
                }
            }
        }

        for (i, row) in self.begin_string_trigram_storage.iter().enumerate() {
            for (j, &count) in row.iter().enumerate() {
                if count != 0 {
                    writeln!(out, "[^]\t{}\t{}\t{}", TEXT_REPS[i], TEXT_REPS[j], count)?;
                }
            }
        }

        for (i, row) in self.end_string_trigram_storage.iter().enumerate() {
            for (j, &count) in row.iter().enumerate() {
                if count != 0 {
                    writeln!(out, "{}\t{}\t[$]\t{}", TEXT_REPS[i], TEXT_REPS[j], count)?;
                }
            }
        }

        out.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn empty_model() -> StringModel {
        StringModel::new(
            vec![vec![vec![0; 128]; 128]; 128],
            vec![vec![0; 128]; 128],
            vec![vec![0; 128]; 128],
            0,
        )
    }

    #[test]
    fn test_new_and_getters() {
        let model = StringModel::new(
            vec![vec![vec![1; 2]; 2]; 2],
            vec![vec![2; 3]; 3],
            vec![vec![3; 4]; 4],
            42,
        );
        assert_eq!(model.get_trigram_counts().len(), 2);
        assert_eq!(model.get_begin_trigram_counts().len(), 3);
        assert_eq!(model.get_end_trigram_counts().len(), 4);
        assert_eq!(model.get_total_num_trigrams(), 42);
    }

    #[test]
    fn test_set_trigram_counts() {
        let mut model = empty_model();
        model.set_trigram_counts(
            vec![vec![vec![5; 1]; 1]; 1],
            vec![vec![6; 1]; 1],
            vec![vec![7; 1]; 1],
            99,
        );
        assert_eq!(model.get_trigram_counts()[0][0][0], 5);
        assert_eq!(model.get_begin_trigram_counts()[0][0], 6);
        assert_eq!(model.get_end_trigram_counts()[0][0], 7);
        assert_eq!(model.get_total_num_trigrams(), 99);
    }

    #[test]
    fn test_text_reps_printable_characters() {
        assert_eq!(TEXT_REPS[b'A' as usize], "A");
        assert_eq!(TEXT_REPS[b'~' as usize], "~");
    }

    #[test]
    fn test_text_reps_control_characters() {
        assert_eq!(TEXT_REPS[0], "[NUL]");
        assert_eq!(TEXT_REPS[10], "[LF]");
        assert_eq!(TEXT_REPS[32], "[SP]");
        assert_eq!(TEXT_REPS[127], "[DEL]");
    }

    #[test]
    fn test_write_trigram_model_file_basic() {
        let mut trigrams = vec![vec![vec![0; 128]; 128]; 128];
        trigrams[b'a' as usize][b'b' as usize][b'c' as usize] = 5;

        let mut begin = vec![vec![0; 128]; 128];
        begin[b'x' as usize][b'y' as usize] = 2;

        let mut end = vec![vec![0; 128]; 128];
        end[b'y' as usize][b'z' as usize] = 3;

        let model = StringModel::new(trigrams, begin, end, 10);

        let dir = tempdir().unwrap();
        model
            .write_trigram_model_file(
                "test.model",
                &["train1.txt".to_string()],
                "ascii",
                dir.path(),
            )
            .unwrap();

        let contents = std::fs::read_to_string(dir.path().join("test.model")).unwrap();

        assert!(contents.contains("# Model Type: ascii"));
        assert!(contents.contains("# Training file: train1.txt"));
        assert!(contents.contains("# [^] denotes beginning of string"));
        assert!(contents.contains("# [$] denotes end of string"));
        assert!(contents.contains("a\tb\tc\t5"));
        assert!(contents.contains("[^]\tx\ty\t2"));
        assert!(contents.contains("y\tz\t[$]\t3"));
    }

    #[test]
    fn test_write_trigram_model_file_control_char_comment() {
        let mut trigrams = vec![vec![vec![0; 128]; 128]; 128];
        trigrams[0][b'a' as usize][b'b' as usize] = 1;

        let model = StringModel::new(trigrams, vec![vec![0; 128]; 128], vec![vec![0; 128]; 128], 1);

        let dir = tempdir().unwrap();
        model
            .write_trigram_model_file("nul.model", &[], "ascii", dir.path())
            .unwrap();

        let contents = std::fs::read_to_string(dir.path().join("nul.model")).unwrap();

        assert!(contents.contains("# [NUL] denotes null"));
        assert!(contents.contains("[NUL]\ta\tb\t1"));
    }

    #[test]
    fn test_write_trigram_model_file_empty_counts() {
        let model = empty_model();

        let dir = tempdir().unwrap();
        model
            .write_trigram_model_file("empty.model", &[], "ascii", dir.path())
            .unwrap();

        let contents = std::fs::read_to_string(dir.path().join("empty.model")).unwrap();
        assert!(contents.contains("# Model Type: ascii"));
        assert!(!contents.contains('\t'));
    }
}
