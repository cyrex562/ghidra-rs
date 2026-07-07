use std::io::{Read, Write};

use super::object_storage::ObjectStorage;

/// Adapts a byte stream to the [`ObjectStorage`] interface, saving and restoring
/// primitives, strings, and their arrays by reading/writing them directly to/from
/// the wrapped stream.
///
/// An instance is created for either writing or reading, never both, mirroring the
/// two constructors of the Java class. Calling a `put_*` method on a reader-backed
/// instance (or a `get_*` method on a writer-backed one) panics, matching the
/// `NullPointerException` the Java class throws for the same misuse.
///
/// Port of `ghidra.util.ObjectStorageStreamAdapter`.
pub enum ObjectStorageStreamAdapter<'a> {
    Writer(Box<dyn Write + 'a>),
    Reader(Box<dyn Read + 'a>),
}

impl<'a> ObjectStorageStreamAdapter<'a> {
    /// Creates an adapter that writes values to `out`.
    pub fn new_writer(out: impl Write + 'a) -> Self {
        Self::Writer(Box::new(out))
    }

    /// Creates an adapter that reads values from `input`.
    pub fn new_reader(input: impl Read + 'a) -> Self {
        Self::Reader(Box::new(input))
    }

    fn writer(&mut self) -> &mut (dyn Write + 'a) {
        match self {
            Self::Writer(w) => w.as_mut(),
            Self::Reader(_) => panic!("ObjectStorageStreamAdapter: no output stream"),
        }
    }

    fn reader(&mut self) -> &mut (dyn Read + 'a) {
        match self {
            Self::Reader(r) => r.as_mut(),
            Self::Writer(_) => panic!("ObjectStorageStreamAdapter: no input stream"),
        }
    }
}

fn read_i32(r: &mut dyn Read) -> std::io::Result<i32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(i32::from_be_bytes(buf))
}

fn read_i8(r: &mut dyn Read) -> std::io::Result<i8> {
    let mut buf = [0u8; 1];
    r.read_exact(&mut buf)?;
    Ok(buf[0] as i8)
}

fn read_i16(r: &mut dyn Read) -> std::io::Result<i16> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)?;
    Ok(i16::from_be_bytes(buf))
}

fn read_i64(r: &mut dyn Read) -> std::io::Result<i64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(i64::from_be_bytes(buf))
}

fn read_bool(r: &mut dyn Read) -> std::io::Result<bool> {
    let mut buf = [0u8; 1];
    r.read_exact(&mut buf)?;
    Ok(buf[0] != 0)
}

fn read_f32(r: &mut dyn Read) -> std::io::Result<f32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(f32::from_bits(u32::from_be_bytes(buf)))
}

fn read_f64(r: &mut dyn Read) -> std::io::Result<f64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(f64::from_bits(u64::from_be_bytes(buf)))
}

fn read_string(r: &mut dyn Read) -> std::io::Result<String> {
    let len = read_i32(r)?;
    if len < 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "negative length"));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    String::from_utf8(buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

fn read_vec<T>(r: &mut dyn Read, read_one: impl Fn(&mut dyn Read) -> std::io::Result<T>) -> std::io::Result<Vec<T>> {
    let len = read_i32(r)?;
    if len < 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "negative length"));
    }
    let mut result = Vec::with_capacity(len as usize);
    for _ in 0..len {
        result.push(read_one(r)?);
    }
    Ok(result)
}

impl<'a> ObjectStorage for ObjectStorageStreamAdapter<'a> {
    fn put_int(&mut self, value: i32) {
        let _ = self.writer().write_all(&value.to_be_bytes());
    }

    fn put_byte(&mut self, value: i8) {
        let _ = self.writer().write_all(&value.to_be_bytes());
    }

    fn put_short(&mut self, value: i16) {
        let _ = self.writer().write_all(&value.to_be_bytes());
    }

    fn put_long(&mut self, value: i64) {
        let _ = self.writer().write_all(&value.to_be_bytes());
    }

    fn put_string(&mut self, value: &str) {
        let bytes = value.as_bytes();
        let writer = self.writer();
        if writer.write_all(&(bytes.len() as i32).to_be_bytes()).is_err() {
            return;
        }
        let _ = writer.write_all(bytes);
    }

    fn put_boolean(&mut self, value: bool) {
        let _ = self.writer().write_all(&[value as u8]);
    }

    fn put_float(&mut self, value: f32) {
        let _ = self.writer().write_all(&value.to_bits().to_be_bytes());
    }

    fn put_double(&mut self, value: f64) {
        let _ = self.writer().write_all(&value.to_bits().to_be_bytes());
    }

    fn get_int(&mut self) -> i32 {
        read_i32(self.reader()).unwrap_or(0)
    }

    fn get_byte(&mut self) -> i8 {
        read_i8(self.reader()).unwrap_or(0)
    }

    fn get_short(&mut self) -> i16 {
        read_i16(self.reader()).unwrap_or(0)
    }

    fn get_long(&mut self) -> i64 {
        read_i64(self.reader()).unwrap_or(0)
    }

    fn get_boolean(&mut self) -> bool {
        read_bool(self.reader()).unwrap_or(false)
    }

    fn get_string(&mut self) -> String {
        read_string(self.reader()).unwrap_or_default()
    }

    fn get_float(&mut self) -> f32 {
        read_f32(self.reader()).unwrap_or(0.0)
    }

    fn get_double(&mut self) -> f64 {
        read_f64(self.reader()).unwrap_or(0.0)
    }

    fn put_ints(&mut self, value: &[i32]) {
        let writer = self.writer();
        if writer.write_all(&(value.len() as i32).to_be_bytes()).is_err() {
            return;
        }
        for &v in value {
            if writer.write_all(&v.to_be_bytes()).is_err() {
                return;
            }
        }
    }

    fn put_bytes(&mut self, value: &[i8]) {
        let writer = self.writer();
        if writer.write_all(&(value.len() as i32).to_be_bytes()).is_err() {
            return;
        }
        for &v in value {
            if writer.write_all(&v.to_be_bytes()).is_err() {
                return;
            }
        }
    }

    fn put_shorts(&mut self, value: &[i16]) {
        let writer = self.writer();
        if writer.write_all(&(value.len() as i32).to_be_bytes()).is_err() {
            return;
        }
        for &v in value {
            if writer.write_all(&v.to_be_bytes()).is_err() {
                return;
            }
        }
    }

    fn put_longs(&mut self, value: &[i64]) {
        let writer = self.writer();
        if writer.write_all(&(value.len() as i32).to_be_bytes()).is_err() {
            return;
        }
        for &v in value {
            if writer.write_all(&v.to_be_bytes()).is_err() {
                return;
            }
        }
    }

    fn put_floats(&mut self, value: &[f32]) {
        let writer = self.writer();
        if writer.write_all(&(value.len() as i32).to_be_bytes()).is_err() {
            return;
        }
        for &v in value {
            if writer.write_all(&v.to_bits().to_be_bytes()).is_err() {
                return;
            }
        }
    }

    fn put_doubles(&mut self, value: &[f64]) {
        let writer = self.writer();
        if writer.write_all(&(value.len() as i32).to_be_bytes()).is_err() {
            return;
        }
        for &v in value {
            if writer.write_all(&v.to_bits().to_be_bytes()).is_err() {
                return;
            }
        }
    }

    fn put_strings(&mut self, value: &[&str]) {
        let writer = self.writer();
        if writer.write_all(&(value.len() as i32).to_be_bytes()).is_err() {
            return;
        }
        for &v in value {
            let bytes = v.as_bytes();
            if writer.write_all(&(bytes.len() as i32).to_be_bytes()).is_err() {
                return;
            }
            if writer.write_all(bytes).is_err() {
                return;
            }
        }
    }

    fn get_ints(&mut self) -> Vec<i32> {
        read_vec(self.reader(), read_i32).unwrap_or_default()
    }

    fn get_bytes(&mut self) -> Vec<i8> {
        read_vec(self.reader(), read_i8).unwrap_or_default()
    }

    fn get_shorts(&mut self) -> Vec<i16> {
        read_vec(self.reader(), read_i16).unwrap_or_default()
    }

    fn get_longs(&mut self) -> Vec<i64> {
        read_vec(self.reader(), read_i64).unwrap_or_default()
    }

    fn get_floats(&mut self) -> Vec<f32> {
        read_vec(self.reader(), read_f32).unwrap_or_default()
    }

    fn get_doubles(&mut self) -> Vec<f64> {
        read_vec(self.reader(), read_f64).unwrap_or_default()
    }

    fn get_strings(&mut self) -> Vec<String> {
        read_vec(self.reader(), read_string).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip_scalars() {
        let mut buf = Vec::new();
        {
            let mut w = ObjectStorageStreamAdapter::new_writer(&mut buf);
            w.put_int(42);
            w.put_byte(-1);
            w.put_short(1000);
            w.put_long(i64::MAX);
            w.put_string("hello");
            w.put_boolean(true);
            w.put_float(1.5);
            w.put_double(3.14);
        }

        let mut r = ObjectStorageStreamAdapter::new_reader(Cursor::new(buf));
        assert_eq!(r.get_int(), 42);
        assert_eq!(r.get_byte(), -1);
        assert_eq!(r.get_short(), 1000);
        assert_eq!(r.get_long(), i64::MAX);
        assert_eq!(r.get_string(), "hello");
        assert!(r.get_boolean());
        assert_eq!(r.get_float(), 1.5_f32);
        assert_eq!(r.get_double(), 3.14_f64);
    }

    #[test]
    fn roundtrip_arrays() {
        let mut buf = Vec::new();
        {
            let mut w = ObjectStorageStreamAdapter::new_writer(&mut buf);
            w.put_ints(&[1, 2, 3]);
            w.put_bytes(&[-128, 0, 127]);
            w.put_shorts(&[100, 200]);
            w.put_longs(&[i64::MIN, i64::MAX]);
            w.put_floats(&[0.1, 0.2]);
            w.put_doubles(&[1.1, 2.2]);
            w.put_strings(&["foo", "bar"]);
        }

        let mut r = ObjectStorageStreamAdapter::new_reader(Cursor::new(buf));
        assert_eq!(r.get_ints(), vec![1, 2, 3]);
        assert_eq!(r.get_bytes(), vec![-128_i8, 0, 127]);
        assert_eq!(r.get_shorts(), vec![100_i16, 200]);
        assert_eq!(r.get_longs(), vec![i64::MIN, i64::MAX]);
        assert_eq!(r.get_floats(), vec![0.1_f32, 0.2]);
        assert_eq!(r.get_doubles(), vec![1.1_f64, 2.2]);
        assert_eq!(r.get_strings(), vec!["foo".to_string(), "bar".to_string()]);
    }

    #[test]
    fn empty_arrays_roundtrip() {
        let mut buf = Vec::new();
        {
            let mut w = ObjectStorageStreamAdapter::new_writer(&mut buf);
            w.put_ints(&[]);
            w.put_strings(&[]);
        }

        let mut r = ObjectStorageStreamAdapter::new_reader(Cursor::new(buf));
        assert_eq!(r.get_ints(), Vec::<i32>::new());
        assert_eq!(r.get_strings(), Vec::<String>::new());
    }

    #[test]
    fn read_past_end_of_stream_returns_defaults() {
        let mut r = ObjectStorageStreamAdapter::new_reader(Cursor::new(Vec::<u8>::new()));
        assert_eq!(r.get_int(), 0);
        assert_eq!(r.get_byte(), 0);
        assert!(!r.get_boolean());
        assert_eq!(r.get_string(), "");
        assert_eq!(r.get_ints(), Vec::<i32>::new());
    }

    #[test]
    #[should_panic(expected = "no input stream")]
    fn get_on_writer_panics() {
        let mut buf = Vec::new();
        let mut w = ObjectStorageStreamAdapter::new_writer(&mut buf);
        w.get_int();
    }

    #[test]
    #[should_panic(expected = "no output stream")]
    fn put_on_reader_panics() {
        let mut r = ObjectStorageStreamAdapter::new_reader(Cursor::new(Vec::<u8>::new()));
        r.put_int(1);
    }

    #[test]
    fn ordering_preserved() {
        let mut buf = Vec::new();
        {
            let mut w = ObjectStorageStreamAdapter::new_writer(&mut buf);
            w.put_int(1);
            w.put_int(2);
            w.put_int(3);
        }

        let mut r = ObjectStorageStreamAdapter::new_reader(Cursor::new(buf));
        assert_eq!(r.get_int(), 1);
        assert_eq!(r.get_int(), 2);
        assert_eq!(r.get_int(), 3);
    }
}
