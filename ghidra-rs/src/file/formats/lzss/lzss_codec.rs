use std::io::{self, Read, Write};

/// Size of the ring buffer — must be a power of 2.
pub const N: usize = 4096;
/// Upper limit for match length.
pub const F: usize = 18;
/// Minimum match length to encode as a position-and-length pair.
pub const THRESHOLD: usize = 2;
/// Sentinel value meaning "not used" (not in tree).
pub const NIL: usize = N;

struct EncodeState {
    lchild: [usize; N + 1],
    rchild: [usize; N + 257],
    parent: [usize; N + 1],
    text_buf: [u8; N + F - 1],
    match_position: usize,
    match_length: usize,
}

impl EncodeState {
    fn new() -> Self {
        let mut text_buf = [0u8; N + F - 1];
        for b in &mut text_buf[..N - F] {
            *b = b' ';
        }
        Self {
            lchild: [0; N + 1],
            rchild: [NIL; N + 257],
            parent: [NIL; N + 1],
            text_buf,
            match_position: 0,
            match_length: 0,
        }
    }

    fn insert_node(&mut self, r: usize) {
        let mut cmp: i32 = 1;
        let mut p = N + 1 + self.text_buf[r] as usize;
        self.rchild[r] = NIL;
        self.lchild[r] = NIL;
        self.match_length = 0;
        loop {
            if cmp >= 0 {
                if self.rchild[p] != NIL {
                    p = self.rchild[p];
                } else {
                    self.rchild[p] = r;
                    self.parent[r] = p;
                    return;
                }
            } else if self.lchild[p] != NIL {
                p = self.lchild[p];
            } else {
                self.lchild[p] = r;
                self.parent[r] = p;
                return;
            }
            let mut i = 1usize;
            while i < F {
                cmp = self.text_buf[r + i] as i32 - self.text_buf[p + i] as i32;
                if cmp != 0 {
                    break;
                }
                i += 1;
            }
            if i > self.match_length {
                self.match_position = p;
                self.match_length = i;
                if self.match_length >= F {
                    break;
                }
            }
        }
        let lp = self.lchild[p];
        let rp = self.rchild[p];
        let pp = self.parent[p];
        self.parent[r] = pp;
        self.lchild[r] = lp;
        self.rchild[r] = rp;
        self.parent[lp] = r;
        self.parent[rp] = r;
        if self.rchild[pp] == p {
            self.rchild[pp] = r;
        } else {
            self.lchild[pp] = r;
        }
        self.parent[p] = NIL;
    }

    fn delete_node(&mut self, p: usize) {
        if self.parent[p] == NIL {
            return;
        }
        let q;
        if self.rchild[p] == NIL {
            q = self.lchild[p];
        } else if self.lchild[p] == NIL {
            q = self.rchild[p];
        } else {
            let mut q_tmp = self.lchild[p];
            if self.rchild[q_tmp] != NIL {
                while self.rchild[q_tmp] != NIL {
                    q_tmp = self.rchild[q_tmp];
                }
                let pq = self.parent[q_tmp];
                let lq = self.lchild[q_tmp];
                let lp = self.lchild[p];
                self.rchild[pq] = lq;
                self.parent[lq] = pq;
                self.lchild[q_tmp] = lp;
                self.parent[lp] = q_tmp;
            }
            let rp = self.rchild[p];
            self.rchild[q_tmp] = rp;
            self.parent[rp] = q_tmp;
            q = q_tmp;
        }
        let pp = self.parent[p];
        self.parent[q] = pp;
        if self.rchild[pp] == p {
            self.rchild[pp] = q;
        } else {
            self.lchild[pp] = q;
        }
        self.parent[p] = NIL;
    }
}

fn read_byte(src: &mut impl Read) -> io::Result<Option<u8>> {
    let mut buf = [0u8; 1];
    loop {
        match src.read(&mut buf) {
            Ok(1) => return Ok(Some(buf[0])),
            Ok(0) => return Ok(None),
            Ok(_) => unreachable!(),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Decompresses LZSS-encoded data from `src` into `dst`.
///
/// Mirrors `LzssCodec.decompress` from Ghidra's img4lib-based implementation.
pub fn decompress(dst: &mut impl Write, src: &mut impl Read) -> io::Result<()> {
    let mut text_buf = [0u8; N + F - 1];
    for b in &mut text_buf[..N - F] {
        *b = b' ';
    }
    let mut pos = N - F;
    let mut flags = 0u32;
    loop {
        flags >>= 1;
        if flags & 0x100 == 0 {
            match read_byte(src)? {
                None => break,
                Some(c) => flags = c as u32 | 0xFF00,
            }
        }
        if flags & 1 != 0 {
            match read_byte(src)? {
                None => break,
                Some(c) => {
                    dst.write_all(&[c])?;
                    text_buf[pos] = c;
                    pos = (pos + 1) & (N - 1);
                }
            }
        } else {
            let i = match read_byte(src)? {
                None => break,
                Some(b) => b as usize,
            };
            let j_raw = match read_byte(src)? {
                None => break,
                Some(b) => b as usize,
            };
            let back_pos = i | ((j_raw & 0xF0) << 4);
            let match_len = (j_raw & 0x0F) + THRESHOLD;
            for k in 0..=match_len {
                let c = text_buf[(back_pos + k) & (N - 1)];
                dst.write_all(&[c])?;
                text_buf[pos] = c;
                pos = (pos + 1) & (N - 1);
            }
        }
    }
    dst.flush()
}

/// Compresses `src` using LZSS encoding into `dst`.
///
/// Mirrors `LzssCodec.compress` from Ghidra's img4lib-based implementation.
pub fn compress(dst: &mut impl Write, src: &mut impl Read) -> io::Result<()> {
    let mut sp = EncodeState::new();
    let mut code_buf = Vec::<u8>::with_capacity(17);
    code_buf.push(0u8);
    let mut mask: u16 = 1;
    let mut s: usize = 0;
    let mut r: usize = N - F;
    let mut len: usize = 0;

    while len < F {
        match read_byte(src)? {
            None => break,
            Some(b) => {
                sp.text_buf[r + len] = b;
                len += 1;
            }
        }
    }
    if len == 0 {
        return Ok(());
    }

    for i in 1..=F {
        sp.insert_node(r - i);
    }
    sp.insert_node(r);

    loop {
        if sp.match_length > len {
            sp.match_length = len;
        }
        if sp.match_length <= THRESHOLD {
            sp.match_length = 1;
            code_buf[0] |= mask as u8;
            code_buf.push(sp.text_buf[r]);
        } else {
            code_buf.push(sp.match_position as u8);
            code_buf.push(
                (((sp.match_position >> 4) & 0xF0) | (sp.match_length - (THRESHOLD + 1))) as u8,
            );
        }
        mask <<= 1;
        if mask == 0x100 {
            dst.write_all(&code_buf)?;
            code_buf.clear();
            code_buf.push(0u8);
            mask = 1;
        }
        let last_match_length = sp.match_length;
        let mut i = 0usize;
        while i < last_match_length {
            match read_byte(src)? {
                None => break,
                Some(c) => {
                    sp.delete_node(s);
                    sp.text_buf[s] = c;
                    if s < F - 1 {
                        sp.text_buf[s + N] = c;
                    }
                    s = (s + 1) & (N - 1);
                    r = (r + 1) & (N - 1);
                    sp.insert_node(r);
                    i += 1;
                }
            }
        }
        while i < last_match_length {
            sp.delete_node(s);
            s = (s + 1) & (N - 1);
            r = (r + 1) & (N - 1);
            len -= 1;
            if len != 0 {
                sp.insert_node(r);
            }
            i += 1;
        }
        if len == 0 {
            break;
        }
    }

    if code_buf.len() > 1 {
        dst.write_all(&code_buf)?;
    }
    dst.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn compress_bytes(input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        compress(&mut out, &mut Cursor::new(input)).unwrap();
        out
    }

    fn decompress_bytes(input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        decompress(&mut out, &mut Cursor::new(input)).unwrap();
        out
    }

    #[test]
    fn roundtrip_empty() {
        assert_eq!(compress_bytes(&[]), &[] as &[u8]);
        assert_eq!(decompress_bytes(&[]), &[] as &[u8]);
    }

    #[test]
    fn roundtrip_single_byte() {
        let input = b"A";
        assert_eq!(decompress_bytes(&compress_bytes(input)), input);
    }

    #[test]
    fn roundtrip_ascii_text() {
        let input = b"Hello, world! This is an LZSS compression test.";
        assert_eq!(decompress_bytes(&compress_bytes(input)).as_slice(), input.as_slice());
    }

    #[test]
    fn roundtrip_repeated_pattern() {
        let input: Vec<u8> = b"ABCDEFGH".iter().cycle().take(512).copied().collect();
        assert_eq!(decompress_bytes(&compress_bytes(&input)), input);
    }

    #[test]
    fn roundtrip_all_same_byte() {
        let input = vec![0x42u8; 1024];
        assert_eq!(decompress_bytes(&compress_bytes(&input)), input);
    }

    #[test]
    fn compress_repeated_is_smaller() {
        let input = vec![b'X'; 200];
        let compressed = compress_bytes(&input);
        assert!(compressed.len() < input.len());
    }

    #[test]
    fn roundtrip_binary_data() {
        let input: Vec<u8> = (0..=255u8).collect();
        assert_eq!(decompress_bytes(&compress_bytes(&input)), input);
    }

    #[test]
    fn constants_match_java() {
        assert_eq!(N, 4096);
        assert_eq!(F, 18);
        assert_eq!(THRESHOLD, 2);
        assert_eq!(NIL, N);
    }

    /// Example taken from Wikipedia's LZSS article. Accessed 15 Feb 2019.
    ///
    /// They, in turn, took it from Dr. Seuss's Green Eggs and Ham, as it
    /// contains many repeated words, making for great compression fodder.
    const TEST_TEXT: &str = "I am Sam\n\
        \n\
        Sam I am\n\
        \n\
        That Sam-I-am!\n\
        That Sam-I-am!\n\
        I do not like\n\
        that Sam-I-am!\n\
        \n\
        Do you like green eggs and ham?\n\
        \n\
        I do not like them, Sam-I-am.\n\
        I do not like green eggs and ham.";

    const TEST_COMPRESSED: [u8; 96] = [
        0xff, 0x49, 0x20, 0x61, //
        0x6d, 0x20, 0x53, 0x61, //
        0x6d, 0xf3, 0x0a, 0x0a, //
        0xf3, 0xf0, 0xed, 0xf2, //
        0x0a, 0x0a, 0x54, 0x68, //
        0xfb, 0x61, 0x74, 0xf2, //
        0xf1, 0x2d, 0x49, 0x2d, //
        0x61, 0x6d, 0xfd, 0x21, //
        0x01, 0x0d, 0x49, 0x20, //
        0x64, 0x6f, 0x20, 0x6e, //
        0xff, 0x6f, 0x74, 0x20, //
        0x6c, 0x69, 0x6b, 0x65, //
        0x0a, 0xfd, 0x74, 0x03, //
        0x0b, 0x0a, 0x44, 0x6f, //
        0x20, 0x79, 0x6f, 0xfd, //
        0x75, 0x28, 0x02, 0x20, //
        0x67, 0x72, 0x65, 0x65, //
        0x6e, 0xff, 0x20, 0x65, //
        0x67, 0x67, 0x73, 0x20, //
        0x61, 0x6e, 0x7f, 0x64, //
        0x20, 0x68, 0x61, 0x6d, //
        0x3f, 0x0a, 0x1f, 0x0b, //
        0xbf, 0x20, 0x74, 0x68, //
        0x65, 0x6d, 0x2c, 0x06, //
        0x06, 0x2e, 0x04, 0x5e, //
        0x0c, 0x4a, 0x0f, 0x2e, //
    ];

    #[test]
    fn test_compress() {
        let out = compress_bytes(TEST_TEXT.as_bytes());
        assert_eq!(out.as_slice(), &TEST_COMPRESSED[..]);
    }

    #[test]
    fn test_decompress() {
        let out = decompress_bytes(&TEST_COMPRESSED);
        assert_eq!(out.as_slice(), TEST_TEXT.as_bytes());
    }
}
