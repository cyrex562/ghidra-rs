use crate::program::model::address::{Address, AddressRange};
use crate::program::model::mem::MemoryAccessException;
use crate::util::MathUtilities;

/// Number of bits in a cache page's offset (a page holds `1 << BITS` bytes).
pub const BITS: u32 = 12;

/// Mask that isolates the page-aligned portion of an address offset.
pub const OFFSET_MASK: i64 = -1i64 << BITS;

/// Number of bytes held by a single cache page.
pub const SIZE: usize = 1 << BITS;

/// Loads bytes on behalf of a [`ByteCache`] when a page is not already cached.
///
/// Java source: `ghidra.trace.database.program.ByteCache#doLoad`, an abstract method
/// that concrete subclasses (or, in Java, anonymous inner classes) implement.
pub trait ByteCacheLoader {
    /// Loads bytes starting at `address` into `buf`, filling from index 0.
    ///
    /// Returns the number of bytes actually loaded, which may be less than
    /// `buf.len()` if the requested range runs past the end of available memory.
    fn do_load(&self, address: &Address, buf: &mut [u8]) -> Result<usize, MemoryAccessException>;
}

/// A single cached page of bytes.
struct Page {
    valid: bool,
    start: Option<Address>,
    bytes: Vec<u8>,
    len: i64,
}

impl Page {
    fn new() -> Self {
        Self {
            valid: false,
            start: None,
            bytes: vec![0u8; SIZE],
            len: 0,
        }
    }

    fn contains(&self, address: &Address, length: i64) -> bool {
        if !self.valid {
            return false;
        }
        let Some(start) = &self.start else {
            return false;
        };
        if !start.same_address_space(address) {
            return false;
        }
        let offset = address.subtract(start);
        let sum = offset.wrapping_add(length);
        (sum as u64) < (self.len as u64)
    }

    fn invalidate(&mut self, _range: &AddressRange) {
        self.valid = false;
    }
}

/// A fixed-size, LRU-ish cache of memory pages read through a [`ByteCacheLoader`].
///
/// Java source: `ghidra.trace.database.program.ByteCache`. The Java class is
/// declared `abstract` with a single abstract method, `doLoad`; that extension
/// point is modeled here as the `L: ByteCacheLoader` type parameter instead of
/// subclassing.
pub struct ByteCache<L: ByteCacheLoader> {
    loader: L,
    pages: Vec<Page>,
}

impl<L: ByteCacheLoader> ByteCache<L> {
    /// Creates a cache with `page_count` pages, backed by `loader`.
    pub fn new(page_count: usize, loader: L) -> Self {
        let pages = (0..page_count).map(|_| Page::new()).collect();
        Self { loader, pages }
    }

    /// Returns whether `len` bytes starting at `address` could ever be cached,
    /// i.e. fit within the cache's total capacity from the containing page.
    pub fn can_cache(&self, address: &Address, len: i32) -> bool {
        let cache_buf_off = address.offset() & !OFFSET_MASK;
        cache_buf_off + (len as i64) < (self.pages.len() as i64) * (SIZE as i64)
    }

    /// Reads a single byte at `address`, loading its page if necessary.
    pub fn read_byte(&mut self, address: &Address) -> Result<u8, MemoryAccessException> {
        let page_start = Address::new(address.space().clone(), address.offset() & OFFSET_MASK);
        self.ensure_page_cached(&page_start, 1)?;
        let cache_buf_off = address.subtract(&page_start) as usize;
        Ok(self.pages[0].bytes[cache_buf_off])
    }

    /// Fills `buf` with bytes starting at `address`, loading pages as necessary.
    ///
    /// Returns the number of bytes written into `buf` (always `buf.len()` on
    /// success, since a short read is reported as a [`MemoryAccessException`]).
    pub fn read(&mut self, address: &Address, buf: &mut [u8]) -> Result<usize, MemoryAccessException> {
        let start_off = address.offset();
        let start_page = start_off & OFFSET_MASK;

        let mut mem_offset = start_page;
        let mut cache_buf_off = (start_off - start_page) as usize;
        let mut buf_pos = 0usize;
        while buf_pos < buf.len() {
            let required = MathUtilities::unsigned_min_i32(
                (SIZE - cache_buf_off) as i32,
                (buf.len() - buf_pos) as i32,
            ) as usize;
            let page_addr = Address::new(address.space().clone(), mem_offset);
            self.ensure_page_cached(&page_addr, (required + cache_buf_off) as i32)?;
            buf[buf_pos..buf_pos + required]
                .copy_from_slice(&self.pages[0].bytes[cache_buf_off..cache_buf_off + required]);
            buf_pos += required;
            mem_offset += SIZE as i64;
            cache_buf_off = 0;
        }
        Ok(buf_pos)
    }

    /// Invalidates every cached page that may intersect `range`.
    ///
    /// Mirrors the Java implementation, which does not actually check for
    /// intersection and simply invalidates every page unconditionally.
    pub fn invalidate(&mut self, range: &AddressRange) {
        for page in &mut self.pages {
            page.invalidate(range);
        }
    }

    fn choose_page(&self, address: &Address, len: i64) -> Option<usize> {
        self.pages.iter().position(|p| p.contains(address, len))
    }

    /// Ensures a page starting at `address` (and covering at least `len` bytes
    /// from that address) is cached at `self.pages[0]`.
    fn ensure_page_cached(&mut self, address: &Address, len: i32) -> Result<(), MemoryAccessException> {
        let chosen = match self.choose_page(address, len as i64) {
            Some(idx) => idx,
            None => {
                let last = self.pages.len() - 1;
                self.load_page(last, address, len)?;
                last
            }
        };
        if chosen != 0 {
            self.pages.swap(0, chosen);
        }
        Ok(())
    }

    fn load_page(
        &mut self,
        idx: usize,
        address: &Address,
        length: i32,
    ) -> Result<(), MemoryAccessException> {
        self.pages[idx].valid = false;
        let start = Address::new(address.space().clone(), address.offset() & OFFSET_MASK);
        let offset = address.subtract(&start);

        let loader = &self.loader;
        let page = &mut self.pages[idx];
        let loaded = loader.do_load(address, &mut page.bytes)?;
        page.len = loaded as i64;
        page.start = Some(start);
        if page.len < offset.wrapping_add(length as i64) {
            return Err(MemoryAccessException::default());
        }
        page.valid = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;

    struct MemLoader {
        data: Vec<u8>,
    }

    impl ByteCacheLoader for MemLoader {
        fn do_load(&self, address: &Address, buf: &mut [u8]) -> Result<usize, MemoryAccessException> {
            let start = address.offset() as usize;
            if start >= self.data.len() {
                return Ok(0);
            }
            let avail = (self.data.len() - start).min(buf.len());
            buf[..avail].copy_from_slice(&self.data[start..start + avail]);
            Ok(avail)
        }
    }

    struct SharedMemLoader {
        data: Rc<RefCell<Vec<u8>>>,
    }

    impl ByteCacheLoader for SharedMemLoader {
        fn do_load(&self, address: &Address, buf: &mut [u8]) -> Result<usize, MemoryAccessException> {
            let data = self.data.borrow();
            let start = address.offset() as usize;
            if start >= data.len() {
                return Ok(0);
            }
            let avail = (data.len() - start).min(buf.len());
            buf[..avail].copy_from_slice(&data[start..start + avail]);
            Ok(avail)
        }
    }

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
    }

    #[test]
    fn read_byte_loads_page_and_returns_value() {
        let space = space();
        let mut data = vec![0u8; SIZE * 2];
        data[5] = 0xAB;
        let mut cache = ByteCache::new(2, MemLoader { data });

        let value = cache.read_byte(&addr(&space, 5)).unwrap();
        assert_eq!(value, 0xAB);
    }

    #[test]
    fn read_byte_reuses_cached_page() {
        let space = space();
        let data = vec![0u8; SIZE];
        let mut cache = ByteCache::new(1, MemLoader { data });

        cache.read_byte(&addr(&space, 0)).unwrap();
        // Second read of the same page must not error, exercising the cache hit path.
        let value = cache.read_byte(&addr(&space, 10)).unwrap();
        assert_eq!(value, 0);
    }

    #[test]
    fn read_spans_multiple_pages() {
        let space = space();
        let data: Vec<u8> = (0..(SIZE * 2)).map(|i| (i % 256) as u8).collect();
        let mut cache = ByteCache::new(2, MemLoader { data: data.clone() });

        let start = (SIZE - 4) as i64;
        let mut buf = vec![0u8; 8];
        let n = cache.read(&addr(&space, start), &mut buf).unwrap();
        assert_eq!(n, 8);
        assert_eq!(&buf[..], &data[start as usize..start as usize + 8]);
    }

    #[test]
    fn read_past_end_of_memory_is_an_error() {
        let space = space();
        let data = vec![0u8; 4];
        let mut cache = ByteCache::new(1, MemLoader { data });

        let mut buf = vec![0u8; 8];
        let result = cache.read(&addr(&space, 0), &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn can_cache_respects_page_count_capacity() {
        let space = space();
        let cache: ByteCache<MemLoader> = ByteCache::new(1, MemLoader { data: vec![] });

        assert!(cache.can_cache(&addr(&space, 0), 10));
        assert!(!cache.can_cache(&addr(&space, (SIZE - 5) as i64), 10));
    }

    #[test]
    fn invalidate_forces_reload() {
        let space = space();
        let data = Rc::new(RefCell::new(vec![1u8; SIZE]));
        let mut cache = ByteCache::new(1, SharedMemLoader { data: data.clone() });

        assert_eq!(cache.read_byte(&addr(&space, 0)).unwrap(), 1);

        // Mutate the backing store behind the cache's back; without invalidation
        // the cached page would still report the stale value.
        data.borrow_mut()[0] = 2;
        let range = AddressRange::new(addr(&space, 0), addr(&space, (SIZE - 1) as i64));
        cache.invalidate(&range);

        assert_eq!(cache.read_byte(&addr(&space, 0)).unwrap(), 2);
    }
}
