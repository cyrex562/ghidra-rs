use std::sync::Arc;

use crate::program::model::address::AddressSpace;

use super::memory_page::MemoryPage;
use super::MemoryFaultHandler;

/// Shared state for a [`MemoryBankImpl`] implementation.
///
/// Holds the fields Java's `MemoryBank` stores directly: the associated address space, page
/// size, endianness, the derived initialized-mask size, and an optional fault handler.
///
/// Corresponds to the instance fields of `ghidra.pcode.memstate.MemoryBank`.
///
/// # Deprecation
///
/// Deprecated since Ghidra 12.1 and scheduled for removal.
#[deprecated(since = "12.1", note = "scheduled for removal in a future release")]
#[allow(deprecated)]
pub struct MemoryBankState {
    pagesize: i32,
    space: Arc<AddressSpace>,
    is_big_endian: bool,
    initialized_mask_size: i32,
    fault_handler: Option<Arc<dyn MemoryFaultHandler>>,
}

#[allow(deprecated)]
impl MemoryBankState {
    /// A `MemoryBank` must be associated with a specific address space, have a preferred or
    /// natural page size. The page size must be a power of 2.
    ///
    /// # Arguments
    ///
    /// * `space` - the associated address space
    /// * `is_big_endian` - memory endianness
    /// * `pagesize` - the number of bytes in a page (must be a power of 2)
    /// * `fault_handler` - memory fault handler
    pub fn new(
        space: Arc<AddressSpace>,
        is_big_endian: bool,
        pagesize: i32,
        fault_handler: Option<Arc<dyn MemoryFaultHandler>>,
    ) -> Self {
        let initialized_mask_size = (pagesize + 7) / 8;
        Self {
            pagesize,
            space,
            is_big_endian,
            initialized_mask_size,
            fault_handler,
        }
    }

    /// Returns the memory fault handler (may be `None`).
    pub fn fault_handler(&self) -> Option<&Arc<dyn MemoryFaultHandler>> {
        self.fault_handler.as_ref()
    }

    /// Returns `true` if this memory bank is big endian.
    pub fn is_big_endian(&self) -> bool {
        self.is_big_endian
    }

    /// A `MemoryBank` is instantiated with a natural page size. Requests for large chunks of
    /// data may be broken down into units of this size.
    ///
    /// Returns the number of bytes in a page.
    pub fn page_size(&self) -> i32 {
        self.pagesize
    }

    /// Returns the size of a page initialized mask in bytes. Each bit within the mask
    /// corresponds to a data byte within a page.
    pub fn initialized_mask_size(&self) -> i32 {
        self.initialized_mask_size
    }

    /// Returns the `AddressSpace` associated with this bank.
    pub fn space(&self) -> &Arc<AddressSpace> {
        &self.space
    }
}

/// Behavior contract for a paged memory bank backing p-code emulator memory state.
///
/// Java subclasses (`MemoryPageBank`, `UniqueMemoryBank`) override [`get_page`](Self::get_page),
/// [`set_page`](Self::set_page), and [`set_page_initialized`](Self::set_page_initialized) to
/// provide storage for pages; Rust has no inheritance, so implementors instead hold a
/// [`MemoryBankState`] and implement this trait, which supplies the shared control flow
/// ([`set_chunk`](Self::set_chunk), [`set_initialized`](Self::set_initialized),
/// [`get_chunk`](Self::get_chunk)) as default methods built on top.
///
/// Corresponds to `ghidra.pcode.memstate.MemoryBank`.
///
/// # Deprecation
///
/// Deprecated since Ghidra 12.1 and scheduled for removal.
#[deprecated(since = "12.1", note = "scheduled for removal in a future release")]
#[allow(deprecated)]
pub trait MemoryBankImpl: Sized {
    /// Returns the shared bank state (address space, page size, endianness, fault handler).
    fn state(&self) -> &MemoryBankState;

    /// Retrieves the memory page containing the aligned page offset `addr`.
    ///
    /// This routine only retrieves data from a single page in the memory bank. `addr` is
    /// always the aligned offset of the desired page.
    fn get_page(&mut self, addr: i64) -> &mut MemoryPage;

    /// This routine writes data only to a single page of the memory bank. Bytes need not be
    /// written to the exact start of the page, but all bytes must be written to only one page
    /// when using this routine. A page is a fixed number of bytes, and the address of a page
    /// is always aligned based on this size.
    ///
    /// # Arguments
    ///
    /// * `addr` - the aligned offset of the desired page
    /// * `val` - the bytes to be written into the page
    /// * `skip` - the offset into the page where bytes will be written
    /// * `size` - the number of bytes to be written
    /// * `buf_offset` - the offset in `val` from which to get the bytes
    fn set_page(&mut self, addr: i64, val: &[u8], skip: i32, size: i32, buf_offset: i32);

    /// This routine marks a range within a single page of the memory bank as initialized or
    /// uninitialized. A page is a fixed number of bytes, and the address of a page is always
    /// aligned based on this size.
    ///
    /// # Arguments
    ///
    /// * `addr` - the aligned offset of the desired page
    /// * `initialized` - `true` if range should be marked as initialized, `false` if uninitialized
    /// * `skip` - the offset into the page where bytes will be written
    /// * `size` - the number of bytes to be written
    /// * `buf_offset` - the offset in `val` from which to get the bytes
    fn set_page_initialized(
        &mut self,
        addr: i64,
        initialized: bool,
        skip: i32,
        size: i32,
        buf_offset: i32,
    );

    /// This the most general method for writing a sequence of bytes into the memory bank.
    /// The initial offset and page writes will be wrapped within the address space.
    ///
    /// # Arguments
    ///
    /// * `offset` - the start of the byte range to be written. This offset will be wrapped
    ///   within the space
    /// * `size` - the number of bytes to write
    /// * `val` - the sequence of bytes to be written into the bank
    fn set_chunk(&mut self, offset: i64, size: i32, val: &[u8]) {
        let pagesize = self.state().page_size();
        let space = self.state().space().clone();
        let pagemask = (pagesize as i64) - 1;

        let mut offset = offset;
        let mut count = 0;
        let mut buf_offset = 0;
        while count < size {
            let mut cursize = pagesize;
            offset = space.truncate_offset(offset);
            let offalign = offset & !pagemask;
            let mut skip = 0;
            if offalign != offset {
                skip = (offset - offalign) as i32;
                cursize -= skip;
            }
            if size - count < cursize {
                cursize = size - count;
            }
            self.set_page(offalign, val, skip, cursize, buf_offset);
            count += cursize;
            offset += cursize as i64;
            buf_offset += cursize;
        }
    }

    /// This method allows ranges of bytes to marked as initialized or not. There is no
    /// restriction on the offset to write to or the number of bytes to be written, except
    /// that the range must be contained in the address space.
    ///
    /// # Arguments
    ///
    /// * `offset` - the start of the byte range to be written
    /// * `size` - the number of bytes to write
    /// * `initialized` - indicates if the range should be marked as initialized or not
    fn set_initialized(&mut self, offset: i64, size: i32, initialized: bool) {
        let pagesize = self.state().page_size();
        let pagemask = (pagesize as i64) - 1;

        let mut offset = offset;
        let mut count = 0;
        let mut buf_offset = 0;
        while count < size {
            let mut cursize = pagesize;
            let offalign = offset & !pagemask;
            let mut skip = 0;
            if offalign != offset {
                skip = (offset - offalign) as i32;
                cursize -= skip;
            }
            if size - count < cursize {
                cursize = size - count;
            }
            self.set_page_initialized(offalign, initialized, skip, cursize, buf_offset);
            count += cursize;
            offset += cursize as i64;
            buf_offset += cursize;
        }
    }

    /// This is the most general method for reading a sequence of bytes from the memory bank.
    /// There is no restriction on the offset or the number of bytes to read, except that the
    /// range must be contained in the address space.
    ///
    /// # Arguments
    ///
    /// * `addr_offset` - the start of the byte range to read
    /// * `size` - the number of bytes to read
    /// * `res` - where the retrieved bytes should be stored
    /// * `stop_on_uninitialized` - if `true` a partial read is permitted and returned size may
    ///   be smaller than size requested if uninitialized data is encountered
    ///
    /// Returns the number of bytes actually read.
    fn get_chunk(
        &mut self,
        addr_offset: i64,
        size: i32,
        res: &mut [u8],
        stop_on_uninitialized: bool,
    ) -> i32 {
        let pagesize = self.state().page_size();
        let space = self.state().space().clone();
        let fault_handler = self.state().fault_handler().cloned();
        let pagemask = (pagesize as i64) - 1;

        let mut addr_offset = space.truncate_offset(addr_offset);
        let mut count = 0;
        let mut buf_offset = 0;

        while count < size {
            let mut cursize = pagesize;
            let offalign = addr_offset & !pagemask;
            let mut skip = 0;
            if offalign != addr_offset {
                skip = (addr_offset - offalign) as i32;
                cursize -= skip;
            }
            if size - count < cursize {
                cursize = size - count;
            }

            let page = self.get_page(offalign);

            // Read initialized data which is available
            let initialized_byte_count =
                page.initialized_byte_count(skip as usize, cursize as usize) as i32;
            let dst = buf_offset as usize;
            let src = skip as usize;
            let n = initialized_byte_count as usize;
            res[dst..dst + n].copy_from_slice(&page.data[src..src + n]);
            count += initialized_byte_count;

            let mut next_addr_offset =
                space.truncate_offset(addr_offset + initialized_byte_count as i64);
            addr_offset += initialized_byte_count as i64;
            buf_offset += initialized_byte_count;
            cursize -= initialized_byte_count;

            if cursize != 0 {
                // Handle incomplete read from current page
                let skip = skip + initialized_byte_count;
                let fault_addr = space.address(offalign + skip as i64);
                let handled = match &fault_handler {
                    Some(fh) => fh.uninitialized_read(&fault_addr, cursize, &mut page.data, skip),
                    None => false,
                };
                if handled {
                    page.mark_initialized(skip as usize, cursize as usize);
                } else if stop_on_uninitialized {
                    return count;
                }
                let dst = buf_offset as usize;
                let src = skip as usize;
                let n = cursize as usize;
                res[dst..dst + n].copy_from_slice(&page.data[src..src + n]);
                count += cursize;

                next_addr_offset = space.truncate_offset(next_addr_offset + cursize as i64);
                addr_offset += cursize as i64;
                buf_offset += cursize;
            }

            // stop if wrapped midway
            if addr_offset < 0 {
                if next_addr_offset > 0 {
                    break;
                }
            } else if next_addr_offset < addr_offset {
                break;
            }
        }
        count
    }
}

/// A static convenience routine for decoding a value from a sequence of bytes depending on the
/// desired endianness.
///
/// Corresponds to `ghidra.pcode.memstate.MemoryBank#constructValue`.
///
/// # Arguments
///
/// * `ptr` - the bytes to decode
/// * `offset` - a fixed offset from the start of `ptr` used during decode
/// * `size` - the number of bytes
/// * `bigendian` - `true` if the bytes are encoded in big endian form
///
/// Returns the decoded value.
pub fn construct_value(ptr: &[u8], offset: usize, size: usize, bigendian: bool) -> i64 {
    let mut res: i64 = 0;
    if bigendian {
        for i in 0..size {
            res <<= 8;
            res |= ptr[i + offset] as i64 & 0xff;
        }
    } else {
        for i in (0..size).rev() {
            res <<= 8;
            res |= ptr[i + offset] as i64 & 0xff;
        }
    }
    res
}

/// A static convenience routine for encoding bytes from a given value, depending on the
/// desired endianness.
///
/// Corresponds to `ghidra.pcode.memstate.MemoryBank#deconstructValue`.
///
/// # Arguments
///
/// * `ptr` - where the encoded bytes should be written
/// * `offset` - a fixed offset from the start of `ptr` to where to write the bytes
/// * `val` - the value to be encoded
/// * `size` - the number of bytes to encode
/// * `bigendian` - `true` if a big endian encoding is desired
pub fn deconstruct_value(ptr: &mut [u8], offset: usize, val: i64, size: usize, bigendian: bool) {
    let mut val = val;
    if bigendian {
        for i in (0..size).rev() {
            ptr[i + offset] = (val & 0xff) as u8;
            val >>= 8;
        }
    } else {
        for i in 0..size {
            ptr[i + offset] = (val & 0xff) as u8;
            val >>= 8;
        }
    }
}

#[cfg(test)]
mod tests {
    #[allow(deprecated)]
    use super::{construct_value, deconstruct_value, MemoryBankImpl, MemoryBankState};
    use super::super::memory_page::MemoryPage;
    use super::super::MemoryFaultHandler as MemoryFaultHandlerAlias;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use std::collections::HashMap;
    use std::sync::Arc;

    #[allow(deprecated)]
    struct TestBank {
        state: MemoryBankState,
        pages: HashMap<i64, MemoryPage>,
    }

    #[allow(deprecated)]
    impl TestBank {
        fn new(
            space: Arc<AddressSpace>,
            is_big_endian: bool,
            pagesize: i32,
            fault_handler: Option<Arc<dyn MemoryFaultHandlerAlias>>,
        ) -> Self {
            Self {
                state: MemoryBankState::new(space, is_big_endian, pagesize, fault_handler),
                pages: HashMap::new(),
            }
        }
    }

    #[allow(deprecated)]
    impl MemoryBankImpl for TestBank {
        fn state(&self) -> &MemoryBankState {
            &self.state
        }

        fn get_page(&mut self, addr: i64) -> &mut MemoryPage {
            let pagesize = self.state.page_size() as usize;
            self.pages
                .entry(addr)
                .or_insert_with(|| MemoryPage::new(pagesize))
        }

        fn set_page(&mut self, addr: i64, val: &[u8], skip: i32, size: i32, buf_offset: i32) {
            let pagesize = self.state.page_size() as usize;
            let page = self
                .pages
                .entry(addr)
                .or_insert_with(|| MemoryPage::new(pagesize));
            let skip = skip as usize;
            let size = size as usize;
            let buf_offset = buf_offset as usize;
            page.data[skip..skip + size].copy_from_slice(&val[buf_offset..buf_offset + size]);
            page.mark_initialized(skip, size);
        }

        fn set_page_initialized(
            &mut self,
            addr: i64,
            initialized: bool,
            skip: i32,
            size: i32,
            _buf_offset: i32,
        ) {
            let pagesize = self.state.page_size() as usize;
            let page = self
                .pages
                .entry(addr)
                .or_insert_with(|| MemoryPage::new(pagesize));
            if initialized {
                page.mark_initialized(skip as usize, size as usize);
            } else {
                page.mark_uninitialized(skip as usize, size as usize);
            }
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn state_reports_constructor_values() {
        #[allow(deprecated)]
        let state = MemoryBankState::new(ram_space(), true, 16, None);
        assert_eq!(state.page_size(), 16);
        assert!(state.is_big_endian());
        assert_eq!(state.initialized_mask_size(), 2);
        assert!(state.fault_handler().is_none());
    }

    #[test]
    fn initialized_mask_size_rounds_up() {
        #[allow(deprecated)]
        let state = MemoryBankState::new(ram_space(), false, 9, None);
        assert_eq!(state.initialized_mask_size(), 2);
    }

    #[test]
    fn set_chunk_then_get_chunk_round_trips_within_one_page() {
        #[allow(deprecated)]
        let mut bank = TestBank::new(ram_space(), false, 16, None);
        let data = [1u8, 2, 3, 4];
        bank.set_chunk(0x10, 4, &data);

        let mut res = [0u8; 4];
        let n = bank.get_chunk(0x10, 4, &mut res, false);
        assert_eq!(n, 4);
        assert_eq!(res, data);
    }

    #[test]
    fn set_chunk_then_get_chunk_spans_multiple_pages() {
        #[allow(deprecated)]
        let mut bank = TestBank::new(ram_space(), false, 4, None);
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        // page size is 4, so this write spans two pages (offset 2..10)
        bank.set_chunk(2, 8, &data);

        let mut res = [0u8; 8];
        let n = bank.get_chunk(2, 8, &mut res, false);
        assert_eq!(n, 8);
        assert_eq!(res, data);
    }

    #[test]
    fn get_chunk_stops_on_uninitialized_when_requested() {
        #[allow(deprecated)]
        let mut bank = TestBank::new(ram_space(), false, 16, None);
        bank.set_chunk(0, 2, &[0xAA, 0xBB]);
        // bytes [2,4) of the page were never written, so they remain uninitialized

        let mut res = [0u8; 4];
        let n = bank.get_chunk(0, 4, &mut res, true);
        assert_eq!(n, 2);
        assert_eq!(&res[0..2], &[0xAA, 0xBB]);
    }

    #[test]
    fn get_chunk_uses_fault_handler_for_uninitialized_reads() {
        struct FillWithFf;
        #[allow(deprecated)]
        impl MemoryFaultHandlerAlias for FillWithFf {
            fn uninitialized_read(
                &self,
                _address: &Address,
                size: i32,
                buf: &mut [u8],
                buf_offset: i32,
            ) -> bool {
                let start = buf_offset as usize;
                let end = start + size as usize;
                buf[start..end].fill(0xFF);
                true
            }

            fn unknown_address(&self, _address: &Address, _write: bool) -> bool {
                false
            }
        }

        #[allow(deprecated)]
        let mut bank = TestBank::new(ram_space(), false, 16, Some(Arc::new(FillWithFf)));

        let mut res = [0u8; 4];
        let n = bank.get_chunk(0, 4, &mut res, true);
        assert_eq!(n, 4);
        assert_eq!(res, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn set_initialized_marks_range_uninitialized() {
        #[allow(deprecated)]
        let mut bank = TestBank::new(ram_space(), false, 16, None);
        bank.set_chunk(0, 4, &[1, 2, 3, 4]);
        bank.set_initialized(1, 2, false);

        let mut res = [0u8; 4];
        let n = bank.get_chunk(0, 4, &mut res, true);
        // byte 0 is initialized, bytes [1,3) were just marked uninitialized
        assert_eq!(n, 1);
        assert_eq!(res[0], 1);
    }

    #[test]
    fn construct_value_big_endian() {
        let bytes = [0x01u8, 0x02, 0x03, 0x04];
        let val = construct_value(&bytes, 0, 4, true);
        assert_eq!(val, 0x01020304);
    }

    #[test]
    fn construct_value_little_endian() {
        let bytes = [0x01u8, 0x02, 0x03, 0x04];
        let val = construct_value(&bytes, 0, 4, false);
        assert_eq!(val, 0x04030201);
    }

    #[test]
    fn construct_value_with_offset() {
        let bytes = [0xFFu8, 0x01, 0x02, 0x03, 0x04];
        let val = construct_value(&bytes, 1, 4, true);
        assert_eq!(val, 0x01020304);
    }

    #[test]
    fn deconstruct_value_big_endian() {
        let mut bytes = [0u8; 4];
        deconstruct_value(&mut bytes, 0, 0x01020304, 4, true);
        assert_eq!(bytes, [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn deconstruct_value_little_endian() {
        let mut bytes = [0u8; 4];
        deconstruct_value(&mut bytes, 0, 0x01020304, 4, false);
        assert_eq!(bytes, [0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn construct_and_deconstruct_round_trip() {
        for &bigendian in &[true, false] {
            let mut bytes = [0u8; 8];
            deconstruct_value(&mut bytes, 0, 0x1122334455667788u64 as i64, 8, bigendian);
            let val = construct_value(&bytes, 0, 8, bigendian);
            assert_eq!(val, 0x1122334455667788u64 as i64);
        }
    }
}
