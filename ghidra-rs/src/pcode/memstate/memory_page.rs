/// A memory page with optional byte-level initialization tracking.
///
/// Each bit within `initialized_mask` corresponds to a data byte within the page.
/// `None` mask means all bytes are initialized. A `1`-bit in the mask means the
/// corresponding data byte is initialized.
///
/// Corresponds to `ghidra.pcode.memstate.MemoryPage`.
///
/// # Deprecation
///
/// Deprecated since Ghidra 12.1 and scheduled for removal.
#[deprecated(since = "12.1", note = "scheduled for removal in a future release")]
pub struct MemoryPage {
    /// The page data bytes.
    pub data: Vec<u8>,
    initialized_mask: Option<Vec<u8>>,
}

#[allow(deprecated)]
impl MemoryPage {
    /// Construct a new fully initialized page of `page_size` zero bytes.
    pub fn new(page_size: usize) -> Self {
        Self {
            data: vec![0u8; page_size],
            initialized_mask: None,
        }
    }

    /// Construct a memory page from an existing byte buffer (fully initialized).
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            data: bytes,
            initialized_mask: None,
        }
    }

    /// Returns the initialization mask, or `None` if the whole page is initialized.
    pub fn initialized_mask(&self) -> Option<&[u8]> {
        self.initialized_mask.as_deref()
    }

    /// Mark the entire page as uninitialized.
    pub fn set_uninitialized(&mut self) {
        self.initialized_mask = Some(Self::make_mask(self.data.len(), false));
    }

    /// Mark the entire page as initialized.
    pub fn set_initialized(&mut self) {
        self.initialized_mask = Some(Self::make_mask(self.data.len(), true));
    }

    /// Update the initialization mask for `[page_offset, page_offset + size)` using `mask_update`.
    ///
    /// When `mask_update` is `None`, all bytes in the range are marked initialized.
    /// Otherwise only bytes whose corresponding bit is set in `mask_update` are marked
    /// initialized. Lazily allocates `initialized_mask` only when a byte would become
    /// uninitialized (i.e., when a fully-initialized page needs to track partial state).
    pub fn apply_mask_update(
        &mut self,
        page_offset: usize,
        size: usize,
        mask_update: Option<&[u8]>,
    ) {
        let mut mask_offset = page_offset / 8;
        let mut first_bit = page_offset % 8;
        let mut remaining = size;
        while remaining > 0 {
            let s = remaining.min(8 - first_bit);
            remaining -= s;
            let bits = (0xffu32 << first_bit) & ((1u32 << (first_bit + s)) - 1);
            let mut val = bits;
            if let Some(mu) = mask_update {
                val &= mu[mask_offset] as u32;
            }
            if self.initialized_mask.is_none() {
                let test = (val | !bits) as u8;
                if test == 0xffu8 {
                    mask_offset += 1;
                    first_bit = 0;
                    continue;
                }
                self.initialized_mask = Some(Self::make_mask(self.data.len(), true));
            }
            let im = self.initialized_mask.as_mut().unwrap();
            im[mask_offset] = ((im[mask_offset] as u32 & !bits) | val) as u8;
            mask_offset += 1;
            first_bit = 0;
        }
    }

    /// Mark `[page_offset, page_offset + size)` as initialized.
    ///
    /// Has no effect when the page has no mask (already fully initialized). Clears the
    /// mask entirely when the full page is covered.
    pub fn mark_initialized(&mut self, page_offset: usize, size: usize) {
        if self.initialized_mask.is_none() {
            return;
        }
        if page_offset == 0 && size == self.data.len() {
            self.initialized_mask = None;
            return;
        }
        let im = self.initialized_mask.as_mut().unwrap();
        Self::set_mask(im, page_offset, size);
    }

    /// Mark `[page_offset, page_offset + size)` as uninitialized.
    ///
    /// Allocates a fully-initialized mask before clearing the relevant bits when no
    /// mask exists yet.
    pub fn mark_uninitialized(&mut self, page_offset: usize, size: usize) {
        if self.initialized_mask.is_none() {
            self.initialized_mask = Some(Self::make_mask(self.data.len(), true));
        }
        let im = self.initialized_mask.as_mut().unwrap();
        Self::clear_mask(im, page_offset, size);
    }

    /// Count leading initialized bytes in `[page_offset, page_offset + size)`.
    pub fn initialized_byte_count(&self, page_offset: usize, size: usize) -> usize {
        Self::count_initialized(self.initialized_mask.as_deref(), page_offset, size)
    }

    /// Create a mask for `page_size` bytes, all initialized (`0xff`) or all uninitialized (`0x00`).
    pub fn make_mask(page_size: usize, initialized: bool) -> Vec<u8> {
        let len = (page_size + 7) / 8;
        if initialized {
            vec![0xffu8; len]
        } else {
            vec![0u8; len]
        }
    }

    /// Create a mask for `page_size` bytes where `[offset, offset + size)` matches
    /// `initialized`; the remainder is set to `!initialized`.
    pub fn make_mask_region(
        page_size: usize,
        offset: usize,
        size: usize,
        initialized: bool,
    ) -> Vec<u8> {
        let mut mask = Self::make_mask(page_size, true);
        if initialized {
            if offset != 0 {
                Self::clear_mask(&mut mask, 0, offset);
            }
            let end = offset + size;
            if end < page_size {
                Self::clear_mask(&mut mask, end, page_size - end);
            }
        } else if size != 0 {
            Self::clear_mask(&mut mask, offset, size);
        }
        mask
    }

    /// Set (mark initialized) bits in `mask` for `[page_offset, page_offset + size)`.
    pub fn set_mask(mask: &mut [u8], page_offset: usize, size: usize) {
        let mut mask_offset = page_offset / 8;
        let mut first_bit = page_offset % 8;
        let mut remaining = size;
        while remaining > 0 {
            let s = remaining.min(8 - first_bit);
            remaining -= s;
            let bits = (0xffu32 << first_bit) & ((1u32 << (first_bit + s)) - 1);
            mask[mask_offset] |= bits as u8;
            mask_offset += 1;
            first_bit = 0;
        }
    }

    /// Clear (mark uninitialized) bits in `mask` for `[page_offset, page_offset + size)`.
    pub fn clear_mask(mask: &mut [u8], page_offset: usize, size: usize) {
        let mut mask_offset = page_offset / 8;
        let mut first_bit = page_offset % 8;
        let mut remaining = size;
        while remaining > 0 {
            let s = remaining.min(8 - first_bit);
            remaining -= s;
            let bits = (0xffu32 << first_bit) & ((1u32 << (first_bit + s)) - 1);
            mask[mask_offset] &= !(bits as u8);
            mask_offset += 1;
            first_bit = 0;
        }
    }

    /// Count leading initialized bytes in `[page_offset, page_offset + size)`.
    ///
    /// Returns `size` when `mask` is `None` (everything initialized by convention).
    pub fn count_initialized(mask: Option<&[u8]>, page_offset: usize, size: usize) -> usize {
        let mask = match mask {
            None => return size,
            Some(m) => m,
        };
        let mut initialized_count = 0usize;
        let mut mask_offset = page_offset / 8;
        let mut first_bit = page_offset % 8;
        let mut remaining = size;
        while remaining > 0 {
            let s = remaining.min(8 - first_bit);
            remaining -= s;
            let bits = (0xffu32 << first_bit) & ((1u32 << (first_bit + s)) - 1);
            let result = mask[mask_offset] as u32 & bits;
            if result != bits {
                let mut r = result >> first_bit;
                while r & 1 != 0 {
                    initialized_count += 1;
                    r >>= 1;
                }
                return initialized_count;
            }
            initialized_count += s;
            mask_offset += 1;
            first_bit = 0;
        }
        initialized_count
    }
}

#[cfg(test)]
mod tests {
    #[allow(deprecated)]
    use super::MemoryPage;

    #[test]
    fn new_creates_zero_page_no_mask() {
        #[allow(deprecated)]
        let page = MemoryPage::new(8);
        assert_eq!(page.data, vec![0u8; 8]);
        assert!(page.initialized_mask().is_none());
    }

    #[test]
    fn from_bytes_stores_data_no_mask() {
        #[allow(deprecated)]
        let page = MemoryPage::from_bytes(vec![1, 2, 3, 4]);
        assert_eq!(page.data, vec![1u8, 2, 3, 4]);
        assert!(page.initialized_mask().is_none());
    }

    #[test]
    fn set_uninitialized_creates_zero_mask() {
        #[allow(deprecated)]
        let mut page = MemoryPage::new(8);
        page.set_uninitialized();
        assert_eq!(page.initialized_mask(), Some([0u8].as_ref()));
    }

    #[test]
    fn set_initialized_creates_full_mask() {
        #[allow(deprecated)]
        let mut page = MemoryPage::new(8);
        page.set_uninitialized();
        page.set_initialized();
        assert_eq!(page.initialized_mask(), Some([0xffu8].as_ref()));
    }

    #[test]
    fn make_mask_all_initialized() {
        #[allow(deprecated)]
        assert_eq!(MemoryPage::make_mask(8, true), vec![0xffu8]);
    }

    #[test]
    fn make_mask_all_uninitialized() {
        #[allow(deprecated)]
        assert_eq!(MemoryPage::make_mask(8, false), vec![0u8]);
    }

    #[test]
    fn make_mask_non_multiple_of_eight() {
        #[allow(deprecated)]
        let mask = MemoryPage::make_mask(9, true);
        assert_eq!(mask, vec![0xffu8, 0xffu8]);
    }

    #[test]
    fn count_initialized_none_mask_returns_size() {
        #[allow(deprecated)]
        assert_eq!(MemoryPage::count_initialized(None, 0, 8), 8);
        #[allow(deprecated)]
        assert_eq!(MemoryPage::count_initialized(None, 3, 5), 5);
    }

    #[test]
    fn count_initialized_all_bits_set() {
        #[allow(deprecated)]
        assert_eq!(MemoryPage::count_initialized(Some(&[0xff]), 0, 8), 8);
    }

    #[test]
    fn count_initialized_lower_nibble_set() {
        // bits 0-3 set → bytes 0-3 initialized, byte 4 not → returns 4
        #[allow(deprecated)]
        assert_eq!(MemoryPage::count_initialized(Some(&[0x0f]), 0, 8), 4);
    }

    #[test]
    fn count_initialized_upper_nibble_range() {
        // bits 4-7 set; check exactly [4, 4)
        #[allow(deprecated)]
        assert_eq!(MemoryPage::count_initialized(Some(&[0xf0]), 4, 4), 4);
    }

    #[test]
    fn count_initialized_cross_byte_boundary() {
        // first mask byte all set (bytes 0-7), second byte lower nibble (bytes 8-11)
        let mask = [0xffu8, 0x0fu8];
        #[allow(deprecated)]
        assert_eq!(MemoryPage::count_initialized(Some(&mask), 0, 12), 12);
        // byte 12 onwards not initialized; size capped at 12 so returns 12
    }

    #[test]
    fn count_initialized_stops_at_first_gap() {
        // bits 0-1 set, bit 2 clear → returns 2
        #[allow(deprecated)]
        assert_eq!(MemoryPage::count_initialized(Some(&[0b00000011]), 0, 8), 2);
    }

    #[test]
    fn set_mask_sets_middle_bits() {
        let mut mask = vec![0u8];
        #[allow(deprecated)]
        MemoryPage::set_mask(&mut mask, 2, 4);
        // bits 2,3,4,5 → 0b00111100
        assert_eq!(mask[0], 0b00111100);
    }

    #[test]
    fn clear_mask_clears_middle_bits() {
        let mut mask = vec![0xffu8];
        #[allow(deprecated)]
        MemoryPage::clear_mask(&mut mask, 2, 4);
        // bits 2-5 cleared → 0b11000011
        assert_eq!(mask[0], 0b11000011u8);
    }

    #[test]
    fn set_and_clear_mask_cross_byte_boundary() {
        let mut mask = vec![0u8, 0u8];
        // set bytes 6-9 (bits 6,7 in byte 0 and bits 0,1 in byte 1)
        #[allow(deprecated)]
        MemoryPage::set_mask(&mut mask, 6, 4);
        assert_eq!(mask[0], 0b11000000u8);
        assert_eq!(mask[1], 0b00000011u8);

        #[allow(deprecated)]
        MemoryPage::clear_mask(&mut mask, 6, 4);
        assert_eq!(mask[0], 0u8);
        assert_eq!(mask[1], 0u8);
    }

    #[test]
    fn mark_initialized_on_partial_mask() {
        #[allow(deprecated)]
        let mut page = MemoryPage::new(8);
        page.set_uninitialized(); // mask = [0x00]
        page.mark_initialized(0, 4);
        assert_eq!(page.initialized_mask(), Some([0x0fu8].as_ref()));
    }

    #[test]
    fn mark_initialized_full_page_clears_mask() {
        #[allow(deprecated)]
        let mut page = MemoryPage::new(8);
        page.set_uninitialized();
        page.mark_initialized(0, 8);
        assert_eq!(page.initialized_mask(), None);
    }

    #[test]
    fn mark_initialized_no_op_when_no_mask() {
        #[allow(deprecated)]
        let mut page = MemoryPage::new(8);
        page.mark_initialized(0, 4);
        assert!(page.initialized_mask().is_none());
    }

    #[test]
    fn mark_uninitialized_allocates_mask() {
        #[allow(deprecated)]
        let mut page = MemoryPage::new(8);
        page.mark_uninitialized(2, 4);
        // bits 2-5 cleared from 0xff
        assert_eq!(page.initialized_mask(), Some([0b11000011u8].as_ref()));
    }

    #[test]
    fn apply_mask_update_no_allocation_when_all_initialized() {
        #[allow(deprecated)]
        let mut page = MemoryPage::new(8);
        // mask_update all 0xff → every byte in range is initialized → no mask needed
        page.apply_mask_update(0, 8, Some(&[0xff]));
        assert!(page.initialized_mask().is_none());
    }

    #[test]
    fn apply_mask_update_allocates_mask_on_partial() {
        #[allow(deprecated)]
        let mut page = MemoryPage::new(8);
        // mask_update lower nibble only → bytes 4-7 become uninitialized
        page.apply_mask_update(0, 8, Some(&[0x0f]));
        assert_eq!(page.initialized_mask(), Some([0x0fu8].as_ref()));
    }

    #[test]
    fn apply_mask_update_none_update_no_allocation() {
        #[allow(deprecated)]
        let mut page = MemoryPage::new(8);
        // None mask_update treats all bytes as initialized → no mask allocated
        page.apply_mask_update(0, 8, None);
        assert!(page.initialized_mask().is_none());
    }

    #[test]
    fn initialized_byte_count_no_mask() {
        #[allow(deprecated)]
        let page = MemoryPage::new(8);
        assert_eq!(page.initialized_byte_count(0, 8), 8);
    }

    #[test]
    fn initialized_byte_count_partial() {
        #[allow(deprecated)]
        let mut page = MemoryPage::new(8);
        page.mark_uninitialized(4, 4); // bytes 4-7 uninitialized
        assert_eq!(page.initialized_byte_count(0, 8), 4);
    }

    #[test]
    fn make_mask_region_initialized_subrange() {
        // page of 8 bytes; only [2, 6) initialized
        #[allow(deprecated)]
        let mask = MemoryPage::make_mask_region(8, 2, 4, true);
        assert_eq!(mask, vec![0b00111100u8]);
    }

    #[test]
    fn make_mask_region_uninitialized_subrange() {
        // page of 8 bytes; [2, 6) uninitialized, rest initialized
        #[allow(deprecated)]
        let mask = MemoryPage::make_mask_region(8, 2, 4, false);
        assert_eq!(mask, vec![0b11000011u8]);
    }

    #[test]
    fn make_mask_region_zero_size_uninitialized_leaves_all_initialized() {
        #[allow(deprecated)]
        let mask = MemoryPage::make_mask_region(8, 0, 0, false);
        assert_eq!(mask, vec![0xffu8]);
    }
}
