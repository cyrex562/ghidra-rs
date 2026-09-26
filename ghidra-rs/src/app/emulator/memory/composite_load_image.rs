use crate::app::emulator::memory::MemoryLoadImage;
use crate::pcode::load_image::LoadImage;
use crate::pcode::memstate::memory_page::MemoryPage;
use crate::program::model::address::{Address, AddressSetView};

/// Composite load image that delegates to multiple providers based on address ranges.
///
/// This allows multiple memory load image providers to be combined, with each provider
/// handling memory operations for specific address ranges. Providers without address
/// restrictions handle all addresses.
///
/// # Warning
///
/// This implementation assumes that the memory page (specified by addr and size)
/// will only correspond to a single program image.
///
/// Corresponds to `ghidra.app.emulator.memory.CompositeLoadImage`.
#[deprecated(since = "12.1", note = "for removal")]
pub struct CompositeLoadImage {
    providers: Vec<Box<dyn MemoryLoadImage>>,
    addr_sets: Vec<Option<Box<dyn AddressSetView>>>,
}

#[allow(deprecated)]
impl CompositeLoadImage {
    /// Create a new empty CompositeLoadImage.
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
            addr_sets: Vec::new(),
        }
    }

    /// Add a provider with an optional address set view.
    ///
    /// Providers without address restrictions (view is None) are added to the end
    /// and are checked last. Providers with address restrictions are added to the
    /// beginning and are checked first.
    pub fn add_provider(&mut self, provider: Box<dyn MemoryLoadImage>, view: Option<Box<dyn AddressSetView>>) {
        if view.is_none() {
            self.providers.push(provider);
            self.addr_sets.push(None);
        } else {
            self.providers.insert(0, provider);
            self.addr_sets.insert(0, view);
        }
    }
}

#[allow(deprecated)]
impl Default for CompositeLoadImage {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(deprecated)]
impl LoadImage for CompositeLoadImage {
    fn load_fill(
        &self,
        buf: &mut [u8],
        size: i32,
        addr: &Address,
        buf_offset: i32,
        generate_initialized_mask: bool,
    ) -> Option<Vec<u8>> {
        let end_addr = addr.add((size - 1) as i64).expect("address overflow in composite load image");
        for (i, provider) in self.providers.iter().enumerate() {
            if let Some(view) = &self.addr_sets[i] {
                if view.intersects_range(addr, &end_addr) {
                    return provider.load_fill(buf, size, addr, buf_offset, generate_initialized_mask);
                }
            } else {
                return provider.load_fill(buf, size, addr, buf_offset, generate_initialized_mask);
            }
        }
        if generate_initialized_mask {
            Some(MemoryPage::make_mask(size as usize, false))
        } else {
            None
        }
    }
}

#[allow(deprecated)]
impl MemoryLoadImage for CompositeLoadImage {
    fn write_back(&mut self, bytes: &[u8], size: i32, addr: &Address, offset: i32) {
        let end_addr = addr.add((size - 1) as i64).expect("address overflow in composite load image");
        for (i, provider) in self.providers.iter_mut().enumerate() {
            if let Some(view) = &self.addr_sets[i] {
                if view.intersects_range(addr, &end_addr) {
                    provider.write_back(bytes, size, addr, offset);
                }
            }
        }
    }

    fn dispose(&mut self) {
        for provider in &mut self.providers {
            provider.dispose();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::load_image::LoadImage;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, AddressSet};

    struct TestMemoryLoadImage {
        data: Vec<u8>,
        written_data: Vec<u8>,
    }

    impl TestMemoryLoadImage {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                written_data: Vec::new(),
            }
        }

        fn written_data(&self) -> &[u8] {
            &self.written_data
        }
    }

    impl LoadImage for TestMemoryLoadImage {
        fn load_fill(
            &self,
            buf: &mut [u8],
            size: i32,
            _addr: &Address,
            buf_offset: i32,
            _generate_initialized_mask: bool,
        ) -> Option<Vec<u8>> {
            let offset = buf_offset as usize;
            let len = (size as usize).min(buf.len() - offset).min(self.data.len());
            if len > 0 {
                buf[offset..offset + len].copy_from_slice(&self.data[..len]);
            }
            None
        }
    }

    impl MemoryLoadImage for TestMemoryLoadImage {
        fn write_back(&mut self, bytes: &[u8], size: i32, _addr: &Address, offset: i32) {
            let start = offset as usize;
            let len = (size as usize).min(bytes.len() - start);
            if len > 0 {
                self.written_data.extend_from_slice(&bytes[start..start + len]);
            }
        }

        fn dispose(&mut self) {
            self.data.clear();
            self.written_data.clear();
        }
    }

    fn create_address(offset: u64) -> Address {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, offset as i64)
    }

    fn create_address_set(start: u64, end: u64) -> AddressSet {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let start_addr = Address::new(ram.clone(), start as i64);
        let end_addr = Address::new(ram, end as i64);
        let mut set = AddressSet::new();
        set.add_range(&start_addr, &end_addr);
        set
    }

    #[test]
    fn test_composite_load_image_no_providers() {
        let composite = CompositeLoadImage::new();
        let addr = create_address(0x1000);
        let mut buf = [0u8; 4];

        let result = composite.load_fill(&mut buf, 4, &addr, 0, false);
        assert_eq!(result, None);
    }

    #[test]
    fn test_composite_load_image_no_providers_generate_mask() {
        let composite = CompositeLoadImage::new();
        let addr = create_address(0x1000);
        let mut buf = [0u8; 4];

        let result = composite.load_fill(&mut buf, 4, &addr, 0, true);
        assert!(result.is_some());
        let mask = result.unwrap();
        assert_eq!(mask.len(), 1);
        assert_eq!(mask[0], 0);
    }

    #[test]
    fn test_composite_load_image_single_provider_unrestricted() {
        let mut composite = CompositeLoadImage::new();
        let provider = Box::new(TestMemoryLoadImage::new(vec![0xAA, 0xBB, 0xCC, 0xDD]));
        composite.add_provider(provider, None);

        let addr = create_address(0x1000);
        let mut buf = [0u8; 4];
        composite.load_fill(&mut buf, 4, &addr, 0, false);

        assert_eq!(buf, [0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_composite_load_image_provider_with_matching_address_set() {
        let mut composite = CompositeLoadImage::new();
        let provider = Box::new(TestMemoryLoadImage::new(vec![0x11, 0x22, 0x33, 0x44]));
        let addr_set = Box::new(create_address_set(0x1000, 0x1fff));
        composite.add_provider(provider, Some(addr_set));

        let addr = create_address(0x1500);
        let mut buf = [0u8; 4];
        composite.load_fill(&mut buf, 4, &addr, 0, false);

        assert_eq!(buf, [0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn test_composite_load_image_provider_with_non_matching_address_set() {
        let mut composite = CompositeLoadImage::new();
        let provider = Box::new(TestMemoryLoadImage::new(vec![0x11, 0x22, 0x33, 0x44]));
        let addr_set = Box::new(create_address_set(0x2000, 0x2fff));
        composite.add_provider(provider, Some(addr_set));

        let addr = create_address(0x1000);
        let mut buf = [0u8; 4];
        let result = composite.load_fill(&mut buf, 4, &addr, 0, false);

        assert_eq!(result, None);
    }

    #[test]
    fn test_composite_load_image_multiple_providers_priority() {
        let mut composite = CompositeLoadImage::new();

        let provider1 = Box::new(TestMemoryLoadImage::new(vec![0x11, 0x22, 0x33, 0x44]));
        let addr_set1 = Box::new(create_address_set(0x1000, 0x1fff));
        composite.add_provider(provider1, Some(addr_set1));

        let provider2 = Box::new(TestMemoryLoadImage::new(vec![0x55, 0x66, 0x77, 0x88]));
        composite.add_provider(provider2, None);

        let addr = create_address(0x1500);
        let mut buf = [0u8; 4];
        composite.load_fill(&mut buf, 4, &addr, 0, false);

        assert_eq!(buf, [0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn test_composite_load_image_fallback_to_unrestricted_provider() {
        let mut composite = CompositeLoadImage::new();

        let provider1 = Box::new(TestMemoryLoadImage::new(vec![0x11, 0x22, 0x33, 0x44]));
        let addr_set1 = Box::new(create_address_set(0x2000, 0x2fff));
        composite.add_provider(provider1, Some(addr_set1));

        let provider2 = Box::new(TestMemoryLoadImage::new(vec![0x55, 0x66, 0x77, 0x88]));
        composite.add_provider(provider2, None);

        let addr = create_address(0x1500);
        let mut buf = [0u8; 4];
        composite.load_fill(&mut buf, 4, &addr, 0, false);

        assert_eq!(buf, [0x55, 0x66, 0x77, 0x88]);
    }

    #[test]
    fn test_composite_load_image_write_back_matching_provider() {
        let mut composite = CompositeLoadImage::new();

        let provider = Box::new(TestMemoryLoadImage::new(vec![0x00; 4]));
        let addr_set = Box::new(create_address_set(0x1000, 0x1fff));
        composite.add_provider(provider, Some(addr_set));

        let addr = create_address(0x1500);
        let data = [0xAA, 0xBB, 0xCC, 0xDD];
        composite.write_back(&data, 4, &addr, 0);
    }

    #[test]
    fn test_composite_load_image_dispose() {
        let mut composite = CompositeLoadImage::new();

        let provider = Box::new(TestMemoryLoadImage::new(vec![0x11, 0x22, 0x33, 0x44]));
        composite.add_provider(provider, None);

        composite.dispose();
    }
}
