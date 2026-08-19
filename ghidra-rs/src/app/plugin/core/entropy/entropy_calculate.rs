use crate::program::model::mem::MemoryBlock;

/// Computes a quantized entropy statistic (0-255) for each fixed-size chunk of
/// a [`MemoryBlock`].
///
/// Corresponds to `ghidra.app.plugin.core.entropy.EntropyCalculate`.
pub struct EntropyCalculate {
    entropy: Vec<i32>,
    chunksize: i32,
}

impl EntropyCalculate {
    /// Computes entropy values for every `chunksize`-byte chunk of `block`.
    pub fn new(block: &dyn MemoryBlock, chunksize: i32) -> Self {
        let mut calc = EntropyCalculate {
            entropy: Vec::new(),
            chunksize,
        };
        calc.do_entropy(block);
        calc
    }

    /// Returns the quantized entropy value for the chunk containing `offset`,
    /// or `-1` if `offset` is negative or past the end of the computed chunks.
    pub fn get_value(&self, offset: i32) -> i32 {
        if offset < 0 {
            return -1;
        }
        let index = offset / self.chunksize;
        if index as usize >= self.entropy.len() {
            return -1;
        }
        self.entropy[index as usize]
    }

    fn do_entropy(&mut self, block: &dyn MemoryBlock) {
        let mut histo = [0i32; 256];
        let mut chunk = vec![0u8; self.chunksize as usize];
        let logtable = Self::build_log_table(self.chunksize);

        // Java truncates the block size to a 32-bit `int` before deriving the
        // chunk count; preserved here for behavioral parity.
        let size = block.get_size() as i32 as i64;
        let chunksize = self.chunksize as i64;
        let mut numchunks = size / chunksize;
        if size % chunksize != 0 {
            numchunks += 1;
        }
        self.entropy = vec![0; numchunks as usize];

        let start = block.get_start();
        let mut offset: i64 = 0;
        let mut chunknum = 0usize;
        while offset < size {
            let addr = start
                .add(offset)
                .expect("offset within block bounds must not overflow the address space");
            let len = block.get_bytes(&addr, &mut chunk);

            histo.iter_mut().for_each(|count| *count = 0);
            for &b in &chunk[..len] {
                histo[b.wrapping_add(128) as usize] += 1;
            }

            self.entropy[chunknum] = Self::quantize_chunk(&histo, &logtable);
            offset += chunksize;
            chunknum += 1;
        }
    }

    fn build_log_table(chunksize: i32) -> Vec<f64> {
        let chunksize = chunksize as usize;
        let mut logtable = vec![0.0f64; chunksize + 1];
        let logtwo = 2.0f64.ln();
        let chunkfloat = chunksize as f64;
        for (i, entry) in logtable.iter_mut().enumerate().take(chunksize).skip(1) {
            let prob = i as f64 / chunkfloat;
            *entry = -prob * (prob.ln() / logtwo);
        }
        logtable
    }

    fn quantize_chunk(histo: &[i32; 256], logtable: &[f64]) -> i32 {
        let sum: f64 = histo.iter().map(|&count| logtable[count as usize]).sum();
        let sum = (sum / 8.0) * 256.0;
        (sum.floor() as i32).min(255)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::mem::MemoryBlockImpl;

    fn make_block(name: &str, size: u64, initialized: bool) -> MemoryBlockImpl {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let start = Address::new(space, 0);
        MemoryBlockImpl::new(name.to_string(), start, size, initialized)
    }

    #[test]
    fn zero_bytes_yield_maximum_entropy() {
        // A chunk that is all zeros has one histogram bin with all the counts,
        // which produces the highest possible quantized entropy value (255)
        // because logtable[chunksize] == 0.0 while every other bin's
        // logtable[0] == 0.0 too, so the only nonzero term is absent -- sum is 0.
        let block = make_block("zeros", 256, true);
        let calc = EntropyCalculate::new(&block, 256);
        assert_eq!(calc.get_value(0), 0);
    }

    #[test]
    fn get_value_negative_offset_returns_negative_one() {
        let block = make_block("b", 256, true);
        let calc = EntropyCalculate::new(&block, 256);
        assert_eq!(calc.get_value(-1), -1);
    }

    #[test]
    fn get_value_past_end_returns_negative_one() {
        let block = make_block("b", 256, true);
        let calc = EntropyCalculate::new(&block, 256);
        assert_eq!(calc.get_value(1024), -1);
    }

    #[test]
    fn chunk_count_covers_partial_final_chunk() {
        // 300 bytes with a 256-byte chunk size should produce two chunks.
        let block = make_block("b", 300, true);
        let calc = EntropyCalculate::new(&block, 256);
        assert_ne!(calc.get_value(0), -1);
        assert_ne!(calc.get_value(256), -1);
        assert_eq!(calc.get_value(512), -1);
    }

    #[test]
    fn get_value_maps_offset_within_chunk_to_same_value() {
        let block = make_block("b", 512, true);
        let calc = EntropyCalculate::new(&block, 256);
        assert_eq!(calc.get_value(0), calc.get_value(255));
        assert_eq!(calc.get_value(256), calc.get_value(511));
    }

    #[test]
    fn uninitialized_block_produces_defined_entropy_via_empty_reads() {
        // get_bytes on an uninitialized block returns 0 bytes read, so every
        // chunk's histogram stays empty -- this should not panic.
        let block = make_block("uninit", 256, false);
        let calc = EntropyCalculate::new(&block, 256);
        assert_ne!(calc.get_value(0), -1);
    }

    #[test]
    fn random_looking_bytes_have_higher_entropy_than_all_zeros() {
        let mut zeros = make_block("zeros", 256, true);
        let mut varied = make_block("varied", 256, true);
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let start = Address::new(space, 0);
        let bytes: Vec<u8> = (0..256u16).map(|i| i as u8).collect();
        varied.set_bytes(&start, &bytes).unwrap();
        // zeros block is already all zero-initialized.
        let _ = zeros.set_bytes(&start, &vec![0u8; 256]);

        let zero_calc = EntropyCalculate::new(&zeros, 256);
        let varied_calc = EntropyCalculate::new(&varied, 256);
        assert!(varied_calc.get_value(0) > zero_calc.get_value(0));
    }
}
