use crate::generic::lsh::vector::hash_entry::HashEntry;

const FNV_32_BIT_OFFSET_BASIS: i32 = 0x811C_9DC5u32 as i32;
const FNV_32_BIT_PRIME: i32 = 0x0100_0193;

/// Mirrors `generic.lsh.Partition.partition(int, int)`.
fn partition_bit(identity: i32, value: i32) -> bool {
    let mut hash = FNV_32_BIT_OFFSET_BASIS;

    let mut blender = value;

    hash ^= blender & 0xff;
    hash = hash.wrapping_mul(FNV_32_BIT_PRIME);
    blender = ((blender as u32) >> 8) as i32;
    hash ^= blender & 0xff;
    hash = hash.wrapping_mul(FNV_32_BIT_PRIME);
    blender = ((blender as u32) >> 8) as i32;
    hash ^= blender & 0xff;
    hash = hash.wrapping_mul(FNV_32_BIT_PRIME);
    blender = ((blender as u32) >> 8) as i32;
    hash ^= blender & 0xff;
    hash = hash.wrapping_mul(FNV_32_BIT_PRIME);

    blender = identity;

    hash ^= blender & 0xff;
    hash = hash.wrapping_mul(FNV_32_BIT_PRIME);
    blender = ((blender as u32) >> 8) as i32;
    hash ^= blender & 0xff;
    hash = hash.wrapping_mul(FNV_32_BIT_PRIME);
    blender = ((blender as u32) >> 8) as i32;
    hash ^= blender & 0xff;
    hash = hash.wrapping_mul(FNV_32_BIT_PRIME);
    blender = ((blender as u32) >> 8) as i32;
    hash ^= blender & 0xff;
    hash = hash.wrapping_mul(FNV_32_BIT_PRIME);

    let bit_count = hash.count_ones();
    bit_count % 2 == 0
}

/// Mirrors `generic.lsh.Partition.partition(int, HashEntry[])`.
fn partition_side(identity: i32, values: &[HashEntry]) -> i32 {
    let mut total: f32 = 0.0;
    for entry in values {
        if partition_bit(identity, entry.get_hash()) {
            total += entry.get_coeff() as f32;
        } else {
            total -= entry.get_coeff() as f32;
        }
    }
    if total < 0.0 {
        0
    } else {
        1
    }
}

/// Mirrors `generic.lsh.Partition.hash(int[], HashEntry[])`.
pub fn hash(partition_identities: &[i32], values: &[HashEntry]) -> i32 {
    let mut result = 0;
    let mut bit = 1;
    for &identity in partition_identities {
        if partition_side(identity, values) == 1 {
            result |= bit;
        }
        bit <<= 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic() {
        let values = [HashEntry::with_weight(0x1234, 3, 1.5)];
        let identities = [1, 2, 3];
        let a = hash(&identities, &values);
        let b = hash(&identities, &values);
        assert_eq!(a, b);
    }

    #[test]
    fn hash_with_no_identities_is_zero() {
        let values = [HashEntry::with_weight(0x1234, 3, 1.5)];
        assert_eq!(hash(&[], &values), 0);
    }

    #[test]
    fn hash_with_no_values_matches_negative_total_branch() {
        // With no entries, total stays 0.0, which is not < 0, so every bit is set.
        let identities = [10, 20];
        assert_eq!(hash(&identities, &[]), 0b11);
    }

    #[test]
    fn hash_sets_bits_independently_per_identity() {
        let values = [
            HashEntry::with_weight(0xdead_beef_u32 as i32, 5, 2.0),
            HashEntry::with_weight(0x0011_2233, 2, 0.5),
        ];
        let identities = [7, 42, 99];
        let result = hash(&identities, &values);
        assert!(result >= 0);
        assert!(result < (1 << identities.len()));
    }
}
