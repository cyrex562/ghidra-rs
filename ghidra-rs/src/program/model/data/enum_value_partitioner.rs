use super::bit_group::BitGroup;

/// A static utility for partitioning long values into non-intersecting BitGroups.
pub struct EnumValuePartitioner;

impl EnumValuePartitioner {
    /// Partitions the given values into a list of non-intersecting BitGroups.
    ///
    /// # Arguments
    /// * `values` - the values to be partitioned
    /// * `size` - size of enum value in bytes
    ///
    /// # Returns
    /// A vector of BitGroups with non-intersecting bits.
    pub fn partition(values: &[i64], size: i32) -> Vec<BitGroup> {
        let mut list = Vec::new();
        let mut used_bits: i64 = 0;

        for &value in values {
            used_bits |= value;
            let bit_group = BitGroup::new(value);
            Self::merge(&mut list, bit_group);
        }

        let bits = (size * 8) as i64;
        let all_enum_bits = !(-1i64 << bits);
        let unused_bits = !used_bits;
        list.push(BitGroup::new(unused_bits & all_enum_bits));

        list
    }

    fn merge(list: &mut Vec<BitGroup>, mut bit_group: BitGroup) {
        let mut to_remove = Vec::new();
        for (i, existing) in list.iter().enumerate() {
            if bit_group.intersects(existing) {
                bit_group.merge(existing);
                to_remove.push(i);
            }
        }
        for i in to_remove.into_iter().rev() {
            list.remove(i);
        }
        list.push(bit_group);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disjoint_values() {
        let list = EnumValuePartitioner::partition(&[1, 2, 4, 8], 1);
        assert_eq!(list.len(), 5);
    }

    #[test]
    fn test_all_overlapping_values() {
        let list = EnumValuePartitioner::partition(&[1, 2, 4, 8, 15], 1);
        assert_eq!(list.len(), 2);
        let group = &list[0];
        assert_eq!(group.get_mask(), 15);
        let values = group.get_values();
        assert_eq!(values.len(), 5);
        assert!(values.contains(&1));
        assert!(values.contains(&2));
        assert!(values.contains(&4));
        assert!(values.contains(&8));
        assert!(values.contains(&15));
    }

    #[test]
    fn test_some_overlapping_values() {
        let list = EnumValuePartitioner::partition(&[1, 2, 4, 8, 6], 1);
        assert_eq!(list.len(), 4);
        assert_eq!(list[0].get_mask(), 1);
        assert_eq!(list[1].get_mask(), 8);
        assert_eq!(list[2].get_mask(), 6);
    }
}
