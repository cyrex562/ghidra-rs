/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// package db.buffers;

/**
 * <code>ChangeMap</code> facilitates the decoding of change-data 
 * to determine if a specific buffer was modified by the 
 * corresponding buffer file version.
 * @see ChangeMapFile
 */

pub struct ChangeMap {
    pub map_data: Vec<u8>,
    pub max_index: isize,
}

impl ChangeMap {
    pub fn new(map_data: &Vec<u8>) -> ChangeMap {
        ChangeMap {
            map_data: map_data.clone(),
            max_index: (map_data.len() * 8 - 1) as isize,
        }
    }


	/**
	 * Add the specified map data to this map within the size constraints
	 * of this map.
	 * @param otherMapData
	 */
    pub fn add_change_map_data(&mut self, other_map_data: &Vec<u8>) {
        let mut limit = self.map_data.len();
        if other_map_data.len() < limit {
            limit = other_map_data.len();
        }
        for i in 0..limit {
            self.map_data[i] |= other_map_data[i]
        }
    }

	/**
	 * Flag all indexes as changed within this change map.  Index values outside
	 * the size constraints of this map will be ignored.
	 * @param indexes list of indexes to mark as changed
	 */
	pub fn set_changed_indexes(&mut self, indexes: &Vec<isize>) {
        for index in indexes {
            if *index > self.max_index {
                continue;
            }
            let offset = index / 8;
            let bit_mask = 1 << (index % 8);
            self.map_data[offset] |= bit_mask;
        }
	}

	/**
	 * Flag all indexes as unchanged within this change map.  Index values outside
	 * the size constraints of this map will be ignored.
	 * @param indexes list of indexes to mark as unchanged
	 */
	pub fn set_unchanged_indexes(&mut self, indexes: &Vec<isize>) {
        for index in indexes {
			if index > maxIndex {
				continue;
			}
			let mut byte_offset: isize = index / 8;
			let mut bit_mask: isize = !(1 << (index % 8));
			self.map_data[byte_offset] &= bit_mask;
		}
	}

	/**
	 * Returns true if the change map data indicates that the 
	 * specified buffer has been modified.
	 * @param index buffer index
	 */
	pub fn has_changed(&mut self, index: isize) -> bool {
		if self.map_data.is_empty() || index > self.max_index {
			return true; // must be a new buffer index
		}
		let mut byte_offset = index / 8;
		let mut bit_mask = 1 << (index % 8);
		return (self.map_data[byte_offset] & bit_mask) != 0;
	}

	/**
	 * Returns true if the specified index is within the bounds of this map.
	 */
	pub fn contains_index(&self, index: isize) -> bool {
		return index <= self.max_index;
	}
}
