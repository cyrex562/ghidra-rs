#[derive(Clone, Debug, Default)]
pub struct IndexProvider {
    pub next_index: isize,
    pub free_indexes: Vec<isize>,
}

impl IndexProvider {
    fn new() -> IndexProvider {
        IndexProvider {
            next_index: 0,
            free_indexes: Vec::new(),
        }
    }

    fn new2(index_count: isize, free_indexes: &Vec<isize>) -> IndexProvider {
        let mut ip = IndexProvider::new();
        ip.next_index = index_count;
        ip.free_indexes = free_indexes.clone();
        ip
    }

    fn get_index_count(&self) -> isize {
        self.next_index
    }

    fn get_free_index_count(&self) -> isize {
        self.free_indexes.len() as isize
    }

    fn allocate_index(&mut self) -> isize {
        if self.free_indexes.is_empty() {
            self.next_index += 1;
            return self.next_index;
        }
        self.free_indexes.pop().unwrap_or(-1)
    }

    fn allocate_index2(&mut self, index: isize) -> bool {
        if index > self.next_index {
            for i in self.next_index .. index {
                self.free_indexes.push(i);
            }
            self.next_index = index + 1;
            return true;
        }
        return self.free_indexes.remove(index as usize)
    }
}
