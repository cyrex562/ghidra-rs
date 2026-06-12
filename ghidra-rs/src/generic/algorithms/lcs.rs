use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

pub trait LcsTrait<T> {
    fn length_of_x(&self) -> usize;
    fn length_of_y(&self) -> usize;
    fn value_of_x(&self, index: usize) -> T
    where
        T: Clone;
    fn value_of_y(&self, index: usize) -> T
    where
        T: Clone;
    fn matches(&self, x: &T, y: &T) -> bool;

    fn get_size_limit(&self) -> usize {
        1_000_000
    }

    fn get_lcs(&self, monitor: &dyn TaskMonitor) -> Result<Vec<T>, CancelledException>
    where
        T: Clone,
    {
        let nx = self.length_of_x();
        let ny = self.length_of_y();

        if nx == 0 || ny == 0 {
            return Ok(Vec::new());
        }

        if nx * ny > self.get_size_limit() {
            return Ok(Vec::new());
        }

        let mut c = vec![vec![0; ny + 1]; nx + 1];

        for i in 1..=nx {
            monitor.check_cancelled()?;
            for j in 1..=ny {
                let x = self.value_of_x(i - 1);
                let y = self.value_of_y(j - 1);
                if self.matches(&x, &y) {
                    c[i][j] = c[i - 1][j - 1] + 1;
                } else {
                    c[i][j] = std::cmp::max(c[i - 1][j], c[i][j - 1]);
                }
            }
        }

        let mut lcs = Vec::new();
        let mut i = nx;
        let mut j = ny;
        while i > 0 && j > 0 {
            let x = self.value_of_x(i - 1);
            let y = self.value_of_y(j - 1);
            if self.matches(&x, &y) {
                lcs.push(x);
                i -= 1;
                j -= 1;
            } else if c[i - 1][j] >= c[i][j - 1] {
                i -= 1;
            } else {
                j -= 1;
            }
        }
        lcs.reverse();
        Ok(lcs)
    }
}

pub struct GenericLcs<'a, T> {
    x: &'a [T],
    y: &'a [T],
}

impl<'a, T> GenericLcs<'a, T> {
    pub fn new(x: &'a [T], y: &'a [T]) -> Self {
        Self { x, y }
    }
}

impl<'a, T> LcsTrait<T> for GenericLcs<'a, T>
where
    T: PartialEq,
{
    fn length_of_x(&self) -> usize {
        self.x.len()
    }
    fn length_of_y(&self) -> usize {
        self.y.len()
    }
    fn value_of_x(&self, index: usize) -> T
    where
        T: Clone,
    {
        self.x[index].clone()
    }
    fn value_of_y(&self, index: usize) -> T
    where
        T: Clone,
    {
        self.y[index].clone()
    }
    fn matches(&self, x: &T, y: &T) -> bool {
        x == y
    }
}

pub fn get_reducing_lcs<T>(
    x: &[T],
    y: &[T],
    monitor: &dyn TaskMonitor,
) -> Result<Vec<T>, CancelledException>
where
    T: PartialEq + Clone,
{
    if x.is_empty() || y.is_empty() {
        return Ok(Vec::new());
    }

    // Find common prefix
    let mut prefix_len = 0;
    while prefix_len < x.len() && prefix_len < y.len() && x[prefix_len] == y[prefix_len] {
        prefix_len += 1;
    }

    // Find common suffix
    let mut suffix_len = 0;
    while suffix_len < (x.len() - prefix_len)
        && suffix_len < (y.len() - prefix_len)
        && x[x.len() - 1 - suffix_len] == y[y.len() - 1 - suffix_len]
    {
        suffix_len += 1;
    }

    let mut lcs = Vec::with_capacity(prefix_len + suffix_len);
    for i in 0..prefix_len {
        lcs.push(x[i].clone());
    }

    let mid_x = &x[prefix_len..x.len() - suffix_len];
    let mid_y = &y[prefix_len..y.len() - suffix_len];

    if !mid_x.is_empty() && !mid_y.is_empty() {
        let solver = GenericLcs::new(mid_x, mid_y);
        let mid_lcs = solver.get_lcs(monitor)?;
        lcs.extend(mid_lcs);
    }

    for i in 0..suffix_len {
        lcs.push(x[x.len() - suffix_len + i].clone());
    }

    Ok(lcs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;

    #[test]
    fn test_lcs() {
        let x = vec!['a', 'b', 'c', 'd', 'e'];
        let y = vec!['a', 'c', 'e'];
        let monitor = DummyMonitor;
        let lcs = get_reducing_lcs(&x, &y, &monitor).unwrap();
        assert_eq!(lcs, vec!['a', 'c', 'e']);
    }

    #[test]
    fn test_reducing_lcs() {
        let x = vec!['H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'];
        let y = vec!['H', 'e', 'l', 'l', 'o', ' ', 'R', 'u', 's', 't'];
        let monitor = DummyMonitor;
        let lcs = get_reducing_lcs(&x, &y, &monitor).unwrap();
        // LCS should be "Hello " + LCS("World", "Rust")
        // LCS("World", "Rust") is "r" (if lowercase) or nothing.
        // Let's check "Hello "
        assert!(lcs.starts_with(&['H', 'e', 'l', 'l', 'o', ' ']));
    }
}
