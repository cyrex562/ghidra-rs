use std::marker::PhantomData;

use super::lcs::LcsTrait;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// The sequence operations a client supplies for a `ReducingLcs<I, T>`, mirroring the
/// abstract `reduce`/`lengthOf`/`valueOf` methods of the Java `ReducingLcs` class.
pub trait ReducingLcsOps<I, T> {
    /// Creates a subsequence of `i` from `start` (inclusive) to `end` (exclusive), 0-based.
    fn reduce(&self, i: &I, start: usize, end: usize) -> I;
    /// Returns the length of the given sequence.
    fn length_of(&self, i: &I) -> usize;
    /// Returns the value at the given 0-based offset.
    fn value_of(&self, i: &I, offset: usize) -> T;
    /// Returns true if the two elements match.
    fn matches(&self, x: &T, y: &T) -> bool;
}

fn get_end<I, T, O: ReducingLcsOps<I, T>>(ops: &O, i: &I, startn: usize, endn: usize) -> usize {
    let mut end = ops.length_of(i).saturating_sub(endn);
    if end <= startn {
        // boundary condition when the change is only a delete or insert
        end = startn;
    }
    end
}

fn match_count_from_start<I, T, O: ReducingLcsOps<I, T>>(
    ops: &O,
    x_source: &I,
    y_source: &I,
) -> usize {
    let xl = ops.length_of(x_source);
    let yl = ops.length_of(y_source);
    let mut n = 0;
    while n < xl && n < yl {
        let xt = ops.value_of(x_source, n);
        let yt = ops.value_of(y_source, n);
        if !ops.matches(&xt, &yt) {
            return n;
        }
        n += 1;
    }
    0
}

fn match_count_from_end<I, T, O: ReducingLcsOps<I, T>>(
    ops: &O,
    x_source: &I,
    y_source: &I,
) -> usize {
    let xl = ops.length_of(x_source);
    let yl = ops.length_of(y_source);
    let mut n: usize = 0;
    for k in 0..std::cmp::min(xl, yl) {
        let xt = ops.value_of(x_source, xl - 1 - k);
        let yt = ops.value_of(y_source, yl - 1 - k);
        if !ops.matches(&xt, &yt) {
            return n.saturating_sub(1);
        }
        n += 1;
    }
    0
}

/// Calculates the longest common subsequence (LCS) between two sequences of type `I` whose
/// elements are of type `T`.
///
/// This is an optimizing wrapper around [`LcsTrait`] that pre-calculates any shared prefix
/// and suffix of the two given sequences before delegating to the O(n^2) LCS matrix. Doing
/// this reduces the size of the matrix, greatly so in the case that the two inputs are mostly
/// the same at the beginning and end (e.g. an edit of a source file, where the typical
/// change is somewhere in the middle). The shared prefix/suffix are not counted against
/// [`LcsTrait::get_size_limit`], letting callers work around that limit when the inputs have
/// similar beginnings and endings.
pub struct ReducingLcs<I, T, O> {
    ops: O,
    x_source: I,
    x: I,
    y: I,
    startn: usize,
    endn: usize,
    size_limit: usize,
    _marker: PhantomData<T>,
}

impl<I, T, O: ReducingLcsOps<I, T>> ReducingLcs<I, T, O> {
    pub fn new(ops: O, ix: I, iy: I) -> Self {
        let startn = match_count_from_start(&ops, &ix, &iy);
        let endn = match_count_from_end(&ops, &ix, &iy);
        let endx = get_end(&ops, &ix, startn, endn);
        let endy = get_end(&ops, &iy, startn, endn);
        let x = ops.reduce(&ix, startn, endx);
        let y = ops.reduce(&iy, startn, endy);
        Self {
            ops,
            x_source: ix,
            x,
            y,
            startn,
            endn,
            size_limit: 1_000_000,
            _marker: PhantomData,
        }
    }

    /// Changes the size limit of this LCS, past which no calculations will be performed.
    pub fn set_size_limit(&mut self, new_limit: usize) {
        self.size_limit = new_limit;
    }

    /// Returns the longest common subsequence, re-attaching the shared prefix/suffix that
    /// were trimmed away before computing the reduced LCS.
    pub fn get_lcs(&self, monitor: &dyn TaskMonitor) -> Result<Vec<T>, CancelledException>
    where
        T: Clone,
    {
        let reduced_lcs = LcsTrait::get_lcs(self, monitor)?;

        let mut lcs = Vec::with_capacity(reduced_lcs.len() + self.startn + self.endn);

        // add the shared beginning
        for i in 0..self.startn {
            monitor.check_cancelled()?;
            lcs.push(self.ops.value_of(&self.x_source, i));
        }

        // add the calculated LCS
        lcs.extend(reduced_lcs);

        // add the shared end
        let length = self.ops.length_of(&self.x_source);
        let endx = get_end(&self.ops, &self.x_source, self.startn, self.endn);
        for i in endx..length {
            monitor.check_cancelled()?;
            lcs.push(self.ops.value_of(&self.x_source, i));
        }

        Ok(lcs)
    }
}

impl<I, T, O: ReducingLcsOps<I, T>> LcsTrait<T> for ReducingLcs<I, T, O> {
    fn get_size_limit(&self) -> usize {
        self.size_limit
    }

    fn length_of_x(&self) -> usize {
        self.ops.length_of(&self.x)
    }

    fn length_of_y(&self) -> usize {
        self.ops.length_of(&self.y)
    }

    fn value_of_x(&self, index: usize) -> T
    where
        T: Clone,
    {
        self.ops.value_of(&self.x, index)
    }

    fn value_of_y(&self, index: usize) -> T
    where
        T: Clone,
    {
        self.ops.value_of(&self.y, index)
    }

    fn matches(&self, x: &T, y: &T) -> bool {
        self.ops.matches(x, y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;

    struct CharOps;

    impl ReducingLcsOps<String, char> for CharOps {
        fn reduce(&self, i: &String, start: usize, end: usize) -> String {
            i.chars().skip(start).take(end - start).collect()
        }

        fn length_of(&self, i: &String) -> usize {
            i.chars().count()
        }

        fn value_of(&self, i: &String, offset: usize) -> char {
            i.chars().nth(offset).unwrap()
        }

        fn matches(&self, x: &char, y: &char) -> bool {
            x == y
        }
    }

    fn lcs_of(x: &str, y: &str) -> String {
        let reducing = ReducingLcs::new(CharOps, x.to_string(), y.to_string());
        reducing.get_lcs(&DummyMonitor).unwrap().into_iter().collect()
    }

    #[test]
    fn test_identical() {
        assert_eq!(lcs_of("DEADBEEF", "DEADBEEF"), "DEADBEEF");
    }

    #[test]
    fn test_similar() {
        assert_eq!(lcs_of("DEADBEEF", "DEEDBEAD"), "DEDBE");

        let x = "Some really long string that might complicate things.\
                 Hooray for really long strings that span multiple lines!";
        let y = "Some other really long string that might complicate things.\
                 Hooray for really loooooong strings that span multiple lines in java!";
        assert_eq!(lcs_of(x, y), x);
    }

    #[test]
    fn test_different() {
        assert_eq!(lcs_of("DEAD", "CANND"), "AD");
        assert_eq!(lcs_of("DEADBEEFISGOOD", "CANNDBEEFISBAD"), "ADBEEFISD");
        assert_eq!(
            lcs_of("this here is one string", "here a different string is"),
            "here in string"
        );
    }

    #[test]
    fn test_insert_only() {
        let x = "Line not modified";
        let y = "Line not not modified";
        assert_eq!(lcs_of(x, y), x);
    }

    #[test]
    fn test_removal_only() {
        let x = "Line not modified";
        let y = "Line modified";
        assert_eq!(lcs_of(x, y), y);
    }

    #[test]
    fn test_size_limit() {
        let x = "This is a line that has not been modified";
        let y = "This is a line that has been modified";

        let mut reducing = ReducingLcs::new(CharOps, x.to_string(), y.to_string());
        reducing.set_size_limit(10);
        let actual: String = reducing.get_lcs(&DummyMonitor).unwrap().into_iter().collect();
        // 'y' is common, since it is 'x', with only a delete
        assert_eq!(actual, y);

        // same as 'x', but with different start/end
        let z = format!("Start Mod {} End Mod", x);
        let mut reducing = ReducingLcs::new(CharOps, x.to_string(), z);
        reducing.set_size_limit(10);
        let actual = reducing.get_lcs(&DummyMonitor).unwrap();
        assert!(actual.is_empty());
    }
}
