use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::io::{self, Read};
use std::rc::Rc;

use super::byte_pattern::BytePattern;
use super::byte_sequence::ByteSequence;
use super::extended_byte_sequence::ExtendedByteSequence;
use super::input_stream_buffer_byte_sequence::InputStreamBufferByteSequence;
use super::r#match::Match;
use crate::util::task::TaskMonitor;

const DEFAULT_BUFFER_SIZE: usize = 4096;

/// Port of `ghidra.util.bytesearch.BulkPatternSearcher`.
///
/// State machine for searching for a list of [`BytePattern`]s simultaneously in a byte
/// sequence. Once constructed from a list of patterns, it can be used any number of times to
/// search byte sequences. There are an assortment of search methods to meet various client
/// needs:
///  - Searching a byte buffer with the result being an iterator over matches.
///  - Searching a byte buffer with the results being added to a given list.
///  - Searching an input stream with the results being added to a given list.
///  - Searching an [`ExtendedByteSequence`] with the results being added to a given list.
pub struct BulkPatternSearcher<T: BytePattern> {
    states: Vec<SearchState<T>>,
    start_state: usize,
    buffer_size: usize,
    unique_state_count: usize,
    max_pattern_length: usize,
}

impl<T: BytePattern + Clone + Eq + Hash> BulkPatternSearcher<T> {
    /// Constructs a searcher for the given patterns, building the internal state machine used
    /// by every search method.
    pub fn new(patterns: Vec<T>) -> Self {
        let max_pattern_length = patterns.iter().map(|p| p.size()).max().unwrap_or(0);
        let (start_state, states, unique_state_count) = Self::build_state_machine(&patterns);
        Self {
            states,
            start_state,
            buffer_size: DEFAULT_BUFFER_SIZE,
            unique_state_count,
            max_pattern_length,
        }
    }

    /// Searches the given byte buffer for any of this searcher's patterns, returning an
    /// iterator that yields matches one at a time.
    pub fn search_iter<'a>(&'a self, input: &'a [u8]) -> impl Iterator<Item = Match<T>> + 'a {
        self.search_iter_len(input, input.len())
    }

    /// Searches the given byte buffer up to `length` bytes for any of this searcher's
    /// patterns, returning an iterator that yields matches one at a time.
    pub fn search_iter_len<'a>(
        &'a self,
        input: &'a [u8],
        length: usize,
    ) -> impl Iterator<Item = Match<T>> + 'a {
        ByteArrayMatchIterator::new(self, input, length)
    }

    /// Searches for the patterns in the given byte array, adding match results to `results`.
    pub fn search(&self, input: &[u8], results: &mut Vec<Match<T>>) {
        self.search_len(input, input.len(), results);
    }

    /// Searches for the patterns in the given byte array, using only the first `num_bytes`
    /// bytes, adding match results to `results`.
    pub fn search_len(&self, input: &[u8], num_bytes: usize, results: &mut Vec<Match<T>>) {
        for pattern_start in 0..num_bytes {
            let mut state_idx = self.start_state;
            for &byte in &input[pattern_start..num_bytes] {
                match self.states[state_idx].next_states[byte as usize] {
                    Some(next) => {
                        self.states[next].add_matches(results, pattern_start as u64);
                        state_idx = next;
                    }
                    None => break,
                }
            }
        }
    }

    /// Searches for the patterns in the given byte array that start at the first byte in the
    /// array, using up to `num_bytes` bytes. Resulting matches are added to `results`.
    pub fn matches(&self, input: &[u8], num_bytes: usize, results: &mut Vec<Match<T>>) {
        let mut state_idx = self.start_state;
        for &byte in &input[..num_bytes] {
            match self.states[state_idx].next_states[byte as usize] {
                Some(next) => {
                    self.states[next].add_matches(results, 0);
                    state_idx = next;
                }
                None => break,
            }
        }
    }

    /// Searches for the patterns in the given [`ExtendedByteSequence`], adding match results to
    /// `results`. Users of this method may have split a larger byte sequence into chunks and
    /// the final match position needs to be the sum of the chunk offset plus the offset within
    /// this chunk.
    pub fn search_extended(&self, bytes: &ExtendedByteSequence, results: &mut Vec<Match<T>>) {
        self.search_extended_with_offset(bytes, results, 0);
    }

    fn search_extended_with_offset(
        &self,
        bytes: &ExtendedByteSequence,
        results: &mut Vec<Match<T>>,
        stream_offset: u64,
    ) {
        let pre_len = bytes.pre_len() as isize;
        let main_len = bytes.len() as isize;
        let extended_len = bytes.extended_len() as isize;
        for start in -pre_len..main_len {
            let mut state_idx = self.start_state;
            for j in start..extended_len {
                let index = bytes.get_byte_signed(j) as usize;
                match self.states[state_idx].next_states[index] {
                    Some(next) => {
                        self.states[next].add_matches_filtered_by_effective_start(
                            results,
                            start,
                            0,
                            main_len - 1,
                            stream_offset,
                        );
                        state_idx = next;
                    }
                    None => break,
                }
            }
        }
    }

    /// Searches for the patterns in the given input stream, adding match results to `results`.
    pub fn search_stream(
        &self,
        input_stream: &mut dyn Read,
        results: &mut Vec<Match<T>>,
        monitor: &dyn TaskMonitor,
    ) -> io::Result<()> {
        self.search_stream_max(input_stream, None, results, monitor)
    }

    /// Searches for the patterns in the given input stream, adding match results to `results`.
    /// `max_read` limits the offset into the input stream where a match can *start*; `None`
    /// means unrestricted. Additional bytes may be read past `max_read` to complete a pattern
    /// that starts before the limit.
    pub fn search_stream_max(
        &self,
        input_stream: &mut dyn Read,
        max_read: Option<u64>,
        results: &mut Vec<Match<T>>,
        monitor: &dyn TaskMonitor,
    ) -> io::Result<()> {
        let buf_size = self.max_pattern_length.max(self.buffer_size);
        let mut stream_offset: u64 = 0;

        // The basic strategy is to use two byte buffers and create a virtual buffer with those
        // two buffers. The first pass will look for patterns that start in the 1st buffer but
        // can extend into the second buffer. This is to ensure that we find patterns that span
        // buffers.
        //
        // Then the second buffer is swapped to be the 1st buffer and new data is read into what
        // was the 1st buffer, but is now the 2nd buffer. This pattern is repeated until all the
        // data is processed up to the number of bytes specified by max_read. No patterns will
        // be matched in any data in the stream past that point, but data past that point may be
        // used to complete a pattern.
        let mut pre = StreamBuffer::new(buf_size);
        let mut main = StreamBuffer::new(buf_size);
        let mut post = StreamBuffer::new(buf_size);

        {
            let mut restricted = RestrictedStream::new(&mut *input_stream, max_read);
            main.load(&mut restricted, buf_size)?;
            post.load(&mut restricted, buf_size)?;

            while main.len() > 0 && post.len() > 0 {
                if monitor.is_cancelled() {
                    return Ok(());
                }

                let combined = ExtendedByteSequence::new(
                    main.as_byte_sequence(),
                    Some(pre.as_byte_sequence()),
                    Some(post.as_byte_sequence()),
                    self.max_pattern_length,
                );
                self.search_extended_with_offset(&combined, results, stream_offset);
                monitor.increment_progress(main.len() as i64);
                stream_offset += main.len() as u64;

                // rotate buffers and load data into second buffer
                let tmp = pre;
                pre = main;
                main = post;
                post = tmp;
                post.load(&mut restricted, buf_size)?;
            }
        }
        // just have to read a bit more to finish last pattern and we go beyond restricted
        // max_read so use an unrestricted stream
        let mut unrestricted = RestrictedStream::new(&mut *input_stream, None);
        post.load(&mut unrestricted, self.max_pattern_length)?;
        let combined = ExtendedByteSequence::new(
            main.as_byte_sequence(),
            Some(pre.as_byte_sequence()),
            Some(post.as_byte_sequence()),
            self.max_pattern_length,
        );
        self.search_extended_with_offset(&combined, results, stream_offset);
        monitor.increment_progress(main.len() as i64);
        Ok(())
    }

    /// Sets the buffer size used when using one of the search methods that takes an input
    /// stream. Mostly used for testing.
    pub fn set_buffer_size(&mut self, buffer_size: usize) {
        self.buffer_size = buffer_size;
    }

    /// Returns the length of the longest pattern.
    pub fn get_max_pattern_length(&self) -> usize {
        self.max_pattern_length
    }

    /// Returns the number of unique states generated. Used for testing.
    pub fn get_unique_state_count(&self) -> usize {
        self.unique_state_count
    }

    fn build_state_machine(patterns: &[T]) -> (usize, Vec<SearchState<T>>, usize) {
        let mut states = vec![SearchState {
            active_patterns: patterns.to_vec(),
            completed_patterns: None,
            next_states: Vec::new(),
            level: 0,
        }];
        let mut unprocessed: VecDeque<usize> = VecDeque::new();
        unprocessed.push_back(0);

        // We use a map that uses the same unique (patterns, level) key as the key and the
        // resulting state's index as the value. This way, if a newly-computed transition is
        // equal to an existing state, we reuse the existing state instead of creating a
        // duplicate.
        let mut dedup_cache: HashMap<(Vec<T>, usize), usize> = HashMap::new();
        while let Some(idx) = unprocessed.pop_front() {
            Self::compute_transitions(idx, &mut states, &mut unprocessed, &mut dedup_cache);
        }
        let unique_state_count = dedup_cache.len() + 1; // add 1 for the root state which wasn't cached
        (0, states, unique_state_count)
    }

    fn compute_transitions(
        idx: usize,
        states: &mut Vec<SearchState<T>>,
        unprocessed: &mut VecDeque<usize>,
        dedup_cache: &mut HashMap<(Vec<T>, usize), usize>,
    ) {
        let level = states[idx].level;
        let active_patterns = states[idx].active_patterns.clone();

        let completed_patterns = Self::build_fully_matched_patterns_list(&active_patterns, level);
        let is_terminal = completed_patterns
            .as_ref()
            .is_some_and(|completed| completed.len() == active_patterns.len());

        let mut next_states = vec![None; 256];
        if !is_terminal {
            for byte_value in 0u16..256 {
                let matched_patterns: Vec<T> = active_patterns
                    .iter()
                    .filter(|pattern| pattern.is_match(level, byte_value as u8))
                    .cloned()
                    .collect();
                if !matched_patterns.is_empty() {
                    let next_idx = Self::get_or_create_state(
                        matched_patterns,
                        level + 1,
                        states,
                        dedup_cache,
                        unprocessed,
                    );
                    next_states[byte_value as usize] = Some(next_idx);
                }
            }
        }

        states[idx].completed_patterns = completed_patterns;
        states[idx].next_states = next_states;
    }

    fn get_or_create_state(
        patterns: Vec<T>,
        level: usize,
        states: &mut Vec<SearchState<T>>,
        dedup_cache: &mut HashMap<(Vec<T>, usize), usize>,
        unprocessed: &mut VecDeque<usize>,
    ) -> usize {
        let key = (patterns.clone(), level);
        if let Some(&existing) = dedup_cache.get(&key) {
            return existing;
        }
        let idx = states.len();
        states.push(SearchState {
            active_patterns: patterns,
            completed_patterns: None,
            next_states: Vec::new(),
            level,
        });
        dedup_cache.insert(key, idx);
        unprocessed.push_back(idx);
        idx
    }

    fn build_fully_matched_patterns_list(active_patterns: &[T], level: usize) -> Option<Vec<T>> {
        let list: Vec<T> =
            active_patterns.iter().filter(|pattern| pattern.size() == level).cloned().collect();
        if list.is_empty() {
            None
        } else {
            Some(list)
        }
    }
}

/// A single state in the state machine that represents one or more active patterns that have
/// matched the sequence of bytes so far.
struct SearchState<T> {
    active_patterns: Vec<T>,    // patterns that have matched the input bytes so far
    completed_patterns: Option<Vec<T>>, // the active patterns that have completely matched
    next_states: Vec<Option<usize>>, // next state (transition) for each possible input byte
    level: usize,                // the number of bytes that have been matched so far
}

impl<T: BytePattern + Clone> SearchState<T> {
    fn add_matches<C: Extend<Match<T>>>(&self, results: &mut C, start: u64) {
        if let Some(completed) = &self.completed_patterns {
            results.extend(completed.iter().map(|pattern| Match::new(pattern.clone(), start, pattern.size())));
        }
    }

    fn add_matches_filtered_by_effective_start(
        &self,
        results: &mut Vec<Match<T>>,
        start: isize,
        min: isize,
        max: isize,
        stream_offset: u64,
    ) {
        let Some(completed) = &self.completed_patterns else {
            return;
        };
        for pattern in completed {
            let actual_start = start + pattern.pre_sequence_length() as isize;
            if actual_start >= min && actual_start <= max {
                let match_start = if start >= 0 {
                    stream_offset + start as u64
                } else {
                    stream_offset - (-start) as u64
                };
                results.push(Match::new(pattern.clone(), match_start, pattern.size()));
            }
        }
    }
}

/// Iterator that lazily scans a byte buffer, yielding matches one at a time.
struct ByteArrayMatchIterator<'a, T: BytePattern> {
    searcher: &'a BulkPatternSearcher<T>,
    bytes: &'a [u8],
    length: usize,
    pattern_start: usize,
    result_buffer: VecDeque<Match<T>>,
}

impl<'a, T: BytePattern + Clone + Eq + Hash> ByteArrayMatchIterator<'a, T> {
    fn new(searcher: &'a BulkPatternSearcher<T>, input: &'a [u8], length: usize) -> Self {
        let mut iter = Self {
            searcher,
            bytes: input,
            length: length.min(input.len()),
            pattern_start: 0,
            result_buffer: VecDeque::new(),
        };
        iter.find_next();
        iter
    }

    fn find_next(&mut self) {
        while self.pattern_start < self.length && self.result_buffer.is_empty() {
            let mut state_idx = self.searcher.start_state;
            for &byte in &self.bytes[self.pattern_start..self.length] {
                match self.searcher.states[state_idx].next_states[byte as usize] {
                    Some(next) => state_idx = next,
                    None => break,
                }
                self.searcher.states[state_idx]
                    .add_matches(&mut self.result_buffer, self.pattern_start as u64);
            }
            self.pattern_start += 1;
        }
    }
}

impl<'a, T: BytePattern + Clone + Eq + Hash> Iterator for ByteArrayMatchIterator<'a, T> {
    type Item = Match<T>;

    fn next(&mut self) -> Option<Match<T>> {
        let next_result = self.result_buffer.pop_front();
        if self.result_buffer.is_empty() {
            self.find_next();
        }
        next_result
    }
}

/// Shares an [`InputStreamBufferByteSequence`] between the owning [`StreamBuffer`] (which loads
/// data into it) and any number of [`ByteSequence`] views handed to an [`ExtendedByteSequence`]
/// (which only reads from it), so the buffer can be reused across search calls and rotated
/// between the pre/main/post roles.
struct StreamBuffer(Rc<RefCell<InputStreamBufferByteSequence>>);

impl StreamBuffer {
    fn new(buffer_size: usize) -> Self {
        Self(Rc::new(RefCell::new(InputStreamBufferByteSequence::new(buffer_size))))
    }

    fn load<R: Read>(&self, reader: &mut R, amount: usize) -> io::Result<()> {
        self.0.borrow_mut().load(reader, amount)
    }

    fn len(&self) -> usize {
        self.0.borrow().len()
    }

    fn as_byte_sequence(&self) -> Box<dyn ByteSequence> {
        Box::new(StreamBufferView(Rc::clone(&self.0)))
    }
}

struct StreamBufferView(Rc<RefCell<InputStreamBufferByteSequence>>);

impl ByteSequence for StreamBufferView {
    fn len(&self) -> usize {
        self.0.borrow().len()
    }

    fn get_byte(&self, index: usize) -> u8 {
        self.0.borrow().get_byte(index)
    }

    fn get_bytes(&self, start: usize, length: usize) -> Vec<u8> {
        self.0.borrow().get_bytes(start, length)
    }
}

/// A reader that limits how many bytes may be pulled from an inner reader, treating the limit
/// as an end-of-stream marker rather than an error.
struct RestrictedStream<'a, R: Read + ?Sized> {
    inner: &'a mut R,
    max_read: Option<u64>,
    total_read: u64,
}

impl<'a, R: Read + ?Sized> RestrictedStream<'a, R> {
    fn new(inner: &'a mut R, max_read: Option<u64>) -> Self {
        Self { inner, max_read, total_read: 0 }
    }
}

impl<'a, R: Read + ?Sized> Read for RestrictedStream<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let amount_to_read = match self.max_read {
            Some(max) => {
                let remaining = max.saturating_sub(self.total_read);
                (buf.len() as u64).min(remaining) as usize
            }
            None => buf.len(),
        };
        let n = self.inner.read(&mut buf[..amount_to_read])?;
        self.total_read += n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::exception::CancelledException;
    use crate::util::task::{CancelledListener, DummyMonitor};
    use std::io::Cursor;

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct SimplePattern {
        bytes: Vec<u8>,
    }

    impl SimplePattern {
        fn new(bytes: &[u8]) -> Self {
            Self { bytes: bytes.to_vec() }
        }
    }

    impl BytePattern for SimplePattern {
        fn size(&self) -> usize {
            self.bytes.len()
        }

        fn is_match(&self, pattern_offset: usize, byte_value: u8) -> bool {
            self.bytes.get(pattern_offset).map_or(false, |&b| b == byte_value)
        }

        fn pre_sequence_length(&self) -> usize {
            0
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct PrefixedPattern {
        bytes: Vec<u8>,
        pre_len: usize,
    }

    impl BytePattern for PrefixedPattern {
        fn size(&self) -> usize {
            self.bytes.len()
        }

        fn is_match(&self, pattern_offset: usize, byte_value: u8) -> bool {
            self.bytes.get(pattern_offset).map_or(false, |&b| b == byte_value)
        }

        fn pre_sequence_length(&self) -> usize {
            self.pre_len
        }
    }

    struct VecSeq(Vec<u8>);

    impl ByteSequence for VecSeq {
        fn len(&self) -> usize {
            self.0.len()
        }

        fn get_byte(&self, index: usize) -> u8 {
            self.0[index]
        }
    }

    struct CancelledMonitor;

    impl TaskMonitor for CancelledMonitor {
        fn is_cancelled(&self) -> bool {
            true
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), CancelledException> {
            Ok(())
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            0
        }
        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {}
    }

    #[test]
    fn search_iter_finds_single_match() {
        let searcher = BulkPatternSearcher::new(vec![SimplePattern::new(&[0xAA, 0xBB])]);
        let input = [0x00, 0xAA, 0xBB, 0x00];
        let matches: Vec<_> = searcher.search_iter(&input).collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].get_start(), 1);
        assert_eq!(matches[0].get_length(), 2);
    }

    #[test]
    fn search_finds_overlapping_matches() {
        let searcher = BulkPatternSearcher::new(vec![
            SimplePattern::new(&[0x01, 0x02]),
            SimplePattern::new(&[0x02, 0x03]),
        ]);
        let input = [0x01, 0x02, 0x03];
        let mut results = Vec::new();
        searcher.search(&input, &mut results);
        let mut starts: Vec<u64> = results.iter().map(|m| m.get_start()).collect();
        starts.sort();
        assert_eq!(starts, vec![0, 1]);
    }

    #[test]
    fn matches_only_checks_prefix() {
        let searcher = BulkPatternSearcher::new(vec![SimplePattern::new(&[0xAA, 0xBB])]);

        let mut results = Vec::new();
        searcher.matches(&[0xAA, 0xBB, 0xCC], 3, &mut results);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].get_start(), 0);

        let mut results2 = Vec::new();
        searcher.matches(&[0x00, 0xAA, 0xBB], 3, &mut results2);
        assert!(results2.is_empty());
    }

    #[test]
    fn max_pattern_length_is_longest_pattern() {
        let searcher = BulkPatternSearcher::new(vec![
            SimplePattern::new(&[0x01]),
            SimplePattern::new(&[0x01, 0x02, 0x03]),
        ]);
        assert_eq!(searcher.get_max_pattern_length(), 3);
    }

    #[test]
    fn max_pattern_length_is_zero_for_no_patterns() {
        let searcher: BulkPatternSearcher<SimplePattern> = BulkPatternSearcher::new(vec![]);
        assert_eq!(searcher.get_max_pattern_length(), 0);
    }

    #[test]
    fn unique_state_count_for_single_byte_pattern() {
        let searcher = BulkPatternSearcher::new(vec![SimplePattern::new(&[0x01])]);
        assert_eq!(searcher.get_unique_state_count(), 2);
    }

    #[test]
    fn search_extended_finds_match_spanning_main_and_post() {
        let searcher = BulkPatternSearcher::new(vec![SimplePattern::new(&[0xAA, 0xBB])]);
        let main: Box<dyn ByteSequence> = Box::new(VecSeq(vec![0x00, 0xAA]));
        let post: Box<dyn ByteSequence> = Box::new(VecSeq(vec![0xBB, 0x00]));
        let combined = ExtendedByteSequence::new(main, None, Some(post), 2);

        let mut results = Vec::new();
        searcher.search_extended(&combined, &mut results);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].get_start(), 1);
        assert_eq!(results[0].get_length(), 2);
    }

    #[test]
    fn search_extended_filters_out_of_range_lookback_match() {
        // The pattern is fully matchable using look-behind ("pre") bytes, but its effective
        // start (with no pre-sequence offset) falls before the current chunk, so it must not be
        // reported here -- it was already reported by the chunk that owned it as "main".
        let searcher = BulkPatternSearcher::new(vec![SimplePattern::new(&[0x10, 0x20])]);
        let main: Box<dyn ByteSequence> = Box::new(VecSeq(vec![0x20]));
        let pre: Box<dyn ByteSequence> = Box::new(VecSeq(vec![0x10]));
        let combined = ExtendedByteSequence::new(main, Some(pre), None, 2);

        let mut results = Vec::new();
        searcher.search_extended(&combined, &mut results);

        assert!(results.is_empty());
    }

    #[test]
    fn search_extended_with_offset_reports_kept_lookback_match() {
        let pattern = PrefixedPattern { bytes: vec![0x10, 0x20], pre_len: 1 };
        let searcher = BulkPatternSearcher::new(vec![pattern]);
        let main: Box<dyn ByteSequence> = Box::new(VecSeq(vec![0x20]));
        let pre: Box<dyn ByteSequence> = Box::new(VecSeq(vec![0x10]));
        let combined = ExtendedByteSequence::new(main, Some(pre), None, 2);

        let mut results = Vec::new();
        searcher.search_extended_with_offset(&combined, &mut results, 10);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].get_start(), 9);
        assert_eq!(results[0].get_length(), 2);
    }

    #[test]
    fn search_stream_finds_matches_across_buffer_chunks() {
        let mut searcher = BulkPatternSearcher::new(vec![SimplePattern::new(&[0xAA, 0xBB])]);
        searcher.set_buffer_size(2);

        let data = vec![0x00, 0xAA, 0xBB, 0x00, 0xAA, 0xBB];
        let mut cursor = Cursor::new(data);
        let mut results = Vec::new();
        let monitor = DummyMonitor;
        searcher.search_stream(&mut cursor, &mut results, &monitor).unwrap();

        let mut starts: Vec<u64> = results.iter().map(|m| m.get_start()).collect();
        starts.sort();
        assert_eq!(starts, vec![1, 4]);
    }

    #[test]
    fn search_stream_returns_early_when_cancelled() {
        let mut searcher = BulkPatternSearcher::new(vec![SimplePattern::new(&[0xAA])]);
        searcher.set_buffer_size(1);

        let data = vec![0xAA, 0xAA, 0xAA, 0xAA];
        let mut cursor = Cursor::new(data);
        let mut results = Vec::new();
        let monitor = CancelledMonitor;
        searcher.search_stream(&mut cursor, &mut results, &monitor).unwrap();

        assert!(results.is_empty());
    }
}
