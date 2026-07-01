/// Tests for [`GraphPath`](crate::graph::graph_path::GraphPath).
///
/// Corresponds to `GraphPathTest` in the original Ghidra Java source (`ghidra.graph`).
#[cfg(test)]
mod tests {
    use crate::graph::graph_path::GraphPath;
    use rand::Rng;
    use std::collections::HashSet;

    /// Builds a `GraphPath<i32>` filled with 21 vertices (0..=20), mirroring the Java
    /// `setUp()` fixture.
    fn new_graph_path() -> GraphPath<i32> {
        let mut graph_path = GraphPath::new();
        for i in 0..=20 {
            graph_path.add(i);
        }
        graph_path
    }

    #[test]
    fn test_copy() {
        let mut graph_path = GraphPath::new();
        graph_path.add(1);
        graph_path.add(2);
        graph_path.add(3);

        let graph_path_copy = graph_path.copy();

        assert!(graph_path_copy.contains(&1));
        assert!(graph_path_copy.contains(&2));
        assert!(graph_path_copy.contains(&3));
        assert_eq!(graph_path_copy.size(), 3);
    }

    #[test]
    fn test_starts_with_smaller_graph_path() {
        let graph_path = new_graph_path();

        let mut graph_path_start = GraphPath::new();
        for i in 0..5 {
            graph_path_start.add(i);
        }

        assert!(graph_path.starts_with(&graph_path_start));
        assert!(!graph_path.starts_with(&GraphPath::with_vertex(6)));
    }

    #[test]
    fn test_starts_with_larger_graph_path() {
        let graph_path = new_graph_path();

        let mut larger_graph_path = GraphPath::new();
        for i in 0..25 {
            larger_graph_path.add(i);
        }

        assert!(!graph_path.starts_with(&larger_graph_path));
    }

    #[test]
    fn test_get_common_start_path() {
        let mut shared_start_path = GraphPath::new();
        for i in 0..10 {
            shared_start_path.add(i);
        }

        let mut different_path = shared_start_path.copy();
        for i in 90..100 {
            different_path.add(i);
        }

        let common_start_path_result = shared_start_path.get_common_start_path(&different_path);
        for i in 0..common_start_path_result.size() {
            assert_eq!(shared_start_path.get(i), common_start_path_result.get(i));
        }

        assert_eq!(shared_start_path.size(), common_start_path_result.size());
    }

    #[test]
    fn test_size() {
        let mut graph_path = GraphPath::new();
        graph_path.add(1);
        graph_path.add(2);
        graph_path.add(3);

        assert_eq!(graph_path.size(), 3);
    }

    #[test]
    fn test_contains() {
        let mut graph_path = new_graph_path();
        let mut rng = rand::thread_rng();

        let random_int: i32 = rng.gen_range(1002..2000);
        graph_path.add(random_int);
        assert!(graph_path.contains(&random_int));
        assert!(!graph_path.contains(&1001));

        let random_int_2: i32 = rng.gen_range(1002..2000);
        graph_path.add(random_int_2);
        assert!(graph_path.contains(&random_int_2));
        assert!(!graph_path.contains(&1001));
    }

    #[test]
    fn test_get_last() {
        let graph_path = new_graph_path();
        assert_eq!(*graph_path.get_last(), 20);
    }

    #[test]
    fn test_depth() {
        let graph_path = new_graph_path();
        let mut rng = rand::thread_rng();
        let random_int = rng.gen_range(0..graph_path.size() as i32);
        assert_eq!(graph_path.depth(&random_int), Some(random_int as usize));
    }

    #[test]
    fn test_get() {
        let graph_path = new_graph_path();
        let mut rng = rand::thread_rng();
        let random_int = rng.gen_range(0..graph_path.size() as i32);
        assert_eq!(*graph_path.get(random_int as usize), random_int);
    }

    #[test]
    fn test_remove_last() {
        let mut graph_path = new_graph_path();
        assert_eq!(*graph_path.get_last(), 20);
        assert_eq!(graph_path.remove_last(), 20);
        assert_eq!(*graph_path.get_last(), 19);
    }

    #[test]
    fn test_get_predecessors() {
        let graph_path = new_graph_path();

        let mut predecessors = HashSet::new();
        for i in 0..=10 {
            predecessors.insert(i);
        }

        let predecessors_set = graph_path.get_predecessors(&10);
        assert_eq!(predecessors, predecessors_set);
    }

    #[test]
    fn test_get_predecessors_larger_index() {
        let graph_path = new_graph_path();
        let predecessors_set = graph_path.get_predecessors(&21);
        assert_eq!(predecessors_set.len(), 0);
    }

    #[test]
    fn test_get_successors() {
        let graph_path = new_graph_path();

        let mut successors = HashSet::new();
        for i in 10..=20 {
            successors.insert(i);
        }

        let successors_set = graph_path.get_successors(&10);
        assert_eq!(successors, successors_set);
    }

    #[test]
    fn test_get_successors_larger_index() {
        let graph_path = new_graph_path();
        let successors_set = graph_path.get_successors(&(graph_path.size() as i32));
        assert_eq!(successors_set.len(), 0);
    }
}
