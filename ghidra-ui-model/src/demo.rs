//! Simple in-memory view models: the U1b demo tool's panes and test fixtures.

use std::collections::BTreeMap;

use crate::view_models::{CellValue, FormField, FormModel, NodeId, StyledRun, TableModel, TextModel, TreeModel};

/// A table backed by a `Vec` of rows, with sort and substring filter.
pub struct VecTable {
    columns: Vec<String>,
    rows: Vec<Vec<CellValue>>,
    view: Vec<usize>,
    filter: String,
}

impl VecTable {
    /// A table with these columns and rows.
    pub fn new(columns: Vec<String>, rows: Vec<Vec<CellValue>>) -> Self {
        let view = (0..rows.len()).collect();
        Self { columns, rows, view, filter: String::new() }
    }

    fn refilter(&mut self) {
        let needle = self.filter.to_lowercase();
        let keep: Vec<usize> = self
            .view_order()
            .into_iter()
            .filter(|&i| needle.is_empty() || self.rows[i].iter().any(|c| c.to_string().to_lowercase().contains(&needle)))
            .collect();
        self.view = keep;
    }

    fn view_order(&self) -> Vec<usize> {
        let mut all: Vec<usize> = self.view.clone();
        let mut seen = vec![false; self.rows.len()];
        for &i in &all {
            seen[i] = true;
        }
        all.extend((0..self.rows.len()).filter(|i| !seen[*i]));
        all
    }
}

fn cmp_cells(a: &CellValue, b: &CellValue) -> std::cmp::Ordering {
    use CellValue::*;
    match (a, b) {
        (Int(x), Int(y)) => x.cmp(y),
        (Address(x), Address(y)) => x.cmp(y),
        (Bool(x), Bool(y)) => x.cmp(y),
        _ => a.to_string().cmp(&b.to_string()),
    }
}

impl TableModel for VecTable {
    fn column_count(&self) -> usize {
        self.columns.len()
    }
    fn column_name(&self, column: usize) -> String {
        self.columns.get(column).cloned().unwrap_or_default()
    }
    fn row_count(&self) -> usize {
        self.view.len()
    }
    fn cell(&self, row: usize, column: usize) -> CellValue {
        self.view.get(row).and_then(|&i| self.rows[i].get(column)).cloned().unwrap_or(CellValue::Empty)
    }
    fn sort(&mut self, column: usize, ascending: bool) {
        let mut order = self.view_order();
        order.sort_by(|&a, &b| {
            let o = cmp_cells(
                self.rows[a].get(column).unwrap_or(&CellValue::Empty),
                self.rows[b].get(column).unwrap_or(&CellValue::Empty),
            );
            if ascending { o } else { o.reverse() }
        });
        self.view = order;
        self.refilter();
    }
    fn set_filter(&mut self, text: &str) {
        self.filter = text.to_owned();
        self.refilter();
    }
}

/// A tree built from `/`-separated paths.
pub struct StaticTree {
    labels: Vec<String>,
    parents: Vec<Option<usize>>,
    children: Vec<Vec<usize>>,
    addresses: Vec<Option<u64>>,
}

impl StaticTree {
    /// Builds a tree; the first path segment is the root.
    pub fn from_paths(paths: &[&str]) -> Self {
        let mut t = StaticTree { labels: Vec::new(), parents: Vec::new(), children: Vec::new(), addresses: Vec::new() };
        let mut index: BTreeMap<(Option<usize>, String), usize> = BTreeMap::new();
        for path in paths {
            let mut parent: Option<usize> = None;
            for seg in path.split('/').filter(|s| !s.is_empty()) {
                let key = (parent, seg.to_owned());
                let id = match index.get(&key) {
                    Some(&id) => id,
                    None => {
                        let id = t.labels.len();
                        t.labels.push(seg.to_owned());
                        t.parents.push(parent);
                        t.children.push(Vec::new());
                        t.addresses.push(None);
                        if let Some(p) = parent {
                            t.children[p].push(id);
                        }
                        index.insert(key, id);
                        id
                    }
                };
                parent = Some(id);
            }
        }
        t
    }

    /// [`Self::from_paths`] with the address each path's last node starts at
    /// (a program tree's fragments).
    pub fn with_locations(paths: &[(&str, Option<u64>)]) -> Self {
        let names: Vec<&str> = paths.iter().map(|(p, _)| *p).collect();
        let mut t = Self::from_paths(&names);
        for (path, address) in paths {
            if let Some(node) = t.find_path(path) {
                t.addresses[node] = *address;
            }
        }
        t
    }

    fn find_path(&self, path: &str) -> Option<usize> {
        let mut node: Option<usize> = None;
        for seg in path.split('/').filter(|s| !s.is_empty()) {
            let candidates: Vec<usize> = match node {
                None => (0..self.labels.len()).filter(|&i| self.parents[i].is_none()).collect(),
                Some(n) => self.children[n].clone(),
            };
            node = Some(candidates.into_iter().find(|&c| self.labels[c] == seg)?);
        }
        node
    }
}

impl TreeModel for StaticTree {
    fn root(&self) -> NodeId {
        NodeId(0)
    }
    fn child_count(&self, node: NodeId) -> usize {
        self.children.get(node.0 as usize).map_or(0, Vec::len)
    }
    fn child(&self, node: NodeId, index: usize) -> NodeId {
        NodeId(self.children[node.0 as usize][index] as u64)
    }
    fn parent(&self, node: NodeId) -> Option<NodeId> {
        self.parents.get(node.0 as usize).copied().flatten().map(|p| NodeId(p as u64))
    }
    fn label(&self, node: NodeId) -> String {
        self.labels.get(node.0 as usize).cloned().unwrap_or_default()
    }
    /// A fragment's own start, else a module's: the minimum of its descendants.
    fn location(&self, node: NodeId) -> Option<u64> {
        let n = node.0 as usize;
        if n >= self.labels.len() {
            return None;
        }
        self.addresses[n].or_else(|| self.children[n].iter().filter_map(|&c| self.location(NodeId(c as u64))).min())
    }
}

/// Plain lines of text.
pub struct LinesText {
    lines: Vec<String>,
}

impl LinesText {
    /// Wraps lines.
    pub fn new(lines: Vec<String>) -> Self {
        Self { lines }
    }
}

impl TextModel for LinesText {
    fn line_count(&self) -> usize {
        self.lines.len()
    }
    fn line(&self, index: usize) -> Vec<StyledRun> {
        self.lines.get(index).map(|l| vec![StyledRun::plain(l.clone())]).unwrap_or_default()
    }
}

/// A form over an ordered field list.
pub struct MapForm {
    fields: Vec<FormField>,
}

impl MapForm {
    /// Wraps fields.
    pub fn new(fields: Vec<FormField>) -> Self {
        Self { fields }
    }
}

impl FormModel for MapForm {
    fn fields(&self) -> Vec<FormField> {
        self.fields.clone()
    }
    fn set(&mut self, key: &str, value: &str) -> Result<(), String> {
        let field = self.fields.iter_mut().find(|f| f.key == key).ok_or_else(|| format!("unknown field {key}"))?;
        field.validate(value)?;
        field.value = value.trim().to_owned();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::view_models::TableModel;

    #[test]
    fn a_tree_node_goes_to_its_address_or_its_descendants_minimum() {
        use crate::view_models::{NodeId, TreeModel};
        let t = StaticTree::with_locations(&[("ls/.text", Some(0x30)), ("ls/.data", Some(0x20)), ("ls/.bss", None), ("ls/seg/.x", Some(0x50))]);
        let label = |n: NodeId| t.label(n);
        let find = |name: &str| (0..t.labels.len() as u64).map(NodeId).find(|&n| label(n) == name).unwrap();
        assert_eq!(t.location(find(".text")), Some(0x30));
        assert_eq!(t.location(find(".bss")), None);
        assert_eq!(t.location(find("seg")), Some(0x50));
        assert_eq!(t.location(t.root()), Some(0x20)); // module: its address set's minimum
        assert_eq!(t.location(NodeId(99)), None);
    }

    #[test]
    fn a_rows_location_is_the_clicked_address_else_its_first_address() {
        let t = VecTable::new(
            vec!["Name".into(), "From".into(), "To".into()],
            vec![
                vec![CellValue::Text("a".into()), CellValue::Address(0x10), CellValue::Address(0x20)],
                vec![CellValue::Text("b".into()), CellValue::Int(3), CellValue::Text("x".into())],
            ],
        );
        assert_eq!(t.location(0, 2), Some(0x20));
        assert_eq!(t.location(0, 0), Some(0x10));
        assert_eq!(t.location(1, 1), None);
        assert_eq!(t.location(5, 0), None);
    }
}
