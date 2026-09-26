use egui::Color32;

/// Provides foreground colors for items that may differ from a recorded baseline ("modified").
///
/// The generic parameter `C` is a rendering context from which the baseline (unmodified)
/// foreground colors can be derived. Implementors supply the "diff" colors used when an
/// item differs from its recorded snapshot; the context supplies the standard colors.
///
/// The key dispatch method is [`foreground_for`], which selects among the four color
/// combinations based on `is_modified` and `is_selected`.
///
/// Ported from `ghidra.app.plugin.core.debug.gui.model.ColorsModified`.
pub trait ColorsModified<C> {
    /// Foreground color for a **modified**, **unselected** item.
    fn diff_foreground(&self, ctx: &C) -> Color32;

    /// Foreground color for a **modified**, **selected** item.
    fn diff_sel_foreground(&self, ctx: &C) -> Color32;

    /// Foreground color for an **unmodified**, **unselected** item.
    fn foreground(&self, ctx: &C) -> Color32;

    /// Foreground color for an **unmodified**, **selected** item.
    fn sel_foreground(&self, ctx: &C) -> Color32;

    /// Returns the appropriate foreground color for the given modification and selection state.
    fn foreground_for(&self, ctx: &C, is_modified: bool, is_selected: bool) -> Color32 {
        if is_modified {
            if is_selected {
                self.diff_sel_foreground(ctx)
            } else {
                self.diff_foreground(ctx)
            }
        } else if is_selected {
            self.sel_foreground(ctx)
        } else {
            self.foreground(ctx)
        }
    }
}

/// Color context for a table widget, carrying the standard foreground colors.
///
/// Analogous to the `JTable` passed as context to `ColorsModified.InTable` in the Java
/// source. `JTable.getForeground()` and `JTable.getSelectionForeground()` are inlined as
/// fields.
pub struct TableColors {
    /// Foreground color for unselected rows (analogous to `JTable.getForeground()`).
    pub foreground: Color32,
    /// Foreground color for selected rows (analogous to `JTable.getSelectionForeground()`).
    pub selection_foreground: Color32,
}

/// Extends [`ColorsModified`] for table rendering contexts.
///
/// Implementors supply only the diff colors. The unmodified baseline foreground colors
/// are read from the [`TableColors`] context, mirroring the Java `InTable` defaults
/// (`table.getForeground()` / `table.getSelectionForeground()`).
///
/// Ported from `ghidra.app.plugin.core.debug.gui.model.ColorsModified.InTable`.
pub trait InTable {
    /// Foreground color for a modified, unselected table cell.
    fn diff_foreground(&self, ctx: &TableColors) -> Color32;
    /// Foreground color for a modified, selected table cell.
    fn diff_sel_foreground(&self, ctx: &TableColors) -> Color32;
}

impl<T: InTable> ColorsModified<TableColors> for T {
    fn diff_foreground(&self, ctx: &TableColors) -> Color32 {
        InTable::diff_foreground(self, ctx)
    }

    fn diff_sel_foreground(&self, ctx: &TableColors) -> Color32 {
        InTable::diff_sel_foreground(self, ctx)
    }

    fn foreground(&self, ctx: &TableColors) -> Color32 {
        ctx.foreground
    }

    fn sel_foreground(&self, ctx: &TableColors) -> Color32 {
        ctx.selection_foreground
    }
}

/// Color context for a tree widget, carrying the text selection colors.
///
/// Analogous to the `JTree` / `TreeCellRenderer` pair used by `ColorsModified.InTree`
/// in the Java source. `getTextNonSelectionColor()` and `getTextSelectionColor()` from the
/// Java `TreeCellRenderer` interface are inlined as fields.
pub struct TreeColors {
    /// Text color for non-selected tree nodes (analogous to `getTextNonSelectionColor()`).
    pub text_non_selection: Color32,
    /// Text color for selected tree nodes (analogous to `getTextSelectionColor()`).
    pub text_selection: Color32,
}

/// Extends [`ColorsModified`] for tree rendering contexts.
///
/// Implementors supply only the diff colors. The unmodified baseline foreground colors
/// are read from the [`TreeColors`] context, mirroring the Java `InTree` defaults
/// (`getTextNonSelectionColor()` / `getTextSelectionColor()`).
///
/// Ported from `ghidra.app.plugin.core.debug.gui.model.ColorsModified.InTree`.
pub trait InTree {
    /// Foreground color for a modified, unselected tree node.
    fn diff_foreground(&self, ctx: &TreeColors) -> Color32;
    /// Foreground color for a modified, selected tree node.
    fn diff_sel_foreground(&self, ctx: &TreeColors) -> Color32;
}

impl<T: InTree> ColorsModified<TreeColors> for T {
    fn diff_foreground(&self, ctx: &TreeColors) -> Color32 {
        InTree::diff_foreground(self, ctx)
    }

    fn diff_sel_foreground(&self, ctx: &TreeColors) -> Color32 {
        InTree::diff_sel_foreground(self, ctx)
    }

    fn foreground(&self, ctx: &TreeColors) -> Color32 {
        ctx.text_non_selection
    }

    fn sel_foreground(&self, ctx: &TreeColors) -> Color32 {
        ctx.text_selection
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RED: Color32 = Color32::from_rgb(255, 0, 0);
    const GREEN: Color32 = Color32::from_rgb(0, 255, 0);
    const BLUE: Color32 = Color32::from_rgb(0, 0, 255);
    const WHITE: Color32 = Color32::WHITE;
    const BLACK: Color32 = Color32::BLACK;

    struct TableRenderer {
        diff_fg: Color32,
        diff_sel_fg: Color32,
    }

    impl InTable for TableRenderer {
        fn diff_foreground(&self, _ctx: &TableColors) -> Color32 {
            self.diff_fg
        }
        fn diff_sel_foreground(&self, _ctx: &TableColors) -> Color32 {
            self.diff_sel_fg
        }
    }

    struct TreeRenderer {
        diff_fg: Color32,
        diff_sel_fg: Color32,
    }

    impl InTree for TreeRenderer {
        fn diff_foreground(&self, _ctx: &TreeColors) -> Color32 {
            self.diff_fg
        }
        fn diff_sel_foreground(&self, _ctx: &TreeColors) -> Color32 {
            self.diff_sel_fg
        }
    }

    fn table_ctx() -> TableColors {
        TableColors {
            foreground: BLACK,
            selection_foreground: WHITE,
        }
    }

    fn tree_ctx() -> TreeColors {
        TreeColors {
            text_non_selection: BLACK,
            text_selection: WHITE,
        }
    }

    #[test]
    fn table_unmodified_unselected_uses_table_foreground() {
        let r = TableRenderer { diff_fg: RED, diff_sel_fg: GREEN };
        let ctx = table_ctx();
        assert_eq!(r.foreground_for(&ctx, false, false), BLACK);
    }

    #[test]
    fn table_unmodified_selected_uses_table_selection_foreground() {
        let r = TableRenderer { diff_fg: RED, diff_sel_fg: GREEN };
        let ctx = table_ctx();
        assert_eq!(r.foreground_for(&ctx, false, true), WHITE);
    }

    #[test]
    fn table_modified_unselected_uses_diff_foreground() {
        let r = TableRenderer { diff_fg: RED, diff_sel_fg: GREEN };
        let ctx = table_ctx();
        assert_eq!(r.foreground_for(&ctx, true, false), RED);
    }

    #[test]
    fn table_modified_selected_uses_diff_sel_foreground() {
        let r = TableRenderer { diff_fg: RED, diff_sel_fg: GREEN };
        let ctx = table_ctx();
        assert_eq!(r.foreground_for(&ctx, true, true), GREEN);
    }

    #[test]
    fn tree_unmodified_unselected_uses_text_non_selection() {
        let r = TreeRenderer { diff_fg: BLUE, diff_sel_fg: RED };
        let ctx = tree_ctx();
        assert_eq!(r.foreground_for(&ctx, false, false), BLACK);
    }

    #[test]
    fn tree_unmodified_selected_uses_text_selection() {
        let r = TreeRenderer { diff_fg: BLUE, diff_sel_fg: RED };
        let ctx = tree_ctx();
        assert_eq!(r.foreground_for(&ctx, false, true), WHITE);
    }

    #[test]
    fn tree_modified_unselected_uses_diff_foreground() {
        let r = TreeRenderer { diff_fg: BLUE, diff_sel_fg: RED };
        let ctx = tree_ctx();
        assert_eq!(r.foreground_for(&ctx, true, false), BLUE);
    }

    #[test]
    fn tree_modified_selected_uses_diff_sel_foreground() {
        let r = TreeRenderer { diff_fg: BLUE, diff_sel_fg: RED };
        let ctx = tree_ctx();
        assert_eq!(r.foreground_for(&ctx, true, true), RED);
    }

    #[test]
    fn direct_foreground_and_sel_foreground_via_colors_modified_trait() {
        let r = TableRenderer { diff_fg: RED, diff_sel_fg: GREEN };
        let ctx = table_ctx();
        // foreground() and sel_foreground() come from the blanket impl
        assert_eq!(ColorsModified::<TableColors>::foreground(&r, &ctx), BLACK);
        assert_eq!(ColorsModified::<TableColors>::sel_foreground(&r, &ctx), WHITE);
        assert_eq!(ColorsModified::<TableColors>::diff_foreground(&r, &ctx), RED);
        assert_eq!(ColorsModified::<TableColors>::diff_sel_foreground(&r, &ctx), GREEN);
    }
}
