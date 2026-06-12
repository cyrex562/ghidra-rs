use eframe::egui;

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 600.0])
            .with_title("Ghidra-rs"),
        ..Default::default()
    };
    eframe::run_native(
        "ghidra_rs_app",
        native_options,
        Box::new(|_cc| Ok(Box::new(GhidraApp::default()))),
    )
}

struct GhidraApp {
    name: String,
    version: String,
}

impl Default for GhidraApp {
    fn default() -> Self {
        Self {
            name: "Ghidra-rs".to_owned(),
            version: "0.1.0".to_owned(),
        }
    }
}

impl eframe::App for GhidraApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading(format!("{} v{}", self.name, self.version));
            ui.separator();
            ui.label("Welcome to the Rust port of Ghidra.");
            ui.label("Phase 1: Foundation (Framework/Utility)");
        });
    }
}
