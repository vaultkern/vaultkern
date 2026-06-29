#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod app {
    use std::sync::Arc;

    use eframe::egui;
    use egui::{Color32, FontData, FontDefinitions, FontFamily, FontId, RichText, Stroke};
    use vaultkern_native_setup::windows_setup;
    use vaultkern_native_setup::{BrowserDiagnosis, BrowserKind, RegistrationStatus};

    pub fn run() -> eframe::Result<()> {
        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([760.0, 640.0])
                .with_min_inner_size([680.0, 560.0]),
            ..Default::default()
        };

        eframe::run_native(
            "VaultKern Native Setup",
            options,
            Box::new(|cc| {
                configure_fonts(&cc.egui_ctx);
                configure_style(&cc.egui_ctx);
                Ok(Box::new(NativeSetupApp::new()))
            }),
        )
    }

    struct NativeSetupApp {
        extension_id: String,
        chrome: Option<BrowserDiagnosis>,
        edge: Option<BrowserDiagnosis>,
        message: String,
        diagnostics: String,
    }

    impl NativeSetupApp {
        fn new() -> Self {
            let extension_id = std::env::args()
                .nth(1)
                .or_else(|| std::env::var("VAULTKERN_EXTENSION_ID").ok())
                .unwrap_or_default();
            let mut app = Self {
                extension_id,
                chrome: None,
                edge: None,
                message: String::new(),
                diagnostics: String::new(),
            };
            app.refresh();
            app
        }

        fn refresh(&mut self) {
            self.chrome = self.load(BrowserKind::Chrome);
            self.edge = self.load(BrowserKind::Edge);
            self.diagnostics = self.collect_diagnostics();
        }

        fn load(&mut self, browser: BrowserKind) -> Option<BrowserDiagnosis> {
            match windows_setup::diagnose_browser(browser, self.extension_id.trim()) {
                Ok(diagnosis) => Some(diagnosis),
                Err(error) => {
                    self.message = error;
                    None
                }
            }
        }

        fn register(&mut self, browser: BrowserKind) {
            match windows_setup::default_config(browser, self.extension_id.trim())
                .and_then(|config| windows_setup::register_browser(&config))
            {
                Ok(()) => self.message = format!("{} registered.", browser.label()),
                Err(error) => {
                    self.message = format!("{} registration failed: {error}", browser.label())
                }
            }
            self.refresh();
        }

        fn unregister(&mut self, browser: BrowserKind) {
            match windows_setup::unregister_browser(browser) {
                Ok(()) => self.message = format!("{} unregistered.", browser.label()),
                Err(error) => {
                    self.message = format!("{} unregister failed: {error}", browser.label())
                }
            }
            self.refresh();
        }

        fn collect_diagnostics(&self) -> String {
            let mut lines = Vec::new();
            lines.push(format!("extension id: {}", self.extension_id.trim()));
            for diagnosis in [&self.chrome, &self.edge].into_iter().flatten() {
                lines.push(String::new());
                lines.push(diagnosis.diagnostic_text());
            }
            lines.join("\n")
        }
    }

    impl eframe::App for NativeSetupApp {
        fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
            egui::Frame::NONE
                .fill(palette::APP_BG)
                .inner_margin(egui::Margin::same(24))
                .show(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            header(ui);
                            ui.add_space(18.0);
                            self.extension_panel(ui);
                            ui.add_space(18.0);

                            let chrome = self.chrome.clone();
                            browser_card(ui, BrowserKind::Chrome, chrome.as_ref(), self);
                            ui.add_space(12.0);
                            let edge = self.edge.clone();
                            browser_card(ui, BrowserKind::Edge, edge.as_ref(), self);
                            ui.add_space(16.0);

                            if !self.message.is_empty() {
                                info_bar(ui, &self.message);
                                ui.add_space(12.0);
                            }

                            diagnostics_panel(ui, &self.diagnostics);
                        });
                });
        }
    }

    impl NativeSetupApp {
        fn extension_panel(&mut self, ui: &mut egui::Ui) {
            egui::Frame::NONE
                .fill(Color32::WHITE)
                .stroke(Stroke::new(1.0, palette::BORDER))
                .corner_radius(egui::CornerRadius::same(8))
                .inner_margin(egui::Margin::symmetric(18, 16))
                .show(ui, |ui| {
                    ui.label(
                        RichText::new("Extension ID")
                            .size(15.0)
                            .color(palette::MUTED)
                            .strong(),
                    );
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        let response = ui.add(
                            egui::TextEdit::singleline(&mut self.extension_id)
                                .desired_width(390.0)
                                .hint_text("Chrome extension id"),
                        );
                        if response.changed() {
                            self.refresh();
                        }

                        if secondary_button(ui, "Refresh").clicked() {
                            self.refresh();
                        }

                        if secondary_button(ui, "Copy diagnostics").clicked() {
                            ui.ctx().copy_text(self.diagnostics.clone());
                            self.message = "Diagnostics copied.".into();
                        }
                    });

                    if self.extension_id.trim().is_empty() {
                        ui.add_space(10.0);
                        warning_bar(
                            ui,
                            "Enter the Chrome extension id before registering a browser.",
                        );
                    }
                });
        }
    }

    fn configure_style(ctx: &egui::Context) {
        ctx.set_visuals(egui::Visuals::light());
        let mut style = (*ctx.style_of(egui::Theme::Light)).clone();
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(12.0, 7.0);
        style.text_styles.insert(
            egui::TextStyle::Heading,
            FontId::new(24.0, FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Body,
            FontId::new(15.0, FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Button,
            FontId::new(15.0, FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Monospace,
            FontId::new(13.0, FontFamily::Monospace),
        );
        style.visuals.override_text_color = Some(palette::TEXT);
        style.visuals.panel_fill = palette::APP_BG;
        style.visuals.window_fill = palette::APP_BG;
        style.visuals.widgets.inactive.bg_fill = Color32::WHITE;
        style.visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, palette::TEXT);
        style.visuals.widgets.hovered.bg_fill = palette::BUTTON_HOVER;
        style.visuals.widgets.active.bg_fill = palette::BUTTON_ACTIVE;
        style.visuals.selection.bg_fill = palette::ACCENT;
        ctx.set_style_of(egui::Theme::Light, style);
    }

    fn configure_fonts(ctx: &egui::Context) {
        let mut fonts = FontDefinitions::default();
        insert_font(
            &mut fonts,
            "Segoe UI",
            r"C:\Windows\Fonts\segoeui.ttf",
            &[FontFamily::Proportional],
        );
        insert_font(
            &mut fonts,
            "Microsoft YaHei",
            r"C:\Windows\Fonts\msyh.ttc",
            &[FontFamily::Proportional],
        );
        insert_font(
            &mut fonts,
            "Consolas",
            r"C:\Windows\Fonts\consola.ttf",
            &[FontFamily::Monospace],
        );
        ctx.set_fonts(fonts);
    }

    fn insert_font(fonts: &mut FontDefinitions, name: &str, path: &str, families: &[FontFamily]) {
        let Ok(bytes) = std::fs::read(path) else {
            return;
        };

        fonts
            .font_data
            .insert(name.into(), Arc::new(FontData::from_owned(bytes)));
        for family in families {
            fonts
                .families
                .entry(family.clone())
                .or_default()
                .insert(0, name.into());
        }
    }

    fn header(ui: &mut egui::Ui) {
        ui.label(
            RichText::new("VaultKern Native Setup")
                .size(24.0)
                .color(palette::TEXT)
                .strong(),
        );
        ui.add(
            egui::Label::new(
                RichText::new("Register the native messaging host for this Windows user.")
                    .size(16.0)
                    .color(palette::MUTED),
            )
            .wrap(),
        );
    }

    fn browser_card(
        ui: &mut egui::Ui,
        browser: BrowserKind,
        diagnosis: Option<&BrowserDiagnosis>,
        app: &mut NativeSetupApp,
    ) {
        egui::Frame::NONE
            .fill(Color32::WHITE)
            .stroke(Stroke::new(1.0, palette::BORDER))
            .corner_radius(egui::CornerRadius::same(8))
            .inner_margin(egui::Margin::symmetric(18, 16))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(browser.label())
                            .size(22.0)
                            .color(palette::TEXT)
                            .strong(),
                    );
                    ui.add_space(8.0);
                    match diagnosis {
                        Some(diagnosis) => status_badge(ui, diagnosis.status),
                        None => status_badge(ui, RegistrationStatus::NeedsRepair),
                    }
                });

                ui.add_space(8.0);
                match diagnosis {
                    Some(diagnosis) => {
                        ui.add(
                            egui::Label::new(
                                RichText::new(&diagnosis.detail)
                                    .size(16.0)
                                    .color(palette::MUTED),
                            )
                            .wrap(),
                        );
                    }
                    None => {
                        ui.add(
                            egui::Label::new(
                                RichText::new("Unable to read browser registration status.")
                                    .size(16.0)
                                    .color(palette::MUTED),
                            )
                            .wrap(),
                        );
                    }
                }

                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    let can_register = !app.extension_id.trim().is_empty()
                        && diagnosis
                            .map(|diagnosis| {
                                diagnosis.status != RegistrationStatus::BrowserMissing
                                    && diagnosis.status != RegistrationStatus::RuntimeMissing
                            })
                            .unwrap_or(false);

                    if primary_button(ui, "Register / Repair", can_register).clicked() {
                        app.register(browser);
                    }

                    if secondary_button(ui, "Unregister").clicked() {
                        app.unregister(browser);
                    }
                });

                if let Some(diagnosis) = diagnosis {
                    ui.add_space(10.0);
                    egui::CollapsingHeader::new("Details")
                        .id_salt((browser.label(), "details"))
                        .default_open(false)
                        .show(ui, |ui| {
                            detail_row(ui, "Registry", diagnosis.config.registry_key());
                            detail_row(
                                ui,
                                "Registered manifest",
                                &optional_path(&diagnosis.registry_manifest_path),
                            );
                            detail_row(
                                ui,
                                "Expected manifest",
                                &diagnosis.manifest_path.display().to_string(),
                            );
                            detail_row(
                                ui,
                                "Runtime",
                                &diagnosis.runtime_path.display().to_string(),
                            );
                            detail_row(ui, "Browser", &optional_path(&diagnosis.browser_path));
                        });
                }
            });
    }

    fn diagnostics_panel(ui: &mut egui::Ui, diagnostics: &str) {
        egui::CollapsingHeader::new("Diagnostics")
            .default_open(false)
            .show(ui, |ui| {
                egui::Frame::NONE
                    .fill(palette::DETAIL_BG)
                    .corner_radius(egui::CornerRadius::same(6))
                    .inner_margin(egui::Margin::same(12))
                    .show(ui, |ui| {
                        ui.add(
                            egui::Label::new(
                                RichText::new(diagnostics)
                                    .monospace()
                                    .size(13.0)
                                    .color(palette::TEXT),
                            )
                            .wrap(),
                        );
                    });
            });
    }

    fn status_badge(ui: &mut egui::Ui, status: RegistrationStatus) {
        let (text, fg, bg) = match status {
            RegistrationStatus::Registered => ("Ready", palette::READY, palette::READY_BG),
            RegistrationStatus::NotRegistered => {
                ("Not registered", palette::WARN, palette::WARN_BG)
            }
            RegistrationStatus::NeedsRepair => ("Needs repair", palette::WARN, palette::WARN_BG),
            RegistrationStatus::BrowserMissing => {
                ("Browser missing", palette::MUTED, palette::SOFT_BG)
            }
            RegistrationStatus::RuntimeMissing => {
                ("Runtime missing", palette::DANGER, palette::DANGER_BG)
            }
        };

        egui::Frame::NONE
            .fill(bg)
            .corner_radius(egui::CornerRadius::same(12))
            .inner_margin(egui::Margin::symmetric(10, 5))
            .show(ui, |ui| {
                ui.label(RichText::new(text).size(14.0).color(fg).strong());
            });
    }

    fn primary_button(ui: &mut egui::Ui, text: &str, enabled: bool) -> egui::Response {
        ui.add_enabled(
            enabled,
            egui::Button::new(RichText::new(text).strong().color(Color32::WHITE))
                .fill(palette::ACCENT)
                .corner_radius(egui::CornerRadius::same(6)),
        )
    }

    fn secondary_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
        ui.add(
            egui::Button::new(RichText::new(text).color(palette::TEXT))
                .fill(Color32::WHITE)
                .stroke(Stroke::new(1.0, palette::BORDER))
                .corner_radius(egui::CornerRadius::same(6)),
        )
    }

    fn warning_bar(ui: &mut egui::Ui, text: &str) {
        egui::Frame::NONE
            .fill(palette::WARN_BG)
            .corner_radius(egui::CornerRadius::same(6))
            .inner_margin(egui::Margin::symmetric(12, 8))
            .show(ui, |ui| {
                ui.label(RichText::new(text).color(palette::WARN).strong());
            });
    }

    fn info_bar(ui: &mut egui::Ui, text: &str) {
        egui::Frame::NONE
            .fill(palette::SOFT_BG)
            .corner_radius(egui::CornerRadius::same(6))
            .inner_margin(egui::Margin::symmetric(12, 8))
            .show(ui, |ui| {
                ui.label(RichText::new(text).color(palette::TEXT));
            });
    }

    fn detail_row(ui: &mut egui::Ui, label: &str, value: &str) {
        ui.horizontal_wrapped(|ui| {
            ui.set_min_height(22.0);
            ui.label(
                RichText::new(format!("{label}:"))
                    .size(14.0)
                    .color(palette::MUTED)
                    .strong(),
            );
            ui.label(RichText::new(value).size(14.0).color(palette::TEXT));
        });
    }

    fn optional_path(path: &Option<std::path::PathBuf>) -> String {
        path.as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "not found".into())
    }

    mod palette {
        use super::egui::Color32;

        pub const APP_BG: Color32 = Color32::from_rgb(245, 247, 250);
        pub const BORDER: Color32 = Color32::from_rgb(181, 190, 204);
        pub const TEXT: Color32 = Color32::from_rgb(15, 23, 42);
        pub const MUTED: Color32 = Color32::from_rgb(51, 65, 85);
        pub const SOFT_BG: Color32 = Color32::from_rgb(229, 236, 246);
        pub const DETAIL_BG: Color32 = Color32::from_rgb(232, 238, 247);
        pub const BUTTON_HOVER: Color32 = Color32::from_rgb(218, 227, 240);
        pub const BUTTON_ACTIVE: Color32 = Color32::from_rgb(199, 213, 232);
        pub const ACCENT: Color32 = Color32::from_rgb(30, 82, 170);
        pub const READY: Color32 = Color32::from_rgb(0, 92, 59);
        pub const READY_BG: Color32 = Color32::from_rgb(196, 239, 220);
        pub const WARN: Color32 = Color32::from_rgb(116, 65, 0);
        pub const WARN_BG: Color32 = Color32::from_rgb(255, 230, 176);
        pub const DANGER: Color32 = Color32::from_rgb(153, 27, 27);
        pub const DANGER_BG: Color32 = Color32::from_rgb(254, 210, 210);
    }
}

#[cfg(windows)]
fn main() -> eframe::Result<()> {
    app::run()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("vaultkern-native-setup GUI is available on Windows.");
}
