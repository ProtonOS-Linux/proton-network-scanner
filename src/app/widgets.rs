//! Small drawing helpers shared by both tabs: colours, the logo, severity
//! tags, toolbar sizing and the empty-state message.

use eframe::egui::{self, Color32, CornerRadius, RichText, Sense, Stroke, Vec2};

use crate::vuln::score::Severity;

/// Proton blue: main buttons, selection, progress.
pub const ACCENT: Color32 = Color32::from_rgb(31, 111, 235);
/// Logo magenta (also used for report branding).
pub const MAGENTA: Color32 = Color32::from_rgb(200, 28, 146);
/// Darker brand magenta (pressed buttons, borders).
pub const MAGENTA_DARK: Color32 = Color32::from_rgb(132, 16, 98);
/// "Good" green (live devices, confirmed-OK states).
pub const GREEN: Color32 = Color32::from_rgb(46, 160, 67);
/// Warning amber.
pub const AMBER: Color32 = Color32::from_rgb(210, 153, 34);
/// Error / danger red.
pub const RED: Color32 = Color32::from_rgb(207, 34, 46);

/// Height of every control in the toolbars, so text boxes, buttons and menus
/// line up and rows have the same rhythm.
pub const CONTROL_H: f32 = 30.0;

/// Apply toolbar sizing to `ui`: equal control heights and comfortable gaps
/// (the vertical gap matters when a toolbar wraps onto a second line).
pub fn toolbar_spacing(ui: &mut egui::Ui) {
    let s = ui.spacing_mut();
    s.interact_size.y = CONTROL_H;
    s.item_spacing = Vec2::new(8.0, 10.0);
    s.button_padding = Vec2::new(12.0, 6.0);
}

/// A bold toolbar label, vertically centred on the controls next to it.
pub fn toolbar_label(ui: &mut egui::Ui, text: &str) {
    let galley = ui.painter().layout_no_wrap(
        text.to_string(),
        egui::FontId::proportional(14.0),
        ui.visuals().strong_text_color(),
    );
    let (rect, _) = ui.allocate_exact_size(Vec2::new(galley.size().x, CONTROL_H), Sense::hover());
    let pos = egui::pos2(rect.left(), rect.center().y - galley.size().y / 2.0);
    ui.painter().galley(pos, galley, ui.visuals().strong_text_color());
}

/// A single-line text box exactly `CONTROL_H` tall.
pub fn text_box<'t>(text: &'t mut String, width: f32, hint: &str, limit: usize) -> egui::TextEdit<'t> {
    egui::TextEdit::singleline(text)
        .hint_text(hint)
        .desired_width(width)
        .char_limit(limit)
        .min_size(Vec2::new(width, CONTROL_H))
        .align(egui::Align2::LEFT_CENTER)
        .margin(Vec2::new(8.0, 6.0))
}

/// The big coloured action button (Scan / Start / Stop).
pub fn action_button(label: &str, fill: Color32) -> egui::Button<'static> {
    egui::Button::new(RichText::new(label.to_string()).size(15.0).strong().color(Color32::WHITE))
        .fill(fill)
        .min_size(Vec2::new(110.0, CONTROL_H + 2.0))
}

/// A secondary toolbar button with the standard height.
pub fn tool_button(label: &str) -> egui::Button<'static> {
    egui::Button::new(label.to_string()).min_size(Vec2::new(0.0, CONTROL_H))
}

/// Radar logo on a magenta tile, painted with shapes (crisp at any scale).
pub fn logo(ui: &mut egui::Ui, size: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let p = ui.painter();
    let k = size / 36.0;
    p.rect_filled(rect, CornerRadius::same((9.0 * k) as u8), MAGENTA);
    // Darker lower half for a subtle gradient feel.
    let lower = egui::Rect::from_min_max(egui::pos2(rect.left(), rect.center().y), rect.max);
    p.rect_filled(
        lower,
        CornerRadius { nw: 0, ne: 0, sw: (9.0 * k) as u8, se: (9.0 * k) as u8 },
        MAGENTA_DARK.linear_multiply(0.35),
    );
    let c = rect.center();
    let white = Stroke::new(1.5 * k, Color32::WHITE);
    for r in [5.0, 9.5, 14.0] {
        p.circle_stroke(c, r * k, white);
    }
    p.line_segment([c, c + Vec2::new(9.0, -11.0) * k], Stroke::new(2.0 * k, Color32::WHITE));
    p.circle_filled(c + Vec2::new(6.5, -6.5) * k, 2.2 * k, Color32::WHITE);
    p.circle_filled(c, 2.0 * k, Color32::WHITE);
}

/// Colour for a severity level (same colours as the reports).
pub fn severity_color(s: Severity) -> Color32 {
    let (r, g, b) = s.rgb();
    Color32::from_rgb(r, g, b)
}

/// "Confirmed" / "Version match" / "May be backported" / "Unverified",
/// coloured by how much to trust the finding.
pub fn confidence_label(ui: &mut egui::Ui, c: crate::vuln::Confidence) -> egui::Response {
    use crate::vuln::Confidence::*;
    let (icon, color) = match c {
        Confirmed => ("✔", GREEN),
        VersionMatch => ("≈", ui.visuals().text_color()),
        Backported => ("?", AMBER),
        Unverified => ("⚠", Color32::from_rgb(139, 92, 246)),
    };
    ui.label(RichText::new(format!("{icon} {}", c.label())).color(color)).on_hover_text(c.help())
}

/// A small filled label like `CRITICAL`.
pub fn severity_tag(ui: &mut egui::Ui, s: Severity) -> egui::Response {
    let text = s.label().to_uppercase();
    let galley = ui.painter().layout_no_wrap(text, egui::FontId::proportional(10.5), Color32::WHITE);
    let size = galley.size() + Vec2::new(12.0, 5.0);
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(size.x.max(64.0), size.y), Sense::hover());
    ui.painter().rect_filled(rect, CornerRadius::same(4), severity_color(s));
    ui.painter().galley(rect.center() - galley.size() / 2.0, galley, Color32::WHITE);
    resp
}

/// "KEV" badge for known-exploited vulnerabilities.
pub fn kev_badge(ui: &mut egui::Ui) {
    let galley = ui.painter().layout_no_wrap("KEV".into(), egui::FontId::proportional(10.0), Color32::WHITE);
    let (rect, resp) = ui.allocate_exact_size(galley.size() + Vec2::new(10.0, 4.0), Sense::hover());
    ui.painter().rect_filled(rect, CornerRadius::same(4), RED);
    ui.painter().galley(rect.center() - galley.size() / 2.0, galley, Color32::WHITE);
    resp.on_hover_text("Known exploited: listed in CISA's KEV catalog");
}

/// Centered message for an empty table.
pub fn empty_state(ui: &mut egui::Ui, icon: &str, busy: bool, busy_text: &str, title: &str, text: &str) {
    ui.add_space(ui.available_height() * 0.28);
    ui.vertical_centered(|ui| {
        ui.label(RichText::new(icon).size(42.0).weak());
        if busy {
            ui.spinner();
            ui.label(busy_text);
        } else {
            ui.label(RichText::new(title).size(17.0).strong());
            ui.label(RichText::new(text).weak());
        }
    });
}

/// A value that can be copied with a right-click menu instead of text
/// selection (selection would turn the mouse into a text cursor and steal
/// clicks from tables).
pub fn copy_value(ui: &mut egui::Ui, text: impl Into<RichText>, copy: &str) -> egui::Response {
    let resp = ui.add(egui::Label::new(text.into()).wrap().sense(Sense::click()));
    let copy = copy.to_string();
    resp.context_menu(|ui| {
        if ui.button("📋 Copy").clicked() {
            ui.ctx().copy_text(copy.clone());
            ui.close();
        }
    });
    resp
}
