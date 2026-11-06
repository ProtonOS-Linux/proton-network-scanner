//! "Ping test" window for the selected device: live latency chart, packet
//! loss, min/avg/max and jitter, with a plain-language verdict.

use std::net::Ipv4Addr;
use std::time::Duration;

use eframe::egui::{self, Color32, CornerRadius, RichText, Sense, Stroke, Vec2, pos2};

use super::widgets::{ACCENT, AMBER, GREEN, RED, action_button, toolbar_spacing};
use crate::scanner::pingtest::{PingOptions, PingTest, Probe};

/// State of the ping window (kept while it is open).
pub struct PingWindow {
    pub ip: Ipv4Addr,
    pub name: String,
    open_ports: Vec<u16>,
    count_idx: usize,
    interval_idx: usize,
    test: Option<PingTest>,
    pub open: bool,
    ctx: egui::Context,
}

/// Choices for how many pings to send (0 = until stopped).
const COUNTS: [(u32, &str); 4] = [(10, "10 pings"), (50, "50 pings"), (100, "100 pings"), (0, "Continuous")];
/// Choices for the time between pings, in milliseconds.
const INTERVALS: [(u64, &str); 4] =
    [(200, "every 0.2 s"), (500, "every 0.5 s"), (1000, "every 1 s"), (2000, "every 2 s")];

impl PingWindow {
    /// Open the window and start pinging right away.
    pub fn new(ctx: &egui::Context, ip: Ipv4Addr, name: String, open_ports: Vec<u16>) -> PingWindow {
        let mut w = PingWindow {
            ip,
            name,
            open_ports,
            count_idx: 1,
            interval_idx: 2,
            test: None,
            open: true,
            ctx: ctx.clone(),
        };
        w.start();
        w
    }

    /// Start (or restart) the ping test with the chosen count and interval.
    fn start(&mut self) {
        let opts = PingOptions {
            count: COUNTS[self.count_idx].0,
            interval: Duration::from_millis(INTERVALS[self.interval_idx].0),
            timeout: Duration::from_millis(1_000),
        };
        let ctx = self.ctx.clone();
        self.test = Some(PingTest::start(self.ip, opts, &self.open_ports, move || ctx.request_repaint()));
    }

    /// Is a ping test currently running?
    pub fn running(&self) -> bool {
        self.test.as_ref().is_some_and(|t| t.running)
    }

    /// Draw the window. Returns false once it has been closed.
    pub fn show(&mut self, ctx: &egui::Context) -> bool {
        if let Some(t) = &mut self.test {
            t.poll();
        }

        let title = if self.name.is_empty() {
            format!("Ping test — {}", self.ip)
        } else {
            format!("Ping test — {} ({})", self.name, self.ip)
        };
        let mut open = self.open;
        egui::Window::new(title)
            .id(egui::Id::unique("ping-window"))
            .open(&mut open)
            .pivot(egui::Align2::CENTER_CENTER)
            .default_pos(ctx.content_rect().center())
            .default_size([620.0, 430.0])
            .min_width(520.0)
            .collapsible(false)
            .show(ctx, |ui| self.contents(ui));
        self.open = open;
        if !self.open {
            // Dropping the test stops its thread.
            self.test = None;
        }
        self.open
    }

    /// Window contents: options, live statistics, the latency chart and a verdict.
    fn contents(&mut self, ui: &mut egui::Ui) {
        // ---- Controls ----
        ui.horizontal_wrapped(|ui| {
            toolbar_spacing(ui);
            let running = self.running();
            if running {
                if ui.add(action_button("■  Stop", RED)).clicked()
                    && let Some(t) = &self.test
                {
                    t.stop();
                }
            } else if ui.add(action_button("▶  Start", ACCENT)).clicked() {
                self.start();
            }
            ui.add_enabled_ui(!running, |ui| {
                egui::ComboBox::from_id_salt("ping-count").selected_text(COUNTS[self.count_idx].1).show_ui(ui, |ui| {
                    for (i, (_, label)) in COUNTS.iter().enumerate() {
                        ui.selectable_value(&mut self.count_idx, i, *label);
                    }
                });
                egui::ComboBox::from_id_salt("ping-interval").selected_text(INTERVALS[self.interval_idx].1).show_ui(
                    ui,
                    |ui| {
                        for (i, (_, label)) in INTERVALS.iter().enumerate() {
                            ui.selectable_value(&mut self.interval_idx, i, *label);
                        }
                    },
                );
            });
            if let Some(t) = &self.test {
                let how = match t.probe {
                    Probe::Icmp => "ICMP echo".to_string(),
                    Probe::Tcp(p) => format!("TCP connect to port {p} (ping not allowed)"),
                };
                ui.label(RichText::new(how).weak());
            }
        });
        ui.add_space(8.0);

        let Some(t) = &self.test else { return };
        let s = &t.stats;

        // ---- Statistics cards ----
        let ms = |v: Option<f32>| v.map(|x| format!("{x:.1} ms")).unwrap_or_else(|| "—".into());
        let loss_color = match s.loss_percent() {
            0.0 => GREEN,
            l if l < 5.0 => AMBER,
            _ => RED,
        };
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = Vec2::new(8.0, 8.0);
            stat(ui, "Sent", s.sent.to_string(), None);
            stat(ui, "Received", s.received.to_string(), None);
            stat(ui, "Lost", format!("{} ({:.1}%)", s.lost(), s.loss_percent()), Some(loss_color));
            stat(ui, "Min", ms((s.received > 0).then_some(s.min)), None);
            stat(ui, "Average", ms(s.avg()), None);
            stat(ui, "Max", ms((s.received > 0).then_some(s.max)), None);
            stat(ui, "Jitter", ms(s.jitter()), None);
        });
        ui.add_space(8.0);

        // ---- Chart ----
        // Leave room for the whole planned run (or a minute when continuous).
        let planned = if COUNTS[self.count_idx].0 == 0 { 60 } else { COUNTS[self.count_idx].0 as usize };
        chart(ui, t, planned);
        ui.add_space(6.0);

        // ---- Verdict ----
        if s.sent >= 5 {
            let (text, color) = verdict(s.loss_percent(), s.avg(), s.jitter());
            ui.label(RichText::new(text).color(color).strong());
        } else if t.running {
            ui.label(RichText::new("Measuring…").weak());
        }
    }
}

/// One statistic in a small rounded card.
fn stat(ui: &mut egui::Ui, label: &str, value: String, color: Option<Color32>) {
    egui::Frame::new()
        .fill(ui.visuals().faint_bg_color)
        .corner_radius(CornerRadius::same(8))
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.set_min_width(62.0);
            ui.vertical(|ui| {
                ui.label(RichText::new(label).small().weak());
                let mut v = RichText::new(value).strong().size(15.0);
                if let Some(c) = color {
                    v = v.color(c);
                }
                ui.label(v);
            });
        });
}

/// Bar chart of the most recent samples; lost packets are red marks.
fn chart(ui: &mut egui::Ui, t: &PingTest, planned: usize) {
    let width = ui.available_width().max(200.0);
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 170.0), Sense::hover());
    let p = ui.painter_at(rect);
    let bg = ui.visuals().extreme_bg_color;
    p.rect_filled(rect, CornerRadius::same(8), bg);

    let plot = rect.shrink2(Vec2::new(44.0, 14.0)).translate(Vec2::new(18.0, 0.0));
    let text_color = ui.visuals().weak_text_color();
    let grid = ui.visuals().widgets.noninteractive.bg_stroke.color;

    // How many bars fit (at least 3 px each); show the newest ones.
    let max_bars = ((plot.width() / 4.0) as usize).max(10);
    let n = t.samples.len().min(max_bars);
    // Bar slots: enough for the planned run so bars fill the chart, never
    // narrower than 4 px (older samples scroll off the left).
    let slots = planned.max(n).clamp(10, max_bars);
    let recent: Vec<Option<f32>> = t.samples.iter().skip(t.samples.len() - n).copied().collect();
    let top = recent.iter().flatten().fold(1.0f32, |m, v| m.max(*v)) * 1.2;
    let top = nice_ceiling(top);

    // Grid lines with labels.
    for i in 0..=4 {
        let v = top * i as f32 / 4.0;
        let y = plot.bottom() - plot.height() * i as f32 / 4.0;
        p.line_segment([pos2(plot.left(), y), pos2(plot.right(), y)], Stroke::new(0.5, grid));
        let label = if top <= 5.0 { format!("{v:.1} ms") } else { format!("{v:.0} ms") };
        p.text(
            pos2(plot.left() - 6.0, y),
            egui::Align2::RIGHT_CENTER,
            label,
            egui::FontId::proportional(10.0),
            text_color,
        );
    }
    if n == 0 {
        p.text(
            plot.center(),
            egui::Align2::CENTER_CENTER,
            "Waiting for the first reply…",
            egui::FontId::proportional(12.0),
            text_color,
        );
        return;
    }
    let slot = plot.width() / slots as f32;
    let bar_w = (slot * 0.7).max(2.0);
    for (i, s) in recent.iter().enumerate() {
        let x = plot.left() + slot * i as f32 + slot / 2.0;
        match s {
            Some(ms) => {
                let h = (ms / top).clamp(0.0, 1.0) * plot.height();
                let color = if *ms > 150.0 { AMBER } else { ACCENT };
                p.rect_filled(
                    egui::Rect::from_min_max(
                        pos2(x - bar_w / 2.0, plot.bottom() - h.max(1.5)),
                        pos2(x + bar_w / 2.0, plot.bottom()),
                    ),
                    CornerRadius::same(1),
                    color,
                );
            }
            None => {
                p.rect_filled(
                    egui::Rect::from_min_max(pos2(x - bar_w / 2.0, plot.top()), pos2(x + bar_w / 2.0, plot.bottom())),
                    CornerRadius::ZERO,
                    RED.linear_multiply(0.45),
                );
            }
        }
    }
    // Legend: coloured squares with labels, top right.
    let font = egui::FontId::proportional(10.0);
    let mut x = plot.right();
    for (label, color) in [("lost", RED.linear_multiply(0.6)), ("reply", ACCENT)] {
        let r = p.text(pos2(x, rect.top() + 4.0), egui::Align2::RIGHT_TOP, label, font.clone(), text_color);
        let sq = egui::Rect::from_min_size(pos2(r.left() - 12.0, r.center().y - 4.0), Vec2::splat(8.0));
        p.rect_filled(sq, CornerRadius::same(1), color);
        x = sq.left() - 10.0;
    }
}

/// Round the chart's top value up to 1, 2 or 5 × 10ⁿ ms.
fn nice_ceiling(v: f32) -> f32 {
    let mag = 10f32.powf(v.max(1.0).log10().floor());
    for m in [1.0, 2.0, 5.0, 10.0] {
        if v <= m * mag {
            return m * mag;
        }
    }
    10.0 * mag
}

/// Plain-language summary of the connection quality.
fn verdict(loss: f32, avg: Option<f32>, jitter: Option<f32>) -> (String, Color32) {
    let Some(avg) = avg else { return ("No replies: the device is offline or blocks this kind of probe.".into(), RED) };
    let jitter = jitter.unwrap_or(0.0);
    if loss == 0.0 && avg < 30.0 && jitter < 10.0 {
        ("Excellent: no packet loss and low, steady latency.".into(), GREEN)
    } else if loss < 1.0 && avg < 100.0 && jitter < 30.0 {
        ("Good: fine for browsing, streaming and calls.".into(), GREEN)
    } else if loss < 5.0 && avg < 250.0 {
        ("Fair: some loss or delay — video calls and games may stutter (weak Wi-Fi or a busy network).".into(), AMBER)
    } else {
        ("Poor: heavy packet loss or delay — check the cable / Wi-Fi signal or the device itself.".into(), RED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceilings() {
        assert_eq!(nice_ceiling(0.3), 1.0);
        assert_eq!(nice_ceiling(3.4), 5.0);
        assert_eq!(nice_ceiling(12.0), 20.0);
        assert_eq!(nice_ceiling(480.0), 500.0);
    }

    #[test]
    fn verdicts() {
        assert_eq!(verdict(0.0, Some(3.0), Some(1.0)).1, GREEN);
        assert_eq!(verdict(3.0, Some(40.0), Some(5.0)).1, AMBER);
        assert_eq!(verdict(30.0, Some(40.0), None).1, RED);
        assert_eq!(verdict(100.0, None, None).1, RED);
    }
}
