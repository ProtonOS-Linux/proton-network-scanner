//! The app icon (a radar sweep on a magenta tile), drawn pixel by pixel at start
//! so no image decoder or image file is needed. The same design is in
//! `assets/proton-ip-scanner.svg` for menus and the desktop.

use eframe::egui::IconData;

/// 64×64 RGBA icon for the window title bar / taskbar.
pub fn window_icon() -> IconData {
    /// Icon size in pixels (square).
    const N: usize = 64;
    let mut rgba = vec![0u8; N * N * 4];
    let c = (N as f32 - 1.0) / 2.0;

    for y in 0..N {
        for x in 0..N {
            let (fx, fy) = (x as f32 - c, y as f32 - c);
            let i = (y * N + x) * 4;

            // Rounded square tile (corner radius 14) — background.
            let (ax, ay) = (fx.abs() - (c - 14.0), fy.abs() - (c - 14.0));
            let outside = ax > 0.0 && ay > 0.0 && (ax * ax + ay * ay).sqrt() > 14.0;
            if outside {
                continue; // transparent
            }
            // Vertical magenta gradient: #DC2696 at the top to #8E106A at the bottom.
            let t = y as f32 / N as f32;
            let mut px = [(220.0 - 78.0 * t) as u8, (38.0 - 22.0 * t) as u8, (150.0 - 44.0 * t) as u8, 255u8];

            let r = (fx * fx + fy * fy).sqrt();
            let angle = fy.atan2(fx); // -π..π, 0 = right
            // Three thin rings.
            let ring = [9.0f32, 17.0, 25.0].iter().any(|&rr| (r - rr).abs() < 1.1);
            // Sweep: a soft wedge from 12 o'clock to 2 o'clock.
            let sweep = r < 25.0 && (-1.57..-0.5).contains(&angle);
            // Centre dot and a "found device" blip.
            let dot = r < 3.2;
            let blip = ((fx - 11.0).powi(2) + (fy + 12.0).powi(2)).sqrt() < 3.4;

            if ring || dot || blip {
                px = [255, 255, 255, 255];
            } else if sweep {
                px = [px[0] / 2 + 120, px[1] / 2 + 95, px[2] / 2 + 115, 255];
            }
            rgba[i..i + 4].copy_from_slice(&px);
        }
    }
    IconData { rgba, width: N as u32, height: N as u32 }
}
