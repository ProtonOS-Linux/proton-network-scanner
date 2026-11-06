//! PDF report, written directly (no PDF library, no font files).
//!
//! It uses the three standard PDF fonts every reader has built in
//! (Helvetica, Helvetica-Bold, Courier) with WinAnsi encoding, so the file is
//! small and needs nothing embedded. Text is wrapped with the real Helvetica
//! character widths (from the Adobe font metrics), and every string is
//! escaped, so text from scanned devices or NVD cannot break the PDF syntax.
//!
//! Layout: A4 portrait, 48 pt margins.
//! 1. Title band, scope and a severity summary.
//! 2. Top 10 vulnerabilities by priority.
//! 3. One block per vulnerability (with every affected host:port).
//! 4. Informational findings, hosts & services, how the scores work.

use std::fmt::Write as _;

use super::{METHOD_NOTES, ReportData};
use crate::vuln::score::Severity;

/// A4 page width in PDF points (1/72 inch).
const PAGE_W: f32 = 595.0;
/// A4 page height in PDF points.
const PAGE_H: f32 = 842.0;
/// Page margin on every side.
const MARGIN: f32 = 48.0;
/// Width available for text and tables.
const CONTENT_W: f32 = PAGE_W - 2.0 * MARGIN;
/// Lowest y for content (space for the footer below it).
const BOTTOM: f32 = MARGIN + 18.0;

/// Magenta (matches the app logo).
const BRAND: Rgb = (190, 24, 140);
/// Dark magenta for headings and the title bar.
const BRAND_DARK: Rgb = (110, 14, 82);
/// Body text colour.
const TEXT: Rgb = (30, 33, 41);
/// Secondary (grey) text colour.
const MUTED: Rgb = (95, 102, 115);
/// Colour of separator lines.
const RULE: Rgb = (220, 224, 230);
/// Background of every other table row.
const ZEBRA: Rgb = (246, 247, 249);
/// Green for the user's review marks and comments (readable on white).
const REVIEW_GREEN: Rgb = (21, 128, 61);

/// An RGB colour, 0–255 per channel.
type Rgb = (u8, u8, u8);

/// The three standard PDF fonts used (no font files are embedded).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Font {
    Regular,
    Bold,
    Mono,
}

impl Font {
    /// Resource name of the font inside the PDF.
    fn res(self) -> &'static str {
        match self {
            Font::Regular => "F1",
            Font::Bold => "F2",
            Font::Mono => "F3",
        }
    }
}

/// Helvetica / Helvetica-Bold advance widths for ASCII 32..=126 (1/1000 em).
const HELV: [u16; 95] = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556,
    556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833,
    722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556,
    556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334,
    260, 334, 584,
];
/// Character widths of Helvetica-Bold for ASCII 32–126, in 1/1000 em.
const HELV_BOLD: [u16; 95] = [
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556,
    556, 556, 556, 333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833,
    722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556, 333, 556, 611, 556, 611,
    556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389,
    280, 389, 584,
];

/// Map a character to a WinAnsi byte (unknown characters become '?').
fn win_ansi(c: char) -> u8 {
    match c {
        ' '..='~' => c as u8,
        '\u{a0}'..='\u{ff}' => c as u32 as u8, // Latin-1 range is identical in WinAnsi
        '…' => 0x85,
        '‘' => 0x91,
        '’' => 0x92,
        '“' => 0x93,
        '”' => 0x94,
        '•' => 0x95,
        '–' => 0x96,
        '—' => 0x97,
        '€' => 0x80,
        '™' => 0x99,
        '\t' | '\n' | '\r' => b' ',
        _ => b'?',
    }
}

/// Width of one character in 1/1000 em (used to wrap and align text).
fn char_width(c: char, font: Font) -> f32 {
    let b = win_ansi(c);
    match font {
        Font::Mono => 600.0,
        _ if (32..=126).contains(&b) => {
            let i = usize::from(b - 32);
            f32::from(if font == Font::Bold { HELV_BOLD[i] } else { HELV[i] })
        }
        _ => 556.0,
    }
}

/// Width of a string in points at the given font size.
fn text_width(s: &str, size: f32, font: Font) -> f32 {
    s.chars().map(|c| char_width(c, font)).sum::<f32>() * size / 1000.0
}

/// Shorten `s` with "…" so it fits `width`.
fn fit(s: &str, size: f32, font: Font, width: f32) -> String {
    if text_width(s, size, font) <= width {
        return s.to_string();
    }
    let ell = char_width('…', font) * size / 1000.0;
    let mut out = String::new();
    let mut w = 0.0;
    for c in s.chars() {
        let cw = char_width(c, font) * size / 1000.0;
        if w + cw + ell > width {
            break;
        }
        out.push(c);
        w += cw;
    }
    out.push('…');
    out
}

/// Greedy word wrap; very long words (URLs, vectors) are split by width.
fn wrap(s: &str, size: f32, font: Font, width: f32) -> Vec<String> {
    let mut lines = Vec::new();
    for para in s.split('\n') {
        let mut line = String::new();
        for word in para.split_whitespace() {
            let candidate = if line.is_empty() { word.to_string() } else { format!("{line} {word}") };
            if text_width(&candidate, size, font) <= width {
                line = candidate;
                continue;
            }
            if !line.is_empty() {
                lines.push(std::mem::take(&mut line));
            }
            // Break a word that is wider than the whole line.
            let mut piece = String::new();
            for c in word.chars() {
                if text_width(&format!("{piece}{c}"), size, font) > width && !piece.is_empty() {
                    lines.push(std::mem::take(&mut piece));
                }
                piece.push(c);
            }
            line = piece;
        }
        lines.push(line);
    }
    lines
}

/// Escape for a PDF literal string: `( ) \` escaped, non-ASCII as octal.
fn pdf_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        let b = win_ansi(c);
        match b {
            b'(' | b')' | b'\\' => {
                o.push('\\');
                o.push(b as char);
            }
            32..=126 => o.push(b as char),
            _ => {
                let _ = write!(o, "\\{b:03o}");
            }
        }
    }
    o
}

/// PDF colour operands "r g b" (0–1) for a colour.
fn rgb(c: Rgb) -> String {
    format!("{:.3} {:.3} {:.3}", f32::from(c.0) / 255.0, f32::from(c.1) / 255.0, f32::from(c.2) / 255.0)
}

/// Page-by-page drawing with an automatic "cursor" (y goes down the page).
struct Doc {
    pages: Vec<String>,
    cur: String,
    y: f32,
}

impl Doc {
    /// An empty document with one page.
    fn new() -> Doc {
        Doc { pages: Vec::new(), cur: String::new(), y: PAGE_H - MARGIN }
    }

    /// Finish the current page and start a new one.
    fn new_page(&mut self) {
        self.pages.push(std::mem::take(&mut self.cur));
        self.y = PAGE_H - MARGIN;
        // Thin brand line at the top of continuation pages.
        self.rect(0.0, PAGE_H - 6.0, PAGE_W, 6.0, BRAND);
    }

    /// Start a new page if less than `h` points are left.
    fn need(&mut self, h: f32) {
        if self.y - h < BOTTOM {
            self.new_page();
        }
    }

    /// Draw text at (x, y); the text is escaped so it cannot break the PDF.
    fn text(&mut self, x: f32, y: f32, size: f32, font: Font, color: Rgb, s: &str) {
        let _ = writeln!(
            self.cur,
            "BT /{} {size:.1} Tf {} rg {x:.2} {y:.2} Td ({}) Tj ET",
            font.res(),
            rgb(color),
            pdf_str(s)
        );
    }

    /// Draw a filled rectangle.
    fn rect(&mut self, x: f32, y: f32, w: f32, h: f32, color: Rgb) {
        let _ = writeln!(self.cur, "{} rg {x:.2} {y:.2} {w:.2} {h:.2} re f", rgb(color));
    }

    /// Draw a thin horizontal line across the content width.
    fn hline(&mut self, y: f32, color: Rgb) {
        let _ = writeln!(self.cur, "{} RG 0.6 w {MARGIN:.2} {y:.2} m {:.2} {y:.2} l S", rgb(color), PAGE_W - MARGIN);
    }

    /// Wrapped paragraph at the cursor.
    fn para(&mut self, x: f32, width: f32, size: f32, font: Font, color: Rgb, s: &str) {
        let lead = size * 1.35;
        for line in wrap(s, size, font, width) {
            self.need(lead);
            self.y -= lead;
            self.text(x, self.y + size * 0.3, size, font, color, &line);
        }
    }

    /// A section heading (starts a new page if there is too little room left).
    fn heading(&mut self, s: &str) {
        self.need(40.0);
        self.y -= 26.0;
        self.text(MARGIN, self.y, 14.0, Font::Bold, BRAND_DARK, s);
        self.y -= 6.0;
        self.hline(self.y, BRAND);
        self.y -= 4.0;
    }

    /// Small coloured severity label; returns its width.
    fn tag(&mut self, x: f32, y: f32, sev: Severity) -> f32 {
        let label = sev.label().to_uppercase();
        let w = text_width(&label, 7.5, Font::Bold) + 10.0;
        self.rect(x, y - 3.0, w, 12.0, sev.rgb());
        self.text(x + 5.0, y, 7.5, Font::Bold, (255, 255, 255), &label);
        w
    }

    /// Simple table: header row + rows, each cell shortened to its column.
    fn table(&mut self, cols: &[(&str, f32)], rows: &[Vec<String>], sev_col: Option<(usize, &[Severity])>) {
        let size = 8.0;
        let row_h = 15.0;
        let draw_header = |d: &mut Doc| {
            d.need(row_h * 2.0);
            d.y -= row_h;
            d.rect(MARGIN, d.y - 4.0, CONTENT_W, row_h, BRAND_DARK);
            let mut x = MARGIN + 4.0;
            for (name, w) in cols {
                d.text(x, d.y, size, Font::Bold, (255, 255, 255), name);
                x += w;
            }
        };
        draw_header(self);
        for (i, row) in rows.iter().enumerate() {
            if self.y - row_h < BOTTOM {
                self.new_page();
                draw_header(self);
            }
            self.y -= row_h;
            if i % 2 == 1 {
                self.rect(MARGIN, self.y - 4.0, CONTENT_W, row_h, ZEBRA);
            }
            let mut x = MARGIN + 4.0;
            for (c, (cell, (_, w))) in row.iter().zip(cols).enumerate() {
                match sev_col {
                    Some((sc, sevs)) if sc == c => {
                        if let Some(s) = sevs.get(i) {
                            self.tag(x, self.y, *s);
                        }
                    }
                    _ => {
                        let t = fit(cell, size, Font::Regular, w - 6.0);
                        self.text(x, self.y, size, Font::Regular, TEXT, &t);
                    }
                }
                x += w;
            }
        }
        self.y -= 6.0;
    }

    /// Serialise all pages into a PDF file.
    fn finish(mut self, title: &str) -> Vec<u8> {
        self.pages.push(std::mem::take(&mut self.cur));
        let n = self.pages.len();
        // Footer with page numbers on every page (total is known only now).
        for (i, page) in self.pages.iter_mut().enumerate() {
            let left = format!("Proton IP Scanner  |  {}", title);
            let right = format!("Page {} of {n}", i + 1);
            let rw = text_width(&right, 8.0, Font::Regular);
            let _ = writeln!(
                page,
                "{} RG 0.6 w {MARGIN:.2} {:.2} m {:.2} {:.2} l S",
                rgb(RULE),
                MARGIN + 4.0,
                PAGE_W - MARGIN,
                MARGIN + 4.0
            );
            let _ = writeln!(
                page,
                "BT /F1 8 Tf {} rg {MARGIN:.2} {:.2} Td ({}) Tj ET",
                rgb(MUTED),
                MARGIN - 8.0,
                pdf_str(&left)
            );
            let _ = writeln!(
                page,
                "BT /F1 8 Tf {} rg {:.2} {:.2} Td ({}) Tj ET",
                rgb(MUTED),
                PAGE_W - MARGIN - rw,
                MARGIN - 8.0,
                pdf_str(&right)
            );
        }

        // Objects: 1 catalog, 2 pages, 3-5 fonts, 6 info, then page + content per page.
        let mut out: Vec<u8> = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n".to_vec();
        let mut offsets: Vec<usize> = Vec::new();
        let mut obj = |out: &mut Vec<u8>, body: &[u8]| {
            offsets.push(out.len());
            out.extend_from_slice(format!("{} 0 obj\n", offsets.len()).as_bytes());
            out.extend_from_slice(body);
            out.extend_from_slice(b"\nendobj\n");
        };
        let kids: Vec<String> = (0..n).map(|i| format!("{} 0 R", 7 + 2 * i)).collect();
        obj(&mut out, b"<< /Type /Catalog /Pages 2 0 R >>");
        obj(&mut out, format!("<< /Type /Pages /Kids [{}] /Count {n} >>", kids.join(" ")).as_bytes());
        for base in ["Helvetica", "Helvetica-Bold", "Courier"] {
            obj(
                &mut out,
                format!("<< /Type /Font /Subtype /Type1 /BaseFont /{base} /Encoding /WinAnsiEncoding >>").as_bytes(),
            );
        }
        obj(
            &mut out,
            format!("<< /Title ({}) /Producer (Proton IP Scanner {}) >>", pdf_str(title), env!("CARGO_PKG_VERSION"))
                .as_bytes(),
        );
        for (i, content) in self.pages.iter().enumerate() {
            let page = format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] \
                 /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents {} 0 R >>",
                8 + 2 * i
            );
            obj(&mut out, page.as_bytes());
            let mut stream = format!("<< /Length {} >>\nstream\n", content.len()).into_bytes();
            stream.extend_from_slice(content.as_bytes());
            stream.extend_from_slice(b"\nendstream");
            obj(&mut out, &stream);
        }
        let xref_at = out.len();
        let mut xref = format!("xref\n0 {}\n0000000000 65535 f \n", offsets.len() + 1);
        for o in &offsets {
            let _ = writeln!(xref, "{o:010} 00000 n ");
        }
        let _ = write!(
            xref,
            "trailer\n<< /Size {} /Root 1 0 R /Info 6 0 R >>\nstartxref\n{xref_at}\n%%EOF\n",
            offsets.len() + 1
        );
        out.extend_from_slice(xref.as_bytes());
        out
    }
}

/// Build the report.
pub fn build(d: &ReportData<'_>) -> Vec<u8> {
    let mut doc = Doc::new();

    // ---- Title band ------------------------------------------------------
    doc.rect(0.0, PAGE_H - 96.0, PAGE_W, 96.0, BRAND);
    doc.rect(0.0, PAGE_H - 100.0, PAGE_W, 4.0, BRAND_DARK);
    doc.text(MARGIN, PAGE_H - 50.0, 22.0, Font::Bold, (255, 255, 255), "Vulnerability Assessment Report");
    doc.text(
        MARGIN,
        PAGE_H - 72.0,
        10.0,
        Font::Regular,
        (255, 228, 245),
        &format!("Proton IP Scanner {}  |  {}", env!("CARGO_PKG_VERSION"), d.generated),
    );
    doc.y = PAGE_H - 112.0;

    // ---- Scope ---------------------------------------------------------------
    let scope = [
        ("Targets", d.targets.clone()),
        ("Hosts assessed", d.hosts.to_string()),
        ("Open services", d.services.len().to_string()),
        ("Scan speed", d.speed.clone()),
        ("Duration", format!("{:.0} seconds", d.duration_secs)),
        ("Vulnerability data", d.cve_data.clone()),
        ("Reviewed", {
            let (done, all) = d.reviewed_count();
            format!("{done} of {all} findings marked as reviewed")
        }),
    ];
    for (k, v) in scope {
        doc.y -= 15.0;
        doc.text(MARGIN, doc.y, 9.0, Font::Bold, MUTED, k);
        doc.text(MARGIN + 110.0, doc.y, 9.0, Font::Regular, TEXT, &fit(&v, 9.0, Font::Regular, CONTENT_W - 110.0));
    }

    // ---- Severity summary boxes -------------------------------------------
    doc.heading("Summary");
    let box_w = (CONTENT_W - 5.0 * 8.0) / 6.0;
    doc.y -= 58.0;
    for (i, (sev, count)) in d.counts().iter().enumerate() {
        let x = MARGIN + i as f32 * (box_w + 8.0);
        doc.rect(x, doc.y, box_w, 52.0, sev.rgb());
        let num = count.to_string();
        doc.text(
            x + (box_w - text_width(&num, 20.0, Font::Bold)) / 2.0,
            doc.y + 24.0,
            20.0,
            Font::Bold,
            (255, 255, 255),
            &num,
        );
        let label = sev.label();
        doc.text(
            x + (box_w - text_width(label, 9.0, Font::Bold)) / 2.0,
            doc.y + 9.0,
            9.0,
            Font::Bold,
            (255, 255, 255),
            label,
        );
    }
    doc.y -= 6.0;
    let groups = d.groups();
    let distinct = groups.iter().filter(|g| !matches!(g.finding.severity, Severity::Info | Severity::Review)).count();
    let kev = groups.iter().filter(|g| g.finding.kev).count();
    doc.para(
        MARGIN,
        CONTENT_W,
        9.0,
        Font::Regular,
        MUTED,
        &format!(
            "Counts are findings per host. {distinct} distinct vulnerabilities (excluding informational), {kev} of them \
             known to be exploited (CISA KEV)."
        ),
    );
    for n in d.notes {
        doc.para(MARGIN, CONTENT_W, 9.0, Font::Bold, (180, 83, 9), &format!("Note: {n}"));
    }

    // ---- Top 10 ----------------------------------------------------------------
    doc.heading("Top 10 vulnerabilities by priority");
    if d.top10.is_empty() {
        doc.para(
            MARGIN,
            CONTENT_W,
            9.5,
            Font::Regular,
            TEXT,
            "No vulnerabilities above informational level were found.",
        );
    } else {
        let cols = [
            ("#", 16.0),
            ("Severity", 58.0),
            ("ID", 78.0),
            ("Vulnerability", 162.0),
            ("Hosts", 30.0),
            ("CVSS", 34.0),
            ("EPSS", 34.0),
            ("PPR", 28.0),
            ("KEV", 27.0),
            ("Reviewed", 32.0),
        ];
        let rows: Vec<Vec<String>> = d
            .top10
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let f = &t.finding;
                vec![
                    (i + 1).to_string(),
                    String::new(),
                    f.id.clone(),
                    f.title.clone(),
                    t.hosts.to_string(),
                    f.cvss.as_ref().map(|c| format!("{:.1}", c.score)).unwrap_or_else(|| "-".into()),
                    f.epss.map(|e| format!("{:.1}%", e.probability * 100.0)).unwrap_or_else(|| "-".into()),
                    format!("{:.1}", f.ppr),
                    if f.kev { "Yes".into() } else { String::new() },
                    match d.review_status(&f.id).as_str() {
                        "" => String::new(),
                        "Yes" => "Yes".into(),
                        _ => "Part".into(),
                    },
                ]
            })
            .collect();
        let sevs: Vec<Severity> = d.top10.iter().map(|t| t.finding.severity).collect();
        doc.table(&cols, &rows, Some((1, &sevs)));
    }

    // ---- Detailed findings ----------------------------------------------------
    doc.heading("Findings");
    let (main, info): (Vec<_>, Vec<_>) = groups.iter().partition(|g| g.finding.severity != Severity::Info);
    // "Needs manual check" items get their own section after the real findings.
    let (review, main): (Vec<_>, Vec<_>) = main.into_iter().partition(|g| g.finding.severity == Severity::Review);
    if main.is_empty() {
        doc.para(
            MARGIN,
            CONTENT_W,
            9.5,
            Font::Regular,
            TEXT,
            "No vulnerabilities above informational level were found.",
        );
    }
    let sections = [(None, main), (Some("Needs manual check"), review)];
    for (heading, list) in &sections {
        if let Some(h) = heading {
            if list.is_empty() {
                continue;
            }
            doc.heading(h);
            doc.para(
                MARGIN,
                CONTENT_W,
                9.0,
                Font::Regular,
                MUTED,
                "The scanner could see these programs but not their exact version, so known vulnerabilities could be \
             neither confirmed nor ruled out. They are not counted as vulnerabilities and may be false positives: \
             check the installed version as described for each one.",
            );
        }
        for g in list {
            let f = g.finding;
            doc.need(90.0);
            doc.y -= 18.0;
            let w = doc.tag(MARGIN, doc.y, f.severity);
            let head = format!("{}  {}", f.id, if f.kev { "|  KNOWN EXPLOITED (CISA KEV)" } else { "" });
            doc.text(MARGIN + w + 8.0, doc.y, 9.5, Font::Bold, if f.kev { (185, 28, 28) } else { BRAND_DARK }, &head);
            doc.y -= 5.0; // breathing room between the tag line and the title
            doc.para(MARGIN, CONTENT_W, 10.5, Font::Bold, TEXT, &f.title);
            let scores = format!(
                "CVSS {}: {}   |   EPSS: {}   |   PPR: {:.1}{}",
                f.cvss.as_ref().map(|c| c.version.as_str()).unwrap_or("-"),
                f.cvss.as_ref().map(|c| format!("{:.1}", c.score)).unwrap_or_else(|| "not scored".into()),
                f.epss
                    .map(|e| format!("{:.2}% (percentile {:.0})", e.probability * 100.0, e.percentile * 100.0))
                    .unwrap_or_else(|| "-".into()),
                f.ppr,
                f.published.as_ref().map(|p| format!("   |   Published: {p}")).unwrap_or_default(),
            ) + &format!("   |   Confidence: {}", f.confidence.label());
            let scores = if f.severity == Severity::Review {
                format!("Confidence: {} — not a confirmed vulnerability, needs a manual check", f.confidence.label())
            } else {
                scores
            };
            doc.para(MARGIN, CONTENT_W, 8.5, Font::Regular, MUTED, &scores);
            if let Some(c) = &f.cvss
                && !c.vector.is_empty()
            {
                doc.para(MARGIN, CONTENT_W, 7.5, Font::Mono, MUTED, &c.vector);
            }
            let locs: Vec<String> = g.locations.iter().map(|(ip, p)| format!("{ip}:{p}")).collect();
            let affected = format!(
                "Affected ({}): {}{}",
                locs.len(),
                locs.join(", "),
                f.product.as_ref().map(|p| format!("   -   {p}")).unwrap_or_default()
            );
            doc.para(MARGIN, CONTENT_W, 9.0, Font::Bold, TEXT, &affected);
            // The user's review mark and comments (from the details panel).
            let status = d.review_status(&f.id);
            let comments = d.comments(&f.id);
            if !status.is_empty() || !comments.is_empty() {
                let status = if status.is_empty() { "No".to_string() } else { status };
                doc.para(MARGIN, CONTENT_W, 9.0, Font::Bold, REVIEW_GREEN, &format!("Reviewed: {status}"));
                // The user's comments stand out: bold green, like the review mark.
                for (loc, text) in &comments {
                    doc.para(
                        MARGIN + 8.0,
                        CONTENT_W - 8.0,
                        9.0,
                        Font::Bold,
                        REVIEW_GREEN,
                        &format!("Comment ({loc}): {text}"),
                    );
                }
            }
            doc.para(MARGIN, CONTENT_W, 9.0, Font::Regular, TEXT, &f.description);
            doc.y -= 2.0;
            doc.para(MARGIN, CONTENT_W, 9.0, Font::Regular, TEXT, &format!("Solution: {}", f.solution));
            if !f.evidence.is_empty() {
                doc.para(MARGIN, CONTENT_W, 8.5, Font::Regular, MUTED, &format!("Evidence: {}", f.evidence));
            }
            for r in f.references.iter().take(3) {
                doc.para(MARGIN + 8.0, CONTENT_W - 8.0, 7.5, Font::Mono, (37, 99, 235), r);
            }
            doc.y -= 6.0;
            doc.need(4.0);
            doc.hline(doc.y, RULE);
        }
    }

    // ---- Informational ----------------------------------------------------------
    if !info.is_empty() {
        doc.heading("Informational findings");
        let cols = [("ID", 60.0), ("Finding", 175.0), ("Where", 120.0), ("Details", 144.0)];
        let rows: Vec<Vec<String>> = info
            .iter()
            .map(|g| {
                let locs: Vec<String> = g.locations.iter().map(|(ip, p)| format!("{ip}:{p}")).collect();
                vec![g.finding.id.clone(), g.finding.title.clone(), locs.join(", "), g.finding.evidence.clone()]
            })
            .collect();
        doc.table(&cols, &rows, None);
    }

    // ---- Services ---------------------------------------------------------------
    if !d.services.is_empty() {
        doc.heading("Hosts and services");
        let mut svcs: Vec<_> = d.services.iter().collect();
        svcs.sort_by_key(|s| (s.ip, s.port));
        let cols = [("Host", 90.0), ("Port", 40.0), ("Service", 120.0), ("Software", 249.0)];
        let rows: Vec<Vec<String>> = svcs
            .iter()
            .map(|s| {
                let sw: Vec<String> = s.products.iter().map(|p| p.label()).collect();
                vec![
                    s.ip.to_string(),
                    s.port.to_string(),
                    s.name.clone(),
                    if sw.is_empty() { s.banner.clone().unwrap_or_default() } else { sw.join(", ") },
                ]
            })
            .collect();
        doc.table(&cols, &rows, None);
    }

    // ---- Method -----------------------------------------------------------------
    doc.heading("How the scores work");
    for (k, v) in METHOD_NOTES {
        doc.need(30.0);
        doc.para(MARGIN, CONTENT_W, 9.0, Font::Bold, TEXT, k);
        doc.para(MARGIN, CONTENT_W, 9.0, Font::Regular, MUTED, v);
        doc.y -= 4.0;
    }
    doc.y -= 6.0;
    doc.para(
        MARGIN,
        CONTENT_W,
        8.5,
        Font::Regular,
        MUTED,
        "This report was produced by an automated scan. It can miss vulnerabilities (closed or filtered ports, \
         software that hides its version) and can include false positives. Only scan networks you own or have \
         permission to assess.",
    );

    doc.finish("Vulnerability Assessment Report")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widths_and_wrap() {
        assert!((text_width("Hello", 10.0, Font::Regular) - 22.78).abs() < 0.01);
        let lines = wrap("The quick brown fox jumps over the lazy dog", 10.0, Font::Regular, 80.0);
        assert!(lines.len() > 1);
        assert!(lines.iter().all(|l| text_width(l, 10.0, Font::Regular) <= 80.0));
        // A single huge "word" is split, not overflowed.
        let url = "https://example.com/".to_string() + &"a".repeat(300);
        assert!(wrap(&url, 8.0, Font::Mono, 200.0).iter().all(|l| text_width(l, 8.0, Font::Mono) <= 200.0));
        assert!(fit("A very long vulnerability title indeed", 8.0, Font::Regular, 60.0).ends_with('…'));
    }

    #[test]
    fn strings_are_escaped() {
        assert_eq!(pdf_str("a(b)c\\d"), "a\\(b\\)c\\\\d");
        assert_eq!(pdf_str("café …"), "caf\\351 \\205");
        assert_eq!(pdf_str(") Tj ET 0 0 m"), "\\) Tj ET 0 0 m");
        assert_eq!(pdf_str("日本"), "??");
    }

    #[test]
    fn xref_offsets_are_correct() {
        let mut d = Doc::new();
        d.text(50.0, 700.0, 12.0, Font::Bold, TEXT, "Hello (PDF)");
        d.new_page();
        d.text(50.0, 700.0, 12.0, Font::Regular, TEXT, "Page two");
        let pdf = d.finish("Test");
        assert!(pdf.starts_with(b"%PDF-1.4"));
        assert!(pdf.ends_with(b"%%EOF\n"));
        // Work on bytes: the binary comment in line 2 is not UTF-8.
        let tail_at = pdf.windows(10).rposition(|w| w == b"startxref\n").unwrap() + 10;
        let tail = std::str::from_utf8(&pdf[tail_at..]).unwrap();
        let xref_at: usize = tail.lines().next().unwrap().parse().unwrap();
        let table = std::str::from_utf8(&pdf[xref_at..]).unwrap();
        let mut checked = 0;
        // Every xref entry must point at "N 0 obj".
        for (n, line) in table.lines().skip(3).take_while(|l| l.ends_with(" n ")).enumerate() {
            let off: usize = line[..10].parse().unwrap();
            assert!(pdf[off..].starts_with(format!("{} 0 obj", n + 1).as_bytes()), "object {} offset wrong", n + 1);
            checked += 1;
        }
        assert_eq!(checked, 10); // 6 fixed objects + 2 pages × (page + content)
    }
}
