//! Excel (.xlsx) report: Summary, Top 10, Findings (one row per host),
//! Vulnerabilities (grouped), Services and Method sheets.
//!
//! Text is always written with `write_string`, which stores it as text — a
//! value such as `=HYPERLINK(...)` from a hostile banner is shown literally
//! and never evaluated as a formula.

use rust_xlsxwriter::{Color, Format, FormatAlign, FormatBorder, Workbook, Worksheet, XlsxError};

use super::{METHOD_NOTES, ReportData};
use crate::vuln::score::Severity;

/// Build the workbook in memory.
pub fn build(d: &ReportData<'_>) -> Result<Vec<u8>, XlsxError> {
    let mut wb = Workbook::new();
    let head = Format::new()
        .set_bold()
        .set_font_color(Color::White)
        .set_background_color(Color::RGB(0x8E1B6E))
        .set_border(FormatBorder::Thin);
    let wrap = Format::new().set_text_wrap().set_align(FormatAlign::Top);
    let title = Format::new().set_bold().set_font_size(16);
    let bold = Format::new().set_bold();
    let num1 = Format::new().set_num_format("0.0").set_align(FormatAlign::Top);
    let pct = Format::new().set_num_format("0.00%").set_align(FormatAlign::Top);
    let sev_fmt = |s: Severity| {
        let (r, g, b) = s.rgb();
        Format::new()
            .set_bold()
            .set_font_color(Color::White)
            .set_background_color(Color::RGB((u32::from(r) << 16) | (u32::from(g) << 8) | u32::from(b)))
            .set_align(FormatAlign::Center)
            .set_align(FormatAlign::Top)
    };

    // ---- Summary -----------------------------------------------------------
    let ws = wb.add_worksheet();
    ws.set_name("Summary")?;
    ws.set_column_width(0, 26)?;
    ws.set_column_width(1, 70)?;
    ws.write_string_with_format(0, 0, "Proton IP Scanner - Vulnerability Assessment", &title)?;
    let info = [
        ("Generated", d.generated.clone()),
        ("Targets", d.targets.clone()),
        ("Hosts assessed", d.hosts.to_string()),
        ("Open services", d.services.len().to_string()),
        ("Scan speed", d.speed.clone()),
        ("Duration", format!("{:.0} s", d.duration_secs)),
        ("Vulnerability data", d.cve_data.clone()),
    ];
    let mut row = 2;
    for (k, v) in info {
        ws.write_string_with_format(row, 0, k, &bold)?;
        ws.write_string(row, 1, v)?;
        row += 1;
    }
    row += 1;
    ws.write_string_with_format(row, 0, "Severity", &head)?;
    ws.write_string_with_format(row, 1, "Findings (host x vulnerability)", &head)?;
    for (s, n) in d.counts() {
        row += 1;
        ws.write_string_with_format(row, 0, s.label(), &sev_fmt(s))?;
        ws.write_number(row, 1, n as f64)?;
    }
    if !d.notes.is_empty() {
        row += 2;
        ws.write_string_with_format(row, 0, "Notes", &bold)?;
        for n in d.notes {
            row += 1;
            ws.write_string_with_format(row, 1, n, &wrap)?;
        }
    }

    // ---- Top 10 ------------------------------------------------------------
    let ws = wb.add_worksheet();
    ws.set_name("Top 10")?;
    header(
        ws,
        &head,
        &[
            ("#", 4),
            ("ID", 17),
            ("Vulnerability", 60),
            ("Severity", 10),
            ("Hosts", 7),
            ("CVSS", 7),
            ("CVSS ver.", 9),
            ("EPSS", 9),
            ("PPR", 7),
            ("KEV", 6),
            ("Confidence", 16),
        ],
    )?;
    for (i, t) in d.top10.iter().enumerate() {
        let r = i as u32 + 1;
        let f = &t.finding;
        ws.write_number(r, 0, (i + 1) as f64)?;
        ws.write_string_with_format(r, 1, &f.id, &wrap)?;
        ws.write_string_with_format(r, 2, &f.title, &wrap)?;
        ws.write_string_with_format(r, 3, f.severity.label(), &sev_fmt(f.severity))?;
        ws.write_number(r, 4, t.hosts as f64)?;
        cvss_cells(ws, r, 5, f, &num1)?;
        epss_cell(ws, r, 7, f, &pct)?;
        ws.write_number_with_format(r, 8, r1(f.ppr), &num1)?;
        ws.write_string(r, 9, if f.kev { "Yes" } else { "" })?;
        ws.write_string(r, 10, f.confidence.label())?;
    }
    ws.set_freeze_panes(1, 0)?;

    // ---- Findings (one row per host) ---------------------------------------
    let ws = wb.add_worksheet();
    ws.set_name("Findings")?;
    header(
        ws,
        &head,
        &[
            ("Severity", 10),
            ("ID", 17),
            ("Title", 55),
            ("Host", 15),
            ("Port", 7),
            ("Service", 16),
            ("Software", 22),
            ("CVSS", 7),
            ("CVSS ver.", 9),
            ("EPSS", 9),
            ("EPSS pct.", 9),
            ("PPR", 7),
            ("KEV", 6),
            ("Published", 11),
            ("Description", 70),
            ("Solution", 50),
            ("Evidence", 50),
            ("References", 50),
            ("Confidence", 16),
        ],
    )?;
    let mut sorted: Vec<_> = d.findings.iter().collect();
    sorted.sort_by(|a, b| a.rank_cmp(b));
    for (i, f) in sorted.iter().enumerate() {
        let r = i as u32 + 1;
        ws.write_string_with_format(r, 0, f.severity.label(), &sev_fmt(f.severity))?;
        ws.write_string_with_format(r, 1, &f.id, &wrap)?;
        ws.write_string_with_format(r, 2, &f.title, &wrap)?;
        ws.write_string_with_format(r, 3, f.ip.to_string(), &wrap)?;
        ws.write_number_with_format(r, 4, f64::from(f.port), &wrap)?;
        ws.write_string_with_format(r, 5, &f.service, &wrap)?;
        ws.write_string_with_format(r, 6, f.product.as_deref().unwrap_or(""), &wrap)?;
        cvss_cells(ws, r, 7, f, &num1)?;
        epss_cell(ws, r, 9, f, &pct)?;
        if let Some(e) = f.epss {
            ws.write_number_with_format(r, 10, r5(e.percentile), &pct)?;
        }
        ws.write_number_with_format(r, 11, r1(f.ppr), &num1)?;
        ws.write_string(r, 12, if f.kev { "Yes" } else { "" })?;
        ws.write_string(r, 13, f.published.as_deref().unwrap_or(""))?;
        ws.write_string_with_format(r, 14, &f.description, &wrap)?;
        ws.write_string_with_format(r, 15, &f.solution, &wrap)?;
        ws.write_string_with_format(r, 16, &f.evidence, &wrap)?;
        ws.write_string_with_format(r, 17, f.references.join("\n"), &wrap)?;
        ws.write_string(r, 18, f.confidence.label())?;
    }
    if !sorted.is_empty() {
        ws.autofilter(0, 0, sorted.len() as u32, 18)?;
    }
    ws.set_freeze_panes(1, 0)?;

    // ---- Vulnerabilities (grouped) ------------------------------------------
    let ws = wb.add_worksheet();
    ws.set_name("Vulnerabilities")?;
    header(
        ws,
        &head,
        &[
            ("Severity", 10),
            ("ID", 17),
            ("Title", 60),
            ("Affected", 30),
            ("CVSS", 7),
            ("CVSS ver.", 9),
            ("EPSS", 9),
            ("PPR", 7),
            ("KEV", 6),
            ("Confidence", 16),
        ],
    )?;
    let groups = d.groups();
    for (i, g) in groups.iter().enumerate() {
        let r = i as u32 + 1;
        let f = g.finding;
        ws.write_string_with_format(r, 0, f.severity.label(), &sev_fmt(f.severity))?;
        ws.write_string_with_format(r, 1, &f.id, &wrap)?;
        ws.write_string_with_format(r, 2, &f.title, &wrap)?;
        let locs: Vec<String> = g.locations.iter().map(|(ip, p)| format!("{ip}:{p}")).collect();
        ws.write_string_with_format(r, 3, locs.join("\n"), &wrap)?;
        cvss_cells(ws, r, 4, f, &num1)?;
        epss_cell(ws, r, 6, f, &pct)?;
        ws.write_number_with_format(r, 7, r1(f.ppr), &num1)?;
        ws.write_string(r, 8, if f.kev { "Yes" } else { "" })?;
        ws.write_string(r, 9, f.confidence.label())?;
    }
    if !groups.is_empty() {
        ws.autofilter(0, 0, groups.len() as u32, 9)?;
    }
    ws.set_freeze_panes(1, 0)?;

    // ---- Services ------------------------------------------------------------
    let ws = wb.add_worksheet();
    ws.set_name("Services")?;
    header(ws, &head, &[("Host", 15), ("Port", 7), ("Service", 22), ("Software", 40), ("CPE", 55), ("Banner", 60)])?;
    let mut svcs: Vec<_> = d.services.iter().collect();
    svcs.sort_by_key(|s| (s.ip, s.port));
    for (i, s) in svcs.iter().enumerate() {
        let r = i as u32 + 1;
        ws.write_string(r, 0, s.ip.to_string())?;
        ws.write_number(r, 1, f64::from(s.port))?;
        ws.write_string(r, 2, &s.name)?;
        ws.write_string(r, 3, s.products.iter().map(|p| p.label()).collect::<Vec<_>>().join(", "))?;
        ws.write_string(r, 4, s.products.iter().filter_map(|p| p.cpe.clone()).collect::<Vec<_>>().join("\n"))?;
        ws.write_string(r, 5, s.banner.as_deref().unwrap_or(""))?;
    }
    ws.set_freeze_panes(1, 0)?;

    // ---- Method --------------------------------------------------------------
    let ws = wb.add_worksheet();
    ws.set_name("Method")?;
    ws.set_column_width(0, 24)?;
    ws.set_column_width(1, 110)?;
    for (i, (k, v)) in METHOD_NOTES.iter().enumerate() {
        ws.write_string_with_format(i as u32, 0, *k, &bold)?;
        ws.write_string_with_format(i as u32, 1, *v, &wrap)?;
    }

    wb.save_to_buffer()
}

/// Write the bold header row and set column widths.
fn header(ws: &mut Worksheet, fmt: &Format, cols: &[(&str, u16)]) -> Result<(), XlsxError> {
    for (i, (name, width)) in cols.iter().enumerate() {
        ws.write_string_with_format(0, i as u16, *name, fmt)?;
        ws.set_column_width(i as u16, *width)?;
    }
    Ok(())
}

/// Write the CVSS score and version cells (empty when not scored).
fn cvss_cells(ws: &mut Worksheet, r: u32, c: u16, f: &crate::vuln::Finding, num: &Format) -> Result<(), XlsxError> {
    if let Some(cv) = &f.cvss {
        ws.write_number_with_format(r, c, r1(cv.score), num)?;
        ws.write_string(r, c + 1, &cv.version)?;
    }
    Ok(())
}

/// Write the EPSS probability cell as a percentage (empty when unknown).
fn epss_cell(ws: &mut Worksheet, r: u32, c: u16, f: &crate::vuln::Finding, pct: &Format) -> Result<(), XlsxError> {
    if let Some(e) = f.epss {
        ws.write_number_with_format(r, c, r5(e.probability), pct)?;
    }
    Ok(())
}

/// f32 → f64 rounded to 1 decimal (avoids 9.800000190734863 in cells).
fn r1(v: f32) -> f64 {
    (f64::from(v) * 10.0).round() / 10.0
}

/// f32 → f64 rounded to 5 decimals (EPSS precision).
fn r5(v: f32) -> f64 {
    (f64::from(v) * 100_000.0).round() / 100_000.0
}
