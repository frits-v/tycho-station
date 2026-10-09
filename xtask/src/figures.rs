//! Figures: CUE documents under `figures/`, exported by `cue`, rendered by stencil into
//! `docs/figures/` in a light and a dark variant, and spliced into `docs/design.html`.

use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

use crate::release::{run_bounded, Exit};

const FIGURES_DIR: &str = "figures";
const OUTPUT_DIR: &str = "docs/figures";
const DESIGN_PAGE: &str = "docs/design.html";
const GRAMMAR_PACKAGE: &str = "./grammar:tycho";
const GRAMMAR_FILE: &str = "tycho.json";
const VENDORED_REV_FILE: &str = "figures/cue.mod/pkg/github.com/frits-v/stencil/cue/rev";
const MISE_FILE: &str = "mise.toml";
const STENCIL_PIN: &str = "\"cargo:https://github.com/frits-v/stencil\" = { version = \"rev:";
const VARIANTS: [&str; 2] = ["light", "dark"];
const OUTPUT_EXTENSIONS: [&str; 2] = ["svg", "png"];
const PNG_SCALE: &str = "1";
const FIGURES_MAX: usize = 16;
const FILE_MAX_BYTES: u64 = 8 << 20;
const DEFECTS_MAX_LINES: usize = 40;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
const FONT_BLOCK_OPEN: &str = "  <defs>\n    <style>\n";
const FONT_BLOCK_CLOSE: &str = "    </style>\n  </defs>\n";
const FONT_FACE_LINE: &str = "      @font-face ";

/// How a `cue` run ended: 0 passed, 1 rejected the input; anything else is unusable.
#[derive(Debug, PartialEq, Eq)]
enum CueOutcome {
    Passed(String),
    Rejected,
    Unrecognised(String),
}

/// One line of `stencil check` output.
#[derive(Debug, PartialEq, Eq)]
enum CheckLine {
    Passed { check: String, examined: u64 },
    NotApplicable { check: String },
    Failed { check: String, defects: u64 },
    Defect(String),
    Summary { passed: u64, failed: u64 },
    Unrecognised(String),
}

/// How `stencil check` or `stencil render` ended: exit 0 clean, 1 a defect in the document,
/// 2 could not run.
#[derive(Debug, PartialEq, Eq)]
enum StencilOutcome {
    Clean(String),
    Defective(String),
    CouldNotRun,
    Unrecognised(String),
}

/// The head of a stencil SVG: the opening tag, then either the style block of embedded
/// font faces or the drawing itself.
#[derive(Debug, PartialEq, Eq)]
enum SvgHead {
    EmbeddedFonts { open_tag: String, drawing: String },
    NoFontBlock,
    Unrecognised(String),
}

/// One rendered document of a figure.
#[derive(Debug)]
struct Render {
    figure: String,
    variant: &'static str,
    label: String,
}

impl Render {
    fn stem(&self) -> String {
        format!("{}-{}", self.figure, self.variant)
    }
}

fn decode_cue(exit: &Exit, stdout: String) -> CueOutcome {
    match exit {
        Exit::Code(0) => CueOutcome::Passed(stdout),
        Exit::Code(1) => CueOutcome::Rejected,
        other => CueOutcome::Unrecognised(format!("{other:?}")),
    }
}

fn decode_stencil(exit: &Exit, stdout: String) -> StencilOutcome {
    match exit {
        Exit::Code(0) => StencilOutcome::Clean(stdout),
        Exit::Code(1) => StencilOutcome::Defective(stdout),
        Exit::Code(2) => StencilOutcome::CouldNotRun,
        other => StencilOutcome::Unrecognised(format!("{other:?}")),
    }
}

/// `check <name>: examined <n> <unit>, <d> defect(s)` or `..., not applicable: <reason>`.
fn decode_check_line(line: &str) -> CheckLine {
    if let Some(defect) = line.strip_prefix("defect ") {
        return CheckLine::Defect(defect.to_string());
    }
    if let Some(summary) = line.strip_prefix("stencil check: ") {
        return decode_summary(summary)
            .unwrap_or_else(|| CheckLine::Unrecognised(line.to_string()));
    }
    let Some(rest) = line.strip_prefix("check ") else {
        return CheckLine::Unrecognised(line.to_string());
    };
    let Some((check, report)) = rest.split_once(": examined ") else {
        return CheckLine::Unrecognised(line.to_string());
    };
    let check = check.to_string();
    let Some((counted, verdict)) = report.split_once(", ") else {
        return CheckLine::Unrecognised(line.to_string());
    };
    let examined = counted
        .split_whitespace()
        .next()
        .and_then(|n| n.parse::<u64>().ok());
    if verdict.starts_with("not applicable: ") && examined == Some(0) {
        return CheckLine::NotApplicable { check };
    }
    let defects = verdict
        .strip_suffix(" defects")
        .or_else(|| verdict.strip_suffix(" defect"))
        .and_then(|n| n.parse::<u64>().ok());
    match (examined, defects) {
        (Some(examined), Some(0)) if examined > 0 => CheckLine::Passed { check, examined },
        (Some(_), Some(defects)) => CheckLine::Failed { check, defects },
        _ => CheckLine::Unrecognised(line.to_string()),
    }
}

/// `14 checks, 6 passed, 0 failed, 8 not applicable`.
fn decode_summary(summary: &str) -> Option<CheckLine> {
    let parts: Vec<&str> = summary.split(", ").collect();
    let count = |index: usize, unit: &str| -> Option<u64> {
        parts
            .get(index)?
            .strip_suffix(unit)?
            .trim()
            .parse::<u64>()
            .ok()
    };
    count(0, " checks")?;
    count(3, " not applicable")?;
    Some(CheckLine::Summary {
        passed: count(1, " passed")?,
        failed: count(2, " failed")?,
    })
}

/// Every line of a clean `stencil check`: no defect, no failed check, a summary with no
/// failure and at least one check that examined something. Any other line is a defect.
fn check_report_defects(stdout: &str) -> Vec<String> {
    let mut defects = Vec::new();
    let mut passed_checks = 0_u64;
    let mut summary_seen = false;
    for line in stdout.lines() {
        match decode_check_line(line) {
            CheckLine::Passed { .. } => passed_checks = passed_checks.saturating_add(1),
            CheckLine::NotApplicable { .. } => {}
            CheckLine::Failed {
                check,
                defects: count,
            } => {
                defects.push(format!("check {check} reported {count} defects"));
            }
            CheckLine::Defect(text) => defects.push(text),
            CheckLine::Summary { passed, failed } => {
                summary_seen = true;
                if failed > 0 || passed == 0 {
                    defects.push(format!("summary: {passed} passed, {failed} failed"));
                }
            }
            CheckLine::Unrecognised(text) => defects.push(format!("unrecognised line: {text}")),
        }
    }
    if !summary_seen {
        defects.push("no summary line".to_string());
    }
    if passed_checks == 0 {
        defects.push("no check examined anything".to_string());
    }
    defects
}

fn decode_svg_head(svg: &str) -> SvgHead {
    let Some((open_tag, rest)) = svg.split_once('\n') else {
        return SvgHead::Unrecognised("no line after the opening tag".to_string());
    };
    if !open_tag.starts_with("<svg ") || !open_tag.ends_with('>') {
        return SvgHead::Unrecognised(format!("opening tag {open_tag:.40}"));
    }
    let Some(styles) = rest.strip_prefix(FONT_BLOCK_OPEN) else {
        return SvgHead::NoFontBlock;
    };
    let Some((faces, drawing)) = styles.split_once(FONT_BLOCK_CLOSE) else {
        return SvgHead::Unrecognised("font style block is not closed".to_string());
    };
    if faces.lines().count() == 0 || !faces.lines().all(|l| l.starts_with(FONT_FACE_LINE)) {
        return SvgHead::Unrecognised("style block holds more than font faces".to_string());
    }
    SvgHead::EmbeddedFonts {
        open_tag: open_tag.to_string(),
        drawing: drawing.to_string(),
    }
}

fn escape_attribute(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The SVG as the design page inlines it: no embedded fonts (the page loads Inter), every
/// id and reference prefixed with the render's stem so two inlined figures never share an
/// id, and a class that the page's theme rules show or hide.
fn page_svg(svg: &str, render: &Render) -> Result<String, String> {
    let (open_tag, drawing) = match decode_svg_head(svg) {
        SvgHead::EmbeddedFonts { open_tag, drawing } => (open_tag, drawing),
        SvgHead::NoFontBlock => return Err("SVG carries no embedded fonts".to_string()),
        SvgHead::Unrecognised(reason) => return Err(format!("unrecognised SVG head: {reason}")),
    };
    let prefix = format!("{}-", render.stem());
    let attributes = format!(
        "<svg class=\"fig-{}\" role=\"img\" aria-label=\"{}\" ",
        render.variant,
        escape_attribute(&render.label)
    );
    let open_tag = open_tag.replacen("<svg ", &attributes, 1);
    let drawing = drawing
        .replace(" id=\"", &format!(" id=\"{prefix}"))
        .replace("url(#", &format!("url(#{prefix}"))
        .replace("href=\"#", &format!("href=\"#{prefix}"));
    Ok(format!("{open_tag}\n{drawing}"))
}

fn figure_names() -> Result<Vec<String>, String> {
    let entries =
        fs::read_dir(FIGURES_DIR).map_err(|e| format!("cannot read {FIGURES_DIR}: {e}"))?;
    let mut names = Vec::new();
    for entry in entries.flatten().take(FIGURES_MAX.saturating_add(1)) {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("cue") {
            continue;
        }
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            names.push(stem.to_string());
        }
    }
    if names.len() > FIGURES_MAX {
        return Err(format!(
            "more than {FIGURES_MAX} figures under {FIGURES_DIR}"
        ));
    }
    names.sort();
    Ok(names)
}

fn run_cue(arguments: &[&str]) -> Result<String, String> {
    let mut command = Command::new("cue");
    command.current_dir(FIGURES_DIR).args(arguments);
    let captured = run_bounded(&mut command, COMMAND_TIMEOUT);
    match decode_cue(&captured.exit, captured.stdout) {
        CueOutcome::Passed(stdout) => Ok(stdout),
        CueOutcome::Rejected => Err(format!("cue {} rejected the figures", arguments.join(" "))),
        CueOutcome::Unrecognised(exit) => Err(format!("cue {} ended {exit}", arguments.join(" "))),
    }
}

fn run_stencil(arguments: &[&str]) -> Result<String, String> {
    let mut command = Command::new("stencil");
    command.args(arguments);
    let captured = run_bounded(&mut command, COMMAND_TIMEOUT);
    match decode_stencil(&captured.exit, captured.stdout) {
        StencilOutcome::Clean(stdout) => Ok(stdout),
        StencilOutcome::Defective(stdout) => Err(format!(
            "stencil {} found defects:\n{}",
            arguments.join(" "),
            stdout
                .lines()
                .filter(|l| l.starts_with("defect"))
                .collect::<Vec<_>>()
                .join("\n")
        )),
        StencilOutcome::CouldNotRun => {
            Err(format!("stencil {} could not run", arguments.join(" ")))
        }
        StencilOutcome::Unrecognised(exit) => {
            Err(format!("stencil {} ended {exit}", arguments.join(" ")))
        }
    }
}

/// The exported `figures` value must hold exactly one entry per figure file, each with a
/// light and a dark document.
fn split_documents(exported: &str, names: &[String]) -> Result<Vec<(Render, Value)>, String> {
    let value: Value =
        serde_json::from_str(exported).map_err(|e| format!("cue export is not JSON: {e}"))?;
    let figures = value.as_object().ok_or("cue export is not an object")?;
    let mut keys: Vec<&String> = figures.keys().collect();
    keys.sort();
    if keys
        .iter()
        .map(|k| k.as_str())
        .ne(names.iter().map(String::as_str))
    {
        return Err(format!(
            "exported figures {keys:?} differ from the files {names:?}"
        ));
    }
    let mut documents = Vec::new();
    for name in names {
        let variants = figures
            .get(name)
            .and_then(Value::as_object)
            .ok_or_else(|| format!("figure {name} is not an object"))?;
        for variant in VARIANTS {
            let page = variants
                .get(variant)
                .and_then(Value::as_object)
                .ok_or_else(|| format!("figure {name} has no {variant} document"))?;
            let render = Render {
                figure: name.clone(),
                variant,
                label: page_label(page),
            };
            documents.push((render, Value::Object(page.clone())));
        }
    }
    Ok(documents)
}

fn page_label(page: &Map<String, Value>) -> String {
    let field = |key: &str| {
        page.get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    format!("{}: {}", field("title"), field("lede"))
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let file = fs::File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(FILE_MAX_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if u64::try_from(bytes.len()).map_or(true, |n| n > FILE_MAX_BYTES) {
        return Err(format!("{} exceeds {FILE_MAX_BYTES} bytes", path.display()));
    }
    Ok(bytes)
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// Exports, checks and renders every figure into `build`, leaving `<stem>.svg` (the page
/// form) and `<stem>.png` there. Returns the renders in figure order.
fn build(build_dir: &Path) -> Result<Vec<Render>, String> {
    let names = figure_names()?;
    if names.is_empty() {
        return Err(format!("no figures under {FIGURES_DIR}"));
    }
    run_cue(&["vet", "-c", GRAMMAR_PACKAGE])?;
    run_cue(&["vet", "-c", "."])?;
    let grammar = run_cue(&["export", GRAMMAR_PACKAGE, "-e", "grammar", "--out", "json"])?;
    write(&build_dir.join(GRAMMAR_FILE), grammar.as_bytes())?;
    let exported = run_cue(&["export", ".", "-e", "figures", "--out", "json"])?;
    let documents = split_documents(&exported, &names)?;
    let mut renders = Vec::new();
    for (render, page) in documents {
        let stem = render.stem();
        let document = build_dir.join(format!("{stem}.json"));
        let text = serde_json::to_string_pretty(&page).map_err(|e| e.to_string())?;
        write(&document, text.as_bytes())?;
        render_one(build_dir, &document, &render)?;
        renders.push(render);
    }
    Ok(renders)
}

fn render_one(build_dir: &Path, document: &Path, render: &Render) -> Result<(), String> {
    let document_arg = document.to_string_lossy();
    let report = run_stencil(&["check", &document_arg])?;
    let defects = check_report_defects(&report);
    if !defects.is_empty() {
        return Err(format!(
            "stencil check {}: {}",
            render.stem(),
            defects.join("; ")
        ));
    }
    let raw_dir = build_dir.join("raw");
    let raw_arg = raw_dir.to_string_lossy();
    run_stencil(&[
        "render",
        &document_arg,
        "--out-dir",
        &raw_arg,
        "--scale",
        PNG_SCALE,
    ])?;
    let stem = render.stem();
    let svg = read_bounded(&raw_dir.join(format!("{stem}.svg")))?;
    let svg = String::from_utf8(svg).map_err(|e| format!("{stem}.svg is not UTF-8: {e}"))?;
    let page = page_svg(&svg, render).map_err(|e| format!("{stem}.svg: {e}"))?;
    write(&build_dir.join(format!("{stem}.svg")), page.as_bytes())?;
    let png = read_bounded(&raw_dir.join(format!("{stem}.png")))?;
    write(&build_dir.join(format!("{stem}.png")), &png)
}

fn marker(name: &str) -> (String, String) {
    (
        format!("<!-- figure:{name} -->\n"),
        format!("<!-- /figure:{name} -->"),
    )
}

/// Replaces what stands between a figure's two markers in the design page.
fn splice(page: &str, name: &str, content: &str) -> Result<String, String> {
    let (open, close) = marker(name);
    if page.matches(&open).count() != 1 || page.matches(&close).count() != 1 {
        return Err(format!(
            "{DESIGN_PAGE} needs exactly one `{}` pair",
            open.trim()
        ));
    }
    let (before, rest) = page.split_once(&open).ok_or("open marker vanished")?;
    let (_, after) = rest
        .split_once(&close)
        .ok_or_else(|| format!("{DESIGN_PAGE}: `{close}` must follow `{}`", open.trim()))?;
    Ok(format!("{before}{open}{content}{close}{after}"))
}

/// The design page with every figure's markers holding its rendered SVGs.
fn spliced_page(page: &str, build_dir: &Path, renders: &[Render]) -> Result<String, String> {
    let mut page = page.to_string();
    let mut names: Vec<&str> = renders.iter().map(|r| r.figure.as_str()).collect();
    names.dedup();
    for name in names {
        let mut content = String::new();
        for render in renders.iter().filter(|r| r.figure == name) {
            let svg = read_bounded(&build_dir.join(format!("{}.svg", render.stem())))?;
            content.push_str(&String::from_utf8_lossy(&svg));
        }
        page = splice(&page, name, &content)?;
    }
    Ok(page)
}

fn build_dir() -> Result<PathBuf, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir = env::temp_dir().join(format!("tycho-figures-{}-{nanos}", process::id()));
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    Ok(dir)
}

fn remove(dir: &Path) {
    if let Err(error) = fs::remove_dir_all(dir) {
        eprintln!("xtask: could not remove {}: {error}", dir.display());
    }
}

fn output_files(renders: &[Render]) -> Vec<String> {
    renders
        .iter()
        .flat_map(|r| {
            OUTPUT_EXTENSIONS
                .iter()
                .map(move |e| format!("{}.{e}", r.stem()))
        })
        .collect()
}

pub fn render_figures() -> i32 {
    let dir = match build_dir() {
        Ok(dir) => dir,
        Err(error) => return fail("render-figures", &error),
    };
    let result = build(&dir).and_then(|renders| install(&dir, &renders).map(|()| renders));
    remove(&dir);
    match result {
        Ok(renders) => {
            println!(
                "xtask render-figures: rendered {} figures, {} documents, into {OUTPUT_DIR}",
                count_figures(&renders),
                renders.len()
            );
            0
        }
        Err(error) => fail("render-figures", &error),
    }
}

fn install(build_dir: &Path, renders: &[Render]) -> Result<(), String> {
    let output = Path::new(OUTPUT_DIR);
    fs::create_dir_all(output).map_err(|e| format!("cannot create {OUTPUT_DIR}: {e}"))?;
    let expected = output_files(renders);
    for stale in listed_files(output)?
        .iter()
        .filter(|f| !expected.contains(f))
    {
        fs::remove_file(output.join(stale)).map_err(|e| format!("cannot remove {stale}: {e}"))?;
    }
    for file in &expected {
        write(&output.join(file), &read_bounded(&build_dir.join(file))?)?;
    }
    let page = read_page()?;
    write(
        Path::new(DESIGN_PAGE),
        spliced_page(&page, build_dir, renders)?.as_bytes(),
    )
}

fn read_page() -> Result<String, String> {
    let bytes = read_bounded(Path::new(DESIGN_PAGE))?;
    String::from_utf8(bytes).map_err(|e| format!("{DESIGN_PAGE} is not UTF-8: {e}"))
}

fn listed_files(dir: &Path) -> Result<Vec<String>, String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    Ok(entries
        .flatten()
        .take(FIGURES_MAX.saturating_mul(VARIANTS.len()).saturating_mul(4))
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .collect())
}

fn count_figures(renders: &[Render]) -> usize {
    let mut names: Vec<&str> = renders.iter().map(|r| r.figure.as_str()).collect();
    names.dedup();
    names.len()
}

fn fail(name: &str, error: &str) -> i32 {
    eprintln!("xtask {name}: {error}");
    1
}

/// The pinned stencil revision in `mise.toml` must be the one the vendored CUE package was
/// copied from.
fn pin_defects() -> Vec<String> {
    let pinned = fs::read_to_string(MISE_FILE).ok().and_then(|text| {
        let (_, rest) = text.split_once(STENCIL_PIN)?;
        rest.split_once('"').map(|(rev, _)| rev.to_string())
    });
    let vendored = fs::read_to_string(VENDORED_REV_FILE)
        .ok()
        .map(|text| text.trim().to_string());
    match (pinned, vendored) {
        (Some(pinned), Some(vendored)) if pinned == vendored => Vec::new(),
        (Some(pinned), Some(vendored)) => vec![format!(
            "{MISE_FILE} pins stencil {pinned}; {VENDORED_REV_FILE} says {vendored}"
        )],
        (None, _) => vec![format!("{MISE_FILE} has no stencil pin by rev")],
        (_, None) => vec![format!("cannot read {VENDORED_REV_FILE}")],
    }
}

fn compare_outputs(build_dir: &Path, renders: &[Render]) -> Result<Vec<String>, String> {
    let mut defects = pin_defects();
    let expected = output_files(renders);
    let output = Path::new(OUTPUT_DIR);
    for extra in listed_files(output)?
        .iter()
        .filter(|f| !expected.contains(f))
    {
        defects.push(format!("{OUTPUT_DIR}/{extra} is not a rendered figure"));
    }
    for file in &expected {
        let fresh = read_bounded(&build_dir.join(file))?;
        match read_bounded(&output.join(file)) {
            Ok(committed) if committed == fresh => {}
            Ok(_) => defects.push(format!("{OUTPUT_DIR}/{file} differs from its source")),
            Err(error) => defects.push(error),
        }
    }
    let page = read_page()?;
    if spliced_page(&page, build_dir, renders)? != page {
        defects.push(format!("{DESIGN_PAGE} does not hold the rendered figures"));
    }
    Ok(defects)
}

pub fn check_figures() -> i32 {
    let dir = match build_dir() {
        Ok(dir) => dir,
        Err(error) => return fail("check-figures", &error),
    };
    let result = build(&dir)
        .and_then(|renders| compare_outputs(&dir, &renders).map(|defects| (renders, defects)));
    remove(&dir);
    let (renders, defects) = match result {
        Ok(outcome) => outcome,
        Err(error) => return fail("check-figures", &error),
    };
    let figures = count_figures(&renders);
    if figures == 0 {
        return fail(
            "check-figures",
            "examined 0 figures; a check over nothing is a failure",
        );
    }
    if defects.is_empty() {
        println!(
            "xtask check-figures: examined {figures} figures, {} documents, no defects",
            renders.len()
        );
        return 0;
    }
    let mut report = format!("examined {figures} figures, {} defects", defects.len());
    for defect in defects.iter().take(DEFECTS_MAX_LINES) {
        report.push_str("\n  ");
        report.push_str(defect);
    }
    fail("check-figures", &report)
}

#[cfg(test)]
mod tests;
