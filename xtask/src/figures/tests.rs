use super::*;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/figures");
const RENDERED: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/figures");
const LEGEND_GROUP: &str = "data-id=\"/legend\"";
const FACT_BULLET: &str = "\u{2022} ";

fn fixture(name: &str) -> String {
    fs::read_to_string(format!("{FIXTURES}/{name}")).unwrap_or_default()
}

fn render(variant: &'static str) -> Render {
    Render {
        figure: "sample".to_string(),
        variant,
        label: "Sample: a \"quoted\" lede".to_string(),
    }
}

#[test]
fn cue_exit_codes_map_to_outcomes_and_anything_else_is_unrecognised() {
    assert_eq!(
        decode_cue(&Exit::Code(0), "{}".to_string()),
        CueOutcome::Passed("{}".to_string())
    );
    assert_eq!(
        decode_cue(&Exit::Code(1), String::new()),
        CueOutcome::Rejected
    );
    for exit in [
        Exit::Code(2),
        Exit::Signal,
        Exit::TimedOut,
        Exit::OutputTooLarge,
    ] {
        assert!(matches!(
            decode_cue(&exit, String::new()),
            CueOutcome::Unrecognised(_)
        ));
    }
}

#[test]
fn stencil_exit_codes_map_to_outcomes_and_anything_else_is_unrecognised() {
    assert!(matches!(
        decode_stencil(&Exit::Code(0), String::new()),
        StencilOutcome::Clean(_)
    ));
    assert!(matches!(
        decode_stencil(&Exit::Code(1), String::new()),
        StencilOutcome::Defective(_)
    ));
    assert_eq!(
        decode_stencil(&Exit::Code(2), String::new()),
        StencilOutcome::CouldNotRun
    );
    assert!(matches!(
        decode_stencil(&Exit::Code(3), String::new()),
        StencilOutcome::Unrecognised(_)
    ));
    assert!(matches!(
        decode_stencil(&Exit::NotStarted("missing".to_string()), String::new()),
        StencilOutcome::Unrecognised(_)
    ));
}

#[test]
fn a_captured_clean_check_report_has_no_defects() {
    let report = fixture("check-clean.txt");
    assert!(report.lines().count() > 1, "fixture missing");
    assert_eq!(check_report_defects(&report), Vec::<String>::new());
}

#[test]
fn a_captured_defective_check_report_names_the_defect() {
    let defects = check_report_defects(&fixture("check-defects.txt"));
    assert!(
        defects
            .iter()
            .any(|d| d.starts_with("links-avoid-boxes /links/0")),
        "{defects:?}"
    );
    assert!(
        defects.iter().any(|d| d.contains("1 failed")),
        "{defects:?}"
    );
}

#[test]
fn check_lines_decode_into_each_state() {
    assert_eq!(
        decode_check_line("check links-routed: examined 12 links, 0 defects"),
        CheckLine::Passed {
            check: "links-routed".to_string(),
            examined: 12
        }
    );
    assert_eq!(
        decode_check_line(
            "check pipes-land: examined 0 pipe ends, not applicable: page has no pipes"
        ),
        CheckLine::NotApplicable {
            check: "pipes-land".to_string()
        }
    );
    assert_eq!(
        decode_check_line("check links-avoid-boxes: examined 137 pairs, 1 defect"),
        CheckLine::Failed {
            check: "links-avoid-boxes".to_string(),
            defects: 1
        }
    );
    assert_eq!(
        decode_check_line("stencil check: 14 checks, 6 passed, 0 failed, 8 not applicable"),
        CheckLine::Summary {
            passed: 6,
            failed: 0
        }
    );
    assert!(matches!(
        decode_check_line("check text-fits-box: examined 0 text runs, 0 defects"),
        CheckLine::Failed { .. }
    ));
    for line in [
        "",
        "warning: something new",
        "check x: examined many, 0 defects",
    ] {
        assert!(
            matches!(decode_check_line(line), CheckLine::Unrecognised(_)),
            "{line}"
        );
    }
}

#[test]
fn a_report_without_summary_or_passing_check_is_defective() {
    assert_eq!(check_report_defects("").len(), 2);
    let all_not_applicable =
        "check pipes-land: examined 0 pipe ends, not applicable: page has no pipes\n\
         stencil check: 1 checks, 0 passed, 0 failed, 1 not applicable\n";
    assert!(!check_report_defects(all_not_applicable).is_empty());
}

#[test]
fn the_captured_svg_head_carries_embedded_fonts() {
    let head = fixture("stencil-head.svg");
    let SvgHead::EmbeddedFonts { open_tag, drawing } = decode_svg_head(&head) else {
        panic!("captured head did not decode as embedded fonts");
    };
    assert!(open_tag.starts_with("<svg xmlns="));
    assert!(drawing.starts_with("  <rect "));
    assert!(!drawing.contains("@font-face"));
}

#[test]
fn svg_heads_without_fonts_or_with_other_styles_are_not_usable() {
    let plain = "<svg width=\"1\">\n  <rect/>\n</svg>\n";
    assert_eq!(decode_svg_head(plain), SvgHead::NoFontBlock);
    let styled = "<svg width=\"1\">\n  <defs>\n    <style>\n      .a { fill: red; }\n    </style>\n  </defs>\n";
    assert!(matches!(decode_svg_head(styled), SvgHead::Unrecognised(_)));
    let unclosed = "<svg width=\"1\">\n  <defs>\n    <style>\n      @font-face { }\n";
    assert!(matches!(
        decode_svg_head(unclosed),
        SvgHead::Unrecognised(_)
    ));
    assert!(matches!(
        decode_svg_head("<html>\n"),
        SvgHead::Unrecognised(_)
    ));
    assert!(page_svg(plain, &render("light")).is_err());
}

#[test]
fn the_page_form_drops_fonts_and_prefixes_every_id_and_reference() {
    let head = format!(
        "{}    <text x=\"1\" y=\"2\" {SVG_FONT} font-size=\"12\">a</text>\n",
        fixture("stencil-head.svg")
    );
    let page = page_svg(&head, &render("dark")).unwrap_or_default();
    assert!(page.starts_with(
        "<svg class=\"fig-dark\" role=\"img\" aria-label=\"Sample: a &quot;quoted&quot; lede\" xmlns="
    ));
    assert!(!page.contains("@font-face"));
    assert!(page.contains(" id=\"sample-dark-arrow-clear-solid-3\""));
    assert!(page.contains("data-id=\"\""));
    assert!(!page.contains(" id=\"arrow-"));
    assert!(!page.contains(SVG_FONT));
    assert!(page.contains(PAGE_FONT));
}

#[test]
fn committed_page_svgs_name_a_font_stack_not_bare_inter() {
    let files = listed_files(Path::new(RENDERED)).unwrap_or_default();
    let svgs: Vec<&String> = files
        .iter()
        .filter(|f| Path::new(f).extension().is_some_and(|e| e == "svg"))
        .collect();
    assert_eq!(svgs.len(), 8, "{files:?}");
    for file in svgs {
        let svg = fs::read_to_string(format!("{RENDERED}/{file}")).unwrap_or_default();
        assert!(!svg.contains(SVG_FONT), "{file} names bare Inter");
        assert!(svg.contains(PAGE_FONT), "{file} has no font stack");
    }
}

/// A fresh directory under the system temp directory, unique to the test.
fn scratch(name: &str) -> PathBuf {
    let dir = env::temp_dir().join(format!("tycho-figures-test-{}-{name}", process::id()));
    if dir.exists() {
        fs::remove_dir_all(&dir).unwrap();
    }
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn more_figures_than_the_limit_fail_and_only_cue_files_count() {
    let dir = scratch("figure-limit");
    for index in 0..FIGURES_MAX {
        fs::write(dir.join(format!("f{index:02}.cue")), "").unwrap();
    }
    fs::write(dir.join("notes.txt"), "").unwrap();
    assert_eq!(figure_names(&dir).map(|n| n.len()), Ok(FIGURES_MAX));
    fs::write(dir.join("one-more.cue"), "").unwrap();
    assert!(figure_names(&dir).is_err());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_directory_over_the_entry_limit_is_an_error_not_a_truncation() {
    let dir = scratch("entry-limit");
    for index in 0..DIR_ENTRIES_MAX {
        fs::write(dir.join(format!("e{index:03}")), "").unwrap();
    }
    assert_eq!(listed_files(&dir).map(|n| n.len()), Ok(DIR_ENTRIES_MAX));
    fs::write(dir.join("one-more"), "").unwrap();
    assert!(listed_files(&dir).is_err());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_file_one_byte_over_the_limit_is_refused() {
    let dir = scratch("file-limit");
    let path = dir.join("large");
    let limit = usize::try_from(FILE_MAX_BYTES).unwrap();
    fs::write(&path, vec![b'a'; limit]).unwrap();
    assert_eq!(read_bounded(&path).map(|b| b.len()), Ok(limit));
    fs::write(&path, vec![b'a'; limit + 1]).unwrap();
    assert!(read_bounded(&path).is_err());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn vendored_files_must_match_the_pin_and_their_recorded_digests() {
    let dir = scratch("vendored");
    fs::write(dir.join("core.cue"), "package stencil\n").unwrap();
    let digest = sha256_hex(b"package stencil\n");
    fs::write(dir.join("rev"), format!("abc\n{digest}  core.cue\n")).unwrap();
    assert_eq!(vendored_defects(&dir, "abc"), Vec::<String>::new());
    assert_eq!(vendored_defects(&dir, "def").len(), 1);
    fs::write(dir.join("extra.cue"), "").unwrap();
    assert_eq!(vendored_defects(&dir, "abc").len(), 1);
    fs::remove_file(dir.join("extra.cue")).unwrap();
    fs::write(dir.join("core.cue"), "package changed\n").unwrap();
    assert_eq!(vendored_defects(&dir, "abc").len(), 1);
    fs::write(dir.join("rev"), "abc\n").unwrap();
    assert!(!vendored_defects(&dir, "abc").is_empty());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_committed_vendored_package_matches_the_pin() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    let dir = Path::new(root).join(VENDORED_DIR);
    let rev = fs::read_to_string(dir.join("rev")).unwrap_or_default();
    let commit = rev.lines().next().unwrap_or_default();
    assert_eq!(commit.len(), 40);
    assert_eq!(vendored_defects(&dir, commit), Vec::<String>::new());
}

#[test]
fn splice_fills_one_marker_pair_and_rejects_a_missing_or_doubled_pair() {
    let page = "a\n<!-- figure:x -->\nold\n<!-- /figure:x -->\nb\n";
    assert_eq!(
        splice(page, "x", "new\n"),
        Ok("a\n<!-- figure:x -->\nnew\n<!-- /figure:x -->\nb\n".to_string())
    );
    assert!(splice(page, "y", "new\n").is_err());
    let doubled = format!("{page}{page}");
    assert!(splice(&doubled, "x", "new\n").is_err());
    assert!(splice("<!-- /figure:x --><!-- figure:x -->\n", "x", "").is_err());
}

/// One `<text>` element: its position, a style key and its decoded content.
#[derive(Debug)]
struct TextRun {
    x: String,
    y: f64,
    size: f64,
    style: String,
    text: String,
}

fn attribute(tag: &str, name: &str) -> Option<String> {
    let start = tag.find(&format!(" {name}=\""))?;
    let rest = tag.get(start.saturating_add(name.len()).saturating_add(3)..)?;
    rest.split_once('"').map(|(value, _)| value.to_string())
}

fn decode_entities(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

/// Text runs in document order. The original SVGs style text by class, the rendered ones by
/// font attributes; texts inside the rendered legend group are skipped.
fn text_runs(svg: &str) -> Vec<TextRun> {
    let mut runs = Vec::new();
    let mut legend_indent: Option<usize> = None;
    for line in svg.lines() {
        let indent = line.len().saturating_sub(line.trim_start().len());
        if line.contains(LEGEND_GROUP) {
            legend_indent = Some(indent);
            continue;
        }
        if legend_indent.is_some_and(|depth| depth == indent && line.trim() == "</g>") {
            legend_indent = None;
            continue;
        }
        if legend_indent.is_some() {
            continue;
        }
        runs.extend(line_runs(line));
    }
    runs
}

fn line_runs(line: &str) -> Vec<TextRun> {
    let mut runs = Vec::new();
    for piece in line.split("<text").skip(1) {
        let Some((tag, rest)) = piece.split_once('>') else {
            continue;
        };
        let Some((content, _)) = rest.split_once("</text>") else {
            continue;
        };
        let class = attribute(tag, "class").unwrap_or_default();
        let size = attribute(tag, "font-size")
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or_else(|| class_size(&class));
        let weight = attribute(tag, "font-weight").unwrap_or_default();
        runs.push(TextRun {
            x: attribute(tag, "x").unwrap_or_default(),
            y: attribute(tag, "y")
                .and_then(|s| s.parse::<f64>().ok())
                .unwrap_or(0.0),
            size,
            style: format!("{class}|{size}|{weight}"),
            text: decode_entities(content),
        });
    }
    runs
}

/// Font sizes of the hand-drawn SVGs' classes, from the design page's stylesheet.
fn class_size(class: &str) -> f64 {
    if class == "t m" || class.contains("mono") {
        11.0
    } else if class.starts_with("lbl") {
        10.5
    } else {
        12.5
    }
}

/// Wrapped lines of one paragraph rejoin: consecutive runs at the same x in the same style,
/// each one line below the last. The key drops whitespace, so a wrap at any character and
/// runs of spaces compare equal, and drops the bullet stencil draws before a fact.
fn labels(svg: &str) -> Vec<String> {
    let mut joined: Vec<(String, TextRun)> = Vec::new();
    for run in text_runs(svg) {
        let continues = joined.last().is_some_and(|(_, last)| {
            last.x == run.x
                && last.style == run.style
                && run.y > last.y
                && run.y - last.y <= run.size * 1.6
        });
        match joined.last_mut() {
            Some((text, last)) if continues => {
                text.push(' ');
                text.push_str(&run.text);
                *last = run;
            }
            _ => joined.push((run.text.clone(), run)),
        }
    }
    let mut keys: Vec<String> = joined
        .into_iter()
        .map(|(text, _)| {
            let text = text.strip_prefix(FACT_BULLET).unwrap_or(&text).to_string();
            text.split_whitespace().collect::<String>()
        })
        .collect();
    keys.sort();
    keys
}

fn compare_labels(figure: &str, added: &[&str]) {
    let original = labels(&fixture(&format!("{figure}.original.svg")));
    let rendered_svg =
        fs::read_to_string(format!("{RENDERED}/{figure}-light.svg")).unwrap_or_default();
    let mut rendered = labels(&rendered_svg);
    let added: Vec<String> = added
        .iter()
        .map(|a| a.split_whitespace().collect::<String>())
        .collect();
    for label in &added {
        let count = rendered.iter().filter(|r| *r == label).count();
        assert_eq!(
            count, 1,
            "{figure}: added label {label} appears {count} times"
        );
    }
    rendered.retain(|label| !added.contains(label));
    assert!(!original.is_empty(), "{figure}: no original labels");
    let missing: Vec<&String> = original.iter().filter(|l| !rendered.contains(l)).collect();
    let extra: Vec<&String> = rendered.iter().filter(|l| !original.contains(l)).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "{figure}: missing {missing:?}, extra {extra:?}"
    );
    assert_eq!(
        original.len(),
        rendered.len(),
        "{figure}: label counts differ"
    );
}

#[test]
fn topology_keeps_every_label_of_the_hand_drawn_figure() {
    compare_labels("topology", &[]);
}

#[test]
fn lifecycle_keeps_every_label_and_adds_the_handler_box_label() {
    compare_labels("lifecycle", &["WorkUnit run handler"]);
}

#[test]
fn escalation_keeps_every_label_of_the_hand_drawn_figure() {
    compare_labels("escalation", &[]);
}

#[test]
fn deep_links_keep_every_label_of_the_hand_drawn_figure() {
    compare_labels("deep-links", &[]);
}
