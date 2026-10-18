//! Core's docs (`docs/LOG.md`, `docs/analysis/*.md`) as sources Custos cites:
//! a section is found by its `## ` heading and cited by file, heading and
//! line. Custos never paraphrases a doc into a number or a diagnosis; it shows
//! what a section states, and where (contract rule 9).
use std::path::Path;

use serde::Serialize;

use crate::Sources;

/// A cited section of one of Core's docs.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DocRef {
    /// "docs/LOG.md" or "docs/analysis/<name>.md", as in Core's repo.
    pub doc: String,
    /// The file Custos read it from.
    pub path: String,
    /// The section heading, without the `## `.
    pub heading: String,
    /// 1-based line of the heading.
    pub line: usize,
    /// Why this section is cited (what it was matched on).
    pub why: Option<String>,
}

/// One `## ` section of a markdown doc.
#[derive(Clone, Debug)]
pub struct Section {
    pub heading: String,
    pub line: usize,
    pub body: String,
}

pub fn sections(text: &str) -> Vec<Section> {
    let mut out: Vec<Section> = Vec::new();
    for (i, l) in text.lines().enumerate() {
        if let Some(h) = l.strip_prefix("## ") {
            out.push(Section { heading: h.trim().to_string(), line: i + 1, body: String::new() });
        } else if let Some(s) = out.last_mut() {
            s.body.push_str(l);
            s.body.push('\n');
        }
    }
    out
}

/// Every doc Custos reads, as (doc name in Core's repo, path): LOG.md first,
/// then docs/analysis/*.md by name. Missing files are left out.
pub fn docs(src: &Sources) -> Vec<(String, std::path::PathBuf)> {
    let mut out = Vec::new();
    let log = src.docs_dir.join("LOG.md");
    if log.is_file() {
        out.push(("docs/LOG.md".to_string(), log));
    }
    let mut analysis: Vec<_> = std::fs::read_dir(src.docs_dir.join("analysis"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "md"))
        .collect();
    analysis.sort();
    for p in analysis {
        let name = p.file_name().unwrap_or_default().to_string_lossy().into_owned();
        out.push((format!("docs/analysis/{name}"), p));
    }
    out
}

fn cite(doc: &str, path: &Path, s: &Section, why: Option<String>) -> DocRef {
    DocRef { doc: doc.to_string(), path: path.display().to_string(), heading: s.heading.clone(), line: s.line, why }
}

/// The section of `doc` ("LOG.md" or "analysis/<name>.md") headed `heading`,
/// if it states every one of `quotes` (each found verbatim in its body, line
/// breaks and runs of spaces read as one space).
pub fn stated(src: &Sources, doc: &str, heading: &str, quotes: &[&str]) -> Option<DocRef> {
    let path = src.docs_dir.join(doc);
    let text = std::fs::read_to_string(&path).ok()?;
    let s = sections(&text).into_iter().find(|s| s.heading == heading)?;
    let flat = |t: &str| t.split_whitespace().collect::<Vec<_>>().join(" ");
    let body = flat(&s.body);
    quotes.iter().all(|q| body.contains(&flat(q))).then(|| cite(&format!("docs/{doc}"), &path, &s, None))
}

/// The sections that discuss a kernel at a shape: they name the impl itself,
/// or both its family and the shape. In doc order (LOG.md first).
pub fn about(src: &Sources, impl_: &str, family: &str, shape: &str) -> Vec<DocRef> {
    let mut out = Vec::new();
    for (doc, path) in docs(src) {
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        for s in sections(&text) {
            let why = if s.body.contains(impl_) || s.heading.contains(impl_) {
                Some(format!("names {impl_}"))
            } else if s.body.contains(family) && s.body.contains(shape) {
                Some(format!("names {family} and {shape}"))
            } else {
                None
            };
            if let Some(why) = why {
                out.push(cite(&doc, &path, &s, Some(why)));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_on_level_two_headings() {
        let s = sections("# T\nintro\n## A\none\n### sub\ntwo\n## B\nthree\n");
        assert_eq!(s.len(), 2);
        assert_eq!((s[0].heading.as_str(), s[0].line), ("A", 3));
        assert_eq!(s[0].body, "one\n### sub\ntwo\n");
        assert_eq!((s[1].heading.as_str(), s[1].body.as_str()), ("B", "three\n"));
    }
}
