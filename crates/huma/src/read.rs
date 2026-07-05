//! Huma Read — on-device reading mode: extract the main article text from a
//! page and produce a faithful extractive summary.
//!
//! Scope note (documented deviation, per project rules): the spec suggests a
//! small quantized LLM via Candle for summarization. This uses **extractive**
//! summarization (TextRank-style sentence ranking) instead of a generative
//! model. Rationale: (1) it runs fully on-device with no multi-GB model
//! download and no GPU dependency; (2) an extractive summary is composed of
//! real sentences from the page, so it *cannot hallucinate* — which is
//! exactly the property the spec's verification demands ("a genuine summary
//! of the page's actual content, not a hallucinated generic response"). A
//! generative Candle path can layer on top later.

/// Split raw page text into clean sentences.
fn sentences(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        cur.push(c);
        if matches!(c, '.' | '!' | '?') {
            // End the sentence unless it looks like an abbreviation / decimal.
            let next_is_space_or_end = chars.peek().map(|n| n.is_whitespace()).unwrap_or(true);
            if next_is_space_or_end {
                let s = cur.trim().to_string();
                if s.split_whitespace().count() >= 4 {
                    out.push(s);
                }
                cur.clear();
            }
        }
    }
    let tail = cur.trim();
    if tail.split_whitespace().count() >= 4 {
        out.push(tail.to_string());
    }
    out
}

const STOPWORDS: &[&str] = &[
    "the", "a", "an", "and", "or", "but", "of", "to", "in", "on", "for", "with",
    "as", "by", "at", "is", "are", "was", "were", "be", "been", "it", "this",
    "that", "these", "those", "from", "he", "she", "they", "we", "you", "i",
    "his", "her", "their", "our", "your", "its", "not", "no", "do", "does",
    "did", "have", "has", "had", "will", "would", "can", "could", "may", "also",
];

fn tokenize(s: &str) -> Vec<String> {
    s.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() > 2 && !STOPWORDS.contains(w))
        .map(|w| w.to_string())
        .collect()
}

/// Produce an extractive summary of at most `max_sentences`, preserving the
/// original order of the chosen sentences. Sentences are scored by the sum of
/// their words' corpus frequencies (a fast TextRank approximation), with a
/// mild position prior (earlier sentences matter more in articles).
pub fn summarize(text: &str, max_sentences: usize) -> String {
    let sents = sentences(text);
    if sents.len() <= max_sentences {
        return sents.join(" ");
    }

    // Word frequencies across the document.
    let mut freq: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
    for s in &sents {
        for w in tokenize(s) {
            *freq.entry(w).or_insert(0.0) += 1.0;
        }
    }
    let max_f = freq.values().cloned().fold(1.0, f64::max);

    // Score each sentence.
    let mut scored: Vec<(usize, f64)> = sents
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let toks = tokenize(s);
            if toks.is_empty() {
                return (i, 0.0);
            }
            let base: f64 = toks.iter().map(|w| freq.get(w).copied().unwrap_or(0.0) / max_f).sum();
            let norm = base / (toks.len() as f64).sqrt();
            // Position prior: first few sentences get a small boost.
            let pos = if i < 3 { 1.15 } else { 1.0 };
            (i, norm * pos)
        })
        .collect();

    // Pick the top-N, then restore document order.
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let mut chosen: Vec<usize> = scored.iter().take(max_sentences).map(|(i, _)| *i).collect();
    chosen.sort_unstable();
    chosen
        .into_iter()
        .map(|i| sents[i].clone())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Extract readable article text from a plain-text-ified DOM dump. The heavy
/// DOM→text extraction happens in the page (JS Readability-style walk); this
/// cleans whitespace and drops boilerplate-looking short lines.
pub fn clean_extracted(text: &str) -> String {
    text.lines()
        .map(|l| l.trim())
        .filter(|l| l.split_whitespace().count() >= 5)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARTICLE: &str = "The Tor network routes traffic through a series of \
volunteer-run relays to conceal a user's location and usage. It was originally \
developed by the United States Naval Research Laboratory. Today it is maintained \
by the non-profit Tor Project. Traffic is encrypted in layers, like an onion, \
which is where the name comes from. Each relay decrypts only one layer, learning \
only the previous and next hop. This design prevents any single relay from \
knowing both the origin and the destination of the traffic. Arti is a newer \
implementation of Tor written in the Rust programming language. It aims to be \
more secure and maintainable than the original C implementation. Bananas are an \
unrelated tropical fruit and have nothing to do with anonymity networks.";

    #[test]
    fn summary_is_faithful_and_shorter() {
        let summary = summarize(ARTICLE, 3);
        // Every summary sentence must appear verbatim in the source (extractive
        // => no hallucination).
        for sent in summary.split(". ") {
            let s = sent.trim_end_matches('.').trim();
            if s.len() < 8 {
                continue;
            }
            assert!(
                ARTICLE.contains(s),
                "summary sentence not found verbatim in source: {s:?}"
            );
        }
        // Shorter than the source.
        assert!(summary.len() < ARTICLE.len());
        // Captures the core topic (Tor), not the irrelevant banana sentence.
        assert!(summary.to_lowercase().contains("tor"));
        assert!(!summary.to_lowercase().contains("banana"), "kept an irrelevant sentence");
    }

    #[test]
    fn short_text_returned_whole() {
        let t = "Only one sentence here about rust programming language.";
        assert_eq!(summarize(t, 3), t);
    }
}
