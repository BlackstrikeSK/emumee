use super::*;
use std::time::Instant;

fn chars(s: &str) -> Vec<char> {
    s.chars().collect()
}

/// Compile and return the matched substrings over `text`.
fn matches(pattern: &str, text: &str) -> Vec<String> {
    let p = compile(pattern).expect("compiles");
    let cs = chars(text);
    p.find_all(&cs)
        .into_iter()
        .map(|(s, e)| cs[s..e].iter().collect())
        .collect()
}

/// Matched `(start, end)` spans over `text`.
fn spans(pattern: &str, text: &str) -> Vec<(usize, usize)> {
    compile(pattern).expect("compiles").find_all(&chars(text))
}

#[test]
fn literals_and_dot() {
    assert_eq!(matches("abc", "xxabcxxabc"), vec!["abc", "abc"]);
    assert_eq!(matches("a.c", "a1c a2c abc"), vec!["a1c", "a2c", "abc"]);
    // `.` excludes newline (no DOTALL).
    assert!(matches("a.c", "a\nc").is_empty());
}

#[test]
fn character_classes_ranges_and_negation() {
    assert_eq!(matches("[a-f0-9]+", "zz deadbeef zz"), vec!["deadbeef"]);
    assert_eq!(matches("[^ ]+", "ab cd"), vec!["ab", "cd"]);
    // `]` as the first member is a literal; `-` at the end is a literal.
    assert_eq!(matches("[]-]+", "a]-]b"), vec!["]-]"]);
}

#[test]
fn shorthand_classes_are_ascii() {
    assert_eq!(matches(r"\d+", "ab12cd345"), vec!["12", "345"]);
    assert_eq!(matches(r"\w+", "a_b!!c9"), vec!["a_b", "c9"]);
    assert_eq!(matches(r"[\dx]+", "x1y2x3"), vec!["x1", "2x3"]);
    assert_eq!(matches(r"\D+", "12ab34"), vec!["ab"]);
}

#[test]
fn quantifiers_are_greedy_longest() {
    assert_eq!(matches("ab?c", "ac abc"), vec!["ac", "abc"]);
    assert_eq!(matches("a+", "baaab aa"), vec!["aaa", "aa"]);
    assert_eq!(matches("a*b", "b ab aaab"), vec!["b", "ab", "aaab"]);
    // bounded repeat
    assert_eq!(matches("a{2,3}", "a aa aaa aaaa"), vec!["aa", "aaa", "aaa"]);
    assert_eq!(matches("a{2}", "a aa aaa"), vec!["aa", "aa"]);
    assert_eq!(matches("a{2,}", "a aa aaaa"), vec!["aa", "aaaa"]);
}

#[test]
fn alternation_and_groups() {
    assert_eq!(matches("cat|dog", "a cat and a dog"), vec!["cat", "dog"]);
    assert_eq!(matches("(ab)+", "abab x ababab"), vec!["abab", "ababab"]);
    assert_eq!(matches("a(b|c)d", "abd acd aed"), vec!["abd", "acd"]);
    // leftmost-longest picks the longer alternative at the same start
    assert_eq!(matches("ab|abc", "abc"), vec!["abc"]);
}

#[test]
fn escapes_resolve_to_literals_and_codepoints() {
    assert_eq!(matches(r"a\.b", "a.b axb"), vec!["a.b"]);
    assert_eq!(matches(r"\x41\x42", "xABx"), vec!["AB"]);
    assert_eq!(matches(r"A", "zAz"), vec!["A"]);
    assert_eq!(matches(r"\(\)", "()"), vec!["()"]);
}

#[test]
fn realistic_indicator_patterns() {
    assert_eq!(
        matches(r"[a-f0-9]{32}", "md5=d41d8cd98f00b204e9800998ecf8427e!"),
        vec!["d41d8cd98f00b204e9800998ecf8427e"]
    );
    assert_eq!(
        matches(r"AKIA[A-Z0-9]{6}", "key AKIAABCDEF rest"),
        vec!["AKIAABCDEF"]
    );
    assert_eq!(
        matches(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+", "mail a.b_c@evil.test end"),
        vec!["a.b_c@evil.test"]
    );
}

#[test]
fn matches_are_non_overlapping_and_leftmost() {
    // Overlapping candidates: only the leftmost non-overlapping ones are kept.
    assert_eq!(spans("aa", "aaaa"), vec![(0, 2), (2, 4)]);
    assert_eq!(spans("aba", "ababa"), vec![(0, 3)]);
}

#[test]
fn empty_matches_do_not_stall_or_emit() {
    // `a*` can match empty everywhere; only the non-empty runs are reported and
    // the scan terminates.
    assert_eq!(matches("a*", "xaaxbx"), vec!["aa"]);
    assert_eq!(matches("a*", "xaax"), vec!["aa"]);
    assert_eq!(matches("x*", "yyy"), Vec::<String>::new());
}

#[test]
fn refuses_constructs_outside_the_subset() {
    assert_eq!(compile("").unwrap_err(), CompileError::Empty);
    assert_eq!(compile("^abc").unwrap_err(), CompileError::Unsupported); // anchor
    assert_eq!(compile("abc$").unwrap_err(), CompileError::Unsupported); // anchor
    assert_eq!(compile("(?:ab)").unwrap_err(), CompileError::Unsupported); // group ext
    assert_eq!(compile("(?P<n>a)").unwrap_err(), CompileError::Unsupported); // named
    assert_eq!(compile(r"a\1").unwrap_err(), CompileError::Unsupported); // backref
    assert_eq!(compile("a*?").unwrap_err(), CompileError::Repeat); // lazy
    assert_eq!(compile("a**").unwrap_err(), CompileError::Repeat); // stacked
    assert_eq!(compile("*a").unwrap_err(), CompileError::Repeat); // nothing to repeat
    assert_eq!(compile("(ab").unwrap_err(), CompileError::Syntax); // unbalanced
    assert_eq!(compile("ab)").unwrap_err(), CompileError::Syntax); // unbalanced
    assert_eq!(compile("[abc").unwrap_err(), CompileError::Syntax); // unterminated class
    assert_eq!(compile(r"a\q").unwrap_err(), CompileError::Syntax); // unknown escape
    assert_eq!(compile("[z-a]").unwrap_err(), CompileError::Syntax); // inverted range
}

#[test]
fn bounds_are_enforced_at_compile_time() {
    assert_eq!(compile("a{0,2000}").unwrap_err(), CompileError::TooLarge); // > MAX_REPEAT
    assert_eq!(compile("a{5000}").unwrap_err(), CompileError::TooLarge);
    // A chain of large bounded repeats overflows MAX_STATES and is refused.
    let big = "(abcd){1000}".to_string() + "(efgh){1000}" + "(ijkl){1000}" + "(mnop){1000}";
    assert_eq!(compile(&big).unwrap_err(), CompileError::TooLarge);
}

#[test]
fn brace_that_is_not_a_quantifier_is_literal() {
    assert_eq!(matches("a{b}", "a{b}c"), vec!["a{b}"]);
    assert_eq!(matches(r"\{\d+\}", "x{123}y"), vec!["{123}"]);
}

#[test]
fn pathological_pattern_stays_linear_and_safe() {
    // The classic catastrophic-backtracking case. A real regex backtracker takes
    // exponential time on this; our set-simulation must finish instantly.
    let p = compile("(a+)+b").expect("compiles");
    let text: Vec<char> = std::iter::repeat_n('a', 5000).collect();
    let start = Instant::now();
    let found = p.find_all(&text); // no trailing 'b' => no match
    let elapsed = start.elapsed();
    assert!(found.is_empty());
    assert!(
        elapsed.as_secs() < 2,
        "pathological scan took {elapsed:?}; must be linear"
    );
}

#[test]
fn large_input_scan_is_bounded() {
    let p = compile(r"[a-f0-9]{16}").expect("compiles");
    let text: Vec<char> = std::iter::repeat_n('a', 200_000).collect();
    let start = Instant::now();
    let found = p.find_all(&text);
    assert_eq!(found.len(), 200_000 / 16);
    assert!(start.elapsed().as_secs() < 2);
}
