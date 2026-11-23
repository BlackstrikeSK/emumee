//! A bounded, linear-time matcher for custom memory-string indicator patterns.
//!
//! This is deliberately **not** a general regex engine. It compiles a restricted
//! grammar to a Thompson NFA and simulates it with a set-based (Pike-style) pass,
//! so matching is linear in `input_len * states` with **no backtracking** — it is
//! ReDoS-safe by construction, not by a runtime timeout. Every bound below is a
//! compile-time admission check: an over-complex pattern is *refused*, never
//! accepted and then run slowly.
//!
//! Supported subset (see `docs/native-pe/m8-plan.md`):
//!   literals, `.` (any scalar except `\n`/`\r`), char classes `[...]` with ranges,
//!   negation and `\d \w \s` shorthands, escapes
//!   `\d \D \w \W \s \S \. \\ \[ \] \( \) \{ \} \| \+ \* \? \t \n \r \xHH \uHHHH`,
//!   greedy quantifiers `* + ?` and bounded `{m} {m,} {m,n}`, non-capturing groups
//!   `(...)`, and alternation `|`.
//! Refused (→ `CompileError`): `^`/`$` anchors, `(?...)` extensions, lazy
//! quantifiers, backreferences, unknown escapes, and anything exceeding the bounds.
//!
//! `\d`/`\w`/`\s` are the ASCII classes (digit, `[A-Za-z0-9_]`, ASCII whitespace)
//! so the subset is fully deterministic and host-locale-independent.

/// Largest `{m,n}`/`{m}` upper bound; keeps bounded repeats from exploding states.
pub const MAX_REPEAT: usize = 1024;
/// Largest compiled NFA program (instructions) per pattern.
pub const MAX_STATES: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
pub enum CompileError {
    /// Empty source pattern.
    Empty,
    /// Syntactically malformed (unbalanced group/class, bad `{m,n}`, dangling escape).
    Syntax,
    /// A quantifier with nothing to repeat, or stacked on another quantifier.
    Repeat,
    /// A construct outside the supported subset (anchors, `(?...)`, lazy, backrefs).
    Unsupported,
    /// Compiled program would exceed `MAX_STATES`, or a `{m,n}` exceeds `MAX_REPEAT`.
    TooLarge,
}

// ---------------------------------------------------------------------------
// Grammar / AST
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum ClassItem {
    Char(char),
    Range(char, char),
    Digit,
    NotDigit,
    Word,
    NotWord,
    Space,
    NotSpace,
}

#[derive(Clone, Debug)]
struct Class {
    negated: bool,
    items: Vec<ClassItem>,
}

fn ascii_digit(c: char) -> bool {
    c.is_ascii_digit()
}
fn ascii_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}
fn ascii_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c')
}

impl ClassItem {
    fn matches(&self, c: char) -> bool {
        match self {
            ClassItem::Char(x) => c == *x,
            ClassItem::Range(a, b) => *a <= c && c <= *b,
            ClassItem::Digit => ascii_digit(c),
            ClassItem::NotDigit => !ascii_digit(c),
            ClassItem::Word => ascii_word(c),
            ClassItem::NotWord => !ascii_word(c),
            ClassItem::Space => ascii_space(c),
            ClassItem::NotSpace => !ascii_space(c),
        }
    }
}

impl Class {
    fn matches(&self, c: char) -> bool {
        let any = self.items.iter().any(|i| i.matches(c));
        any != self.negated
    }
}

#[derive(Clone, Debug)]
enum Matcher {
    /// Any scalar except `\n`/`\r` (Python `re` default, no DOTALL).
    Any,
    Char(char),
    Class(Class),
}

impl Matcher {
    fn matches(&self, c: char) -> bool {
        match self {
            Matcher::Any => c != '\n' && c != '\r',
            Matcher::Char(x) => c == *x,
            Matcher::Class(class) => class.matches(c),
        }
    }
}

#[derive(Clone, Debug)]
enum Ast {
    Empty,
    Atom(Matcher),
    Concat(Vec<Ast>),
    Alt(Vec<Ast>),
    /// Greedy `{min, max}`; `max == None` is unbounded (`*`/`+`/`{m,}`).
    Repeat(Box<Ast>, usize, Option<usize>),
}

// ---------------------------------------------------------------------------
// Parser (recursive descent over scalars)
// ---------------------------------------------------------------------------

struct Parser<'a> {
    chars: &'a [char],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }
    fn bump(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }
    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn parse_alt(&mut self) -> Result<Ast, CompileError> {
        let mut branches = vec![self.parse_concat()?];
        while self.eat('|') {
            branches.push(self.parse_concat()?);
        }
        if branches.len() == 1 {
            Ok(branches.pop().expect("one branch"))
        } else {
            Ok(Ast::Alt(branches))
        }
    }

    fn parse_concat(&mut self) -> Result<Ast, CompileError> {
        let mut items = Vec::new();
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                break;
            }
            let atom = self.parse_atom()?;
            let quantified = self.parse_quantifier(atom)?;
            items.push(quantified);
        }
        match items.len() {
            0 => Ok(Ast::Empty),
            1 => Ok(items.pop().expect("one item")),
            _ => Ok(Ast::Concat(items)),
        }
    }

    /// Apply a trailing quantifier to `atom`, refusing lazy forms and stacking.
    fn parse_quantifier(&mut self, atom: Ast) -> Result<Ast, CompileError> {
        let (min, max) = match self.peek() {
            Some('*') => {
                self.pos += 1;
                (0, None)
            }
            Some('+') => {
                self.pos += 1;
                (1, None)
            }
            Some('?') => {
                self.pos += 1;
                (0, Some(1))
            }
            Some('{') => match self.try_parse_brace() {
                Some(range) => range?,
                // Not a valid `{m,n}`: `{` was consumed as a literal atom already,
                // so this branch is unreachable from parse_atom. Guard anyway.
                None => return Ok(atom),
            },
            _ => return Ok(atom),
        };
        // Reject a repeat applied to something that can only match empty, and
        // reject stacked/lazy quantifiers (`a**`, `a*?`).
        if matches!(atom, Ast::Empty) {
            return Err(CompileError::Repeat);
        }
        if matches!(self.peek(), Some('*') | Some('+') | Some('?')) {
            return Err(CompileError::Repeat);
        }
        if let Some(n) = max {
            if n < min {
                return Err(CompileError::Syntax);
            }
            if n > MAX_REPEAT {
                return Err(CompileError::TooLarge);
            }
        } else if min > MAX_REPEAT {
            return Err(CompileError::TooLarge);
        }
        Ok(Ast::Repeat(Box::new(atom), min, max))
    }

    /// Parse `{m}`, `{m,}`, `{m,n}` starting at a `{`. Returns None (without
    /// consuming) if the brace does not form a valid quantifier (treated as a
    /// literal by `parse_atom`).
    fn try_parse_brace(&mut self) -> Option<Result<(usize, Option<usize>), CompileError>> {
        let start = self.pos;
        debug_assert_eq!(self.chars.get(start), Some(&'{'));
        let mut at = start + 1;
        let read_num = |at: &mut usize| -> Option<usize> {
            let first = *at;
            let mut value: usize = 0;
            while let Some(d) = self.chars.get(*at).and_then(|c| c.to_digit(10)) {
                value = value.checked_mul(10)?.checked_add(d as usize)?;
                *at += 1;
                if value > MAX_REPEAT {
                    // keep consuming digits so the caller sees a well-formed brace
                    while self.chars.get(*at).is_some_and(|c| c.is_ascii_digit()) {
                        *at += 1;
                    }
                    return Some(usize::MAX);
                }
            }
            if *at == first {
                None
            } else {
                Some(value)
            }
        };
        let min = read_num(&mut at)?;
        let max = if self.chars.get(at) == Some(&',') {
            at += 1;
            if self.chars.get(at) == Some(&'}') {
                None
            } else {
                Some(read_num(&mut at)?)
            }
        } else {
            Some(min)
        };
        if self.chars.get(at) != Some(&'}') {
            return None; // not a quantifier; literal `{`
        }
        self.pos = at + 1;
        if min == usize::MAX || matches!(max, Some(usize::MAX)) {
            return Some(Err(CompileError::TooLarge));
        }
        Some(Ok((min, max)))
    }

    fn parse_atom(&mut self) -> Result<Ast, CompileError> {
        match self.peek() {
            None => Err(CompileError::Syntax),
            Some('(') => {
                self.pos += 1;
                if self.peek() == Some('?') {
                    return Err(CompileError::Unsupported); // (?:...), (?=...), (?P<..>)
                }
                let inner = self.parse_alt()?;
                if !self.eat(')') {
                    return Err(CompileError::Syntax);
                }
                Ok(inner)
            }
            Some(')') => Err(CompileError::Syntax),
            Some('[') => self.parse_class(),
            Some('^') | Some('$') => Err(CompileError::Unsupported),
            Some('*') | Some('+') | Some('?') => Err(CompileError::Repeat),
            Some('{') => {
                // A `{` that does not open a valid quantifier is a literal.
                if self.try_parse_brace().is_some() {
                    // It *is* a quantifier but there is no preceding atom here.
                    Err(CompileError::Repeat)
                } else {
                    self.pos += 1;
                    Ok(Ast::Atom(Matcher::Char('{')))
                }
            }
            Some('.') => {
                self.pos += 1;
                Ok(Ast::Atom(Matcher::Any))
            }
            Some('\\') => {
                self.pos += 1;
                self.parse_escape()
            }
            Some(c) => {
                self.pos += 1;
                Ok(Ast::Atom(Matcher::Char(c)))
            }
        }
    }

    /// Parse an escape in the *concatenation* context (returns an Ast atom).
    fn parse_escape(&mut self) -> Result<Ast, CompileError> {
        let c = self.bump().ok_or(CompileError::Syntax)?;
        if let Some(class) = escape_class(c) {
            return Ok(Ast::Atom(Matcher::Class(class)));
        }
        let literal = self.escape_literal(c)?;
        Ok(Ast::Atom(Matcher::Char(literal)))
    }

    /// Resolve a non-class escape to a literal scalar (shared with class parsing).
    fn escape_literal(&mut self, c: char) -> Result<char, CompileError> {
        Ok(match c {
            't' => '\t',
            'n' => '\n',
            'r' => '\r',
            'x' => self.read_hex(2)?,
            'u' => self.read_hex(4)?,
            '\\' | '.' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '^' | '$'
            | '-' | '/' => c,
            '0'..='9' => return Err(CompileError::Unsupported), // backreference / octal
            _ => return Err(CompileError::Syntax),               // unknown escape
        })
    }

    fn read_hex(&mut self, n: usize) -> Result<char, CompileError> {
        let mut value: u32 = 0;
        for _ in 0..n {
            let d = self
                .bump()
                .and_then(|c| c.to_digit(16))
                .ok_or(CompileError::Syntax)?;
            value = value * 16 + d;
        }
        char::from_u32(value).ok_or(CompileError::Syntax)
    }

    fn parse_class(&mut self) -> Result<Ast, CompileError> {
        debug_assert_eq!(self.peek(), Some('['));
        self.pos += 1;
        let negated = self.eat('^');
        let mut items: Vec<ClassItem> = Vec::new();
        // A `]` as the very first class member is a literal (Python/POSIX rule).
        let mut first = true;
        loop {
            match self.peek() {
                None => return Err(CompileError::Syntax),
                Some(']') if !first => {
                    self.pos += 1;
                    break;
                }
                _ => {}
            }
            first = false;
            let (lo, shorthand) = self.class_member()?;
            if let Some(item) = shorthand {
                items.push(item);
                continue;
            }
            let lo = lo.expect("literal member");
            // Range `a-z` when a `-` is followed by a non-`]` member.
            if self.peek() == Some('-') && self.chars.get(self.pos + 1) != Some(&']') {
                self.pos += 1; // consume '-'
                let (hi, hi_class) = self.class_member()?;
                if hi_class.is_some() {
                    return Err(CompileError::Syntax); // `a-\d`
                }
                let hi = hi.expect("range end");
                if hi < lo {
                    return Err(CompileError::Syntax);
                }
                items.push(ClassItem::Range(lo, hi));
            } else {
                items.push(ClassItem::Char(lo));
            }
        }
        if items.is_empty() {
            return Err(CompileError::Syntax);
        }
        Ok(Ast::Atom(Matcher::Class(Class { negated, items })))
    }

    /// One class member: either a literal scalar or a `\d`-style shorthand.
    fn class_member(&mut self) -> Result<(Option<char>, Option<ClassItem>), CompileError> {
        match self.bump().ok_or(CompileError::Syntax)? {
            '\\' => {
                let c = self.bump().ok_or(CompileError::Syntax)?;
                if let Some(Class { items, .. }) = escape_class(c) {
                    // Shorthand classes carry through as a single item.
                    if items.len() == 1 {
                        return Ok((None, Some(items.into_iter().next().expect("one"))));
                    }
                }
                let literal = self.escape_literal(c)?;
                Ok((Some(literal), None))
            }
            '[' => Err(CompileError::Unsupported), // nested class / POSIX `[:...:]`
            c => Ok((Some(c), None)),
        }
    }
}

/// `\d \D \w \W \s \S` → a single-item class; other escapes → None.
fn escape_class(c: char) -> Option<Class> {
    let item = match c {
        'd' => ClassItem::Digit,
        'D' => ClassItem::NotDigit,
        'w' => ClassItem::Word,
        'W' => ClassItem::NotWord,
        's' => ClassItem::Space,
        'S' => ClassItem::NotSpace,
        _ => return None,
    };
    Some(Class {
        negated: false,
        items: vec![item],
    })
}

// ---------------------------------------------------------------------------
// Compiler: AST → Thompson NFA program
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum Inst {
    /// Consume one matching scalar, then fall through to `self_index + 1`.
    Char(Matcher),
    /// Epsilon to both targets.
    Split(usize, usize),
    /// Epsilon to one target.
    Jmp(usize),
    /// Accept.
    Match,
}

#[derive(Debug)]
pub struct Pattern {
    prog: Vec<Inst>,
}

struct Compiler {
    prog: Vec<Inst>,
}

impl Compiler {
    fn push(&mut self, inst: Inst) -> Result<usize, CompileError> {
        if self.prog.len() >= MAX_STATES {
            return Err(CompileError::TooLarge);
        }
        self.prog.push(inst);
        Ok(self.prog.len() - 1)
    }

    fn emit(&mut self, ast: &Ast) -> Result<(), CompileError> {
        match ast {
            Ast::Empty => {
                // A no-op that falls through; a Jmp to the next instruction keeps
                // the "Char falls through to +1" invariant intact for callers.
                let j = self.push(Inst::Jmp(0))?;
                self.prog[j] = Inst::Jmp(self.prog.len());
                Ok(())
            }
            Ast::Atom(m) => {
                self.push(Inst::Char(m.clone()))?;
                Ok(())
            }
            Ast::Concat(items) => {
                for item in items {
                    self.emit(item)?;
                }
                Ok(())
            }
            Ast::Alt(branches) => self.emit_alt(branches),
            Ast::Repeat(inner, min, max) => self.emit_repeat(inner, *min, *max),
        }
    }

    fn emit_alt(&mut self, branches: &[Ast]) -> Result<(), CompileError> {
        let mut end_jmps = Vec::new();
        let mut pending_split: Option<usize> = None;
        for (i, branch) in branches.iter().enumerate() {
            if let Some(s) = pending_split.take() {
                if let Inst::Split(o1, _) = self.prog[s] {
                    self.prog[s] = Inst::Split(o1, self.prog.len());
                }
            }
            if i + 1 < branches.len() {
                let s = self.push(Inst::Split(0, 0))?;
                self.prog[s] = Inst::Split(s + 1, 0); // out1 = body; out2 patched later
                self.emit(branch)?;
                let j = self.push(Inst::Jmp(0))?;
                end_jmps.push(j);
                pending_split = Some(s);
            } else {
                self.emit(branch)?;
            }
        }
        let end = self.prog.len();
        for j in end_jmps {
            self.prog[j] = Inst::Jmp(end);
        }
        Ok(())
    }

    fn emit_optional(&mut self, inner: &Ast) -> Result<(), CompileError> {
        let s = self.push(Inst::Split(0, 0))?;
        self.prog[s] = Inst::Split(s + 1, 0); // greedy: try the body first
        self.emit(inner)?;
        self.prog[s] = match self.prog[s] {
            Inst::Split(o1, _) => Inst::Split(o1, self.prog.len()),
            _ => unreachable!("split"),
        };
        Ok(())
    }

    fn emit_star(&mut self, inner: &Ast) -> Result<(), CompileError> {
        let s = self.push(Inst::Split(0, 0))?;
        self.prog[s] = Inst::Split(s + 1, 0);
        self.emit(inner)?;
        self.push(Inst::Jmp(s))?;
        self.prog[s] = match self.prog[s] {
            Inst::Split(o1, _) => Inst::Split(o1, self.prog.len()),
            _ => unreachable!("split"),
        };
        Ok(())
    }

    fn emit_repeat(
        &mut self,
        inner: &Ast,
        min: usize,
        max: Option<usize>,
    ) -> Result<(), CompileError> {
        for _ in 0..min {
            self.emit(inner)?;
        }
        match max {
            Some(n) => {
                for _ in 0..(n - min) {
                    self.emit_optional(inner)?;
                }
            }
            None => self.emit_star(inner)?,
        }
        Ok(())
    }
}

pub fn compile(source: &str) -> Result<Pattern, CompileError> {
    if source.is_empty() {
        return Err(CompileError::Empty);
    }
    let chars: Vec<char> = source.chars().collect();
    let mut parser = Parser { chars: &chars, pos: 0 };
    let ast = parser.parse_alt()?;
    if parser.pos != chars.len() {
        return Err(CompileError::Syntax); // trailing `)` or unparsed input
    }
    let mut compiler = Compiler { prog: Vec::new() };
    compiler.emit(&ast)?;
    compiler.push(Inst::Match)?;
    Ok(Pattern { prog: compiler.prog })
}

// ---------------------------------------------------------------------------
// Simulation: leftmost-longest, non-overlapping, linear-time
// ---------------------------------------------------------------------------

struct Threads {
    list: Vec<(usize, usize)>, // (pc, start)
    seen: Vec<u32>,
    generation: u32,
}

impl Threads {
    fn new(len: usize) -> Self {
        Self {
            list: Vec::new(),
            seen: vec![0; len],
            generation: 0,
        }
    }
    fn reset(&mut self) {
        self.list.clear();
        self.generation += 1;
    }
}

impl Pattern {
    /// Find all non-overlapping, leftmost-longest, non-empty matches as
    /// `(start, end)` scalar-index spans into `text`. Linear in `text.len() *
    /// states`; never backtracks.
    pub fn find_all(&self, text: &[char]) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < text.len() {
            match self.leftmost_from(text, pos) {
                Some((s, e)) => {
                    out.push((s, e));
                    pos = e; // non-overlapping; e > s guaranteed
                }
                None => break,
            }
        }
        out
    }

    fn leftmost_from(&self, text: &[char], lo: usize) -> Option<(usize, usize)> {
        let mut best: Option<(usize, usize)> = None;
        let mut clist = Threads::new(self.prog.len());
        clist.reset();
        self.add(&mut clist, 0, lo, lo, &mut best);
        let n = text.len();
        let mut i = lo;
        while i < n {
            let mut nlist = Threads::new(self.prog.len());
            nlist.reset();
            let ch = text[i];
            for idx in 0..clist.list.len() {
                let (pc, start) = clist.list[idx];
                if let Inst::Char(m) = &self.prog[pc] {
                    if m.matches(ch) {
                        self.add(&mut nlist, pc + 1, start, i + 1, &mut best);
                    }
                }
            }
            clist = nlist;
            // Seed a fresh potential start at i+1, unless a leftmost start is locked.
            if best.is_none_or(|(bs, _)| i < bs) {
                self.add(&mut clist, 0, i + 1, i + 1, &mut best);
            }
            if let Some((bs, _)) = best {
                clist.list.retain(|(_, s)| *s <= bs);
            }
            if clist.list.is_empty() && best.is_some() {
                break;
            }
            i += 1;
        }
        best
    }

    /// Epsilon-closure insertion. `pos` is the input index reached (chars consumed
    /// from `start`); reaching `Match` records a candidate ending at `pos`.
    fn add(
        &self,
        threads: &mut Threads,
        pc: usize,
        start: usize,
        pos: usize,
        best: &mut Option<(usize, usize)>,
    ) {
        let mut stack = vec![(pc, start)];
        while let Some((pc, start)) = stack.pop() {
            if threads.seen[pc] == threads.generation {
                continue;
            }
            threads.seen[pc] = threads.generation;
            match self.prog[pc] {
                Inst::Jmp(x) => stack.push((x, start)),
                Inst::Split(a, b) => {
                    stack.push((b, start));
                    stack.push((a, start));
                }
                Inst::Match => record(best, start, pos),
                Inst::Char(_) => threads.list.push((pc, start)),
            }
        }
    }
}

/// Leftmost (smallest start) wins; for the leftmost start, longest end wins.
/// Empty matches are discarded so a nullable pattern cannot stall the scan.
fn record(best: &mut Option<(usize, usize)>, start: usize, end: usize) {
    if end <= start {
        return;
    }
    match best {
        None => *best = Some((start, end)),
        Some((bs, be)) => {
            if start < *bs || (start == *bs && end > *be) {
                *best = Some((start, end));
            }
        }
    }
}

#[cfg(test)]
mod tests;
