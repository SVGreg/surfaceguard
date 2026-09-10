package report

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/SVGreg/surfaceguard/pkg/model"
)

const (
	// defaultWidth is the wrap width used when $COLUMNS says nothing. It is a
	// constant rather than the real terminal size on purpose: a report that is
	// piped, redirected with --out, or captured in CI must be byte-stable, and
	// asking the tty would make it depend on the window it happened to run in.
	defaultWidth = 100
	minWidth     = 40
	maxWidth     = 200
	// tabStop expands a tab to a fixed number of spaces. Fixed rather than
	// tab-stop-aware because the only thing that matters is that the line and
	// the underline beneath it expand *identically*, so the marker stays under
	// the match.
	tabStop  = "    "
	ellipsis = "…"
	// windowLead is how much of the line before the match a window keeps, so a
	// match at column 4000 of a minified file still shows what precedes it.
	windowLead = 8
)

// wrapWidth is the column at which prose (rationale, fix) is wrapped and
// source lines are cut. Options.Width is the only input: like NoColor, whether
// a terminal is involved is the caller's question to answer, so Text stays a
// pure function of its arguments and a test never depends on the environment.
func wrapWidth(opt Options) int {
	w := opt.Width
	if w == 0 {
		w = defaultWidth
	}
	if w < minWidth {
		w = minWidth
	}
	if w > maxWidth {
		w = maxWidth
	}
	return w
}

func expandTabs(s string) string { return strings.ReplaceAll(s, "\t", tabStop) }

// runeOffset returns the byte offset of the n-th rune of s, counting an
// invalid byte as one rune — the same accounting pkg/rules used to produce
// Finding.Column, so the two always agree about where a column is.
func runeOffset(s string, n int) int {
	i := 0
	for n > 0 && i < len(s) {
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
		n--
	}
	return i
}

// wrapLines greedily wraps text to width columns, breaking on spaces only.
// A word longer than the width — a URL, a long flag — overflows rather than
// being split, because a broken URL is not copy-pasteable and a split
// `--flag-name` reads as two different flags.
func wrapLines(text string, width int) []string {
	if width < 8 {
		width = 8
	}
	var out []string
	var line strings.Builder
	n := 0
	for _, word := range strings.Fields(text) {
		wl := utf8.RuneCountInString(word)
		switch {
		case n == 0:
			line.WriteString(word)
			n = wl
		case n+1+wl <= width:
			line.WriteByte(' ')
			line.WriteString(word)
			n += 1 + wl
		default:
			out = append(out, line.String())
			line.Reset()
			line.WriteString(word)
			n = wl
		}
	}
	if n > 0 {
		out = append(out, line.String())
	}
	if len(out) == 0 {
		return []string{""}
	}
	return out
}

// lineFrame renders a finding's source line for a terminal of the given budget
// in columns, and reports where the matched span lands in what it returns.
//
// Everything printed here is attacker-authored, so each piece is sanitized
// before it is measured: the offsets are computed on the *escaped* text, or a
// line containing a control character would push the marker out of alignment
// with the very span it is meant to point at. A width of 0 means "no span to
// mark" — the finding carried no column.
func lineFrame(f model.Finding, budget int) (text string, start, width int) {
	raw := f.LineText
	if raw == "" {
		return "", 0, 0
	}
	n := utf8.RuneCountInString(raw)
	c, e := clampSpan(f.Column-1, f.EndColumn-1, n)
	pre := sanitize(expandTabs(raw[:runeOffset(raw, c)]))
	mid := sanitize(expandTabs(raw[runeOffset(raw, c):runeOffset(raw, e)]))
	post := sanitize(expandTabs(raw[runeOffset(raw, e):]))
	if f.Column <= 0 {
		// No column: show the line, mark nothing.
		return clip(pre+mid+post, budget), 0, 0
	}

	full := []rune(pre + mid + post)
	start, width = utf8.RuneCountInString(pre), utf8.RuneCountInString(mid)
	if len(full) <= budget {
		return string(full), start, width
	}

	// Window around the match: keep a little of what precedes it, then as much
	// as fits, marking each cut end with an ellipsis.
	from := 0
	if start > windowLead {
		from = start - windowLead
	}
	if from+budget > len(full) {
		from = max(0, len(full)-budget)
	}
	size := budget
	head := from > 0
	if head {
		size--
	}
	to := min(len(full), from+size)
	tail := to < len(full)
	if tail {
		size--
		to = min(len(full), from+size)
	}
	text = string(full[from:to])
	start -= from
	if head {
		text = ellipsis + text
		start++
	}
	if tail {
		text += ellipsis
	}
	outLen := utf8.RuneCountInString(text)
	if start > outLen {
		start = outLen
	}
	if start < 0 {
		start = 0
	}
	if start+width > outLen {
		width = outLen - start
	}
	if width < 1 {
		width = 1
	}
	return text, start, width
}

// clampSpan bounds a [c,e) rune span to a line of n runes.
func clampSpan(c, e, n int) (int, int) {
	if c < 0 {
		c = 0
	}
	if c > n {
		c = n
	}
	if e < c {
		e = c
	}
	if e > n {
		e = n
	}
	return c, e
}

// clip truncates an already-sanitized string to n columns, marking the cut.
func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	if n < 1 {
		return ""
	}
	return string([]rune(s)[:n-1]) + ellipsis
}

// writeFrame prints the source frame: Context lines above the match, the
// matched line with its span highlighted, the marker row, then Context lines
// below. Context lines come from Options.Sources; without it the frame is the
// matched line alone, which is still the point of the feature.
func writeFrame(w io.Writer, f model.Finding, opt Options, col func(string) string, fc *frameCache) {
	sevC := severityColor(f.Severity, col)
	src := fc.sourceLines(f, opt)
	first, last := f.StartLine, f.StartLine
	if len(src) > 0 && opt.Context > 0 {
		first = max(1, f.StartLine-opt.Context)
		last = min(len(src), f.StartLine+opt.Context)
	}
	gw := len(strconv.Itoa(max(last, 1)))
	budget := wrapWidth(opt) - gw - 5
	if budget < minWidth/2 {
		budget = minWidth / 2
	}

	text, start, width := lineFrame(f, budget)
	if text == "" && len(src) == 0 {
		return // nothing to show: no line text and no source to fall back on
	}
	ctx := func(n int) {
		if n < 1 || n > len(src) || n == f.StartLine {
			return
		}
		fmt.Fprintf(w, "  %s%*d │%s %s\n", col(cGray), gw, n, col(cReset),
			clip(sanitize(expandTabs(src[n-1])), budget))
	}
	for n := first; n < f.StartLine; n++ {
		ctx(n)
	}
	if text == "" {
		// The line was too long to keep (see rules.maxLineText) but the source
		// is at hand, so show it from there rather than dropping the frame.
		raw := src[min(f.StartLine, len(src))-1]
		text = clip(sanitize(expandTabs(raw)), budget)
	}
	r := []rune(text)
	if width > 0 && start+width <= len(r) {
		fmt.Fprintf(w, "  %s%*d │%s %s%s%s%s%s%s\n", col(cGray), gw, f.StartLine, col(cReset),
			string(r[:start]), sevC+col(cBold), string(r[start:start+width]), col(cReset), string(r[start+width:]), col(cReset))
		note := underlineNote(f)
		fmt.Fprintf(w, "  %s%*s ╵%s %s%s%s%s%s%s\n", col(cGray), gw, "", col(cReset),
			strings.Repeat(" ", start), sevC, strings.Repeat("━", width), col(cGray), note, col(cReset))
	} else {
		fmt.Fprintf(w, "  %s%*d │%s %s\n", col(cGray), gw, f.StartLine, col(cReset), text)
	}
	for n := f.StartLine + 1; n <= last; n++ {
		ctx(n)
	}
}

// underlineNote is what follows the marker row. It carries the finding's
// excerpt only when the excerpt says something the underlined text does not —
// a homoglyph rule reports "ignоre (U+043E)" for text that reads as "ignore",
// and that codepoint is the whole finding, invisible in the line above. When
// the excerpt is the matched text, or the truncated head of it, the underline
// already shows it and repeating it is noise.
func underlineNote(f model.Finding) string {
	ex := strings.TrimSpace(f.Excerpt)
	if ex == "" || f.LineText == "" {
		return ""
	}
	n := utf8.RuneCountInString(f.LineText)
	c, e := clampSpan(f.Column-1, f.EndColumn-1, n)
	matched := strings.TrimSpace(f.LineText[runeOffset(f.LineText, c):runeOffset(f.LineText, e)])
	if matched == "" || strings.HasPrefix(matched, ex) {
		return ""
	}
	return "  " + sanitize(ex)
}

// frameCache splits each source file into lines once per report. A bundle's
// findings cluster in a handful of files — 65 findings over three files is
// typical — so without it the same file is re-split for every one of them.
type frameCache struct{ files map[string][]string }

func newFrameCache() *frameCache { return &frameCache{files: map[string][]string{}} }

// sourceLines returns the file's lines for context rendering, or nil.
func (c *frameCache) sourceLines(f model.Finding, opt Options) []string {
	if opt.Sources == nil || f.File == "" || f.StartLine < 1 {
		return nil
	}
	lines, cached := c.files[f.File]
	if !cached {
		if b, ok := opt.Sources(f.File); ok {
			lines = strings.Split(string(b), "\n")
			for i := range lines {
				lines[i] = strings.TrimSuffix(lines[i], "\r")
			}
		}
		c.files[f.File] = lines
	}
	if f.StartLine > len(lines) {
		return nil
	}
	return lines
}
