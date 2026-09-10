package rules

import (
	"strings"
	"unicode/utf8"
)

// maxLineText caps how much of a source line a finding carries. Lines this long
// are not prose or code a human wrote — they are minified bundles and
// single-line JSON blobs — and the cap keeps one hostile file from putting
// megabytes into every finding, the JSON report, and the terminal. Deciding how
// much of the kept text to *show* is the renderer's job; this is only the
// storage bound.
const maxLineText = 4096

// lineSpan returns the byte span [start,end) of the line containing off,
// excluding the newline itself.
func lineSpan(text string, off int) (start, end int) {
	if off < 0 {
		off = 0
	}
	if off > len(text) {
		off = len(text)
	}
	start = strings.LastIndexByte(text[:off], '\n') + 1
	if i := strings.IndexByte(text[off:], '\n'); i >= 0 {
		end = off + i
	} else {
		end = len(text)
	}
	if start > end {
		return off, off
	}
	return start, end
}

// lineText returns the whole line containing the byte offset off.
func lineText(text string, off int) string {
	start, end := lineSpan(text, off)
	return text[start:end]
}

// locate resolves a match to the source line it sits on and to 1-based rune
// columns within that line. EndColumn is exclusive — the column just past the
// last matched rune — which is what SARIF's region.endColumn means.
//
// Columns are counted in runes, not bytes, because both consumers of them
// count that way: a terminal caret is placed per printed character, and SARIF
// text regions are defined in characters. A match that runs past the end of
// its first line (a regex spanning a newline) is clamped to that line, so the
// span always describes something a reader can point at.
func locate(text string, m match) (col, endCol int, line string) {
	start, end := lineSpan(text, m.start)
	line = strings.TrimSuffix(text[start:end], "\r")
	lineEnd := start + len(line)

	off := m.start
	if off < start {
		off = start
	}
	if off > lineEnd {
		off = lineEnd
	}
	col = utf8.RuneCountInString(text[start:off]) + 1

	stop := m.end
	if stop < off {
		stop = off
	}
	if stop > lineEnd {
		stop = lineEnd
	}
	endCol = col + utf8.RuneCountInString(text[off:stop])

	// Cap the stored line. A match beyond the cap gets no line text at all
	// rather than a misleading prefix that does not contain it — Column stays
	// true either way, so a consumer holding the file can still seek to it.
	if utf8.RuneCountInString(line) > maxLineText {
		if col > maxLineText {
			return col, endCol, ""
		}
		line = string([]rune(line)[:maxLineText])
	}
	return col, endCol, line
}
