// Package attest implements surfaceguard provenance: the SGMT-1 Merkle root over
// a bundle, DSSE Ed25519 signing, the attestation statement, and USF manifest
// fields. This is the interop core specified in design §7.
package attest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"

	"github.com/SVGreg/surfaceguard/pkg/skill"
)

// Domain-separation prefixes (RFC 6962-style, design §7.1).
const (
	leafPrefix     = 0x00
	interiorPrefix = 0x01
)

// FileLeaf is one (path, content-hash) input to the tree.
type FileLeaf struct {
	Path   string
	SHA256 [32]byte
}

// BundleLeaves builds the sorted leaf set for a bundle, hashing SKILL.md in its
// normalized form so USF manifest fields can be added without changing the root
// (design §7.1/§7.5). NOTE: Unicode NFC path normalization is a documented gap
// for first drop; ASCII paths (all current fixtures) are unaffected.
func BundleLeaves(b *skill.Bundle) []FileLeaf {
	leaves := make([]FileLeaf, 0, len(b.Files))
	for _, f := range b.Files {
		content := f.Content
		if f.Path == "SKILL.md" {
			content = NormalizeSkillMD(content)
		}
		leaves = append(leaves, FileLeaf{Path: f.Path, SHA256: sha256.Sum256(content)})
	}
	sort.Slice(leaves, func(i, j int) bool { return leaves[i].Path < leaves[j].Path })
	return leaves
}

// MerkleRoot computes the SGMT-1 root as "sha256:<hex>". Empty set is invalid
// and returns "".
func MerkleRoot(leaves []FileLeaf) string {
	if len(leaves) == 0 {
		return ""
	}
	level := make([][32]byte, len(leaves))
	for i, lf := range leaves {
		level[i] = leafHash(lf)
	}
	for len(level) > 1 {
		var next [][32]byte
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i]) // odd node promoted unchanged
				continue
			}
			next = append(next, interiorHash(level[i], level[i+1]))
		}
		level = next
	}
	return "sha256:" + hex.EncodeToString(level[0][:])
}

// leafHash = SHA256(0x00 || uvarint(len(path)) || path || file_sha256).
func leafHash(lf FileLeaf) [32]byte {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], uint64(len(lf.Path)))
	h.Write(buf[:n])
	h.Write([]byte(lf.Path))
	h.Write(lf.SHA256[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// interiorHash = SHA256(0x01 || left || right).
func interiorHash(l, r [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{interiorPrefix})
	h.Write(l[:])
	h.Write(r[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

var (
	// fmBlockRe splits SKILL.md into (opening delimiter)(front-matter body)
	// (closing delimiter), leaving the rest as the tail. The closing delimiter
	// is anchored at a line start with (?m)^ rather than by requiring a
	// preceding newline, so an *empty* block ("---\n---\n") matches too: the
	// old form demanded at least one newline between the delimiters, and
	// WriteUSFFields then rejected such a manifest with the misleading "has no
	// front-matter block". Anchoring keeps a mid-line "---" (e.g. "a---b")
	// from being mistaken for the close. The body capture therefore *includes*
	// its trailing newline, which is also why a reserved line sitting last in
	// the block is now stripped cleanly instead of leaving a blank line behind.
	fmBlockRe    = regexp.MustCompile(`(?sm)\A(\x{FEFF}?---\r?\n)(.*?)(^---\r?\n?)`)
	reservedLine = regexp.MustCompile(`(?im)^(content_hash|signature):.*\r?\n?`)

	// reservedKey finds a reserved line; reservedScalar says it is safe to drop.
	// A line may leave the Merkle leaf only when its value is a single-line plain
	// or *balanced* quoted scalar (design §7.5: "single-line, top-level
	// plain/quoted scalars ... verifier rejects multi-line or nested forms").
	// Dropping any other shape lets the unauthenticated line change how the
	// authenticated ones parse: `signature: "` before a signed line and
	// `content_hash: "` after it turn that line into the inside of a string, so
	// `disable-model-invocation: true` or `allowed-tools:` vanishes from the
	// manifest while the root, and so the signature, still verify.
	reservedKey    = regexp.MustCompile(`(?i)^(content_hash|signature):`)
	reservedScalar = regexp.MustCompile(`(?i)^(?:content_hash|signature):[ \t]*` +
		`(?:"(?:[^"\\\r\n]|\\.)*"|'(?:[^'\r\n]|'')*'|[A-Za-z0-9+/=:._-]+)[ \t]*\r?\n?$`)
)

// NormalizeSkillMD strips the two USF reserved front-matter lines
// (content_hash, signature) so the manifest can carry them without altering the
// Merkle leaf (design §7.5). Line-based, front-matter block only.
func NormalizeSkillMD(content []byte) []byte {
	m := fmBlockRe.FindSubmatchIndex(content)
	if m == nil {
		return content
	}
	open := content[m[2]:m[3]]
	body := content[m[4]:m[5]]
	closeD := content[m[6]:m[7]]
	rest := content[m[1]:]
	cleaned := stripSafeReserved(body)
	var out []byte
	out = append(out, open...)
	out = append(out, cleaned...)
	out = append(out, closeD...)
	out = append(out, rest...)
	return out
}

// stripSafeReserved drops the reserved lines that are safe to exclude from the
// Merkle leaf and keeps every other byte. A reserved line stays in the leaf, so
// any edit to it is a root mismatch, when:
//   - its value is not a single-line plain or balanced quoted scalar (an open
//     quote, a block scalar `|`/`>`, a flow `{`/`[`, an anchor, an empty value);
//   - the next line is indented, which would make that line a continuation or a
//     child of the reserved key rather than of the key it was signed under;
//   - its key occurs more than once, since the extra copy is a duplicate key
//     that changes how a YAML parser reads the whole block.
//
// The writer (WriteUSFFields) emits exactly one `%q`-quoted line per key, which
// is always dropped, so a legitimately written manifest normalizes as before.
func stripSafeReserved(body []byte) []byte {
	lines := bytes.SplitAfter(body, []byte("\n"))
	seen := map[string]int{}
	for _, ln := range lines {
		if m := reservedKey.FindSubmatch(ln); m != nil {
			seen[strings.ToLower(string(m[1]))]++
		}
	}
	out := make([]byte, 0, len(body))
	for i, ln := range lines {
		if m := reservedKey.FindSubmatch(ln); m != nil &&
			seen[strings.ToLower(string(m[1]))] == 1 &&
			reservedScalar.Match(ln) &&
			(i+1 >= len(lines) || !startsIndented(lines[i+1])) {
			continue
		}
		out = append(out, ln...)
	}
	return out
}

func startsIndented(ln []byte) bool {
	return len(ln) > 0 && (ln[0] == ' ' || ln[0] == '\t')
}

// StripReservedLines removes content_hash/signature lines from a front-matter
// string (used when emitting USF fields idempotently).
func StripReservedLines(fm string) string {
	return reservedLine.ReplaceAllString(fm, "")
}

// TrimSpaceKeys is a tiny helper kept for symmetry/testing.
func TrimSpaceKeys(s string) string { return strings.TrimSpace(s) }
