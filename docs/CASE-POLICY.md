# Directory case policy

The immutable read-only core now selects lookup from the stored policy of the
directory being searched. `ntfs_stat.case_sensitive` reports that directory's
policy; ordinary files report false. The inspector includes it in `stat-ref`
and other JSON stat responses. A child's stored flag is independent of its
parent's flag. This reader does not create directories or implement inheritance.

## Format facts and supported interpretation

Microsoft documents per-directory case behavior and the WSL-facing
`system.wsl_case_sensitive` interface, rather than a literal NTFS EA storage
requirement. See [Microsoft case sensitivity](https://learn.microsoft.com/en-us/windows/wsl/case-sensitivity).
The original [Keramics NTFS format research](https://keramics.github.io/ntfs.html)
identifies `$STANDARD_INFORMATION.maximum_versions == 0` and `version == 1` for
a sensitive directory. The original
[MFT Browser forensic template](https://github.com/kacos2000/MFT_Browser/blob/master/NTFS%20-%20MFT%20FILE%20Record.tpl)
identifies the low version byte as the case indicator and the remaining bytes
as reserved-storage information. Only published field facts informed this code;
no template or filesystem implementation was copied into the product.

The parser applies the named policy overlay only to directories with disabled
version numbering. Low-byte zero selects insensitive lookup; one selects exact
lookup. Other low-byte values return UNSUPPORTED before publishing a metadata
snapshot. Upper bytes do not select case policy. Positive `maximum_versions`
retains the legacy version-number interpretation and insensitive lookup; this
does not implement legacy file versioning. Both accepted standard-information
value sizes retain their original framing validation.

These observations define the implemented interpretation, not Windows-authored
format qualification. Native flags must still be compared with original disk
records, including storage hints and legacy-volume cases.

## Lookup and ordering

Directory B-tree validation and traversal keep NTFS filename collation: `$UpCase`
first, with original UTF-16 units breaking ties. Sensitive lookup uses this full
order to seek, then requires exact original units. It does not seek by raw UTF-16
alone, normalize Unicode, or depend on the filename namespace byte being POSIX.
`Foo.txt` and `foo.txt` may resolve to different references, including when a
separator divides them between nodes.

Insensitive lookup retains the folded lower bound and successor ambiguity check.
Different stored names with the same folded key remain UNSUPPORTED in that
mode. Sequence validation, parent references, bitmap/fixup checks, ancestor bounds,
visited-node budgets and zero lookup error outputs apply in both modes.

## FSKit projection

Literal names use the owning directory's core lookup. Projected aliases require
canonical spelling in sensitive directories; insensitive directories accept their
existing ASCII case variants and return the canonical spelling. The alias syntax
decoder remains separate from the owning directory's semantic decision.

The selected Apple SDK exposes only a volume-wide `caseFormat` enum, without a
per-directory mixed option. The adapter reports Sensitive to retain distinct
native cache keys; insensitive lookups still return the stored canonical name.
This is a strategy requiring installed acceptance. Component tests cannot prove
native positive/negative name caching, Finder behavior or mount capability
interpretation. Modern reply-framing tests use an opaque context double because
the current bridge ignores caller context; they do not qualify authorization.

## Local checks and remaining acceptance

Seventeen synthetic images cover resident/external/nested/listed indexes, exact
ASCII and Unicode names, ordinary-file version bytes, common/extended standard
information, storage hints, legacy/unknown policies, mixed parent flags, stale
references and damaged ordering/parents. Cache-enabled/disabled reads and complete
required-allocation/I/O fault sweeps check cleanup and retry. Sensitive namespace
components also test aliases, original-name manifests, ordinary spelling and
revocation. Windows corpus verification compares queried native case flags with
reference-addressed core stat, rejects malformed/unknown observations and reports
missing observations as a remaining contract.

The complete local core/component/build results are retained in ACCEPTANCE.md.
Windows corpus acquisition and installed mixed-policy mounts remain unrun. The
macOS 27 protocol runtime remains unrun when its guarded component reports SKIP.
Further acceptance requires Windows-created case collisions/large indexes and
native exact/folded lookup, enumeration, alias and cache behavior on both supported
FSKit protocol runtimes. This change does not close normalization, WSL mount
policy overrides, general pathname semantics or security enforcement.
