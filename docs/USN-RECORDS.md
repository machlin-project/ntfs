# Private USN record framing

[core/usn.c](../core/usn.c) supplies allocation-free, no-I/O decoding, measurement
and canonical encoding of one V2.0 or V3.0 change-journal record. It also provides
a bitwise union of an explicit list of reason words. These are source-side
primitives, with original literal-wire tests in [tests/usn.c](../tests/usn.c).
They do not implement a `$UsnJrnl` writer or change writable admission.

## Published layout and interpretation

Microsoft's [MS-FSCC V2 definition](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/d2a2b53e-bf78-4ef3-90c7-21b918fab304)
defines the scalar widths, byte-counted filename fields and nonnegative signed
USN. Its [V3 definition](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/bb07c6b8-74be-49b5-9723-04f4d9e3e44d)
expands each file identifier from eight to sixteen bytes. The resulting fixed
prefixes end at byte 60 and byte 76. Named byte-array wire structures and static
size/offset assertions live in the private [header](../core/usn.h).

The [Win32 V2 reference](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2)
requires clients to locate the name using `FileNameOffset`, and to advance using
`RecordLength`. It describes 64-bit record alignment in API output buffers and
version-dependent additions before the name. The
[Win32 V3 reference](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v3)
also documents alignment rounding. The helper deliberately supports only minor
version zero; other minor versions and V4 are explicitly unsupported.

These API/protocol layouts do not by themselves establish `$J` sparse allocation,
retention or durable update behavior. In particular, the MS-FSCC page's zero-valued
Reason, TimeStamp, SourceInfo and SecurityId requirement belongs to its enclosing
FSCTL response. It is not imposed on general journal records here.

## Local framing and publication contract

- Decode checks the common header before interpreting a version. Record length
  must contain its fixed prefix, fit the supplied bytes and be divisible by eight.
  Wire addresses themselves may be unaligned.
- The filename offset cannot overlap the fixed prefix. Its offset and byte length
  must be even, and their complete span must fit the record. Names remain borrowed
  UTF-16LE bytes, including zero units and unpaired surrogates; this is framing,
  without filename policy or Unicode normalization.
- File identifiers remain opaque byte arrays. V2 decoding zero-extends them;
  V2 encoding rejects nonzero upper bytes instead of silently truncating them.
  USN sign-bit values refuse. Timestamp, reason, source, security and attribute
  values otherwise retain their bits, including unknown flags, without granting
  those flags operational meaning or claiming full semantic validity.
- Decode exposes the first record's consumed length and borrowed name. It allows
  opaque bytes between the fixed prefix and name, trailing padding and subsequent
  records. There is no sparse `$J` scanner or leading FSCTL cursor parser.
- Encoding places the name immediately after the fixed prefix, without adding a
  terminator, then zero-pads to eight bytes. A WORD bounds filename bytes; the
  largest accepted even length is 65,534. Measured and emitted lengths agree.
  Encoding a decoded record canonicalizes gaps/padding rather than preserving them.
- All errors preserve outputs and all inputs. Outputs must be disjoint from input
  spans and each other, including unused output capacity. Successful encoding
  changes only its returned extent. Typed C descriptions/output objects retain
  their ordinary alignment requirements; wire/name bytes do not.

Reason union checks count multiplication, pointer spans and native word alignment
before its bounded linear walk. Its private work limit is 4,096 input words;
this is an implementation resource budget, not an NTFS field or Windows limit.
Empty input yields zero; unknown bits survive. The caller owns
which words belong together. Close flags do not reset the union, and the helper
does not infer object grouping, event order, rename pairs, timestamps, source
propagation or Windows record coalescing.

## Evidence and remaining work

The original tests cover literal V2/V3 bytes, every truncation and insufficient
capacity of both goldens, all eight wire-address alignments, malformed fields,
unsupported versions, noncanonical offsets, consecutive records, maximum and
empty names, arithmetic/pointer refusal, aliases and unchanged failed outputs.
Each reason bit, the exact work limit, alignment refusals and an explicit
create/close/extend sequence exercise the union. The separate
[fuzz harness](../tests/fuzz_usn.c) checks independent wire fields, input/output
guards, deterministic errors and canonical re-encoding, with standalone original
V2/V3 truncation and single-bit mutation inputs.
Tests are synthetic wire evidence; this document makes no native acceptance claim.

Still required are versioned `$Max`/`$J` acquisition and ownership, native event
selection/coalescing/retention observations, complete coupled FILE/allocation/WAL
publication and interrupted recovery. An active unsupported change-journal
profile continues to refuse mutation. No journal is disabled, discarded or
rewritten to obtain admission. See [write ownership](WRITES.md) and the
[research register](format/13-research-and-coverage.md).

Implementation and fixtures are original repository work based on the Microsoft
definitions above. No foreign filesystem implementation is imported or linked.
