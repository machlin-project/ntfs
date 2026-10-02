# Independent Windows access observations

The collector and offline verifier provide an independent observation path for
the DACL contract in [ACCESS.md](ACCESS.md). The collector calls Windows security
APIs without importing or executing the driver's decision algorithm. The verifier
passes the original descriptor and queried token projection to the freestanding
core. Local synthetic tests verify this tooling; they do not qualify Windows
semantics, installed filesystem authorization, or commercial readiness.

## Acquisition on Windows

Run with Windows CPython from the repository, using a new output directory. An
existing Windows machine suffices; no VM or NTFS image is required for these
in-memory checks.

```powershell
python scripts/collect_windows_access.py --output C:\ntfs-captures\access-next
```

The collector opens the caller's token for QUERY and DUPLICATE and creates an
impersonation copy with explicitly requested rights using
[DuplicateTokenEx](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex).
It creates disposable copies with DISABLE_MAX_PRIVILEGE. It never installs a
thread token, changes the process identity, enables privileges, edits an ACL,
opens a volume/device, or changes file permissions. Every owned handle receives
cleanup registration before further operations; cleanup failures keep acquisition
partial.

The six contexts are the copied caller, deny-only user, deny-only selected group,
restricting user SID, restricting Everyone SID, and duplicate restricting Everyone
SIDs. Construction requests remain separate from actual queried token fields.
User/group attributes, restricting lists and privileges are queried again after
creation. Results are not inferred from the requested transformation. Existing
caller restrictions remain present; actual token fields determine comparison.

[IsTokenRestricted](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-istokenrestricted)
checks the restricting SID list. Privilege removal or deny-only SIDs alone do not
require the second DACL pass. Both its result and the queried list are retained;
disagreement is rejected. Native integrity groups remain in the original record,
separate from the discretionary projection. Authored DACLs do not use those
integrity SIDs as trustees or owners. Unknown user attributes fail acquisition.

Authored descriptors retain owner/group SIDs and ACE order. Cases cover ordered
allow/deny and split grants, group/user membership, inherit-only exclusion,
absent/NULL/empty DACLs, zero requests, generic-mask overlap, ownership, OWNER
RIGHTS and restricting contexts. Group-owner cases are included when an enabled
OWNER group exists. Probe SID selection is checked against the original base
token and group-owner coverage is reported separately.

Restricted-owner combinations and MAXIMUM_ALLOWED probe unsupported core behavior.
A mandatory-label SACL case is an explicit boundary observation outside the DACL
comparison. These cases do not establish integrity or complete authorization.
Object/callback/conditional ACEs, write-restricted tokens, privileges, parent and
traversal alternatives, account mapping and native owning authorization still
need additional contracts and vectors.

Windows MapGenericMask uses the published SDK file mapping.
[AccessCheck](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck)
receives an impersonation token. Each case records API success/error, mapped
request, AccessStatus, granted mask and used privileges. An API failure retains
its error and **no** decision outputs; it is never converted to a denial. A
successful API call with false AccessStatus is a valid denial with zero grant.
Reported privilege use remains outside the DACL comparison.

The manifest stores original descriptor base64/SHA-256, numeric SID values, raw
attributed vectors, construction requests, native results and platform metadata.
It contains account SIDs but no credentials. Keep captures/reports under ignored
generated storage. Partial acquisition retains errors and completed cases;
missing groups or failed contexts remain missing work. An API error can be fully
captured while providing no usable access decision.

## Offline comparison

Copy the acquisition to a POSIX machine and build the diagnostic. Use a new report
directory:

```sh
python3 scripts/build.py .build
python3 tests/windows_access.py artifacts/windows-access/manifest.json \
  --evaluator .build/ntfs-dacl-evaluate --output artifacts/windows-access-review
```

The verifier checks schema/vector set, unique identifiers, original token
projection and construction requests, matrix completeness, descriptor hashes and
bytes, value types, provenance and platform. Complete acquisition cannot omit
planned work or contain acquisition errors. Partial captures remain usable for
diagnosis. The manifest and temporary core request must remain unchanged.
Existing capture/report directories are never overwritten.

Per-case native/core outputs and separate counts remain in `report.json`:

- `passed`: mapped request, allowed status and granted mask match exactly.
- `failed`: mismatch, other core error, execution failure or invalid output.
- `unsupported`: core UNSUPPORTED, without an invented access decision.
- `oracle_errors`: AccessCheck failed without a decision.
- `out_of_plane`: mandatory-label boundary or reported native privilege use.

Missing work, partial acquisition, errors and unsupported/out-of-plane cases keep
the overall result `gaps` and CLI exit status nonzero. The current matrix includes
such probes intentionally. `native_dacl_vectors_verified` requires a complete
Windows capture, every discretionary vector matching, and unchanged original
input. This qualifies only this matrix. Synthetic provenance keeps it false.
`full_authorization_qualified` remains false. Provenance metadata states how the
capture was acquired; it is not a cryptographic attestation of an external run.

## Bounds and transport

SDK information is capped at 1 MiB. SID packets preserve their six-byte authority
and at most 15 subauthorities. Each group/restricting vector has at most 1,024
entries; privilege vectors have at most 64. Fixed-width ctypes SDK layouts derive
offsets/strides, including native pointer alignment. SID pointers are checked
against the returned buffer before dereference. Counts/lengths are checked before
walking vectors.

The manifest cap is 16 MiB, with at most 512 cases and 16 contexts. Diagnostics
have a 10-second deadline, separate 4-KiB stdout/stderr caps, and an allowlisted
environment. Comparison execution has an aggregate 120-second deadline. Timed-out
children are stopped/reaped. Input readers reject special files, including FIFOs,
before bounded reads.

`ntfs-dacl-evaluate` reads one regular request file, capped at 2 MiB with descriptor
bytes capped at 1 MiB. Its little-endian diagnostic header has `NTAC` magic and six
DWORDs: version, desired mask, flags, group count, restricting count and descriptor
byte count. Version is 1; named flag bits encode deny-only user/restricted context.
The body holds an original MS-DTYP user SID, each group's DWORD attributes and SID,
restricting SID packets, then exact descriptor bytes. No pointers or unused
trailing storage are transported.

Malformed transport exits 2 without a core decision. Valid transport emits a
versioned JSON result, including semantic errors and zeroed decisions. The tool
does not authenticate identity. It uses public allocation-free
`ntfs_security_sid_decode` for exact SID packets and default DACL budgets; raising
comparison limits is not part of this transport.

Contract tests use independent SDK-shaped buffers, bad spans/counts, truncations
and ceilings, core decision vectors, fake acquisition/cleanup failures, altered
observations, child-output caps and deadlines. Deliberately coarse fake answers
produce both matches and mismatches; they are not a Windows access implementation.
Standalone SID seeds exercise the existing security fuzz target.

No native Windows acquisition has run for this checkpoint. FSKit has not adopted
the evaluator or diagnostic token projection. Do not use these tools as a native
authenticator or expose their transport as a product API.
