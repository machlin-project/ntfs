# Independent Windows XPRESS-HUFF packet observations

[collect_windows_xpress.py](../scripts/collect_windows_xpress.py) is a bounded
in-memory native oracle for the existing independently authored XPRESS packets.
It does not call the product decoder, compress files, open a device or change a
filesystem setting. Its output directory is new and retains the original data,
packet bytes, author/collector hashes, actual platform and native results.

## Documented API and format boundary

Microsoft documents
[CreateDecompressor](https://learn.microsoft.com/en-us/windows/win32/api/compressapi/nf-compressapi-createdecompressor)
in Cabinet.dll with `COMPRESS_ALGORITHM_XPRESS_HUFF` (4). Combining that algorithm
with `COMPRESS_RAW` selects block mode. The flag value is recorded by Microsoft's
[Windows API metadata](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Storage/Compression/constant.COMPRESS_RAW.html).
The collector configures exact ctypes DWORD, BOOL, handle and SIZE_T signatures;
it calls ResetDecompressor before each independent packet and closes its one
owned handle on success or failure.

In [raw block mode](https://learn.microsoft.com/en-us/windows/win32/cmpapi/using-the-compression-api),
the caller owns block boundaries and supplies both compressed and original sizes.
[Decompress](https://learn.microsoft.com/en-us/windows/win32/api/compressapi/nf-compressapi-decompress)
requires the exact original size in this mode. A success return alone does not
prove content: malformed data or an incorrect output-size contract may still
produce different bytes. This oracle therefore compares every original byte and
the returned length, with guards around both buffers and unchanged-input checks.
Zero-size output is also the API's size-query interface; this qualification covers
nonempty exact-size packets rather than interpreting that query as a data verdict.

[MS-XCA's LZ77+Huffman format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/c0244bfe-fd96-4fe5-97dd-39b9fc99b801)
has a 256-byte table of 512 four-bit symbol lengths followed by canonical-coded
literals and matches. Those are the fields and units used by our independent
[packet author](../tests/wof_fixtures.py). The
[final encoding rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/c7ec7ba9-ca8f-448f-bb85-027c1516db1c)
describe word-oriented bits, interleaved long-length bytes and a recommended EOF
symbol 256, because some decompressors require it. These matching documented
properties justify testing the raw API; actual packet compatibility still needs
the recorded Windows execution. No buffer-mode wrapper is synthesized around a
packet, and no packet is changed after a native refusal.

Compression API's documented LZMS option is a different algorithm. This collector
does not invent an exposed LZX function or apply an XPRESS observation to LZX.
WOF chunk mapping/provider semantics and mounted-file behavior are also separate.

## Authored cases and verdicts

[windows_xpress_fixtures.py](../tests/windows_xpress_fixtures.py) selects unmodified
XPRESS cases from the canonical-width/word-offset suite, short/long/mixed CPU
workloads and the original literal/match/extension/distance grammar suite. Plain
expected bytes come from the fixture authors, never from either decoder. Ordinary
EOF-bearing cases require native success, exact length and exact bytes.
The current inventory contains 398 packets: 394 required and four compatibility
observations, with 651,963 original-plus-packed bytes.

The pre-existing `optional-eof` and `nonzero-padding` variants are explicitly
labelled compatibility observations before execution. Their native rejection is
retained with the Win32 error and reported separately; an acceptance must still
produce the exact expected bytes. Buffer damage or changed source files always
fails, including for rejected compatibility variants. A successful required set
must not be summarized as native acceptance of every optional packet.

Limits are 512 cases, 64 KiB original bytes and 128 KiB compressed bytes per
packet, with a 32 MiB aggregate corpus. Case filenames use owned numeric indexes,
while descriptive identities are unique report fields. The generated corpus and
report use exclusive creation, bounded reads and regular-file/unchanged checks.
Both source inputs and buffer guards survive the native call unchanged.

The report separates authoring, API acquisition, reset, comparison and cleanup
failures. An absent Windows DLL/export or unsupported raw algorithm is an
acquisition refusal with no packet verdict. `native_observation` records an
actual native packet call, not successful qualification by itself; `passed` and
`complete` must also hold, and optional refusals remain explicit. Cleanup cannot
turn a prior failure into success or hide its primary failure stage.

## Execution and remaining evidence

On actual Windows Python:

```sh
python tests/windows_xpress_contract.py
python scripts/collect_windows_xpress.py --output artifacts/windows-xpress
```

[The Python contracts](../tests/windows_xpress_contract.py) use an explicitly
synthetic provider for guard/content/length failures, optional refusals, resource
cleanup, bounds and provenance. They cannot produce a native observation. A
non-Windows collector invocation is a tested acquisition refusal, not Windows
codec evidence. Hosted native execution and its exact source/artifact binding
must be added to the acceptance record before claiming compatibility.

The initial cloud check passes all 13 synthetic contracts and the complete
fixture inventory. A real invocation on the Linux executor returns exit 1 at
acquisition, retains all 796 original corpus files, and records no native packet
calls. Evidence is retained under `artifacts/dots-xpress-oracle/initial/`.
