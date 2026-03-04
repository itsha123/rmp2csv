# RAMMap `.RMP` format (reverse‑engineered notes)

This document describes the `.RMP` snapshot format *as inferred by this repo so far*.

It is intentionally conservative:

- **Confirmed** items are things we can parse deterministically today.
- **Heuristic** items are fields we currently *infer* by fitting PFN record bitfields to other tables in the snapshot.
- **Unknown** items are present in the data but not yet mapped.

The current implementation that backs these notes is in [extract.py](extract.py).

## 1) Big picture

A RAMMap snapshot `.RMP` is an **XML file** that contains:

1. “Normal” XML elements with attributes (metadata / lists), and
2. Very large elements whose text content is a **hex string** representing binary data.

In particular, we’ve observed huge hex-encoded payloads under:

- `<PfnDatabase>` — the page frame database (dominates file size)
- `<PoolInfo>` — pool allocations (smaller but still binary)

The exporter is built around **streaming** these huge tags without loading the entire `.RMP` into memory.

## 2) Common encoding rules

### 2.1 XML namespace handling

XML tags may be namespace-qualified. The parser strips namespaces by splitting on `}`:

- `{namespace}TagName` → `TagName`

### 2.2 Hex text → bytes

Hex blobs are stored as text between an opening and closing tag:

```xml
<PfnDatabase>
  0123456789ABCDEF... (millions of hex chars)
</PfnDatabase>
```

Decoding rules used in this repo:

- Only characters `[0-9a-fA-F]` are treated as hex digits.
- All other characters (whitespace/newlines) are ignored.
- Two hex digits form one byte.

### 2.3 Bytes → integers (endianness)

Where a tag is interpreted as an integer array, it is decoded as:

- **little-endian unsigned** values

Used integer widths:

- `u64` for most tables (`ListCounts`, `PageUseCounts`, `PhysRanges`, `PfnDatabase` words)
- `u32` for `<Process><PFNs>` lists (ordinals into the PFN database)

### 2.4 Page size

The snapshot uses a page size of:

- `PAGE_SIZE_BYTES = 4096` (4 KiB)

This is assumed everywhere we compute sizes/addresses.

## 3) High-level XML structure (known sections)

The exact root element name varies by RAMMap version/build (not required by our parser). The important parts are these sections/tags.

| XML tag / section | Kind | Parsed today? | Notes |
|---|---:|---:|---|
| `FileList/File` | XML elements | Yes | File-backed mapping key → path |
| `ProcessList/Process` | XML elements + nested hex | Yes | Contains `<PFNs>` list of PFN *ordinals* |
| `ListCounts` | hex → `u64[]` | Yes | 8 list-state totals (pages) |
| `PageUseCounts` | hex → `u64[16×8]` | Yes | 16 uses × 8 list states (pages) |
| `PhysRanges` | hex → `u64[]` | Yes | Encoding is version-dependent (see below) |
| `PfnDatabase` | hex → records | Yes | Streamed; record layout partly inferred |
| `PfnDatabase` header | `u64[]` (prefix) | Partly | Contains Priority Summary counters in some versions |
| `PoolInfo` | hex → records | Yes | Record layout mostly known |

## 4) `FileList`

### 4.1 XML layout (confirmed)

We parse the file list as a flat list of elements:

```xml
<FileList>
  <File Key="123" Path="C:\\Windows\\..." />
  ...
</FileList>
```

Confirmed fields:

- `File/@Key` is an **unsigned 64-bit integer**.
- `File/@Path` is a Windows path string.

Usage in this repo:

- Used to label PFNs that reference file-backed pages.
- Used by `file_summary`, `file_details`, and `physical_pages` exports.

## 5) `ProcessList` and per-process PFNs

### 5.1 XML layout (confirmed)

We parse:

```xml
<ProcessList>
  <Process Name="..." ProcessId="1234" SessionId="1">
    <PFNs>...</PFNs>
  </Process>
</ProcessList>
```

Confirmed attributes:

- `Process/@Name` — process image name (string)
- `Process/@ProcessId` — PID (decimal string)
- Some snapshots may use `Process/@Key` as the PID instead of `ProcessId` (the parser accepts either)
- `Process/@SessionId` — session id (decimal string); sometimes `0xFFFFFFFF` means “unknown”

### 5.2 `<Process><PFNs>` encoding (confirmed)

`<PFNs>` is a hex string that decodes into a sequence of **little-endian `u32`** values.

Crucial distinction:

- These `u32` values are **PFN database record ordinals**, *not the PFN number itself*.

This is validated because we can use these ordinals to build the RAMMap “Private” column (counts of these PFNs per PID).

## 6) `ListCounts` (list-state totals)

### 6.1 Encoding (confirmed)

`<ListCounts>` decodes to a `u64[]`.

- The first 8 entries (`vals[0:8]`) are the totals (in pages) for the 8 list states.
- Empirically: `sum(vals[0:8])` matches the number of PFN records.

### 6.2 List-state indices (partly confirmed)

We currently use this index ordering (fallback labels):

Index → label

- `0` = Zeroed
- `1` = Free
- `2` = Standby
- `3` = Modified
- `4` = Modified No-Write
- `5` = Bad
- `6` = Active  (**confirmed**: layout discovery consistently aligns this index)
- `7` = Transition

Only `Active == 6` is explicitly called out as validated in code; the rest are based on RAMMap UI screenshots and should be treated as “best effort”.

## 7) `PageUseCounts` / “Use Counts” tab matrix

### 7.1 Encoding (confirmed)

`<PageUseCounts>` decodes to exactly **128 `u64` values**:

- 16 uses × 8 list states
- row-major: `value[use * 8 + list_state]`

### 7.2 Use indices and labels (heuristic)

The `.RMP` does **not** include the textual labels for uses.

This repo uses labels taken from RAMMap screenshots as a lookup table for the usage rows RAMMap actually displays.

For this snapshot family, RAMMap shows 14 usage rows (plus a computed Total row):

- 0 Process Private
- 1 Mapped File
- 2 Shareable
- 3 Page Table
- 4 Paged Pool
- 5 Nonpaged Pool
- 6 System PTE
- 7 Session Private
- 8 Metafile
- 9 AWE
- 10 Driver Locked
- 11 Kernel Stack
- 12 Unused
- 13 Large Page

Note: `<PageUseCounts>` still contains 16 rows in the file; rows beyond the ones listed above are commonly all zeros. The exporter ignores any additional rows and emits a computed Total row to match RAMMap.

### 7.3 Per-PFN Use field (current implementation)

`<PageUseCounts>` gives totals by Use×List, but the per-page “Use” value shown in RAMMap’s Physical Pages grid comes from the PFN database records.

For the Windows 10/11 snapshot family this repo currently targets, the exporter treats the per-PFN Use code as:

- **`use_code = q0 & 0xF`** (low 4 bits of the PFN record’s `q0`)

Important caveat:

- We still consider it possible that some RAMMap/Windows builds use a *permuted* encoding for the PFN-level use code. The code is structured to allow a code→UI remap, but at the moment we assume identity (i.e., code order already matches the UI row order).

## 8) `PhysRanges`

We have seen (or coded for) two plausible encodings.

### 8.1 Variant A: `count` then `(startPFN, endPFN)` pairs (observed/handled)

In one exporter path we interpret the `u64[]` as:

- `q[0] = count`
- followed by `count` pairs: `(startPFN, endPFN)`

This is used by `_export_physranges_csv()` as a best-effort decode.

If the leading `count` does not look consistent with the blob length, the exporter also falls back to interpreting the array as plain `(startPFN, endPFN)` pairs without a count.

### 8.2 Variant B: `(startPFN, pageCount)` pairs (observed/handled)

In the RAMMap “Physical Ranges” view export, we interpret the same tag as:

- pairs: `(startPFN, pageCount)`
- end PFN (exclusive) = `startPFN + pageCount`

We then merge adjacent/overlapping intervals to match RAMMap’s presentation.

### 8.3 Interpretation notes

- Both variants are plausible across RAMMap / OS builds.
- The code currently prefers the “tab-shaped” output (start/end addresses + size) and treats the underlying representation as ambiguous.

## 9) `PoolInfo`

`<PoolInfo>` is a hex blob decoded into bytes and then parsed as a binary table.

### 9.1 Layout (mostly confirmed)

We parse:

- `u64 count` at offset 0
- then `count` records of size 24 bytes

Record layout (24 bytes):

```text
struct PoolInfoRecord {
  u64 addr;      // offset +0
  u64 size;      // offset +8
  char tag[4];   // offset +16, ASCII
  u32 unk;       // offset +20, currently ignored
}
```

Confirmed/used fields:

- `addr == 0` is treated as an empty record and skipped.
- `tag` decodes as ASCII with replacement on invalid bytes.
- `size` is summed per tag.

Unknown field:

- the final 4 bytes (`unk`) exist structurally (because record size is 24), but we do not currently interpret them.

## 10) `PfnDatabase`

`<PfnDatabase>` is the core of the snapshot and is currently the most “reverse engineered” piece.

### 10.1 Header prefix (partly confirmed)

Before the PFN record run begins, `<PfnDatabase>` contains a short header/prefix of unknown structure.

One part of that prefix is now used as **ground truth** for RAMMap’s Priority Summary tab (see `priority_summary` exporter):

- Interpret the beginning of `<PfnDatabase>` as a `u64[]` stream.
- The exporter reads the first ~32 `u64` values and uses these slices:
  - `header[7:15]` = Standby pages by priority 0..7
  - `header[15:23]` = Repurposed pages by priority 0..7

Values are in **pages**; RAMMap displays **KB** as `pages * 4 KiB`.

Everything else in the header remains unknown.

### 10.2 Raw record stream (confirmed)

We decode `<PfnDatabase>` as a stream of little-endian `u64` values and group them into triples:

```text
(q0, q1, q2)  // 3×u64 = 24 bytes per record
```

Empirical properties:

- The blob begins with a small header of unknown structure.
- After that header, there is a very long run where `q1` increments by exactly `+1` per record.

The parser locates the “real PFN record run” by detecting a streak of `min_sequential_run` consecutive records with `q1 == prev_q1 + 1`.

### 10.3 PFN number vs PFN record ordinal (confirmed)

There are two indices in play:

- **PFN record ordinal**: the 0-based index of a record in the decoded PFN run.
  - This is what `<Process><PFNs>` stores.
  - We often call it “ordinal” in code.

- **PFN number**: the value in `q1`.
  - This is the actual page frame number.
  - Physical address = `PFN_number * 4096`.

Because `q1` is sequential in the main run, ordinals and PFN numbers are related by a constant base:

- `PFN_number = PFN_base + ordinal`

Where `PFN_base` is the `q1` value from the first record in the detected run.

### 10.4 Known / inferred bitfields inside `(q0, q2)`

Most PFN attributes (list state, use, priority, file backing, etc.) are stored as bitfields inside `q0` and `q2`.

Important: **we do not yet have a single “fixed struct”** that works universally. Instead, this repo currently discovers the offsets by fitting to other tables in the snapshot.

#### 10.4.1 List state: 3-bit field (heuristic, but strongly constrained)

Goal: find a 3-bit field that reproduces `ListCounts[0:8]` frequencies.

Search strategy (see `discover_pfn_layout()`):

- Candidate locations: `q0` or `q2`
- Candidate shifts: `{0,1,2,3,4,5,6,7,8,12,16}`
- Extract: `state = (word >> shift) & 0x7`

Validation:

- Compare the observed distribution of `state` over a PFN sample against `ListCounts`.

Confirmed fact from this process:

- The “Active” list-state index used elsewhere is treated as `6` (`active_code = 6`).

#### 10.4.2 Use index: 4-bit field (current assumption)

In the current code, for this snapshot family:

- `use_code = q0 & 0xF`

The textual labels still come from RAMMap UI ordering (not stored in the `.RMP`).

#### 10.4.3 File backing key: 64-bit value with low flag bits (heuristic)

Goal: find where a `FileList` key appears in PFN records.

Observation:

- The file key matches `File/@Key` **after clearing some low bits** (flags/alignment).

Search strategy (see `discover_pfn_layout()`):

- Candidate location: `q0` or `q2`
- Candidate low-bit masks to clear: `0x0`, `0xF`, `0xFF`, `0xFFF`

Extraction used in exports:

- `file_key = word & (~lowmask)`

This supports:

- `file_summary` (count pages per file by list state)
- `physical_pages` (print the file path for file-backed PFNs)

#### 10.4.4 Priority: 3-bit field (grounded by header counters when present)

Some `.RMP` versions embed RAMMap’s Priority Summary counts in the `<PfnDatabase>` header (see section 10.1).

When those header counters are present, the exporter uses them as ground truth:

- Search for a 3-bit field whose distribution over **Standby** PFNs matches `header[7:15]`.

If the header counters aren’t present, the exporter falls back to a best-effort heuristic (entropy-based search on Standby pages).

This supports `priority_summary` and the Priority column in `physical_pages` / `file_details`.

#### 10.4.5 Owner PID: PID-like field (heuristic / snapshot-family specific)

For some snapshots, PFN records appear to carry a PID-like value that matches the RAMMap Physical Pages “Process” column for certain uses.

In the current implementation for this snapshot family, the exporter uses:

- `owner_pid = (q0 >> 9) & 0x7FFFF` (19 bits)

This is treated as heuristic and may not generalize across all Windows/RAMMap versions.

#### 10.4.6 Virtual address: `q2` as VA for non-file-backed PFNs (heuristic)

In the Physical Pages exporter, we currently interpret:

- If the PFN is **not** file-backed (no matching FileKey), then `q2` behaves like a virtual address and is printed as the “Virtual Address” column.
- If the PFN **is** file-backed, `q2` is treated as the file key pointer (and “Virtual Address” is left blank).

This mapping is based on observed coherence in the exported data and should be treated as heuristic.

#### 10.4.7 File-backed `Image` and `Offset` fields (heuristic)

For file-backed PFNs, the exporter derives two extra columns:

- **Image**: inferred from low flag bits of the file-key field (currently: low-bit `0x1` → `Image = Yes`).
- **Offset**: derived from `q0` low 56 bits with the low byte cleared (`offset = (q0 & ((1<<56)-1)) & ~0xFF`).

These derivations are not yet proven against an independent ground truth and should be treated as heuristic.

#### 10.4.8 Pool Tag inference using `PoolInfo` (heuristic)

For pool-related uses (Paged Pool / Nonpaged Pool), the exporter attempts to populate “Pool Tag” by:

- Taking the PFN’s inferred virtual address (section 10.4.6),
- Treating it as a page start address,
- Finding which `PoolInfo` allocations overlap that page and choosing the tag with the largest overlap.

This is a best-effort correlation, not a guaranteed mapping.

#### 10.4.9 Page table frame (PTE frame): PFN-ordinal pointer (heuristic)

For the `processes` view, we need to attribute Standby/Modified pages to processes.

We approximate this by:

1. Identify PFNs whose **Use == Page Table**.
2. Discover a field in PFN records that often points to one of those page-table PFNs.
3. Treat that field as “PTE frame” (a PFN ordinal pointer into the PFN database).

This is discovered using a supervised trick:

- use Private pages (from `<Process><PFNs>`) as samples
- score candidate bitfields by how often they point to known page-table PFNs

The result is used to build a parent graph among page tables and then attribute file-less standby/modified pages to an owning PID via their PTE frame.

### 10.5 What we do *not* know yet

Within PFN records, many RAMMap columns are still not fully reverse engineered. Current status in this repo:

- **Image**: populated only for file-backed pages via a low-bit flag heuristic (not confirmed).
- **Offset**: populated only for file-backed pages via a `q0`-bit heuristic (not confirmed).
- **Process**: populated for some uses using a PID-like field heuristic; still frequently blank/misleading for other use types.
- **Virtual Address**: populated for non-file-backed pages via `q2` heuristic; unknown for file-backed pages.
- **Pool Tag**: best-effort inferred only for pool uses by correlating PFN VA with `PoolInfo`; not guaranteed.

Things still entirely unknown (format-level):

- The full PFN record struct layout (many fields unaccounted for)
- The full `<PfnDatabase>` header struct (beyond the priority counters)

## 11) Practical parsing notes (why the code looks like it does)

- `.RMP` files can be extremely large; parsing must be streaming.
- `xml.etree.ElementTree.iterparse()` is used for normal XML lists (e.g., `FileList`, `ProcessList`).
- For huge hex tags (`PfnDatabase`, `PoolInfo`), we *do not* feed them through an XML DOM; instead we scan raw bytes for `<Tag>` and `</Tag>` boundaries and decode the inner hex text.

This means:

- The streamer currently expects payload tags to appear exactly as `<TagName>` (no attributes). If RAMMap adds attributes (e.g., `<PfnDatabase Version="...">`), the streamer would need to be upgraded.

## 12) How to extend the reverse engineering

If you want to firm up “heuristic” fields into “confirmed” ones, the most effective workflow so far has been:

1. Find a *ground truth* table that RAMMap already provides in the `.RMP` (like `ListCounts` or `PageUseCounts`).
2. Search bitfield candidates in `q0/q2` that reproduce that table’s distribution.
3. Validate across multiple snapshots (different Windows versions, memory sizes).

Good next candidates for grounding:

- A stronger ground truth for per-PFN “owner PID” (if any exists beyond `<Process><PFNs>`)
- Independent validation of file-backed `Image` / `Offset` derivations
- Any tag that provides file offsets / section mapping or VA-to-file mapping

---

## Appendix A: Minimal pseudo-code for decoding hex u64 arrays

```python
# Pseudocode
hex_text = read_inner_text(tag)
bytes_ = hex_decode_ignoring_non_hex(hex_text)
vals = [le_u64(bytes_[i:i+8]) for i in range(0, len(bytes_), 8)]
```

## Appendix B: Terms

- **PFN**: page frame number (Windows memory management).
- **PFN record ordinal**: 0-based index into the PFN database record run.
- **List state**: one of the 8 PFN lists (Active/Standby/Modified/etc).
- **Use**: one of the 16 “usage” buckets shown by RAMMap.
