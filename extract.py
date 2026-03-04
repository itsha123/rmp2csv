from __future__ import annotations

import argparse
import csv
import hashlib
import json
import time
import traceback
import threading
import xml.etree.ElementTree as ET
from bisect import bisect_right
from array import array
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable


PRINTABLE_ASCII = set(range(0x20, 0x7F))

_HEX_TABLE = {
    **{ord(str(i)): i for i in range(10)},
    **{ord(c): 10 + i for i, c in enumerate("abcdef")},
    **{ord(c): 10 + i for i, c in enumerate("ABCDEF")},
}


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


_LOG_LOCK = threading.RLock()
_LOG_HANDLER: Callable[[str], None] | None = None


def set_log_handler(handler: Callable[[str], None] | None) -> None:
    """Set an optional log sink.

    When set, `log()` will call the handler with the fully-formatted log line
    instead of printing to stdout.
    """

    global _LOG_HANDLER
    with _LOG_LOCK:
        _LOG_HANDLER = handler


@contextmanager
def temp_log_handler(handler: Callable[[str], None] | None):
    """Temporarily override the log handler (useful for GUI integration)."""

    global _LOG_HANDLER
    with _LOG_LOCK:
        prev = _LOG_HANDLER
        _LOG_HANDLER = handler
    try:
        yield
    finally:
        with _LOG_LOCK:
            _LOG_HANDLER = prev


def log(msg: str) -> None:
    line = f"[{_ts()}] {msg}"
    with _LOG_LOCK:
        h = _LOG_HANDLER
    if h is not None:
        h(line)
        return
    print(line, flush=True)


def _fmt_secs(secs: float) -> str:
    if secs < 0:
        secs = 0.0
    if secs < 60:
        return f"{secs:.0f}s"
    mins = secs / 60.0
    if mins < 60:
        return f"{mins:.0f}m"
    hrs = mins / 60.0
    return f"{hrs:.1f}h"


def _fmt_hex(x: int) -> str:
    x = int(x)
    if x < 0:
        x &= 0xFFFFFFFFFFFFFFFF
    return f"0x{x:x}"


def _fmt_kb(kb: int, *, blank_zero: bool = False) -> str:
    kb = int(kb)
    if blank_zero and kb == 0:
        return ""
    return f"{kb:,} K"


@dataclass
class Progress:
    label: str
    total: int | None = None
    log_every_s: float = 5.0

    processed: int = 0
    _t0: float = 0.0
    _t_last: float = 0.0
    _logged_once: bool = False

    def __post_init__(self) -> None:
        t = time.monotonic()
        self._t0 = t
        self._t_last = t

    def tick(self, n: int = 1) -> None:
        if n:
            self.processed += int(n)
        now = time.monotonic()
        if (now - self._t_last) >= float(self.log_every_s):
            self._log(now)

    def done(self) -> None:
        if not self._logged_once:
            return
        self._log(time.monotonic(), final=True)

    def _log(self, now: float, *, final: bool = False) -> None:
        elapsed = max(0.001, now - self._t0)
        rate = float(self.processed) / elapsed
        rate_s = f"{rate:,.0f}/s" if rate >= 10 else f"{rate:,.1f}/s"

        if self.total and self.total > 0:
            pct = (float(self.processed) / float(self.total)) * 100.0
            remain = max(0, int(self.total) - int(self.processed))
            eta = (float(remain) / rate) if rate > 0 else 0.0
            tail = f" ({pct:5.1f}%) eta={_fmt_secs(eta)}"
            msg = f"{self.label}: {self.processed:,}/{int(self.total):,} {rate_s}{tail}"
        else:
            msg = f"{self.label}: {self.processed:,} {rate_s}"

        if final:
            msg = f"{msg} (done, elapsed={_fmt_secs(now - self._t0)})"

        log(msg)
        self._t_last = now
        self._logged_once = True


def estimate_total_pfns(snapshot_path: Path) -> int | None:
    """Best-effort estimate of total PFN records.

    In practice, sum(ListCounts[0:8]) matches the number of PFN entries.
    """

    try:
        vals = list(iter_tag_hex_u64(snapshot_path, "ListCounts"))
        if len(vals) >= 8:
            tot = int(sum(vals[:8]))
            return tot if tot > 0 else None
    except Exception:
        return None
    return None


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def strip_xml_ns(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def normalize_xml_key(s: str) -> str:
    return strip_xml_ns(str(s)).strip().lower().replace("-", "").replace("_", "")


def _u64(x: int) -> int:
    return x & 0xFFFFFFFFFFFFFFFF


def _ensure_parent_dir(path: Path) -> None:
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)


def stream_tag_inner_bytes(snapshot_path: Path, tag: str, chunk_size: int = 1024 * 1024) -> Iterable[bytes]:
    """Yield raw bytes contained inside <tag>...</tag> without XML parsing."""

    start = f"<{tag}>".encode("ascii")
    end = f"</{tag}>".encode("ascii")
    buf = bytearray()
    in_tag = False

    with snapshot_path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            buf.extend(chunk)

            while True:
                if not in_tag:
                    i = buf.find(start)
                    if i < 0:
                        if len(buf) > len(start) * 2:
                            del buf[: len(buf) - len(start) * 2]
                        break
                    del buf[: i + len(start)]
                    in_tag = True

                j = buf.find(end)
                if j < 0:
                    keep = len(end) * 2
                    if len(buf) > keep:
                        out = bytes(buf[:-keep])
                        del buf[:-keep]
                        if out:
                            yield out
                    break

                if j > 0:
                    yield bytes(buf[:j])
                del buf[: j + len(end)]
                return


def iter_tag_hex_u64(snapshot_path: Path, tag: str) -> Iterable[int]:
    """Decode a tag whose content is a hex string into little-endian uint64 values."""

    nibble: int | None = None
    b = bytearray()

    for chunk in stream_tag_inner_bytes(snapshot_path, tag):
        for ch in chunk:
            v = _HEX_TABLE.get(ch)
            if v is None:
                continue
            if nibble is None:
                nibble = v
            else:
                b.append((nibble << 4) | v)
                nibble = None
                if len(b) == 8:
                    yield int.from_bytes(b, "little", signed=False)
                    b.clear()


def read_tag_hex_bytes(snapshot_path: Path, tag: str) -> bytes:
    out = bytearray()
    nibble: int | None = None
    for chunk in stream_tag_inner_bytes(snapshot_path, tag):
        for ch in chunk:
            v = _HEX_TABLE.get(ch)
            if v is None:
                continue
            if nibble is None:
                nibble = v
            else:
                out.append((nibble << 4) | v)
                nibble = None
    return bytes(out)


def iter_pfn_database_records(snapshot_path: Path, *, min_sequential_run: int = 64) -> Iterable[tuple[int, int, int]]:
    """Yield (q0, q1, q2) records from <PfnDatabase>, skipping the leading header.

    Empirically, <PfnDatabase> begins with a small header, followed by runs of
    records where q1 increments by exactly +1 per record. Some snapshots have small
    initial runs (e.g. low physical memory ranges) followed by a gap, so we must
    not require an extremely long run to lock onto the correct record alignment.

    q1 in this run is the PFN index and should be used for physical address:
      PhysicalAddress = q1 * 4096
    """

    if min_sequential_run < 32:
        min_sequential_run = 32

    it = iter_tag_hex_u64(snapshot_path, "PfnDatabase")
    buf: deque[tuple[int, int, int]] = deque(maxlen=min_sequential_run + 1)

    prev_q1: int | None = None
    run_len = 0
    in_run = False

    for q0, q1, q2 in zip(it, it, it, strict=False):
        q1i = int(q1)
        if prev_q1 is not None and q1i == prev_q1 + 1:
            run_len += 1
        else:
            run_len = 0

        prev_q1 = q1i

        if in_run:
            yield int(q0), q1i, int(q2)
            continue

        buf.append((int(q0), q1i, int(q2)))
        if run_len >= min_sequential_run:
            # We just observed a long enough +1 streak. The deque now contains
            # exactly the first part of the real PFN run (min_sequential_run+1 records).
            in_run = True
            for rec in buf:
                yield rec
            buf.clear()


PAGE_SIZE_BYTES = 4096
PAGE_KB = PAGE_SIZE_BYTES // 1024


# NOTE: The snapshot encodes only counts; labels are not present in the .RMP.
# The ordering below is taken from the provided RAMMap screenshots.
USECOUNT_LABELS = [
    "Process Private",
    "Mapped File",
    "Shareable",
    "Page Table",
    "Paged Pool",
    "Nonpaged Pool",
    "System PTE",
    "Session Private",
    "Metafile",
    "AWE",
    "Driver Locked",
    "Kernel Stack",
    "Unused",
    "Large Page",
]


# ListCounts order is the canonical order for the 8 PFN list states.
# We only know for sure that index 6 corresponds to "Active" (validated by layout discovery).
LISTSTATE_LABELS_FALLBACK = [
    "Zeroed",
    "Free",
    "Standby",
    "Modified",
    "Modified No-Write",
    "Bad",
    "Active",
    "Transition",
]


LISTSTATE_UI_ORDER = [
    6,  # Active
    2,  # Standby
    3,  # Modified
    4,  # ModifiedNoWrite
    7,  # Transition
    0,  # Zeroed
    1,  # Free
    5,  # Bad
]


def _liststate_ui_name(state_idx: int) -> str:
    return LISTSTATE_LABELS_FALLBACK[int(state_idx)]


def _use_ui_name(use_idx: int) -> str:
    if 0 <= int(use_idx) < len(USECOUNT_LABELS):
        return USECOUNT_LABELS[int(use_idx)]
    return f"Use{int(use_idx)}"


def parse_filelist_keys(snapshot_path: Path) -> dict[int, str]:
    """Return mapping of unsigned 64-bit Key -> Path from <FileList>."""

    key_to_path: dict[int, str] = {}
    ctx = ET.iterparse(str(snapshot_path), events=("end",))
    for _event, elem in ctx:
        tag = strip_xml_ns(elem.tag)
        if tag != "File":
            elem.clear()
            continue
        k = elem.attrib.get("Key")
        p = elem.attrib.get("Path")
        if k is not None and p is not None:
            try:
                kk = _u64(int(k))
            except ValueError:
                kk = None
            if kk is not None:
                key_to_path[kk] = p
        elem.clear()
    return key_to_path


def _iter_hex_u32_le(text: str) -> Iterable[int]:
    """Yield little-endian u32 values from a hex string."""

    nibble: int | None = None
    b = bytearray()
    for ch in text:
        v = _HEX_TABLE.get(ord(ch))
        if v is None:
            continue
        if nibble is None:
            nibble = v
            continue
        b.append((nibble << 4) | v)
        nibble = None
        if len(b) == 4:
            yield int.from_bytes(b, "little", signed=False)
            b.clear()


def parse_process_list(
    snapshot_path: Path,
    *,
    include_pfns: bool = False,
    total_pfns: int | None = None,
) -> tuple[dict[int, dict[str, str]], "array[int] | None", dict[int, int]]:
    """Parse <ProcessList>.

    Returns:
      - proc_info: pid -> {Name, ProcessId, SessionId}
    - owners: optional array mapping PFNDatabase record ordinal -> pid (0 means unknown/unowned)

    In this snapshot format, each <Process> element contains a child <PFNs> hex blob
    listing PFNDatabase record ordinals owned by that process.
    """

    owners: array[int] | None = None
    if include_pfns:
        if total_pfns is None:
            raise ValueError("total_pfns is required when include_pfns=True")
        owners = array("I", [0]) * (int(total_pfns) + 1)

    out: dict[int, dict[str, str]] = {}
    pfn_counts: dict[int, int] = {}
    ctx = ET.iterparse(str(snapshot_path), events=("end",))
    for _event, elem in ctx:
        tag = strip_xml_ns(elem.tag)

        # IMPORTANT: don't clear <PFNs> before its parent <Process> is processed.
        # The PFN list is stored as text content inside the PFNs element.
        if tag == "PFNs":
            continue

        if tag != "Process":
            elem.clear()
            continue

        pid_s = elem.attrib.get("ProcessId") or elem.attrib.get("Key") or ""
        try:
            pid = int(pid_s)
        except ValueError:
            elem.clear()
            continue

        out[int(pid)] = {
            "Name": elem.attrib.get("Name", ""),
            "ProcessId": elem.attrib.get("ProcessId", pid_s),
            "SessionId": elem.attrib.get("SessionId", ""),
        }

        if owners is not None:
            pfn_text = ""
            for child in list(elem):
                if strip_xml_ns(child.tag) == "PFNs":
                    pfn_text = child.text or ""
                    break
            if pfn_text:
                max_idx = len(owners) - 1
                cnt = 0
                for pfn in _iter_hex_u32_le(pfn_text):
                    # PFNs are PFNDatabase record ordinals.
                    if 0 <= int(pfn) <= max_idx:
                        owners[int(pfn)] = int(pid)
                        cnt += 1
                if cnt:
                    pfn_counts[int(pid)] = pfn_counts.get(int(pid), 0) + cnt

        elem.clear()

    # Attach PFN counts into proc_info (used as RAMMap "Private" column).
    for pid, cnt in pfn_counts.items():
        if pid in out:
            out[pid]["PfnCount"] = str(int(cnt))

    return out, owners, pfn_counts


@dataclass(frozen=True)
class OwnerPidLayout:
    word: int  # 0 for q0, 2 for q2
    shift: int
    mask: int


def discover_owner_pid_layout_from_private_pfns(
    snapshot_path: Path,
    private_owner: "array[int]",
    *,
    top_k: int = 32,
    stage1_labeled: int = 8_000,
    stage2_labeled: int = 120_000,
) -> OwnerPidLayout:
    """Discover a PID-like bitfield in PFN records using private PFNs as labels.

    The <Process><PFNs> list behaves like RAMMap's "Private" for Processes tab.
    We use those PFN-record ordinals as supervised labels to locate an owner PID
    field inside q0/q2.
    """

    max_pid = 0
    # Find max pid among labels (sampled) to set a reasonable min bit width.
    sampled = 0
    for pid in private_owner:
        if pid:
            max_pid = max(max_pid, int(pid))
            sampled += 1
            if sampled >= 10_000:
                break
    if max_pid <= 0:
        raise RuntimeError("No private PFN labels available to discover owner PID layout")

    min_bits = max(16, int(max_pid).bit_length())
    bits_list = list(range(min_bits, 33))
    shifts = list(range(0, 61))

    candidates: list[tuple[int, int, int]] = []  # (word, shift, mask)
    for word in (0, 2):
        for shift in shifts:
            for bits in bits_list:
                candidates.append((word, shift, (1 << bits) - 1))

    # Stage 1: coarse scoring across all candidates.
    hits1 = [0] * len(candidates)
    seen1 = 0
    progress = Progress("Sampling PFN records (discover_owner_pid_layout stage1)", total=stage1_labeled)
    for idx, (q0, _q1, q2) in enumerate(iter_pfn_database_records(snapshot_path)):
        if idx >= len(private_owner):
            break
        exp = int(private_owner[idx])
        if exp == 0:
            continue
        q0i, q2i = int(q0), int(q2)
        for i, (word, shift, mask) in enumerate(candidates):
            src = q0i if word == 0 else q2i
            if ((src >> shift) & mask) == exp:
                hits1[i] += 1
        seen1 += 1
        if seen1 % 256 == 0:
            progress.tick(256)
        if seen1 >= stage1_labeled:
            break
    progress.done()

    if seen1 == 0:
        raise RuntimeError("No labeled PFNs encountered during stage1")

    top_idx = sorted(range(len(candidates)), key=lambda i: hits1[i], reverse=True)[: max(1, int(top_k))]
    top = [candidates[i] for i in top_idx]

    # Stage 2: rescore only top-K candidates on a larger labeled set.
    hits2 = [0] * len(top)
    seen2 = 0
    progress = Progress("Sampling PFN records (discover_owner_pid_layout stage2)", total=stage2_labeled)
    for idx, (q0, _q1, q2) in enumerate(iter_pfn_database_records(snapshot_path)):
        if idx >= len(private_owner):
            break
        exp = int(private_owner[idx])
        if exp == 0:
            continue
        q0i, q2i = int(q0), int(q2)
        for i, (word, shift, mask) in enumerate(top):
            src = q0i if word == 0 else q2i
            if ((src >> shift) & mask) == exp:
                hits2[i] += 1
        seen2 += 1
        if seen2 % 1024 == 0:
            progress.tick(1024)
        if seen2 >= stage2_labeled:
            break
    progress.done()

    best_i = max(range(len(top)), key=lambda i: hits2[i])
    word, shift, mask = top[best_i]
    log(f"Owner PID layout (private-supervised): word={word} shift={shift} mask=0x{mask:x} hits={hits2[best_i]}/{seen2}")
    return OwnerPidLayout(word=int(word), shift=int(shift), mask=int(mask))


@dataclass(frozen=True)
class PteFrameLayout:
    word: int
    shift: int
    mask: int


def get_pfn_base(snapshot_path: Path) -> int:
    """Return the PFN number of the first PFNDatabase record."""

    for _q0, q1, _q2 in iter_pfn_database_records(snapshot_path):
        return int(q1)
    raise RuntimeError("PFNDatabase appears to be empty")


def discover_pteframe_layout_from_private_samples(
    private_samples: list[tuple[int, int, int]],
    page_table_ordinals: set[int],
    *,
    total_pfns: int,
) -> PteFrameLayout:
    """Find a field that frequently points at PFNs whose Use == Page Table.

    We treat the extracted value as a PFNDatabase record ordinal and score
    candidates by how often they hit known Page Table ordinals on private-page
    samples.
    """

    if not private_samples:
        raise RuntimeError("No private PFN samples available for PteFrame discovery")
    if not page_table_ordinals:
        raise RuntimeError("No Page Table PFNs found (UseCounts says 0?)")

    # Candidate bitfields: try q0/q2, any shift, and plausible PFN-ordinal masks.
    # We strongly prefer wider masks to reduce chance collisions.
    # total_pfns is ~8.3M here, i.e. ~23 bits.
    bits_list = list(range(20, 29))
    shifts = list(range(0, 61))
    candidates: list[tuple[int, int, int]] = []  # (word, shift, mask)
    for word in (0, 2):
        for shift in shifts:
            for bits in bits_list:
                candidates.append((word, shift, (1 << bits) - 1))

    hits = [0] * len(candidates)
    seen = [0] * len(candidates)
    distinct_hits: list[set[int]] = [set() for _ in range(len(candidates))]

    for q0i, q1i, q2i in private_samples:
        words = (q0i, q1i, q2i)
        for i, (word, shift, mask) in enumerate(candidates):
            v = int((words[word] >> shift) & mask)
            if v == 0 or v > int(total_pfns):
                continue
            seen[i] += 1
            if v in page_table_ordinals:
                hits[i] += 1
                distinct_hits[i].add(v)

    # Prefer candidates with real correlation, not chance collisions.
    # Let chance = |page_table| / 2^bits, and lift = hit_rate / chance.
    # We also want many distinct hits and enough support.
    page_table_n = float(len(page_table_ordinals))

    def score(i: int) -> float:
        s = int(seen[i])
        h = int(hits[i])
        if s <= 0 or h <= 0:
            return -1.0
        word, shift, mask = candidates[i]
        bits = int(mask).bit_length()
        space = float(1 << bits) if bits < 63 else float(2**63)
        chance = (page_table_n / space) if space > 0 else 0.0
        if chance <= 0:
            return -1.0
        hit_rate = float(h) / float(s)
        lift = hit_rate / chance
        dh = float(len(distinct_hits[i]))

        # Penalize tiny support; emphasize lift first, then support.
        # Distinctness helps avoid degenerate fields.
        return lift * (h ** 0.5) * (1.0 + (dh / 250.0))

    best_i = max(range(len(candidates)), key=score)
    word, shift, mask = candidates[best_i]
    log(
        f"PteFrame field guess: word={word} shift={shift} mask=0x{mask:x} "
        f"(hits={hits[best_i]}/{seen[best_i]}, distinct={len(distinct_hits[best_i])})"
    )
    return PteFrameLayout(word=int(word), shift=int(shift), mask=int(mask))


@dataclass(frozen=True)
class PfnLayout:
    state_word: int
    state_shift: int
    active_code: int
    filekey_word: int
    filekey_mask_lowbits: int


def discover_pfn_layout(snapshot_path: Path, file_keys: set[int], sample_records: int = 1_000_000) -> PfnLayout:
    """Best-effort discovery of PFN record fields needed for File Summary (Active)."""

    listcounts = list(iter_tag_hex_u64(snapshot_path, "ListCounts"))
    if len(listcounts) < 8:
        raise RuntimeError(f"Unexpected ListCounts length: {len(listcounts)}")
    expected = listcounts[:8]
    exp_total = int(sum(expected))
    if exp_total <= 0:
        raise RuntimeError("ListCounts sums to 0")
    exp_freq = [int(v) / exp_total for v in expected]

    # q1 is the PFN index; packed fields live in q0/q2.
    state_candidates: list[tuple[int, int]] = [
        (word, shift)
        for word in (0, 2)
        for shift in (0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16)
    ]
    counts = [[0] * 8 for _ in range(len(state_candidates))]

    key_masks = [0, 0xF, 0xFF, 0xFFF]
    key_candidates = [(w, m) for w in (0, 2) for m in key_masks]
    key_hits = [0] * len(key_candidates)

    n_records = 0
    progress = Progress("Sampling PFN records (discover_pfn_layout)", total=int(sample_records) if sample_records else None)
    batch = 0
    for q0, q1, q2 in iter_pfn_database_records(snapshot_path):
        words = (q0, q1, q2)

        for idx, cand in enumerate(state_candidates):
            w, shift = cand
            code = (words[w] >> shift) & 0x7
            counts[idx][code] += 1

        n_records += 1
        batch += 1
        if batch >= 65536:
            progress.tick(batch)
            batch = 0

        for idx, (w, lowmask) in enumerate(key_candidates):
            vv = words[w] & (~lowmask & 0xFFFFFFFFFFFFFFFF)
            if vv in file_keys:
                key_hits[idx] += 1

        if n_records >= sample_records:
            break

    if batch:
        progress.tick(batch)
    progress.done()

    best_state_idx: int | None = None
    best_score: int | None = None
    for idx, c in enumerate(counts):
        tot = float(sum(c))
        if tot <= 0:
            continue
        score = sum(abs((c[i] / tot) - exp_freq[i]) for i in range(8))
        if best_score is None or score < best_score:
            best_score = score
            best_state_idx = idx

    if best_state_idx is None:
        raise RuntimeError("Failed to score state candidates")

    state_word, state_shift = state_candidates[best_state_idx]
    log(f"Discovered state bits: word={state_word} shift={state_shift} (score={best_score:.6f} on {n_records} PFNs)")

    active_code = 6

    best_key_idx = max(range(len(key_candidates)), key=lambda i: key_hits[i])
    filekey_word, filekey_lowmask = key_candidates[best_key_idx]
    log(
        f"File-key field guess: word={filekey_word} clear_lowbits=0x{filekey_lowmask:x} "
        f"(hits={key_hits[best_key_idx]}/{n_records})"
    )

    return PfnLayout(
        state_word=state_word,
        state_shift=state_shift,
        active_code=active_code,
        filekey_word=filekey_word,
        filekey_mask_lowbits=filekey_lowmask,
    )


@dataclass(frozen=True)
class PidLayout:
    pid_word: int
    pid_shift: int
    pid_mask: int


def discover_pid_layout(
    snapshot_path: Path,
    pids: set[int],
    sample_records: int = 1_000_000,
    *,
    state_word: int | None = None,
    state_shift: int | None = None,
    use_layout: "UseLayout | None" = None,
    allowed_states: set[int] | None = None,
    allowed_uses: set[int] | None = None,
) -> PidLayout:
    """Guess where ProcessId is stored inside PFN records.

    Heuristic: find a 32-bit field whose values frequently match known pids.
    """

    if not pids:
        raise RuntimeError("No processes found in ProcessList")

    # Candidates for a PID-like field.
    # In practice, PID-sized fields may include flag bits, so try multiple masks.
    max_pid = max(int(p) for p in pids)
    min_bits = max(1, int(max_pid).bit_length())
    # PIDs in this snapshot fit in <= 19 bits, but keep a small range for safety.
    mask_bits_list = [b for b in range(max(16, min_bits), 33)]
    shifts = list(range(0, 33))
    candidates = [(w, s, b) for w in (0, 1, 2) for s in shifts for b in mask_bits_list]
    total_hits = [0] * len(candidates)
    per_candidate_pid_hits: list[dict[int, int]] = [dict() for _ in range(len(candidates))]
    tested = 0
    processed = 0
    progress = Progress("Sampling PFN records (discover_pid_layout)", total=int(sample_records) if sample_records else None)
    batch = 0

    for q0, q1, q2 in iter_pfn_database_records(snapshot_path):
        words = (q0, q1, q2)
        processed += 1

        if state_word is not None and state_shift is not None and allowed_states is not None:
            st = int((words[state_word] >> state_shift) & 0x7)
            if st not in allowed_states:
                batch += 1
                if batch >= 65536:
                    progress.tick(batch)
                    batch = 0
                continue

        if use_layout is not None and allowed_uses is not None:
            uu = int((words[use_layout.use_word] >> use_layout.use_shift) & 0xF)
            if uu not in allowed_uses:
                batch += 1
                if batch >= 65536:
                    progress.tick(batch)
                    batch = 0
                continue

        for idx, (w, s, b) in enumerate(candidates):
            mask = (1 << b) - 1
            pid = (words[w] >> s) & mask
            if int(pid) in pids:
                total_hits[idx] += 1
                dd = per_candidate_pid_hits[idx]
                ip = int(pid)
                dd[ip] = dd.get(ip, 0) + 1
        tested += 1
        batch += 1
        if batch >= 65536:
            progress.tick(batch)
            batch = 0
        if tested >= sample_records:
            break

    if batch:
        progress.tick(batch)
    progress.done()

    def score(i: int) -> float:
        tot = total_hits[i]
        if tot <= 0:
            return -1.0
        d = per_candidate_pid_hits[i]
        distinct = len(d)
        top = max(d.values()) if d else 0
        top_ratio = (top / tot) if tot else 1.0

        # Prioritize high hit volume, then prefer diversity and avoid degenerate
        # candidates dominated by a single PID.
        s = float(tot) * (1.0 + 0.05 * float(distinct))
        if distinct <= 2:
            s *= 0.05
        if top_ratio > 0.98:
            s *= 0.05
        return s

    best_idx = max(range(len(candidates)), key=score)
    pid_word, pid_shift, pid_bits = candidates[best_idx]
    pid_mask = (1 << int(pid_bits)) - 1

    dd = per_candidate_pid_hits[best_idx]
    distinct = len(dd)
    top = max(dd.values()) if dd else 0
    top_ratio = (top / total_hits[best_idx]) if total_hits[best_idx] else 1.0
    log(
        f"PID field guess: word={pid_word} shift={pid_shift} bits={pid_bits} "
        f"(hits={total_hits[best_idx]}/{tested}, distinct={distinct}, top_ratio={top_ratio:.3f}, processed={processed})"
    )
    return PidLayout(pid_word=pid_word, pid_shift=pid_shift, pid_mask=pid_mask)


@dataclass(frozen=True)
class UseLayout:
    use_word: int
    use_shift: int
    # Mapping from the raw 4-bit use code found in PFN records -> RAMMap UI use index.
    # Many snapshots appear to use a permuted encoding, so we must remap before
    # applying USECOUNT_LABELS / comparing against USECOUNT_LABELS.index(...).
    code_to_ui: tuple[int, ...] = tuple(range(16))

    def to_ui(self, use_code: int) -> int:
        uc = int(use_code) & 0xF
        try:
            return int(self.code_to_ui[uc])
        except Exception:
            return uc


def _hungarian_min_cost_assignment(cost: list[list[float]]) -> list[int]:
    """Return assignment for a square cost matrix.

    Returns a list `assign` where assign[row] = col.

    This is a minimal implementation of the Hungarian algorithm (a.k.a. Kuhn–Munkres)
    for dense square matrices. Complexity: O(n^3), fine for n=16.
    """

    n = len(cost)
    if n == 0:
        return []
    if any(len(r) != n for r in cost):
        raise ValueError("cost matrix must be square")

    # Implementation based on the classic potentials + augmenting path form.
    # Uses 1-based indexing for the algorithmic arrays.
    u = [0.0] * (n + 1)
    v = [0.0] * (n + 1)
    p = [0] * (n + 1)
    way = [0] * (n + 1)

    for i in range(1, n + 1):
        p[0] = i
        j0 = 0
        minv = [float("inf")] * (n + 1)
        used = [False] * (n + 1)
        while True:
            used[j0] = True
            i0 = p[j0]
            delta = float("inf")
            j1 = 0
            for j in range(1, n + 1):
                if used[j]:
                    continue
                cur = float(cost[i0 - 1][j - 1]) - u[i0] - v[j]
                if cur < minv[j]:
                    minv[j] = cur
                    way[j] = j0
                if minv[j] < delta:
                    delta = minv[j]
                    j1 = j
            for j in range(0, n + 1):
                if used[j]:
                    u[p[j]] += delta
                    v[j] -= delta
                else:
                    minv[j] -= delta
            j0 = j1
            if p[j0] == 0:
                break
        while True:
            j1 = way[j0]
            p[j0] = p[j1]
            j0 = j1
            if j0 == 0:
                break

    assign = [-1] * n
    for j in range(1, n + 1):
        i = p[j]
        if 1 <= i <= n:
            assign[i - 1] = j - 1
    return assign


def discover_use_layout(
    snapshot_path: Path,
    state_word: int,
    state_shift: int,
    sample_records: int = 750_000,
) -> UseLayout:
    """Return the PFN Use field location.

    For the snapshot family we've validated here, the per-PFN use index is the
    low 4 bits of q0.

    Note: the textual labels are not stored in the .RMP; they come from
    USECOUNT_LABELS (RAMMap UI order).
    """

    # Keep a small sanity check so obvious format changes fail loudly.
    expected = list(iter_tag_hex_u64(snapshot_path, "PageUseCounts"))
    if len(expected) != 128:
        raise RuntimeError(f"Unexpected PageUseCounts length: {len(expected)}")

    use_word, use_shift = 0, 0
    log(f"Use field: word={use_word} shift={use_shift} (fixed)")
    return UseLayout(use_word=use_word, use_shift=use_shift)


@dataclass(frozen=True)
class PriorityLayout:
    pri_word: int
    pri_shift: int


def discover_priority_layout(
    snapshot_path: Path,
    state_word: int,
    state_shift: int,
    sample_records: int = 350_000,
    avoid: set[tuple[int, int]] | None = None,
) -> PriorityLayout:
    """Discover a 3-bit priority field.

    Priority Summary is stored in the PFNDatabase header as per-priority Standby
    counters. We use those counters as ground truth to discover the per-PFN
    priority bitfield: find a 3-bit field whose distribution on Standby pages
    matches the header.

    If the header isn't present, fall back to a best-effort heuristic.
    """

    avoid = set(avoid or set())

    # Read PFNDatabase header counters (same encoding as Priority Summary).
    header: list[int] = []
    it = iter_tag_hex_u64(snapshot_path, "PfnDatabase")
    for _ in range(32):
        try:
            header.append(int(next(it)))
        except StopIteration:
            break

    expected_standby = None
    if len(header) >= 15:
        exp = [int(x) for x in header[7:15]]
        if sum(exp) > 0:
            expected_standby = exp

    # Candidate 3-bit windows.
    candidates = [(w, s) for w in (0, 2) for s in range(0, 61)]

    # Avoid overlapping known fields (use+state) when caller provided them.
    # `avoid` is a set of (word, shift) where shift is the LSB of another field.
    # Assume those are 3-4 bit packed fields and avoid overlap conservatively.
    def overlaps(word: int, shift: int, aw: int, as_: int, width: int) -> bool:
        if int(word) != int(aw):
            return False
        a0 = int(as_)
        a1 = int(as_) + int(width) - 1
        b0 = int(shift)
        b1 = int(shift) + 2
        return not (b1 < a0 or b0 > a1)

    filtered: list[tuple[int, int]] = []
    for w, s in candidates:
        if (w, s) in avoid:
            continue
        # Avoid state (3 bits)
        if overlaps(w, s, state_word, state_shift, 3):
            continue
        bad = False
        for aw, as_ in avoid:
            # assume 4-bit (use) when word matches; conservative.
            if overlaps(w, s, aw, as_, 4):
                bad = True
                break
        if bad:
            continue
        filtered.append((w, s))
    candidates = filtered

    standby_state_idx = 2

    def score_vs_expected(obs: list[int], obs_total: int, exp: list[int]) -> float:
        if obs_total <= 0:
            return float("inf")
        exp_total = float(sum(exp))
        if exp_total <= 0:
            return float("inf")
        # Compare frequencies (sample-sized expected).
        sc = 0.0
        for i in range(8):
            e = (float(exp[i]) / exp_total) * float(obs_total)
            o = float(obs[i])
            sc += ((o - e) * (o - e)) / (e + 1.0)
        return float(sc)

    if expected_standby is not None:
        # Phase 1: sample some standby PFNs while tracking all candidates.
        target_standby = int(max(50_000, min(250_000, int(sample_records))))
        counts1 = [[0] * 8 for _ in range(len(candidates))]
        standby_seen = 0
        processed = 0
        progress = Progress(
            "Sampling PFN records (discover_priority_layout / phase1)",
            total=int(target_standby),
        )
        batch = 0
        for q0, q1, q2 in iter_pfn_database_records(snapshot_path):
            processed += 1
            words = (q0, q1, q2)
            state = int((words[state_word] >> state_shift) & 0x7)
            if state != standby_state_idx:
                continue
            for ci, (w, s) in enumerate(candidates):
                pri = int((words[w] >> s) & 0x7)
                counts1[ci][pri] += 1
            standby_seen += 1
            batch += 1
            if batch >= 65536:
                progress.tick(batch)
                batch = 0
            if standby_seen >= target_standby:
                break
        if batch:
            progress.tick(batch)
        progress.done()
        if standby_seen <= 0:
            raise RuntimeError("Failed to sample Standby PFNs for priority discovery")

        scored = [
            (score_vs_expected(counts1[i], standby_seen, expected_standby), i)
            for i in range(len(candidates))
        ]
        scored.sort(key=lambda t: t[0])
        top_k = [i for _sc, i in scored[:4]]

        # Phase 2: full scan on standby PFNs, tracking only top-K candidates.
        counts2 = [[0] * 8 for _ in range(len(top_k))]
        standby_total = 0
        total_pfns = estimate_total_pfns(snapshot_path)
        progress2 = Progress("Sampling PFN records (discover_priority_layout / phase2)", total=int(total_pfns) if total_pfns else None)
        batch2 = 0
        for q0, q1, q2 in iter_pfn_database_records(snapshot_path):
            words = (q0, q1, q2)
            state = int((words[state_word] >> state_shift) & 0x7)
            if state != standby_state_idx:
                batch2 += 1
                if batch2 >= 65536:
                    progress2.tick(batch2)
                    batch2 = 0
                continue
            for ti, ci in enumerate(top_k):
                w, s = candidates[ci]
                pri = int((words[w] >> s) & 0x7)
                counts2[ti][pri] += 1
            standby_total += 1
            batch2 += 1
            if batch2 >= 65536:
                progress2.tick(batch2)
                batch2 = 0
        if batch2:
            progress2.tick(batch2)
        progress2.done()

        best_ci = top_k[0]
        best_score = float("inf")
        for ti, ci in enumerate(top_k):
            sc = score_vs_expected(counts2[ti], standby_total, expected_standby)
            if sc < best_score:
                best_score = float(sc)
                best_ci = int(ci)

        pri_word, pri_shift = candidates[int(best_ci)]
        log(
            f"Priority field guess: word={pri_word} shift={pri_shift} (standby_header_score={best_score:.6f}, standby_pages={standby_total})"
        )
        return PriorityLayout(pri_word=pri_word, pri_shift=pri_shift)

    # Fallback heuristic when header counters are unavailable.
    avoid.add((state_word, state_shift))
    candidates = [c for c in candidates if c not in avoid]
    counts = [[0] * 8 for _ in range(len(candidates))]
    standby_seen = 0
    progress = Progress(
        "Sampling PFN records (discover_priority_layout / fallback)",
        total=int(sample_records) if sample_records else None,
    )
    batch = 0
    for q0, q1, q2 in iter_pfn_database_records(snapshot_path):
        words = (q0, q1, q2)
        state = int((words[state_word] >> state_shift) & 0x7)
        if state != standby_state_idx:
            continue
        for i, (w, s) in enumerate(candidates):
            pri = int((words[w] >> s) & 0x7)
            counts[i][pri] += 1
        standby_seen += 1
        batch += 1
        if batch >= 65536:
            progress.tick(batch)
            batch = 0
        if standby_seen >= sample_records:
            break
    if batch:
        progress.tick(batch)
    progress.done()

    if standby_seen <= 0:
        raise RuntimeError("Failed to sample PFN records")

    # Pick the least-degenerate field.
    best_i = min(range(len(candidates)), key=lambda i: max(counts[i]) / max(1, sum(counts[i])))
    pri_word, pri_shift = candidates[best_i]
    log(f"Priority field guess: word={pri_word} shift={pri_shift} (fallback on {standby_seen} standby PFNs)")
    return PriorityLayout(pri_word=pri_word, pri_shift=pri_shift)


def _export_processes_csv(snapshot_path: Path, out_csv: Path, _args: argparse.Namespace) -> int:
    total_pfns = estimate_total_pfns(snapshot_path)
    proc_info, private_owner, _pfn_counts = parse_process_list(
        snapshot_path,
        include_pfns=True,
        total_pfns=total_pfns,
    )
    if not proc_info:
        log("ERROR: no <Process> entries found")
        return 2

    if private_owner is None:
        log("ERROR: failed to build PFN->PID mapping")
        return 2

    pids = set(proc_info.keys())

    # Derive RAMMap "Private" directly from PFN counts (the <PFNs> list).
    per_pid_private_pages: dict[int, int] = {}
    for pid, info in proc_info.items():
        try:
            per_pid_private_pages[int(pid)] = int(info.get("PfnCount", "0"))
        except Exception:
            per_pid_private_pages[int(pid)] = 0

    # Discover state/use fields inside PFNDatabase so we can classify PFNs.
    layout = discover_pfn_layout(snapshot_path, set(), sample_records=200_000)
    state_word, state_shift = layout.state_word, layout.state_shift
    use_layout = discover_use_layout(snapshot_path, state_word=state_word, state_shift=state_shift, sample_records=500_000)

    # Aggregate per process id. RAMMap's Processes tab totals appear to be the sum
    # of the displayed columns (Private + Standby + Modified + Page Table).
    per_pid_standby: dict[int, int] = {pid: 0 for pid in pids}
    per_pid_modified: dict[int, int] = {pid: 0 for pid in pids}
    per_pid_pagetable: dict[int, int] = {pid: 0 for pid in pids}

    standby_state = LISTSTATE_UI_ORDER[1]
    modified_state = LISTSTATE_UI_ORDER[2]
    modified_nw_state = LISTSTATE_UI_ORDER[3]
    pagetable_use = USECOUNT_LABELS.index("Page Table")
    process_private_use = USECOUNT_LABELS.index("Process Private")

    # Owner PID field (empirically stable across this snapshot family).
    # Discovered as: word=0 shift=9 bits=19.
    def owner_pid_from_q0(q0i: int) -> int:
        return int((int(q0i) >> 9) & 0x7FFFF)

    session_private_use = USECOUNT_LABELS.index("Session Private")

    progress = Progress("Scanning PFN database (attribute processes)", total=total_pfns)
    batch = 0
    for idx, (q0, _q1, q2) in enumerate(iter_pfn_database_records(snapshot_path)):
        q0i = int(q0)
        q2i = int(q2)

        pid = owner_pid_from_q0(q0i)

        use_code = int((q0i >> use_layout.use_shift) & 0xF) if use_layout.use_word == 0 else int((q2i >> use_layout.use_shift) & 0xF)
        use = use_layout.to_ui(use_code)

        # Page Table: RAMMap displays this as KB of physical pages tagged as Page Table.
        # Count these pages directly and keep them disjoint from Standby/Modified.
        if pid in pids and int(use) == int(pagetable_use):
            per_pid_pagetable[int(pid)] += 1

        if int(use) == int(pagetable_use):
            batch += 1
            if batch >= 65536:
                progress.tick(batch)
                batch = 0
            continue

        if pid not in pids:
            batch += 1
            if batch >= 65536:
                progress.tick(batch)
                batch = 0
            continue

        state = int(((q0i if state_word == 0 else q2i) >> state_shift) & 0x7)
        if state == standby_state:
            # Heuristic: if this PFN ordinal is listed as "Private" by another PID in <ProcessList>,
            # prefer charging it to that other process instead of this one.
            # Exception: Session Private pages appear to behave differently in RAMMap.
            other = 0
            if idx < len(private_owner):
                other = int(private_owner[idx])
            if other and other != int(pid) and int(use) != int(session_private_use):
                batch += 1
                if batch >= 65536:
                    progress.tick(batch)
                    batch = 0
                continue
            per_pid_standby[int(pid)] += 1
        elif state == modified_state or state == modified_nw_state:
            per_pid_modified[int(pid)] += 1

        batch += 1
        if batch >= 65536:
            progress.tick(batch)
            batch = 0

    if batch:
        progress.tick(batch)
    progress.done()

    _ensure_parent_dir(out_csv)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        # Column names taken from RAMMap screenshot (Processes tab).
        header = ["Process", "Session", "PID", "Private", "Standby", "Modified", "Page Table", "Total"]
        w.writerow(header)

        def total_pages(pid: int) -> int:
            return (
                int(per_pid_private_pages.get(pid, 0))
                + int(per_pid_standby.get(pid, 0))
                + int(per_pid_modified.get(pid, 0))
                + int(per_pid_pagetable.get(pid, 0))
            )

        for pid in sorted(pids, key=total_pages, reverse=True):
            info = proc_info.get(pid, {})
            sess = info.get("SessionId", "")
            try:
                sess_i = int(sess)
                # Some snapshots encode "unknown" as 0xFFFFFFFF; don't print that.
                if sess_i == 0xFFFFFFFF:
                    sess = ""
                else:
                    sess = sess_i
            except Exception:
                pass

            private_pages = int(per_pid_private_pages.get(pid, 0))
            standby_pages = int(per_pid_standby.get(pid, 0))
            modified_pages = int(per_pid_modified.get(pid, 0))
            pagetable_pages = int(per_pid_pagetable.get(pid, 0))
            total_pages_v = private_pages + standby_pages + modified_pages + pagetable_pages

            row = [
                info.get("Name", ""),
                sess,
                pid,
                _fmt_kb(private_pages * PAGE_KB),
                _fmt_kb(standby_pages * PAGE_KB),
                _fmt_kb(modified_pages * PAGE_KB),
                _fmt_kb(pagetable_pages * PAGE_KB),
                _fmt_kb(total_pages_v * PAGE_KB),
            ]
            w.writerow(row)

    log(f"Wrote {out_csv} ({len(pids)} rows)")
    return 0


def _export_physranges_csv(snapshot_path: Path, out_csv: Path, _args: argparse.Namespace) -> int:
    q = list(iter_tag_hex_u64(snapshot_path, "PhysRanges"))
    if not q:
        log("ERROR: <PhysRanges> not found or empty")
        return 2

    ranges: list[tuple[int, int, int]] = []
    count = int(q[0])
    if 1 + 2 * count <= len(q):
        off = 1
        for i in range(count):
            start = int(q[off])
            end = int(q[off + 1])
            off += 2
            ranges.append((i, start, end))
    else:
        for i in range(0, len(q) - 1, 2):
            ranges.append((i // 2, int(q[i]), int(q[i + 1])))

    page_size = 4096
    _ensure_parent_dir(out_csv)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "RangeIndex",
            "StartPFN",
            "EndPFN",
            "Pages",
            "SizeBytes",
            "StartAddressHex",
            "EndAddressHex",
        ])
        for idx, start_pfn, end_pfn in ranges:
            pages = max(0, int(end_pfn) - int(start_pfn))
            size_bytes = pages * page_size
            start_addr = int(start_pfn) * page_size
            end_addr = int(end_pfn) * page_size
            w.writerow([
                idx,
                start_pfn,
                end_pfn,
                pages,
                size_bytes,
                f"0x{start_addr:016x}",
                f"0x{end_addr:016x}",
            ])
    log(f"Wrote {out_csv} ({len(ranges)} rows)")
    return 0


def _export_u64_counts_csv(snapshot_path: Path, tag: str, out_csv: Path) -> int:
    vals = list(iter_tag_hex_u64(snapshot_path, tag))
    if not vals:
        log(f"ERROR: <{tag}> not found or empty")
        return 2

    page_kb = PAGE_KB
    _ensure_parent_dir(out_csv)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Index", "Pages", "KB"])
        for i, pages in enumerate(vals):
            w.writerow([i, int(pages), int(pages) * page_kb])
    log(f"Wrote {out_csv} ({len(vals)} rows)")
    return 0


def _export_usecounts_csv(snapshot_path: Path, out_csv: Path, _args: argparse.Namespace) -> int:
    # RAMMap "Use Counts" is the 16x8 breakdown (Use x List).
    vals = list(iter_tag_hex_u64(snapshot_path, "PageUseCounts"))
    if len(vals) != 128:
        log(f"ERROR: expected 128 u64s in <PageUseCounts>, got {len(vals)}")
        return 2
    m = [vals[i * 8 : (i + 1) * 8] for i in range(16)]

    _ensure_parent_dir(out_csv)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        header = ["Usage", "Total"]
        for st_idx in LISTSTATE_UI_ORDER:
            header.append(_liststate_ui_name(st_idx))
        w.writerow(header)

        col_totals = [0] * 8
        grand_total = 0

        # RAMMap displays a fixed set of usage rows and a computed Total row.
        # Some snapshots also include additional (unused) rows in PageUseCounts;
        # we ignore anything beyond USECOUNT_LABELS.
        for use_idx in range(len(USECOUNT_LABELS)):
            row = m[use_idx]
            total_pages = int(sum(row))
            grand_total += total_pages
            out_row = [_use_ui_name(use_idx), _fmt_kb(total_pages * PAGE_KB)]
            for st_idx in LISTSTATE_UI_ORDER:
                kb = int(row[st_idx]) * PAGE_KB
                col_totals[int(st_idx)] += int(row[st_idx])
                out_row.append(_fmt_kb(kb, blank_zero=True))
            w.writerow(out_row)

        # RAMMap shows a Total row.
        total_row = ["Total", _fmt_kb(grand_total * PAGE_KB)]
        for st_idx in LISTSTATE_UI_ORDER:
            total_row.append(_fmt_kb(int(col_totals[int(st_idx)]) * PAGE_KB, blank_zero=True))
        w.writerow(total_row)

    log(f"Wrote {out_csv} (16 rows)")
    return 0


def _export_pageusecounts_csv(snapshot_path: Path, out_csv: Path, _args: argparse.Namespace) -> int:
    # Back-compat alias: keep the view name "physical_pages" for the per-page export,
    # and expose the 16x8 matrix via "use_counts".
    return _export_usecounts_csv(snapshot_path, out_csv, _args)


def _export_physical_pages_csv(snapshot_path: Path, out_csv: Path, args: argparse.Namespace) -> int:
    # Per-page table (PFN database): column set is RAMMap-specific; many fields are not RE'd yet.
    # We'll emit the exact requested columns and fill what we can.
    proc_info, _private_owner, _pfn_counts = parse_process_list(snapshot_path, include_pfns=False)
    key_to_path = parse_filelist_keys(snapshot_path)
    layout = discover_pfn_layout(snapshot_path, set(key_to_path.keys()) if key_to_path else set(), sample_records=200_000)
    use_layout = discover_use_layout(snapshot_path, state_word=layout.state_word, state_shift=layout.state_shift, sample_records=750_000)
    pri_layout = discover_priority_layout(
        snapshot_path,
        state_word=layout.state_word,
        state_shift=layout.state_shift,
        sample_records=350_000,
        avoid={(use_layout.use_word, use_layout.use_shift)},
    )
    mask_clear = ~layout.filekey_mask_lowbits & 0xFFFFFFFFFFFFFFFF

    active_state = LISTSTATE_UI_ORDER[0]
    standby_state = LISTSTATE_UI_ORDER[1]
    modified_state = LISTSTATE_UI_ORDER[2]
    modified_nw_state = LISTSTATE_UI_ORDER[3]

    # Owner PID field (empirically stable across this snapshot family).
    # Discovered as: q0>>9 (19 bits).
    def owner_pid_from_q0(q0i: int) -> int:
        return int((int(q0i) >> 9) & 0x7FFFF)

    # PoolInfo index for pool-tag lookup (used for Nonpaged/Paged Pool pages).
    pool_allocs: list[tuple[int, int, str]] = []  # (start, end_exclusive, tag)
    try:
        blob = read_tag_hex_bytes(snapshot_path, "PoolInfo")
        if len(blob) >= 8:
            count = int.from_bytes(blob[0:8], "little", signed=False)
            rec_size = 24
            n = min(count, max(0, (len(blob) - 8) // rec_size))
            off = 8
            for _i in range(n):
                addr = int.from_bytes(blob[off : off + 8], "little", signed=False)
                size = int.from_bytes(blob[off + 8 : off + 16], "little", signed=False)
                tag_bytes = blob[off + 16 : off + 20]
                off += rec_size
                if addr == 0 or size == 0:
                    continue
                tag = tag_bytes.decode("ascii", errors="replace")
                pool_allocs.append((int(addr), int(addr + size), tag))
            pool_allocs.sort(key=lambda t: t[0])
    except KeyError:
        pool_allocs = []

    pool_starts = [a for a, _b, _t in pool_allocs]

    def pool_tag_for_page(va_page: int) -> str:
        """Return pool tag for a VA page start by best overlap with PoolInfo allocations."""

        if not pool_allocs or va_page == 0:
            return ""

        page_start = int(va_page)
        page_end = int(va_page + PAGE_SIZE_BYTES)

        # Scan allocations that start near this page. We also walk backwards a bit to catch
        # long allocations that started before the page but still overlap.
        i = bisect_right(pool_starts, page_start) - 1
        best_by_tag: dict[str, int] = {}

        # Walk backward while allocations overlap the page.
        j = i
        while j >= 0:
            a, b, tag = pool_allocs[j]
            if b <= page_start:
                break
            if a < page_end:
                ov = min(b, page_end) - max(a, page_start)
                if ov > 0:
                    best_by_tag[tag] = best_by_tag.get(tag, 0) + int(ov)
            j -= 1

        # Walk forward while allocation starts before page_end.
        j = i + 1
        while j < len(pool_allocs):
            a, b, tag = pool_allocs[j]
            if a >= page_end:
                break
            if b > page_start:
                ov = min(b, page_end) - max(a, page_start)
                if ov > 0:
                    best_by_tag[tag] = best_by_tag.get(tag, 0) + int(ov)
            j += 1

        if not best_by_tag:
            return ""
        return max(best_by_tag.items(), key=lambda kv: kv[1])[0]

    limit = int(getattr(args, "limit", 0) or 0)
    if limit < 0:
        limit = 0

    _ensure_parent_dir(out_csv)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "Physical Address",
                "List",
                "Use",
                "Priority",
                "Image",
                "Offset",
                "File Name",
                "Process",
                "Virtual Address",
                "Pool Tag",
            ]
        )

        # Heuristic to match RAMMap's displayed Process on adjacent Mapped File rows:
        # In the UI, many Mapped File pages appear to borrow the process from a neighboring
        # Process Private page. We only apply a 1-page adjacency rule to avoid broad
        # mis-attribution.
        last_private_proc: tuple[int, str] | None = None  # (phys, proc_s)
        pending_mapped: tuple[int, list[str]] | None = None  # (phys, row)
        PROCESS_COL = 7

        total = limit if limit else estimate_total_pfns(snapshot_path)
        progress = Progress("Scanning PFN database (physical_pages)", total=total)
        batch = 0
        idx = 0
        for q0, pfn, q2 in iter_pfn_database_records(snapshot_path):
            words = (q0, pfn, q2)
            state = int((words[layout.state_word] >> layout.state_shift) & 0x7)
            use_code = int((words[use_layout.use_word] >> use_layout.use_shift) & 0xF)
            use = use_layout.to_ui(use_code)
            use_name = _use_ui_name(use)
            pri = int((words[pri_layout.pri_word] >> pri_layout.pri_shift) & 0x7)
            phys = int(pfn) * PAGE_SIZE_BYTES

            # RAMMap's Physical Pages grid only shows these list types.
            if state == active_state:
                list_name = "Active"
            elif state == standby_state:
                list_name = "Standby"
            elif state == modified_state or state == modified_nw_state:
                list_name = "Modified"
            else:
                batch += 1
                if batch >= 65536:
                    progress.tick(batch)
                    batch = 0
                continue

            # Process: RAMMap's displayed PID aligns with a PID-like field in q0.
            pid = owner_pid_from_q0(int(q0))
            proc_s = ""
            if pid and pid in proc_info:
                info = proc_info.get(pid) or {}
                proc_s = f"{info.get('Name','')} ({pid})"

            file_name = ""
            file_flags = 0
            if key_to_path:
                file_flags = int(words[layout.filekey_word] & int(layout.filekey_mask_lowbits))
                raw_key = int(words[layout.filekey_word] & mask_clear)
                file_name = key_to_path.get(raw_key, "")

            # Virtual Address: for this snapshot family, q2 contains VA for non-file-backed pages.
            # For file-backed pages, q2 is the FileList key pointer.
            virt_s = ""
            if not file_name:
                va = int(q2)
                if va:
                    virt_s = _fmt_hex(va)

            # Offset + Image: derived for file-backed pages.
            img_s = ""
            off_s = ""
            if file_name:
                # Image appears to be flag bit0 in the file-key low nibble.
                img_s = "Yes" if (file_flags & 0x1) else ""

                # Offset: derived from packed q0 bits (low56, ignoring low byte).
                q0i = int(q0)
                low56 = int(q0i & ((1 << 56) - 1))
                off = int(low56 & ~0xFF)
                off_s = _fmt_hex(off)

            pool_tag = ""
            if use_name in ("Nonpaged Pool", "Paged Pool") and virt_s:
                # VA is already the page start address in these rows.
                pool_tag = pool_tag_for_page(int(q2))

            # RAMMap's Physical Pages grid does not show a Process for all uses.
            # Based on observed UI behavior, limit Process display to these use types.
            if use_name not in ("Process Private", "Mapped File"):
                proc_s = ""

            # Fill Mapped File process from a 1-page-adjacent private page (backward).
            if use_name == "Mapped File" and not proc_s and last_private_proc is not None:
                lp_phys, lp_proc = last_private_proc
                if int(phys) - int(lp_phys) == PAGE_SIZE_BYTES:
                    proc_s = lp_proc

            row_out = [
                _fmt_hex(phys),
                list_name,
                use_name,
                pri,
                img_s,
                off_s,
                file_name,
                proc_s,
                virt_s,
                pool_tag,
            ]

            # If we previously deferred a Mapped File row, flush it once we move past it.
            if pending_mapped is not None:
                p_phys, p_row = pending_mapped
                if int(phys) - int(p_phys) > PAGE_SIZE_BYTES:
                    w.writerow(p_row)
                    pending_mapped = None

            # If this is a private page with a known process, it can fill a 1-page-ahead
            # deferred Mapped File row.
            if use_name == "Process Private" and proc_s:
                if pending_mapped is not None:
                    p_phys, p_row = pending_mapped
                    if int(phys) - int(p_phys) == PAGE_SIZE_BYTES and not p_row[PROCESS_COL]:
                        p_row[PROCESS_COL] = proc_s
                        w.writerow(p_row)
                        pending_mapped = None
                last_private_proc = (int(phys), proc_s)

            # Defer Mapped File rows only when Process is still unknown.
            if use_name == "Mapped File" and not proc_s:
                if pending_mapped is not None:
                    # Should be very rare; flush in-order to avoid reordering.
                    w.writerow(pending_mapped[1])
                pending_mapped = (int(phys), row_out)
            else:
                w.writerow(row_out)

            idx += 1
            batch += 1
            if batch >= 65536:
                progress.tick(batch)
                batch = 0
            if limit and idx >= limit:
                break

        if batch:
            progress.tick(batch)
        progress.done()

        if pending_mapped is not None:
            w.writerow(pending_mapped[1])

    log(f"Wrote {out_csv} ({idx} rows)")
    return 0


def _export_priority_summary_csv(snapshot_path: Path, out_csv: Path, args: argparse.Namespace) -> int:
    # RAMMap's Priority Summary values are stored directly in the PFNDatabase header.
    # Empirically (Windows 10/11 snapshot family), the first u64s of <PfnDatabase> are:
    #   [0..]  header/misc
    #   [7:15]  Standby pages by priority (0..7)
    #   [15:23] Repurposed pages by priority (0..7)
    # Values are in pages; RAMMap displays them in KB (page_count * 4 KB).

    header: list[int] = []
    it = iter_tag_hex_u64(snapshot_path, "PfnDatabase")
    for _ in range(32):
        try:
            header.append(int(next(it)))
        except StopIteration:
            break

    standby = [0] * 8
    repurposed = [0] * 8
    if len(header) >= 23:
        standby = [int(x) for x in header[7:15]]
        repurposed = [int(x) for x in header[15:23]]
    else:
        log("ERROR: PFNDatabase header too short to read Priority Summary counters")
        return 2

    _ensure_parent_dir(out_csv)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Priority", "Standby", "Repurposed"])
        standby_sum = 0
        repurposed_sum = 0
        for pri in range(8):
            kb = int(standby[pri]) * PAGE_KB
            standby_sum += int(standby[pri])
            rk = int(repurposed[pri]) * PAGE_KB
            repurposed_sum += int(repurposed[pri])
            w.writerow([pri, _fmt_kb(kb, blank_zero=True), _fmt_kb(rk, blank_zero=True)])

        w.writerow(["Total", _fmt_kb(int(standby_sum) * PAGE_KB), _fmt_kb(int(repurposed_sum) * PAGE_KB)])
    log(f"Wrote {out_csv} (8 rows)")
    return 0


def _export_physical_ranges_csv(snapshot_path: Path, out_csv: Path, _args: argparse.Namespace) -> int:
    # RAMMap tab: Physical Ranges
    # Columns: Start, End, Size
    q = list(iter_tag_hex_u64(snapshot_path, "PhysRanges"))
    if not q:
        log("ERROR: <PhysRanges> not found or empty")
        return 2

    # Observed encoding: pairs of (StartPFN, PageCount).
    if len(q) % 2 != 0:
        q = q[: len(q) - 1]

    intervals: list[tuple[int, int]] = []
    for i in range(0, len(q), 2):
        start_pfn = int(q[i])
        page_count = int(q[i + 1])
        if page_count <= 0:
            continue
        intervals.append((start_pfn, start_pfn + page_count))

    # Merge overlaps (and adjacency) to match RAMMap's presentation.
    intervals.sort()
    merged: list[tuple[int, int]] = []
    for s, e in intervals:
        if not merged:
            merged.append((s, e))
            continue
        ps, pe = merged[-1]
        if s <= pe:
            merged[-1] = (ps, max(pe, e))
        else:
            merged.append((s, e))

    _ensure_parent_dir(out_csv)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Start", "End", "Size"])
        total_pages = 0
        for start_pfn, end_pfn_excl in merged:
            pages = max(0, int(end_pfn_excl) - int(start_pfn))
            total_pages += int(pages)
            start_addr = int(start_pfn) * PAGE_SIZE_BYTES
            end_addr = int(end_pfn_excl) * PAGE_SIZE_BYTES
            w.writerow([_fmt_hex(start_addr), _fmt_hex(end_addr), _fmt_kb(int(pages) * PAGE_KB, blank_zero=True)])

        w.writerow(["Total", "", _fmt_kb(int(total_pages) * PAGE_KB)])
    log(f"Wrote {out_csv} ({len(merged)} rows)")
    return 0


def _export_file_summary_csv(snapshot_path: Path, out_csv: Path, _args: argparse.Namespace) -> int:
    # RAMMap screenshot shows columns: Path, Total, Standby, Modified, Modified No-Write.
    log("Parsing FileList (Key -> Path)...")
    key_to_path = parse_filelist_keys(snapshot_path)
    if not key_to_path:
        log("ERROR: No <File> entries found under <FileList>.")
        return 2
    log(f"Found {len(key_to_path)} files")

    layout = discover_pfn_layout(snapshot_path, set(key_to_path.keys()), sample_records=1_000_000)
    mask_clear = ~layout.filekey_mask_lowbits & 0xFFFFFFFFFFFFFFFF

    standby_idx = 2
    modified_idx = 3
    modnw_idx = 4

    counts_by_key: dict[int, list[int]] = {}
    progress = Progress("Scanning PFN database (file_summary)", total=estimate_total_pfns(snapshot_path))
    batch = 0
    for q0, q1, q2 in iter_pfn_database_records(snapshot_path):
        words = (q0, q1, q2)
        key = int(words[layout.filekey_word] & mask_clear)
        if key not in key_to_path:
            batch += 1
            if batch >= 65536:
                progress.tick(batch)
                batch = 0
            continue
        state = int((words[layout.state_word] >> layout.state_shift) & 0x7)
        row = counts_by_key.get(key)
        if row is None:
            row = [0, 0, 0, 0, 0]
            counts_by_key[key] = row
        row[0] += 1
        if state == standby_idx:
            row[1] += 1
        elif state == modified_idx:
            row[2] += 1
        elif state == modnw_idx:
            row[3] += 1
        elif state == layout.active_code:
            row[4] += 1

        batch += 1
        if batch >= 65536:
            progress.tick(batch)
            batch = 0

    if batch:
        progress.tick(batch)
    progress.done()

    items = sorted(counts_by_key.items(), key=lambda kv: kv[1][0], reverse=True)
    _ensure_parent_dir(out_csv)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Path", "Total", "Standby", "Modified", "Modified No-Write", "Active"])
        for key, (t, s, m, mnw, a) in items:
            w.writerow([
                key_to_path.get(key, ""),
                _fmt_kb(int(t) * PAGE_KB),
                _fmt_kb(int(s) * PAGE_KB, blank_zero=True),
                _fmt_kb(int(m) * PAGE_KB, blank_zero=True),
                _fmt_kb(int(mnw) * PAGE_KB, blank_zero=True),
                _fmt_kb(int(a) * PAGE_KB, blank_zero=True),
            ])

    log(f"Wrote {out_csv} ({len(items)} rows)")
    return 0


def _export_file_details_csv(snapshot_path: Path, out_csv: Path, args: argparse.Namespace) -> int:
    # RAMMap File Details is hierarchical:
    # - Parent rows: Path + Size
    # - Subrows: PhysicalAddress/List/Type/Priority/Image/Offset (Path/Size blank)
    # We emulate this in CSV by emitting one parent row per file key, followed by
    # its subrows.

    key_to_path = parse_filelist_keys(snapshot_path)
    if not key_to_path:
        log("ERROR: No <File> entries found under <FileList>.")
        return 2

    layout = discover_pfn_layout(snapshot_path, set(key_to_path.keys()), sample_records=200_000)
    pri_layout = discover_priority_layout(
        snapshot_path,
        state_word=layout.state_word,
        state_shift=layout.state_shift,
        sample_records=350_000,
        avoid=None,
    )
    mask_clear = ~layout.filekey_mask_lowbits & 0xFFFFFFFFFFFFFFFF

    limit = int(getattr(args, "limit", 0) or 0)
    if limit < 0:
        limit = 0

    tmp_dir = Path("_artifacts") / "tmp_file_details"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    bucket_count = 64
    bucket_files = [(tmp_dir / f"bucket_{i:02d}.tsv") for i in range(bucket_count)]
    handles = [bf.open("wb") for bf in bucket_files]

    pages_by_key: dict[int, int] = {}
    progress = Progress("Scanning PFN database (file_details)", total=estimate_total_pfns(snapshot_path))
    batch = 0
    emitted = 0

    try:
        for q0, pfn, q2 in iter_pfn_database_records(snapshot_path):
            words = (q0, pfn, q2)
            raw_key = int(words[layout.filekey_word] & mask_clear)
            if raw_key not in key_to_path:
                batch += 1
                if batch >= 65536:
                    progress.tick(batch)
                    batch = 0
                continue

            state = int((words[layout.state_word] >> layout.state_shift) & 0x7)
            pri = int((words[pri_layout.pri_word] >> pri_layout.pri_shift) & 0x7)
            phys = int(pfn) * PAGE_SIZE_BYTES

            file_flags = int(words[layout.filekey_word] & int(layout.filekey_mask_lowbits))
            img = 1 if (file_flags & 0x1) else 0
            q0i = int(q0)
            low56 = int(q0i & ((1 << 56) - 1))
            off = int(low56 & ~0xFF)

            pages_by_key[raw_key] = pages_by_key.get(raw_key, 0) + 1

            b = (raw_key * 11400714819323198485) & 0xFFFFFFFFFFFFFFFF
            b = int((b >> 58) & (bucket_count - 1))
            # key\tphys\tstate\tpri\timg\toff\n
            handles[b].write(f"{raw_key}\t{phys}\t{state}\t{pri}\t{img}\t{off}\n".encode("ascii"))

            emitted += 1
            batch += 1
            if batch >= 65536:
                progress.tick(batch)
                batch = 0
            if limit and emitted >= limit:
                break
    finally:
        if batch:
            progress.tick(batch)
        progress.done()
        for h in handles:
            h.close()

    _ensure_parent_dir(out_csv)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Path", "Size", "PhysicalAddress", "List", "Type", "Priority", "Image", "Offset"])

        # Emit per-bucket (keeps memory bounded). Keys within a bucket are sorted by Path.
        for bf in bucket_files:
            if not bf.exists() or bf.stat().st_size == 0:
                continue
            by_key: dict[int, list[tuple[int, int, int, int, int]]] = {}
            with bf.open("rb") as r:
                for line in r:
                    try:
                        k_s, phys_s, state_s, pri_s, img_s, off_s = line.rstrip(b"\n").split(b"\t")
                        k = int(k_s)
                        phys = int(phys_s)
                        st = int(state_s)
                        pri = int(pri_s)
                        img = int(img_s)
                        off = int(off_s)
                    except Exception:
                        continue
                    by_key.setdefault(k, []).append((phys, st, pri, img, off))

            keys = list(by_key.keys())
            keys.sort(key=lambda k: key_to_path.get(k, ""))

            for k in keys:
                path = key_to_path.get(k, "")
                if not path:
                    continue

                pages = int(pages_by_key.get(k, 0))
                w.writerow([path, _fmt_kb(pages * PAGE_KB, blank_zero=True), "", "", "", "", "", ""])

                recs = by_key.get(k, [])
                recs.sort(key=lambda t: t[0])
                for phys, st, pri, img, off in recs:
                    w.writerow([
                        "",
                        "",
                        _fmt_hex(phys),
                        _liststate_ui_name(st),
                        "Mapped File",
                        pri,
                        "Yes" if int(img) else "",
                        _fmt_hex(off),
                    ])

    log(f"Wrote {out_csv} ({len(pages_by_key)} files, {emitted} page rows)")
    return 0


def _export_listcounts_csv(snapshot_path: Path, out_csv: Path, _args: argparse.Namespace) -> int:
    vals = list(iter_tag_hex_u64(snapshot_path, "ListCounts"))
    if len(vals) < 8:
        log(f"ERROR: expected at least 8 u64s in <ListCounts>, got {len(vals)}")
        return 2
    vals = vals[:8]

    _ensure_parent_dir(out_csv)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ListIndex", "List", "Pages", "KB"])
        for idx, pages in enumerate(vals):
            w.writerow([idx, LISTSTATE_LABELS_FALLBACK[idx], int(pages), int(pages) * PAGE_KB])
    log(f"Wrote {out_csv} (8 rows)")
    return 0


def _export_not_implemented(_snapshot_path: Path, _out_csv: Path, args: argparse.Namespace) -> int:
    view = getattr(args, "view", "")
    log(f"ERROR: view not implemented yet: {view}")
    log("This tab requires exact column/row schema mapping from RAMMap.")
    log("If you paste/upload screenshots with headers visible, I will wire it up 1:1.")
    return 2


def _export_poolinfo_csv(snapshot_path: Path, out_csv: Path, _args: argparse.Namespace) -> int:
    blob = read_tag_hex_bytes(snapshot_path, "PoolInfo")
    if len(blob) < 8:
        log("ERROR: PoolInfo too small")
        return 2

    count = int.from_bytes(blob[0:8], "little", signed=False)
    rec_size = 24
    n = min(count, max(0, (len(blob) - 8) // rec_size))
    totals: dict[str, tuple[int, int]] = {}
    off = 8
    for _i in range(n):
        addr = int.from_bytes(blob[off : off + 8], "little", signed=False)
        size = int.from_bytes(blob[off + 8 : off + 16], "little", signed=False)
        tag_bytes = blob[off + 16 : off + 20]
        off += rec_size
        if addr == 0:
            continue
        tag = tag_bytes.decode("ascii", errors="replace")
        allocs, btot = totals.get(tag, (0, 0))
        totals[tag] = (allocs + 1, btot + int(size))

    rows = [(t, a, b) for t, (a, b) in totals.items()]
    rows.sort(key=lambda x: x[2], reverse=True)

    _ensure_parent_dir(out_csv)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Tag", "Allocations", "Bytes", "MiB"])
        for tag, allocs, b in rows:
            w.writerow([tag, allocs, b, round(b / 1024 / 1024, 3)])
    log(f"Wrote {out_csv} ({len(rows)} rows)")
    return 0


def _export_pfn_raw_csv(snapshot_path: Path, out_csv: Path, args: argparse.Namespace) -> int:
    limit = int(getattr(args, "limit", 100_000) or 100_000)
    if limit <= 0:
        log("ERROR: --limit must be > 0")
        return 2

    it = iter_tag_hex_u64(snapshot_path, "PfnDatabase")
    _ensure_parent_dir(out_csv)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Index", "Q0Hex", "Q1Hex", "Q2Hex"])
        i = 0
        for q0, q1, q2 in zip(it, it, it, strict=False):
            w.writerow([i, f"0x{q0:016x}", f"0x{q1:016x}", f"0x{q2:016x}"])
            i += 1
            if i >= limit:
                break
    log(f"Wrote {out_csv} ({limit} max rows)")
    return 0


def _export_filesummary_active_csv(snapshot_path: Path, out_csv: Path, _args: argparse.Namespace) -> int:
    log("Parsing FileList (Key -> Path)...")
    key_to_path = parse_filelist_keys(snapshot_path)
    if not key_to_path:
        log("ERROR: No <File> entries found under <FileList>.")
        return 2
    log(f"Found {len(key_to_path)} files")

    layout = discover_pfn_layout(snapshot_path, set(key_to_path.keys()), sample_records=1_000_000)

    log("Decoding PfnDatabase and aggregating Active pages by file key...")
    active_pages_by_key: dict[int, int] = {}
    total_records = 0
    matched_records = 0

    mask_clear = ~layout.filekey_mask_lowbits & 0xFFFFFFFFFFFFFFFF

    for q0, q1, q2 in iter_pfn_database_records(snapshot_path):
        words = (q0, q1, q2)
        state = (words[layout.state_word] >> layout.state_shift) & 0x7
        if state == layout.active_code:
            raw_key = words[layout.filekey_word] & mask_clear
            if raw_key in key_to_path:
                active_pages_by_key[raw_key] = active_pages_by_key.get(raw_key, 0) + 1
                matched_records += 1
        total_records += 1

    log(f"PFN records: {total_records}")
    log(f"Active+file-backed matches: {matched_records}")
    log(f"Files with nonzero Active: {len(active_pages_by_key)}")

    # Keep legacy function name but delegate to the tab-shaped export.
    return _export_file_summary_csv(snapshot_path, out_csv, _args)


@dataclass(frozen=True)
class ViewSpec:
    name: str
    description: str
    exporter: Callable[[Path, Path, argparse.Namespace], int]


def view_specs() -> list[ViewSpec]:
    return [
        ViewSpec(
            name="use_counts",
            description="RAMMap tab: Use Counts",
            exporter=_export_usecounts_csv,
        ),
        ViewSpec(
            name="physical_ranges",
            description="RAMMap tab: Physical Ranges",
            exporter=_export_physical_ranges_csv,
        ),
        ViewSpec(
            name="physical_pages",
            description="RAMMap tab: Physical Pages (per-page from PFNDatabase)",
            exporter=_export_physical_pages_csv,
        ),
        ViewSpec(
            name="processes",
            description="RAMMap tab: Processes (computed from PFNDatabase)",
            exporter=_export_processes_csv,
        ),
        ViewSpec(
            name="file_summary",
            description="RAMMap tab: File Summary (computed from PFNDatabase + FileList)",
            exporter=_export_file_summary_csv,
        ),
        ViewSpec(
            name="priority_summary",
            description="RAMMap tab: Priority Summary",
            exporter=_export_priority_summary_csv,
        ),
        ViewSpec(
            name="file_details",
            description="RAMMap tab: File Details",
            exporter=_export_file_details_csv,
        ),
        ViewSpec(
            name="pfn_raw",
            description="Debug: raw PFNDatabase dump (requires --limit)",
            exporter=_export_pfn_raw_csv,
        ),
    ]


def export_view(
    snapshot_path: Path,
    *,
    view: str,
    out_csv: Path,
    limit: int = 0,
) -> int:
    """Programmatic entrypoint for running an export.

    Used by both CLI and GUI. Keep this thin: it should just resolve the view and
    invoke the underlying exporter.
    """

    lookup = build_view_lookup()
    key = normalize_xml_key(view)
    spec = lookup.get(key)
    if spec is None:
        raise KeyError(f"Unknown view: {view}")
    args = argparse.Namespace(limit=int(limit))
    return int(spec.exporter(snapshot_path, out_csv, args))


def build_view_lookup() -> dict[str, ViewSpec]:
    out: dict[str, ViewSpec] = {}
    for v in view_specs():
        out[normalize_xml_key(v.name)] = v
    out[normalize_xml_key("filesummary")] = out[normalize_xml_key("file_summary")]
    out[normalize_xml_key("process_list")] = out[normalize_xml_key("processes")]
    out[normalize_xml_key("physicalpages")] = out[normalize_xml_key("physical_pages")]
    out[normalize_xml_key("physicalranges")] = out[normalize_xml_key("physical_ranges")]
    out[normalize_xml_key("physranges")] = out[normalize_xml_key("physical_ranges")]
    out[normalize_xml_key("prioritysummary")] = out[normalize_xml_key("priority_summary")]
    out[normalize_xml_key("filedetails")] = out[normalize_xml_key("file_details")]
    return out


def build_cli_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="rmp2csv — Offline RAMMap .RMP -> CSV exporter")
    sp = p.add_subparsers(dest="command", required=True)

    p_list = sp.add_parser("list-views", help="List supported export views")
    p_list.add_argument("--json", action="store_true", help="Emit JSON instead of text")

    p_exp = sp.add_parser("export", help="Export a view to a CSV")
    p_exp.add_argument("snapshot", help="Path to .rmp file")
    p_exp.add_argument("--view", required=True, help="View name (see list-views)")
    p_exp.add_argument("--out", required=True, help="Output CSV path")
    p_exp.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Optional row limit for huge views (0 = unlimited)",
    )
    p_exp.add_argument(
        "--sha256",
        action="store_true",
        help="Compute and print snapshot SHA256 (can be slow on large files)",
    )
    return p


def main(argv: list[str]) -> int:
    if not argv:
        build_cli_parser().print_help()
        return 0

    args = build_cli_parser().parse_args(argv)
    lookup = build_view_lookup()

    if args.command == "list-views":
        if args.json:
            print(json.dumps([{"name": v.name, "description": v.description} for v in view_specs()], indent=2))
        else:
            for v in view_specs():
                print(f"{v.name}\t{v.description}")
        return 0

    snapshot_path = Path(args.snapshot)
    if not snapshot_path.exists():
        log(f"ERROR: file not found: {snapshot_path}")
        return 2

    out_csv = Path(args.out)
    key = normalize_xml_key(args.view)
    spec = lookup.get(key)
    if spec is None:
        log(f"ERROR: unknown view: {args.view}")
        log("Run: python rmp2csv.py list-views")
        return 2

    log(f"Snapshot: {snapshot_path}")
    if getattr(args, "sha256", False):
        log(f"SHA256: {sha256_file(snapshot_path)}")
    log(f"View: {spec.name}")
    log(f"Out: {out_csv}")
    t0 = time.time()
    try:
        rc = export_view(snapshot_path, view=spec.name, out_csv=out_csv, limit=int(getattr(args, "limit", 0) or 0))
    except Exception:
        log("ERROR: export failed")
        traceback.print_exc()
        return 1
    log(f"Elapsed {time.time() - t0:.2f}s")
    return int(rc)


def cli() -> None:
    """Console-script entrypoint."""

    import sys

    raise SystemExit(main(sys.argv[1:]))


if __name__ == "__main__":
    raise SystemExit(main(__import__("sys").argv[1:]))
