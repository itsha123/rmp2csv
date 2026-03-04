# rmp2csv

Offline `.RMP` (Sysinternals RAMMap snapshot) → CSV exporter.

Reverse-engineering notes on the `.RMP` structure are in [RMP_FORMAT.md](RMP_FORMAT.md).

## Install (PyPI)

Once published, install with:

- `pip install rmp2csv`

GUI extra:

- `pip install "rmp2csv[gui]"`

## CLI

List supported export views:

- `rmp2csv list-views`

Export a specific view to a CSV:

- `rmp2csv export <snapshot.rmp> --view physical_ranges --out physranges.csv`
- `rmp2csv export <snapshot.rmp> --view processes --out processes.csv`
- `rmp2csv export <snapshot.rmp> --view use_counts --out use_counts.csv`
- `rmp2csv export <snapshot.rmp> --view file_summary --out file_summary.csv`

Optional: include a SHA256 of the snapshot (can be slow on large files):

- `rmp2csv export <snapshot.rmp> --view processes --out processes.csv --sha256`

Debug-heavy raw dump (limit rows):

- `rmp2csv export <snapshot.rmp> --view pfn_raw --out pfn_raw.csv --limit 100000`

Note: `extract.py` is still supported as the underlying implementation.

## GUI (optional)

The GUI is a minimal 3-step wizard (select snapshot → select view → choose output + run).

- Install dependency: `pip install PySide6`
- Run: `python rmp2csv_gui.py`

If installed via `pip install "rmp2csv[gui]"`, you can also run:

- `rmp2csv-gui`

## Build & publish (maintainers)

Build wheels/sdist locally:

- `python -m pip install -U build`
- `python -m build`

Upload to PyPI:

- `python -m pip install -U twine`
- `python -m twine upload dist/*`
