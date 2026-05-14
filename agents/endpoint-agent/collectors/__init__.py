"""Endpoint-agent collectors.

Modules in this package shape host signal into CycloneDX 1.6 components for
the A-BOM ingest endpoint. Each collector module exposes a ``collect()``
function returning ``list[dict]`` where each dict is a CycloneDX component
ready to drop into a BOM document.

Currently shipped:

- abom: installed software (dpkg / rpm / Homebrew / macOS .app), OS,
  hardware (CPU / RAM / disks / NICs), browser profiles, AI models.

See docs/architecture/a-bom-design.md for the schema contract.
"""
