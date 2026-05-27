"""Data models for the biz-flow-recon pipeline."""

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SurfaceItem:
    """A single attack surface entry."""
    category: str
    priority: str
    filename: str
    source: str
    description: str
    surface_type: str   # "iface" or "noniface"
    slug: str = ""
