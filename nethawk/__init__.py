"""NetHawk: reconstruct attacks from a packet capture.

Public entry points:
    from nethawk import analyze, Config, __version__
"""
from __future__ import annotations

__version__ = "0.3.1"

from .detect import Config  # noqa: E402
from .analyzer import analyze, analyze_bytes  # noqa: E402
from .models import Analysis, Finding, Incident  # noqa: E402

__all__ = ["__version__", "analyze", "analyze_bytes", "Config", "Analysis", "Finding", "Incident"]
