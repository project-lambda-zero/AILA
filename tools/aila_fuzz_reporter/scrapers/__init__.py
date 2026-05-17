"""Per-engine scrapers. Import the scraper you need from its module."""
from __future__ import annotations

from .afl_plusplus import AflPlusPlusScraper
from .fuzzilli import FuzzilliScraper
from .libfuzzer import LibFuzzerScraper

__all__ = [
    "AflPlusPlusScraper",
    "FuzzilliScraper",
    "LibFuzzerScraper",
]
