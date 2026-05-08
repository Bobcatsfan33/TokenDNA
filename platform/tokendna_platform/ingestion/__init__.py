"""Cloud ingestion layer.

The ingestion layer is the public seam between the open-core collector
and the proprietary intelligence engines.  It:

  * accepts a compressed JSONL frame from a collector POST,
  * validates each event against the schema registry,
  * deduplicates against a recent-event window,
  * routes each event to one or more downstream engines based on its
    ``EventCategory``,
  * applies bounded-queue backpressure so a chatty collector cannot
    starve the platform.

This package is the *interface*; concrete engine integrations live
elsewhere under ``tokendna_platform`` and are wired via the router's
``register_handler`` API.
"""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from .backpressure import BackpressureGate, IngestQueueFull
from .dedup import DedupWindow
from .router import EventRouter
from .schema_registry import SchemaRegistry, UnsupportedSchemaError

__all__ = [
    "BackpressureGate",
    "DedupWindow",
    "EventRouter",
    "IngestQueueFull",
    "SchemaRegistry",
    "UnsupportedSchemaError",
]
