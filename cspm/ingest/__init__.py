"""Ingest Trivy, Prowler and Checkov JSON into the Finding model and dedupe against assay findings."""

from cspm.ingest.core import (
    ASSAY_EQUIVALENT,
    DedupeResult,
    dedupe,
    ingest,
    match_key,
)

__all__ = ["ASSAY_EQUIVALENT", "DedupeResult", "dedupe", "ingest", "match_key"]
