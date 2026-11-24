"""Collectors for AWS, Azure and Terraform plan JSON behind one entry point."""

from __future__ import annotations

from collections.abc import Sequence

from cspm.collectors.aws import collect_aws
from cspm.collectors.azure import collect_azure
from cspm.collectors.terraform_plan import collect_plan
from cspm.contracts import Provider, Resource, ScanMode


def collect(
    provider: Provider, *, mode: ScanMode, source: str | None, regions: Sequence[str] | None = None
) -> list[Resource]:
    """Collect resources for one provider.

    `source` is the emulator endpoint for AWS (None means http://localhost:5000, and must be None in
    live mode), a fixture file or folder for Azure and a plan JSON path for Terraform.
    """
    if provider is Provider.AWS:
        return collect_aws(mode=mode, endpoint=source, regions=regions)
    if provider is Provider.AZURE:
        return collect_azure(mode=mode, source=source)
    return collect_plan(source)


__all__ = ["collect"]
