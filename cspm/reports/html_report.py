"""Single-file HTML report with client-side filters. Inline CSS and JS only, no external assets."""

from __future__ import annotations

import json
from collections.abc import Mapping
from html import escape
from typing import Any

from cspm.reports.model import SEVERITY_ORDER, band_counts, sorted_findings

_CSS = """
:root{--bg:#fff;--fg:#1b1f24;--muted:#57606a;--line:#d0d7de;--head:#f6f8fa;
--critical:#8b0000;--high:#c62828;--medium:#b26a00;--low:#1f6feb;--info:#57606a}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#8d96a0;--line:#30363d;--head:#161b22;
--critical:#ff7b72;--high:#ffa198;--medium:#e3b341;--low:#79c0ff;--info:#8d96a0}}
*{box-sizing:border-box}
body{margin:0;padding:16px;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,sans-serif}
h1{font-size:20px;margin:0 0 8px}
.meta,.counts{color:var(--muted);margin:0 0 12px}
.counts span{margin-right:12px}
.filters{display:flex;flex-wrap:wrap;gap:12px;align-items:center;padding:10px;border:1px solid var(--line);
background:var(--head);border-radius:6px;margin-bottom:12px}
.filters label{white-space:nowrap}
input[type=search],select{font:inherit;padding:4px 6px;border:1px solid var(--line);border-radius:4px;
background:var(--bg);color:var(--fg)}
.wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%}
th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{background:var(--head)}
td.res{word-break:break-all}
.band{font-weight:600;text-transform:uppercase;font-size:12px}
.band-critical{color:var(--critical)}.band-high{color:var(--high)}.band-medium{color:var(--medium)}
.band-low{color:var(--low)}.band-info{color:var(--info)}
details summary{cursor:pointer}
pre{white-space:pre-wrap;word-break:break-all;background:var(--head);padding:8px;border-radius:4px}
#shown{color:var(--muted)}
"""

_JS = """
(function(){
  var rows=Array.prototype.slice.call(document.querySelectorAll('tr.finding'));
  var boxes=Array.prototype.slice.call(document.querySelectorAll('input[name=band]'));
  var control=document.getElementById('control');
  var resource=document.getElementById('resource');
  var shown=document.getElementById('shown');
  function apply(){
    var bands={};boxes.forEach(function(b){if(b.checked){bands[b.value]=true;}});
    var c=control.value;var r=resource.value.trim().toLowerCase();var n=0;
    rows.forEach(function(row){
      var ok=bands[row.dataset.band]&&(!c||row.dataset.controls.split('|').indexOf(c)>=0)
        &&(!r||row.dataset.resource.toLowerCase().indexOf(r)>=0);
      row.hidden=!ok;var d=document.getElementById('d-'+row.dataset.id);if(d){d.hidden=!ok;}
      if(ok){n++;}
    });
    shown.textContent=n+' of '+rows.length+' shown';
  }
  boxes.forEach(function(b){b.addEventListener('change',apply);});
  control.addEventListener('change',apply);
  resource.addEventListener('input',apply);
  apply();
})();
"""


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def _controls(f: Mapping[str, Any]) -> list[str]:
    return [f"{c['framework']}:{c['control_id']}" for c in f["controls"]]


def _row(f: Mapping[str, Any]) -> str:
    controls = _controls(f)
    evidence = json.dumps(f["evidence"], indent=2, sort_keys=True, ensure_ascii=False)
    refs = "".join(f"<li>{_e(r)}</li>" for r in f["references"])
    return (
        f'<tr class="finding" data-id="{_e(f["id"])}" data-band="{_e(f["band"])}" '
        f'data-controls="{_e("|".join(controls))}" data-resource="{_e(f["resource_id"])}">'
        f'<td class="band band-{_e(f["band"])}">{_e(f["band"])}</td>'
        f"<td>{float(f['score']):.1f}</td><td>{_e(f['rule_id'])}</td>"
        f'<td class="res">{_e(f["resource_id"])}</td><td>{_e(f["title"])}</td>'
        f"<td>{_e(', '.join(controls))}</td><td>{_e(f['state'])}</td><td>{_e(f['verification_status'])}</td></tr>"
        f'<tr id="d-{_e(f["id"])}"><td></td><td colspan="7"><details><summary>Details</summary>'
        f"<p><b>Why:</b> {_e(f['rationale'])}</p><p><b>Impact:</b> {_e(f['impact'])}</p>"
        f"<p><b>Fix:</b> {_e(f['remediation'])}</p><p><b>Source:</b> {_e(f['source'])}</p>"
        f"<pre>{_e(evidence)}</pre>"
        f"{'<p><b>References</b></p><ul>' + refs + '</ul>' if refs else ''}"
        "</details></td></tr>"
    )


def to_html(report: Mapping[str, Any]) -> str:
    """Render the full report as one HTML document."""
    scan = report["scan"]
    findings = sorted_findings(report)
    counts = band_counts(report)
    all_controls = sorted({c for f in findings for c in _controls(f)})
    band_boxes = "".join(
        f'<label><input type="checkbox" name="band" value="{b}" checked> {b} ({counts[b]})</label>'
        for b in SEVERITY_ORDER
    )
    options = '<option value="">All controls</option>' + "".join(
        f'<option value="{_e(c)}">{_e(c)}</option>' for c in all_controls
    )
    rows = "".join(_row(f) for f in findings) or '<tr><td colspan="8">No findings.</td></tr>'
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        "style-src 'unsafe-inline'; script-src 'unsafe-inline'\">"
        f"<title>assay-cspm report {_e(scan['scan_id'])}</title><style>{_CSS}</style></head><body>"
        "<h1>assay-cspm findings report</h1>"
        f'<p class="meta">Scan {_e(scan["scan_id"])} | mode {_e(scan["mode"])} | '
        f"providers {_e(', '.join(scan['providers']) or 'none')} | {_e(scan['finished_at'])} | "
        f"{_e(scan['resource_count'])} resources | tool {_e(scan['tool_version'])}</p>"
        f'<p class="counts">{"".join(f"<span>{b}: {counts[b]}</span>" for b in SEVERITY_ORDER)}</p>'
        f'<div class="filters"><span>Severity:</span>{band_boxes}'
        f'<label>Control <select id="control">{options}</select></label>'
        '<label>Resource <input type="search" id="resource" placeholder="filter by resource"></label>'
        '<span id="shown"></span></div>'
        '<div class="wrap"><table><thead><tr><th>Band</th><th>Score</th><th>Rule</th><th>Resource</th>'
        "<th>Title</th><th>Controls</th><th>State</th><th>Verification</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></div>"
        f"<script>{_JS}</script></body></html>\n"
    )
