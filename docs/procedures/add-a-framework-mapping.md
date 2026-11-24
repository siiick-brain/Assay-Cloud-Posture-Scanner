# Add a framework mapping

Mappings link a rule ID to control identifiers in the seven frameworks. They are informed by those frameworks and make no compliance claim.

## Rules for every mapping
- Identifiers only. Never paste control text from a standard into the repo.
- One short rationale line per mapping in our own words. Say why the rule gives evidence for the control, not what the control says.
- Every identifier must exist in the local list under mappings/identifiers/. Gate G13 checks this.
- Every rule needs at least three frameworks. Gate G12 checks this.

## Steps
1. Open the framework file in mappings/ (for example the NIST SP 800-53 one).
2. Add an entry under the rule ID with the control identifier and the rationale line.
3. If the identifier is missing from mappings/identifiers/, add only the identifier and a short neutral label. Check the identifier against the public source by hand.
4. Regenerate the coverage report with `uv run cspm map-coverage`.
5. Run `uv run pytest -q --tb=short` and `pwsh scripts/check-style.ps1 mappings docs`.

## Review checklist
- Does the rationale explain the link in one line?
- Would a reader who knows the framework agree the rule gives partial evidence for the control?
- Is any sentence copied from the standard? If so, rewrite it.
