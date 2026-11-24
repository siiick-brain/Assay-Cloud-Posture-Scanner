# Control mapping

Each rule is informed by controls in seven frameworks. A mapping says the rule checks something a control cares about. It is not a compliance or certification claim, and passing every rule does not mean an organization meets any framework.

## Frameworks

| Key | Framework | Family |
|---|---|---|
| cis-aws-foundations | CIS AWS Foundations Benchmark (identifiers only) | cis-aws |
| nist-800-53 | NIST SP 800-53 Rev. 5 | nist |
| nist-csf | NIST CSF 2.0 | nist |
| iso-27001 | ISO/IEC 27001:2022 Annex A | iso-27001 |
| soc2 | SOC 2 Trust Services Criteria | soc2 |
| nis2 | NIS2 Directive Article 21(2) points (a) to (j) | nis2 |
| iec-62443-4-1 | IEC 62443-4-1 practices (SM, SR, SD, SI, SVV, DM, SUM, SG) | iec-62443-4-1 |
| cra | EU Cyber Resilience Act Annex I | cra |

NIST SP 800-53 and NIST CSF count as one framework family, which gives seven families. Every rule maps to at least three families; tests/unit/test_mapping.py enforces this.

## Files

- `mappings/<key>.yaml`: `framework`, `name`, `family`, `note` and `mappings`, where `mappings` maps a rule ID to a list of `{control, rationale}`. Each rationale is one line in our own words.
- `mappings/identifiers/<key>.txt`: one identifier per line, optionally followed by a short label we wrote ourselves. No standard text is copied. The CIS list has identifiers only.
- `docs/mapping-coverage.md`: generated report. Run `python -m cspm.mapping` (or `cspm map-coverage`) after any mapping change. `python -m cspm.mapping --check` validates without writing.

Identifier lists for NIST are a curated subset, so "controls with no rule" in the coverage report is relative to that subset. ISO/IEC 27001 Annex A, SOC 2, NIS2, IEC 62443-4-1 and CRA Annex I lists are complete at the identifier level. CIS numbers follow benchmark v3.0.0 as the authors understand it; check them against a licensed copy.

## Code

`cspm.mapping.controls_for(rule_id)` returns the `ControlRef` list the engine attaches to each finding. `validate()` reports unknown rules, unknown identifiers, empty rationales and rules below three families. `CSPM_MAPPINGS_DIR` points the loader at another mappings folder, which an installed package needs because `mappings/` sits outside the Python packages.

## Adding a mapping

1. Add the identifier to the local list if it is missing, with no standard text.
2. Add `{control, rationale}` under the rule in the framework YAML. Write the rationale yourself and keep the wording to "informed by".
3. Run `python -m cspm.mapping` and the tests.
