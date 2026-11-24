# IAM least-privilege review

`cspm iam-review <policy.json> --requirements <req.yaml>` reads one IAM policy and a workload requirement file. It reports what is too broad, proposes a smaller policy built from the requirement file and prints a unified diff of current against proposed.

Code: `cspm/iam/review.py` (`review`, `find_issues`, `policy_diff`), `cspm/iam/patterns.py` (escalation list) and `cspm/iam/cli.py` (`main_iam_review(argv) -> int`). `cspm iam-review` calls `main_iam_review`.

## What it flags

| Kind | Severity | Trigger |
|---|---|---|
| full_admin | critical | `Action: "*"` on `Resource: "*"` |
| action_wildcard | high | `Action: "*"` on a narrower resource |
| service_wildcard | medium | `service:*` such as `s3:*` |
| partial_wildcard | low | patterns like `s3:Get*` that grow when AWS adds actions |
| resource_wildcard | medium, low for read-only actions | `Resource: "*"` |
| not_action | high | Allow with `NotAction` |
| not_resource | medium | Allow with `NotResource` |
| escalation | high | a privilege escalation pattern from `cspm/iam/patterns.py` |
| beyond_requirements | medium | an action no requirement entry covers |
| resource_beyond_requirements | medium | a resource no requirement entry covers |

Only Allow statements are checked for breadth. Escalation patterns are matched across the whole policy, so `iam:PassRole` in one statement and `ec2:RunInstances` in another still match.

## Escalation patterns

Our own list, written from how the APIs behave:

- Pass a role to new compute (EC2, Lambda, ECS, Glue, CloudFormation, SageMaker, CodeBuild, Data Pipeline).
- Pass a role and update Lambda code or configuration.
- Update the code of an existing Lambda function.
- Create or set the default version of a managed policy.
- Attach a managed policy to a user, group or role.
- Put an inline policy on a user, group or role.
- Create access keys or console passwords.
- Add a user to a group.
- Edit a role trust policy and assume the role.
- `sts:AssumeRole` on any resource.

## Requirement file

```yaml
workload: report-uploader
permissions:
  - sid: WriteReports
    actions: [s3:PutObject, s3:GetObject]
    resources: ["arn:aws:s3:::example-reports/*"]
```

Each entry becomes one Allow statement in the proposal. An action is kept only when the current policy already grants it on every listed resource and no Deny blocks it. The proposal never widens access: needs the current policy does not grant are listed under "Needed but not granted" and left out. Deny statements are copied over unchanged.

## Exit codes

0 when the current policy has no issues, 1 when it has issues and 2 on unreadable or invalid input. `--out` writes the proposed policy; `--json` prints the full result.

## Before and after

Files: `examples/iam/report-uploader-policy.json`, `examples/iam/report-uploader-requirements.yaml` and `examples/iam/report-uploader-proposed.json`.

Before, the uploader role had storage, logs and some deploy helpers on every resource:

```json
{"Sid": "AppStorage", "Effect": "Allow", "Action": "s3:*", "Resource": "*"},
{"Sid": "AppLogs", "Effect": "Allow",
 "Action": ["logs:CreateLogStream", "logs:PutLogEvents", "logs:Describe*"], "Resource": "*"},
{"Sid": "DeployHelpers", "Effect": "Allow",
 "Action": ["iam:PassRole", "lambda:CreateFunction", "lambda:UpdateFunctionCode", "sts:AssumeRole"],
 "Resource": "*"}
```

The review reports 15 issues: the `s3:*` service wildcard, `logs:Describe*`, three `Resource: "*"` statements, four escalation matches (pass role to a new function, pass role plus code update, code update alone, assume any role) and six actions or resources outside the requirement file.

After, the proposal holds only what the workload needs and reports 0 issues:

```text
--- current
+++ proposed
-      "Sid": "AppStorage",
+      "Sid": "WriteReports",
       "Effect": "Allow",
-      "Action": "s3:*",
-      "Resource": "*"
+      "Action": [
+        "s3:GetObject",
+        "s3:PutObject"
+      ],
+      "Resource": "arn:aws:s3:::example-reports/*"
+    },
+    {
+      "Sid": "ListReports",
+      "Effect": "Allow",
+      "Action": [
+        "s3:ListBucket"
+      ],
+      "Resource": "arn:aws:s3:::example-reports"
     },
     {
       "Sid": "AppLogs",
       "Effect": "Allow",
       "Action": [
         "logs:CreateLogStream",
-        "logs:PutLogEvents",
-        "logs:Describe*"
+        "logs:PutLogEvents"
       ],
-      "Resource": "*"
-    },
-    {
-      "Sid": "DeployHelpers",
-      ...
+      "Resource": "arn:aws:logs:us-east-1:123456789012:log-group:/app/report-uploader:*"
```

The full diff is printed by the command. `tests/unit/test_iam_review.py` checks the proposal against our own detector and against the ASSAY-IAM-001 and ASSAY-IAM-002 rules too.

## Cloudsplaining cross-check

Cloudsplaining 0.8.2 ran in an isolated `uv tool run` environment with `scan-policy-file` on both example policies. Raw output is in `artifacts/cloudsplaining/` (not committed).

- Current policy: privilege escalation through `lambda:UpdateFunctionCode`, data exfiltration (`s3:GetObject`), resource exposure, a service-wide `s3` wildcard, credential exposure through `sts:AssumeRole` and unrestricted infrastructure modification.
- Proposed policy: "There were no results found."

Both tools agree that the proposal is clean. They differ on the original: Cloudsplaining did not report `iam:PassRole` with `lambda:CreateFunction` as escalation, which our list does. It does flag data exfiltration and resource exposure classes that our review does not model.

## Limits

- Condition blocks are ignored, so a statement limited by a condition is judged as if the condition were absent.
- Deny statements are honored when building the proposal but do not reduce the issue list.
- Resource coverage is pattern matching on ARN text. It does not know which actions support resource-level permissions.
- The escalation list covers common paths and is not exhaustive.
