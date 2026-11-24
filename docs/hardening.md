# Ubuntu 24.04 container hardening with OpenSCAP

Item 11. We scanned an Ubuntu 24.04 container with the CIS-aligned Level 1 Server profile from the SCAP Security Guide, applied a small hardening script and scanned again. Every count below comes from a real run on 2026-11-23. This is not a CIS compliance statement or a certification. The profile is informed by the CIS benchmark and the results only say how this one container scored against SSG's automated checks.

## Tools and versions

| Part | Version | Pin | Licence |
|---|---|---|---|
| Base image (scanner and target) | ubuntu:24.04 (24.04.5 LTS) | `sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289` | Ubuntu image terms, packages under their own licences |
| OpenSCAP scanner | 1.3.9 | apt `openscap-scanner=1.3.9+dfsg-1.1ubuntu2` | LGPL-2.1-or-later (checked in /usr/share/doc/libopenscap25t64/copyright) |
| SCAP Security Guide content | 0.1.82 | release zip `sha256:765e84bdce7f9055f9b9c2dd0ee2b713d4255f8eec94eac6d35ea4973c28919c` checked by `ADD --checksum` | BSD-3-Clause (SPDX line in the shipped LICENSE) |
| Datastream | ssg-ubuntu2404-ds.xml | from the zip above | as above |
| Profile | `xccdf_org.ssgproject.content_profile_cis_level1_server` | listed by `oscap info` | |

Why upstream content: Ubuntu 24.04 ships `ssg-debderived` 0.1.71, which only has datastreams up to ubuntu2204. ComplianceAsCode 0.1.82 has `ssg-ubuntu2404-ds.xml` with four CIS-aligned profiles and a STIG profile.

Target packages added on top of the base image so SSH, sudo and cron rules have something to look at: openssh-server 1:9.6p1-3ubuntu13.20, sudo 1.9.15p5-3ubuntu5.24.04.4, cron 3.0pl1-184ubuntu2.

## Method

1. `docker/openscap/Dockerfile` builds the scanner. `docker/target/Dockerfile` builds the target.
2. `scripts/openscap/run.sh before` starts the target, exports its filesystem with `docker export` into a fresh volume and runs `oscap xccdf eval` from the scanner against that copy. The wrapper `docker/openscap/scan-root.sh` sets `OSCAP_PROBE_ROOT` and `OSCAP_EVALUATION_TARGET` the same way `oscap-chroot` does. The scanner never gets privileges or the target's process namespace.
3. `scripts/openscap/run.sh harden` copies `scripts/openscap/harden.sh` into the running target and runs it as root.
4. `scripts/openscap/run.sh after` exports the hardened filesystem and scans again with the same profile.
5. `scripts/openscap/summarize.py` trims both results files for commit and writes `fixtures/recorded/openscap/summary.json`.

Full results, HTML reports and logs stay in artifacts/openscap/ (git ignored). The trimmed results in fixtures/recorded/openscap/ keep the TestResult element unchanged plus the Rule definitions of failed rules. The results carry no host identity: the target is `unknown` and the identifier is `chroot:///target`.

## Results

| Result | Before | After | Delta |
|---|---|---|---|
| pass | 129 | 135 | +6 |
| fail | 9 | 3 | -6 |
| notapplicable | 270 | 270 | 0 |
| notselected | 240 | 240 | 0 |
| other (error, unknown, notchecked, informational, fixed) | 0 | 0 | 0 |
| total rule results | 648 | 648 | |
| SSG default score | 93.64 | 98.04 | +4.39 |

notselected rules are in the datastream but outside this profile. Of the 408 selected rules, 270 were not applicable to a container, so the pass and fail counts cover 138 rules.

## Hardening subset and delta

Each fix in harden.sh targets one rule from the before scan. All six moved from fail to pass and no rule regressed.

| Rule | Severity | Change in harden.sh | After |
|---|---|---|---|
| package_pam_pwquality_installed | medium | install libpam-pwquality 1.4.5-3build1 | pass |
| use_pam_wheel_group_for_su | medium | `pam_wheel.so use_uid group=sugroup` in /etc/pam.d/su, empty group sugroup | pass |
| accounts_umask_etc_bashrc | medium | `umask 027` in /etc/bash.bashrc | pass |
| accounts_umask_etc_profile | medium | `umask 027` in /etc/profile | pass |
| file_permission_user_init_files | medium | dot files of interactive users set to 0740 or less | pass |
| permissions_local_var_log | medium | files under /var/log set to 0640 or less | pass |

harden.sh also sets PASS_MAX_DAYS, PASS_WARN_AGE and UMASK in /etc/login.defs and `minlen = 14` in pwquality.conf. Those rules are notapplicable in a container (see below), so they do not change the counts. They are there because they cost nothing if the image is ever used as a VM base.

Nothing was removed. None of the profile's package removal rules failed: the base image has none of the listed services installed.

## Remaining failures: scanning method, not the target

The three rules still failing are caused by scanning an exported filesystem from a different container. We checked each one.

| Rule | Why it fails | Check we ran |
|---|---|---|
| file_permissions_ungroupowned | The file probe resolves group IDs through the scanner's /etc/group, not the target's. Target groups such as `_ssh`, `crontab`, `systemd-journal` and `ubuntu` do not exist in the scanner, so their files look ungrouped | Copying the target's groups into the scanner's /etc/group turned the rule to pass (artifacts/openscap/diag-ungroupowned.txt). `find / -xdev -nogroup` inside the target returns nothing |
| root_path_all_dirs | Reads root's PATH from a running process environment. A chroot target has no process, so the probe collects nothing and the existence test fails | Same rule run natively in the scanner with the same PATH passes (artifacts/openscap/diag-rootpath.txt) |
| root_path_no_dot | Same environment probe limit as above | Same native check passes |

Running oscap inside the target would avoid these artifacts but would install the scanner into the thing being scanned and change its package list. We kept the outside-in method and documented the three.

## Not applicable in containers and why

SSG decides applicability through CPE platforms attached to each rule or its group. We counted the platform behind every one of the 270 notapplicable results:

| Platform gate | Rules | What it tests |
|---|---|---|
| `system_with_kernel` only | 203 | package linux-base is installed |
| `system_with_kernel` plus a package | 12 | linux-base and, for example, pam, avahi or nftables |
| `not_container` or `machine` | 30 | the scan target is not a container |
| a package that is not installed | 25 | for example gdm, nftables, ufw, iptables or apport |

Containers share the host kernel and have no linux-base, so 215 rules drop out on that gate alone. Some of those are host-only by nature. Others would make sense in a container but SSG gates them the same way. The table below groups them by area and gives our reason each area does not fit a container image.

| Area | Example rules | Reason |
|---|---|---|
| Kernel modules | kernel_module_cramfs_disabled, kernel_module_usb-storage_disabled | Modules load in the host kernel. A container cannot load or block them |
| Kernel parameters | sysctl_net_ipv4_ip_forward, sysctl_kernel_randomize_va_space | sysctl values belong to the host or the container runtime. Files in /etc/sysctl.d are never applied inside the container |
| Bootloader | grub2_password, file_permissions_grub2_cfg | No bootloader in an image |
| Partitions and mount options | partition_for_tmp, mount_option_tmp_noexec, mount_option_var_log_nosuid | The runtime sets mounts. They belong in the compose or Kubernetes spec, not the image |
| Audit and logging daemons | aide_build_database, package_rsyslog_installed, journald_storage | No init system or kernel audit subsystem in the container. Logs go to stdout and the runtime collects them |
| Host firewall | nftables_ensure_default_deny_policy, check_ufw_active | No firewall package installed. Network policy belongs to the host or orchestrator |
| AppArmor | all_apparmor_profiles_in_enforce_complain_mode | The host applies the AppArmor profile to the container |
| Services and time sync | service_cron_enabled, package_chrony_installed | No systemd. The host keeps time |
| SSH, sudo, cron files and PAM password policy | sshd_disable_root_login, sudo_add_use_pty, file_permissions_crontab, accounts_password_pam_minlen | Gated on system_with_kernel by the content even though the packages are installed. These would apply to a VM built from the same image |
| Account checks | account_unique_id | Same system_with_kernel gate |
| Desktop | dconf_gnome_screensaver_lock_enabled | Gated on gdm, which is not installed |
| Password hashing and ageing in login.defs | set_password_hashing_algorithm_logindefs, accounts_maximum_age_login_defs | Gated on system_with_kernel and on package shadow-utils, a Red Hat package name. Ubuntu ships the same tools in passwd |

Installing linux-base into the target would flip these rules to applicable, but the results would then describe a VM that does not exist. We did not do that.

## Ingestion

`cspm.ingest.xccdf.parse_xccdf(path)` turns each failed rule into a `Finding` with `source=openscap`, the SSG rule name as `rule_id`, the XCCDF severity as base severity and the rule's title, rationale and description. `count_results(path)` returns the result counts used in the table above. tests/unit/test_xccdf.py checks both against the recorded runs.

## Reproduce

```sh
sh scripts/openscap/run.sh all
python scripts/openscap/summarize.py
```

The first build downloads the 183 MB SSG release zip once and checks its digest.
