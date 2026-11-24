#!/bin/sh
# Hardening subset for the Ubuntu 24.04 scan target. Runs inside the target as root.
# Each block names the SSG rule it addresses. Safe to run twice.
# Picked from the rules that failed the before scan and make sense in a
# container. See docs/hardening.md for the full reasoning.
set -eu
export DEBIAN_FRONTEND=noninteractive
log() { printf 'harden: %s\n' "$*"; }

# package_pam_pwquality_installed
apt-get update -qq
apt-get install -y -qq --no-install-recommends libpam-pwquality >/dev/null
rm -rf /var/lib/apt/lists/*
log "installed libpam-pwquality $(dpkg-query -W -f='${Version}' libpam-pwquality)"

# use_pam_wheel_group_for_su: only members of an empty group may su.
getent group sugroup >/dev/null || groupadd sugroup
if ! grep -Eq '^auth[[:space:]]+required[[:space:]]+pam_wheel\.so[[:space:]]+use_uid[[:space:]]+group=sugroup' /etc/pam.d/su; then
    sed -i '/^# auth       required   pam_wheel.so$/a auth       required   pam_wheel.so use_uid group=sugroup' /etc/pam.d/su
fi
# The commented anchor line may differ between releases.
grep -q 'pam_wheel.so use_uid group=sugroup' /etc/pam.d/su || printf 'auth       required   pam_wheel.so use_uid group=sugroup
' >> /etc/pam.d/su
log "pam_wheel limits su to the empty group sugroup"

# accounts_umask_etc_bashrc and accounts_umask_etc_profile
for f in /etc/bash.bashrc /etc/profile; do
    grep -Eq '^[[:space:]]*umask[[:space:]]+027' "$f" || printf '\numask 027\n' >> "$f"
done
log "umask 027 set in /etc/bash.bashrc and /etc/profile"

# file_permission_user_init_files: dot files of interactive users at 0740 or less.
awk -F: '$3 >= 1000 && $3 != 65534 && $7 !~ /(nologin|false)$/ {print $6}' /etc/passwd | while read -r home; do
    [ -d "$home" ] || continue
    find "$home" -maxdepth 1 -type f -name '.*' -exec chmod u-s,g-wxs,o= {} +
done
log "interactive user dot files set to 0740 or less"

# permissions_local_var_log: log files readable by owner and group only.
find /var/log -type f -exec chmod g-wx,o-rwx {} +
log "files under /var/log set to 0640 or less"

# Defence in depth. These rules are notapplicable in a container because the
# profile gates them on the linux-base package, so they do not move the counts.
sed -i -E 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t365/; s/^PASS_WARN_AGE.*/PASS_WARN_AGE\t7/; s/^UMASK.*/UMASK\t\t027/' /etc/login.defs
grep -Eq '^minlen' /etc/security/pwquality.conf || printf 'minlen = 14\n' >> /etc/security/pwquality.conf
log "login.defs and pwquality.conf defaults tightened"
