#!/bin/bash
# Installs the PleskMCP server-side pieces on a Plesk (Linux) server. Run as root.
#
#   ./install.sh "<ssh public key of the MCP service>"
#
# Creates the unprivileged SSH user "pleskmcp" with a forced command, installs
# the helper script and the sudoers rule. Nothing here needs or grants root
# access to the MCP service: the helper always runs as a subscription's
# system user (group psacln).
set -euo pipefail

PUBKEY="${1:-}"
if [[ -z "$PUBKEY" ]]; then
    echo "usage: $0 '<ssh public key>'" >&2
    exit 1
fi
HERE="$(cd "$(dirname "$0")" && pwd)"
HELPER_SRC="$HERE/../helper/pleskmcp_helper.py"
[[ -f "$HELPER_SRC" ]] || HELPER_SRC="$HERE/pleskmcp_helper.py"
[[ -f "$HELPER_SRC" ]] || { echo "helper script not found next to this installer" >&2; exit 1; }

PYTHON=/usr/libexec/platform-python
if [[ ! -x "$PYTHON" ]]; then
    PYTHON="$(command -v python3)"
fi
"$PYTHON" -c 'import sys; assert sys.version_info >= (3, 6)'

if ! getent group psacln >/dev/null; then
    echo "group psacln not found: is this a Plesk server?" >&2
    exit 1
fi

# 1. helper script (root owned, world readable, not writable by anyone else)
install -o root -g root -m 0755 "$HELPER_SRC" /usr/local/bin/pleskmcp-helper
sed -i "1s|^#!.*|#!$PYTHON|" /usr/local/bin/pleskmcp-helper
"$PYTHON" -m py_compile /usr/local/bin/pleskmcp-helper

# 2. SSH forced-command wrapper
install -o root -g root -m 0755 "$HERE/pleskmcp-sshwrap" /usr/local/bin/pleskmcp-sshwrap

# 3. sudoers rule
install -o root -g root -m 0440 "$HERE/sudoers-pleskmcp" /etc/sudoers.d/pleskmcp
visudo -cf /etc/sudoers.d/pleskmcp

# 4. SSH user
if ! id pleskmcp >/dev/null 2>&1; then
    useradd --system --create-home --home-dir /var/lib/pleskmcp --shell /bin/bash pleskmcp
fi
install -d -o pleskmcp -g pleskmcp -m 0700 /var/lib/pleskmcp/.ssh
printf 'restrict,command="/usr/local/bin/pleskmcp-sshwrap" %s\n' "$PUBKEY" > /var/lib/pleskmcp/.ssh/authorized_keys
chown pleskmcp:pleskmcp /var/lib/pleskmcp/.ssh/authorized_keys
chmod 0600 /var/lib/pleskmcp/.ssh/authorized_keys

cat <<EOF

Installed:
  /usr/local/bin/pleskmcp-helper      (runs as subscription system users via sudo)
  /usr/local/bin/pleskmcp-sshwrap     (forced command for the SSH key)
  /etc/sudoers.d/pleskmcp
  user pleskmcp, key in /var/lib/pleskmcp/.ssh/authorized_keys

Next steps:
  - Add the IP of the MCP host to Plesk's Fail2ban trusted list:
        plesk bin ip_ban --add-trusted "<mcp host ip>" -description "PleskMCP"
  - Print the host key for PLESK_SSH_HOST_KEY:
        ssh-keyscan -t ed25519 localhost 2>/dev/null | awk '{print \$2, \$3}'
  - Test from the MCP host:
        ssh -i <key> pleskmcp@<server> 'sudo -n -u <sysuser> /usr/local/bin/pleskmcp-helper' <<< '{"op":"ping","domain":"example.com","docroot":"/var/www/vhosts/example.com/httpdocs"}'
EOF
