#!/bin/sh
# The server's one-time setup: `just setup`. Run it as yourself on the VM; it asks sudo for what
# needs root, and running it again is harmless.
#
# - deploy/.env from .env.example, with a generated database password and CACTARIUM_BASE_URL
#   from this machine's name (edit both, and fill in the OAuth apps, before `just up`).
# - `sh setup.sh apache` (also run by `just setup` when apache2 is active): points the virtual
#   host that serves https://DOMAIN/ at the app on 127.0.0.1:PORT. It writes the proxy settings to
#   a file of their own, adds one Include line to that virtual host, keeps a copy of the file it
#   edits, and puts back what it changed if Apache rejects the result.
# - `sh setup.sh firewall` (`just firewall`, never run by `just setup`): ufw denying everything
#   inbound but HTTP and HTTPS from anywhere and SSH from the bastion (SSH_FROM in deploy/.env), on
#   sshd's ports or those SSH_PORTS lists.
#   It refuses to run unless your own SSH session comes from that bastion, so it can't lock you
#   out. Docker's published ports bypass ufw, which is why compose.yaml publishes the app on
#   loopback only.
#
# Adapted from the CactUp tutorial server's deploy/setup.sh (Cactup, feature/notebook-tutorial).
set -eu

deploy=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cd "$deploy"
PATH=$PATH:/usr/sbin:/sbin
sudo=sudo
[ "$(id -u)" -ne 0 ] || sudo=
user=$(id -un)

get() { sed -n "s/^$1=//p" .env | tail -1; }
put() {
    if grep -q "^$1=" .env; then
        sed -i "s|^$1=.*|$1=$2|" .env
    else
        printf '%s=%s\n' "$1" "$2" >> .env
    fi
}

domain() { get CACTARIUM_BASE_URL | sed -e 's|^https\?://||' -e 's|/.*||'; }

apache() {
    domain=$(domain)
    port=$(get PORT); port=${port:-8000}
    snippet=/etc/apache2/cactarium-proxy.conf
    include="    Include $snippet"
    if [ ! -d /etc/apache2/sites-enabled ] || ! command -v a2enmod > /dev/null; then
        echo "apache: no Debian-style Apache here (/etc/apache2, a2enmod); set up the proxy by hand:" >&2
        apache_settings >&2
        return 1
    fi
    vhost=
    for f in /etc/apache2/sites-enabled/*; do
        if awk -v d="$domain" '
            /^[ \t]*<VirtualHost[^>]*:443>/ { in443 = 1 }
            /^[ \t]*<\/VirtualHost>/ { in443 = 0 }
            in443 && tolower($1) ~ /^server(name|alias)$/ { for (i = 2; i <= NF; i++) if ($i == d) found = 1 }
            END { exit !found }' "$f"; then
            vhost=$(readlink -f "$f")
            break
        fi
    done
    if [ -z "$vhost" ]; then
        echo "apache: no enabled site has a :443 virtual host named $domain (CACTARIUM_BASE_URL in deploy/.env)." >&2
        echo "Add to the one that serves https://$domain/:" >&2
        echo "$include" >&2
        apache_settings >&2
        return 1
    fi
    echo "apache: $vhost serves https://$domain/: proxying it to the app on 127.0.0.1:$port"
    previous=$(mktemp)
    had_snippet=no
    if [ -f "$snippet" ]; then
        cp "$snippet" "$previous"
        had_snippet=yes
    fi
    edited=no
    tmp=$(mktemp)
    apache_settings > "$tmp"
    $sudo install -m 0644 "$tmp" "$snippet"
    rm -f "$tmp"
    if ! grep -qF "Include $snippet" "$vhost"; then
        edited=yes
        $sudo cp -p "$vhost" "$vhost.before-cactarium"
        out=$(mktemp)
        awk -v d="$domain" -v inc="$include" '
            /^[ \t]*<VirtualHost[^>]*:443>/ { in443 = 1; named = 0 }
            in443 && tolower($1) ~ /^server(name|alias)$/ { for (i = 2; i <= NF; i++) if ($i == d) named = 1 }
            /^[ \t]*<\/VirtualHost>/ { if (in443 && named && !done) { print inc; done = 1 } in443 = 0 }
            { print }' "$vhost" > "$out"
        $sudo cp "$out" "$vhost"
        rm -f "$out"
        echo "apache: added the Include to $vhost (the original: $vhost.before-cactarium)"
    fi
    $sudo a2enmod -q proxy proxy_http headers
    if ! $sudo apache2ctl configtest; then
        echo "apache: Apache rejects the result; putting back what this changed" >&2
        [ "$edited" = no ] || $sudo cp -p "$vhost.before-cactarium" "$vhost"
        if [ "$had_snippet" = yes ]; then
            $sudo install -m 0644 "$previous" "$snippet"
        else
            $sudo rm -f "$snippet"
        fi
        rm -f "$previous"
        return 1
    fi
    rm -f "$previous"
    $sudo systemctl reload apache2
    echo "apache: reloaded; https://$domain/ answers once 'just up' has started the app (503 until then)"
}

apache_settings() {
    cat <<EOF
# The Cactarium, behind this virtual host: written by deploy/setup.sh (\`just setup\`) and
# included by the virtual host that serves https://$domain/. To undo: remove that Include line.
ProxyPreserveHost On
RequestHeader set X-Forwarded-Proto https
# Cutting a stack release looks up every repo it names (seconds; minutes for a slow forge).
ProxyTimeout 300
# Uploads (.sim files) are at most 1 MB; the app refuses anything over 2 MB anyway.
LimitRequestBody 4194304
# The certificate's renewal (certbot's webroot) keeps working over HTTPS.
ProxyPass /.well-known/acme-challenge/ !
ProxyPass        / http://127.0.0.1:$port/
ProxyPassReverse / http://127.0.0.1:$port/
EOF
}

# The numbers of `ufw status numbered` rules this script made ("# ssh from …") for ports not in $1,
# highest first.
stale_ssh_rules() {
    printf '%s\n' "$2" | awk -v keep=" $(echo $1) " '
        /# ssh from / {
            line = $0; sub(/^\[ */, "", line); split(line, f, /[] ]+/); split(f[2], p, "/")
            if (index(keep, " " p[1] " ") == 0) print f[1]
        }' | sort -rn
}

firewall() {
    from=$(get SSH_FROM)
    if [ -z "$from" ]; then
        echo "firewall: set SSH_FROM in deploy/.env to the host you SSH in through (the bastion)" >&2
        return 1
    fi
    # The bastion's address(es), and the port sshd listens on.
    addrs=$(getent ahostsv4 "$from" | awk '{print $1}' | sort -u)
    if [ -z "$addrs" ]; then
        echo "firewall: cannot resolve SSH_FROM=$from" >&2
        return 1
    fi
    # Never lock yourself out: this session must come from the bastion. (Checked before
    # anything needs root.)
    me=$(echo "${SSH_CONNECTION:-}" | awk '{print $1}')
    if [ -z "$me" ] || ! echo "$addrs" | grep -qx "$me"; then
        echo "firewall: this session comes from '${me:-not SSH}', not from $from ($(echo $addrs)); refusing," >&2
        echo "since SSH would then only be allowed from $from. Run it over SSH through $from." >&2
        return 1
    fi
    # The SSH ports to allow: SSH_PORTS in deploy/.env (say "22 2525" while sshd moves to a new
    # port), else every port sshd listens on now. The port this session came in on is always
    # added, so enabling the firewall can't cut it off.
    ports=$(get SSH_PORTS | tr ',' ' ')
    [ -n "$ports" ] || ports=$($sudo sshd -T 2>/dev/null | awk '$1 == "port" {print $2}')
    ports="$ports $(echo "${SSH_CONNECTION:-}" | awk '{print $4}')"
    ports=$(printf '%s\n' $ports | sort -un)
    [ -n "$ports" ] || ports=22
    for port in $ports; do
        case $port in
            *[!0-9]*) echo "firewall: SSH_PORTS has '$port', not a port number" >&2; return 1 ;;
        esac
    done
    command -v ufw > /dev/null || $sudo apt-get install -y ufw
    $sudo ufw default deny incoming
    $sudo ufw default allow outgoing
    $sudo ufw default deny routed
    for a in $addrs; do
        for port in $ports; do
            $sudo ufw allow from "$a" to any port "$port" proto tcp comment "ssh from $from"
        done
    done
    # Then drop this script's SSH rules for ports no longer listed (after the new ones are in, so
    # SSH is never shut out in between). Highest rule number first: numbers shift on delete.
    stale=$(stale_ssh_rules "$ports" "$($sudo ufw status numbered 2>/dev/null)")
    for n in $stale; do
        $sudo ufw --force delete "$n"
    done
    $sudo ufw allow 80/tcp comment "http (redirects to https)"
    $sudo ufw allow 443/tcp comment https
    $sudo ufw --force enable
    $sudo systemctl enable -q ufw
    $sudo ufw status verbose
    echo "firewall: on, and on again after a reboot (ENABLED=yes in /etc/ufw/ufw.conf)"
}

case "${1:-}" in
    apache) apache; exit ;;
    firewall) firewall; exit ;;
esac

# deploy/.env
if [ ! -f .env ]; then
    cp .env.example .env
    chmod 600 .env
    put POSTGRES_PASSWORD "$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 40)"
    put CACTARIUM_BASE_URL "https://$(hostname -f)"
    echo "setup: wrote deploy/.env; fill in the OAuth apps (GITHUB_*, ORCID_*) and check CACTARIUM_BASE_URL"
fi
if [ -z "$(get POSTGRES_PASSWORD)" ]; then
    put POSTGRES_PASSWORD "$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 40)"
fi

front=ok
if systemctl is-active -q apache2 2>/dev/null; then
    sh "$deploy/setup.sh" apache || front=failed
fi

if [ "$front" = failed ]; then
    echo "setup: all done but Apache's part, which failed (above): fix that, then 'sh deploy/setup.sh apache'" >&2
    exit 1
fi
echo "setup: done. Next: fill in deploy/.env (SSH_FROM too), 'just firewall', then 'just up'."
