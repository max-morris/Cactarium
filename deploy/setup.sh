#!/bin/sh
# The server's one-time setup: `just setup`. Run it as yourself on the VM; it asks sudo for what
# needs root, and running it again is harmless.
#
# - deploy/.env from .env.example, with a generated database password and CACTARIUM_BASE_URL
#   from this machine's name (edit both, and fill in the OAuth apps, before `just up`).
# - Docker access for you (the docker group).
# - `sh setup.sh apache` (also run by `just setup` when apache2 is active): points the virtual
#   host that serves https://DOMAIN/ at the app on 127.0.0.1:PORT. It writes the proxy settings to
#   a file of their own, adds one Include line to that virtual host, keeps a copy of the file it
#   edits, and puts back what it changed if Apache rejects the result.
# - `sh setup.sh backups`: a systemd timer that dumps the database nightly to deploy/backups,
#   keeping the last 30 dumps.
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
# Uploads (.sim files) are at most 1 MB; the app refuses anything over 2 MB anyway.
LimitRequestBody 4194304
# The certificate's renewal (certbot's webroot) keeps working over HTTPS.
ProxyPass /.well-known/acme-challenge/ !
ProxyPass        / http://127.0.0.1:$port/
ProxyPassReverse / http://127.0.0.1:$port/
EOF
}

backups() {
    unit=/etc/systemd/system/cactarium-backup
    tmp=$(mktemp)
    cat > "$tmp" <<EOF
[Unit]
Description=Dump the Cactarium database to $deploy/backups
After=docker.service

[Service]
Type=oneshot
User=$user
WorkingDirectory=$deploy/..
ExecStart=/bin/sh -c 'mkdir -p deploy/backups && docker compose --project-directory deploy -f deploy/compose.yaml exec -T db pg_dump -U cactarium -d cactarium --format=custom > deploy/backups/cactarium-\$\$(date +%%Y%%m%%d-%%H%%M%%S).dump && ls -1t deploy/backups/*.dump | tail -n +31 | xargs -r rm --'
EOF
    $sudo install -m 0644 "$tmp" "$unit.service"
    cat > "$tmp" <<EOF
[Unit]
Description=Nightly Cactarium database dump

[Timer]
OnCalendar=*-*-* 03:30:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
    $sudo install -m 0644 "$tmp" "$unit.timer"
    rm -f "$tmp"
    $sudo systemctl daemon-reload
    $sudo systemctl enable --now cactarium-backup.timer
    echo "backups: nightly at 03:30 to $deploy/backups (copy them off the VM too)"
}

case "${1:-}" in
    apache) apache; exit ;;
    backups) backups; exit ;;
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

# Docker access.
if ! id -nG "$user" | tr ' ' '\n' | grep -qx docker; then
    $sudo usermod -aG docker "$user"
    echo "setup: added $user to the docker group; log out and back in before 'just up'"
fi

front=ok
if systemctl is-active -q apache2 2>/dev/null; then
    sh "$deploy/setup.sh" apache || front=failed
fi
sh "$deploy/setup.sh" backups

if [ "$front" = failed ]; then
    echo "setup: all done but Apache's part, which failed (above): fix that, then 'sh deploy/setup.sh apache'" >&2
    exit 1
fi
echo "setup: done. Next: fill in deploy/.env, then 'just up'."
