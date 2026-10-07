#!/bin/sh
set -eu

usage() {
    cat <<'EOF'
Usage:
  install.sh install-binary <source-binary> <destination-binary>
  install.sh uninstall-binary <destination-binary>
  install.sh dev-swap <source-binary> <destination-binary>
EOF
}

command="${1:-}"
if [ "$#" -gt 0 ]; then
    shift
fi

case "$command" in
    install-binary)
        if [ "$#" -ne 2 ]; then
            usage
            exit 2
        fi
        source_binary="$1"
        destination_binary="$2"
        if [ ! -x "$source_binary" ]; then
            echo "release binary not found or not executable: $source_binary" >&2
            exit 1
        fi
        install -d "$(dirname "$destination_binary")"
        install -m 0755 "$source_binary" "$destination_binary"
        echo "installed $destination_binary"
        ;;

    uninstall-binary)
        if [ "$#" -ne 1 ]; then
            usage
            exit 2
        fi
        rm -f "$1"
        echo "removed $1"
        ;;

    dev-swap)
        if [ "$#" -ne 2 ]; then
            usage
            exit 2
        fi
        source_binary="$1"
        destination_binary="$2"
        if [ ! -x "$source_binary" ]; then
            echo "release binary not found or not executable: $source_binary" >&2
            exit 1
        fi
        if [ "$(id -u)" -eq 0 ]; then
            echo 'Run make dev-swap as your desktop user; it asks for sudo itself.' >&2
            exit 1
        fi
        # The daemon and its windows, not browser-started native hosts.
        running() {
            for pid in $(pgrep -u "$(id -u)" -x boltwarden || true); do
                case "$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)" in
                    *native-host*) ;;
                    *) echo "$pid" ;;
                esac
            done
        }
        if [ -n "$(running)" ]; then
            "$source_binary" quit
            tries=0
            while [ -n "$(running)" ]; do
                tries=$((tries + 1))
                if [ "$tries" -gt 50 ]; then
                    echo "Boltwarden did not quit within 10 seconds: $(running | tr '\n' ' ')" >&2
                    exit 1
                fi
                sleep 0.2
            done
            echo 'stopped the running daemon'
        fi
        sudo install -m 0755 "$source_binary" "$destination_binary"
        echo "replaced $destination_binary"
        setsid -f "$destination_binary" --daemon > /dev/null 2>&1 < /dev/null
        echo "started $destination_binary --daemon"
        if [ -n "$(pgrep -u "$(id -u)" -f 'boltwarden native-host' || true)" ]; then
            echo 'Browser native hosts still run the old binary until the browser reconnects.'
        fi
        ;;

    *)
        usage
        exit 2
        ;;
esac
