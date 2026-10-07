#!/bin/sh
set -eu

usage() {
    cat <<'EOF'
Usage:
  install.sh install-binary <source-binary> <destination-binary>
  install.sh uninstall-binary <destination-binary>
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

    *)
        usage
        exit 2
        ;;
esac
