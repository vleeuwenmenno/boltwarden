#!/bin/sh
set -eu

usage() {
    cat <<'EOF'
Usage:
  install.sh install-binary <source-binary> <destination-binary>
  install.sh uninstall-binary <destination-binary>
  install.sh install-service <binary-path> <service-name> <systemd-user-dir>
  install.sh uninstall-service <service-name> <systemd-user-dir>
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

    install-service)
        if [ "$#" -ne 3 ]; then
            usage
            exit 2
        fi
        binary_path="$1"
        service_name="$2"
        systemd_user_dir="$3"
        service_path="$systemd_user_dir/$service_name"

        if [ ! -x "$binary_path" ]; then
            echo "installed binary not found or not executable: $binary_path" >&2
            echo "Run 'make release' and 'sudo make install' first, or pass BINDIR/PREFIX matching your install path." >&2
            exit 1
        fi

        mkdir -p "$systemd_user_dir"
        cat > "$service_path" <<EOF
[Unit]
Description=Boltwarden
After=graphical-session.target
PartOf=graphical-session.target

[Service]
Type=simple
ExecStart=$binary_path --daemon
Restart=on-failure
RestartSec=2
UMask=0077
LimitCORE=0

[Install]
WantedBy=default.target
EOF

        systemctl --user daemon-reload
        systemctl --user enable --now "$service_name"
        echo "installed and started user service $service_name"
        ;;

    uninstall-service)
        if [ "$#" -ne 2 ]; then
            usage
            exit 2
        fi
        service_name="$1"
        systemd_user_dir="$2"
        service_path="$systemd_user_dir/$service_name"

        systemctl --user disable --now "$service_name" >/dev/null 2>&1 || true
        rm -f "$service_path"
        systemctl --user daemon-reload
        echo "removed user service $service_name"
        ;;

    *)
        usage
        exit 2
        ;;
esac
