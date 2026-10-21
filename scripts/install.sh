#!/bin/sh
set -eu

usage() {
    cat <<'EOF'
Usage:
  install.sh install <source-binary> <destination-binary> <macos-archive> <macos-app-directory>
  install.sh uninstall <destination-binary> <macos-app-directory>
  install.sh install-binary <source-binary> <destination-binary>
  install.sh uninstall-binary <destination-binary>
  install.sh install-app <macos-archive> <macos-app-directory>
  install.sh uninstall-app <macos-app-directory>
  install.sh dev-swap <source-binary> <destination-binary>

  install and uninstall detect the operating system: Linux installs the executable,
  macOS installs Boltwarden.app from the release ZIP. The install-binary,
  uninstall-binary, install-app, and uninstall-app commands skip the detection.
EOF
}

fail() {
    echo "$1" >&2
    exit 1
}

install_binary() {
    source_binary="$1"
    destination_binary="$2"
    if [ ! -x "$source_binary" ]; then
        fail "release binary not found or not executable: $source_binary"
    fi
    install -d "$(dirname "$destination_binary")"
    install -m 0755 "$source_binary" "$destination_binary"
    echo "installed $destination_binary"
}

uninstall_binary() {
    rm -f "$1"
    echo "removed $1"
}

# Process ids of the daemon inside an installed app, excluding short-lived browser
# native hosts, which browsers start from the same executable.
app_daemon_pids() {
    app="$1"
    pgrep -f "$app/Contents/MacOS/boltwarden" 2>/dev/null | while read -r pid; do
        case "$(ps -ww -p "$pid" -o args= 2>/dev/null || true)" in
            *native-host*) ;;
            *) printf '%s\n' "$pid" ;;
        esac
    done
}

stop_app() {
    app="$1"
    binary="$app/Contents/MacOS/boltwarden"
    if [ ! -x "$binary" ] || [ -z "$(app_daemon_pids "$app")" ]; then
        return 0
    fi
    # Quitting when nothing runs is a no-op, but only signal a running daemon.
    "$binary" quit >/dev/null 2>&1 || true
    tries=0
    while [ -n "$(app_daemon_pids "$app")" ]; do
        tries=$((tries + 1))
        if [ "$tries" -gt 50 ]; then
            fail "Boltwarden did not quit within 10 seconds: $app"
        fi
        sleep 0.2
    done
    echo 'stopped the running Boltwarden'
}

verify_archive() {
    archive="$1"
    checksum="$archive.sha256"
    if [ ! -f "$checksum" ]; then
        echo "warning: no checksum next to $archive; skipping verification" >&2
        return 0
    fi
    if ! (cd "$(dirname "$archive")" && shasum -a 256 -c "$(basename "$archive").sha256" >/dev/null); then
        fail "checksum does not match $archive"
    fi
}

install_app() {
    archive="$1"
    app_directory="$2"
    app="$app_directory/Boltwarden.app"

    if [ ! -f "$archive" ]; then
        fail "macOS app archive not found: $archive
Build it with 'make package-macos', or download a release ZIP and pass MACOS_ARCHIVE=/path/to/boltwarden-VERSION-universal-macos.zip"
    fi
    for tool in codesign ditto mktemp open pgrep ps shasum xattr; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            fail "required tool not found: $tool"
        fi
    done
    verify_archive "$archive"

    # Replacing the bundle does not affect an already running copy, so stop it and
    # start the new one again afterwards when it was running.
    running=0
    if [ -d "$app" ] && [ -n "$(app_daemon_pids "$app")" ]; then
        running=1
    fi
    stop_app "$app"

    temporary=$(mktemp -d "${TMPDIR:-/tmp}/boltwarden-install.XXXXXX")
    trap 'rm -rf "$temporary"' EXIT HUP INT TERM
    ditto -x -k "$archive" "$temporary"
    bundle="$temporary/Boltwarden.app"
    if [ ! -d "$bundle" ]; then
        fail "the archive does not contain Boltwarden.app: $archive"
    fi
    if ! codesign --verify --strict --deep "$bundle"; then
        fail "the app signature in $archive does not verify"
    fi

    if ! mkdir -p "$app_directory" 2>/dev/null || [ ! -w "$app_directory" ]; then
        fail "cannot write to $app_directory; pass APP_DEST=<directory>"
    fi
    rm -rf "$app" || fail "cannot replace $app"
    ditto "$bundle" "$app" || fail "cannot install $app"
    if xattr "$app" 2>/dev/null | grep -q '^com.apple.quarantine'; then
        xattr -dr com.apple.quarantine "$app"
        echo 'cleared the download quarantine'
    fi
    echo "installed $app"

    if [ "$running" -eq 1 ]; then
        # --daemon starts the menu bar item without opening quick access.
        open "$app" --args --daemon
        echo 'started Boltwarden'
    fi
}

uninstall_app() {
    app_directory="$1"
    app="$app_directory/Boltwarden.app"
    stop_app "$app"
    if [ ! -d "$app" ]; then
        echo "not installed: $app"
        return 0
    fi
    rm -rf "$app" || fail "cannot remove $app"
    echo "removed $app"
    launch_agent="$HOME/Library/LaunchAgents/nl.mvl.boltwarden.plist"
    if [ -f "$launch_agent" ] && grep -qF "$app" "$launch_agent"; then
        echo 'Turn off Start at login before uninstalling to remove the launch agent.' >&2
    fi
}

command="${1:-}"
if [ "$#" -gt 0 ]; then
    shift
fi

case "$command" in
    install)
        if [ "$#" -ne 4 ]; then
            usage
            exit 2
        fi
        if [ "$(uname -s)" = 'Darwin' ]; then
            install_app "$3" "$4"
        else
            install_binary "$1" "$2"
        fi
        ;;

    uninstall)
        if [ "$#" -ne 2 ]; then
            usage
            exit 2
        fi
        if [ "$(uname -s)" = 'Darwin' ]; then
            uninstall_app "$2"
        else
            uninstall_binary "$1"
        fi
        ;;

    install-binary)
        if [ "$#" -ne 2 ]; then
            usage
            exit 2
        fi
        install_binary "$1" "$2"
        ;;

    uninstall-binary)
        if [ "$#" -ne 1 ]; then
            usage
            exit 2
        fi
        uninstall_binary "$1"
        ;;

    install-app)
        if [ "$#" -ne 2 ]; then
            usage
            exit 2
        fi
        install_app "$1" "$2"
        ;;

    uninstall-app)
        if [ "$#" -ne 1 ]; then
            usage
            exit 2
        fi
        uninstall_app "$1"
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
