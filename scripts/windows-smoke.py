#!/usr/bin/env python3
"""Exercise the exact Windows artifacts on a disposable CI account."""
import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time
import winreg
import zipfile

HOST = 'nl.mvl.boltwarden'
VENDORS = ('Google\\Chrome', 'Microsoft\\Edge', 'Mozilla')


def visible_window(pid):
    user32 = ctypes.WinDLL('user32', use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user32.EnumWindows.argtypes = (callback_type, wintypes.LPARAM)
    user32.EnumChildWindows.argtypes = (wintypes.HWND, callback_type, wintypes.LPARAM)
    user32.GetWindowThreadProcessId.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.DWORD))
    user32.IsWindowVisible.argtypes = (wintypes.HWND,)
    user32.GetWindowTextW.argtypes = (wintypes.HWND, wintypes.LPWSTR, ctypes.c_int)
    titles = []
    errors = []

    @callback_type
    def error_text(window, _):
        text = ctypes.create_unicode_buffer(8192)
        user32.GetWindowTextW(window, text, len(text))
        if text.value:
            errors.append(text.value)
        return True

    @callback_type
    def visit(window, _):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(window, ctypes.byref(owner))
        if owner.value == pid and user32.IsWindowVisible(window):
            title = ctypes.create_unicode_buffer(256)
            user32.GetWindowTextW(window, title, len(title))
            titles.append(title.value)
            if title.value == 'Boltwarden startup error':
                user32.EnumChildWindows(window, error_text, 0)
        return True

    user32.EnumWindows(visit, 0)
    if 'Boltwarden startup error' in titles:
        raise AssertionError('Window renderer failed: ' + '\n'.join(errors))
    return any(title.lower() == 'boltwarden' for title in titles)


def gui_startup(app, software=False):
    # A live daemon/tray alone does not prove that either GUI renderer works.
    for flag in ('--vault-window', '--popup'):
        child = subprocess.Popen([str(app), flag], stdin=subprocess.PIPE,
                                 env=os.environ | {'BOLTWARDEN_DEMO': 'locked',
                                                   'BOLTWARDEN_SOFTWARE_RENDERING': '1' if software else '0'})
        try:
            child.stdin.write(b'show\n')
            child.stdin.flush()
            deadline = time.monotonic() + 30
            while not visible_window(child.pid):
                assert child.poll() is None, f'{flag} exited before opening a window'
                assert time.monotonic() < deadline, f'{flag} did not open a visible window'
                time.sleep(0.1)
            child.stdin.write(b'quit\n')
            child.stdin.flush()
            assert child.wait(timeout=15) == 0
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
            child.stdin.close()


def run(*args):
    return subprocess.run([str(a) for a in args], check=True, timeout=90, capture_output=True)


def native_host(path):
    result = subprocess.run([str(path)], input=b'', capture_output=True, timeout=15, check=True)
    frames = []
    data = result.stdout
    while data:
        if len(data) < 4:
            raise AssertionError('Truncated native frame')
        length = struct.unpack('<I', data[:4])[0]
        frames.append(json.loads(data[4:4 + length]))
        data = data[4 + length:]
    assert frames[0]['type'] == 'HostContext'
    assert frames[0]['host_pid'] > 0
    assert frames[1]['code'] == 'DaemonUnavailable'
    assert len(frames) == 2


def registered(vendor):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f'Software\\{vendor}\\NativeMessagingHosts\\{HOST}') as key:
            return winreg.QueryValueEx(key, None)[0]
    except FileNotFoundError:
        return None


def startup_entry():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run') as key:
            return winreg.QueryValueEx(key, 'Boltwarden')[0]
    except FileNotFoundError:
        return None


def shortcut_registered():
    """Probe the smoke shortcut without sending keystrokes to other applications."""
    user32 = ctypes.WinDLL('user32', use_last_error=True)
    user32.RegisterHotKey.argtypes = (wintypes.HWND, ctypes.c_int, wintypes.UINT, wintypes.UINT)
    user32.UnregisterHotKey.argtypes = (wintypes.HWND, ctypes.c_int)
    # Ctrl+Alt+Shift+F23, with MOD_NOREPEAT, matches the saved test configuration.
    if user32.RegisterHotKey(None, 0xB021, 0x4007, 0x86):
        assert user32.UnregisterHotKey(None, 0xB021)
        return False
    error = ctypes.get_last_error()
    assert error == 1409, f'Unexpected RegisterHotKey failure: {error}'
    return True


def save_shortcut_fixture(data):
    path = data / 'quick-access-shortcut.json'
    path.write_text(json.dumps({
        'ctrl': True, 'alt': True, 'shift': True, 'key': 'F23',
    }), encoding='utf-8')
    # Match the application's private parent DACL explicitly. Wine can add an
    # Everyone ACE to files created through Python despite parent inheritance.
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    pointer = ctypes.c_void_p
    advapi.GetNamedSecurityInfoW.argtypes = (
        wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, pointer, pointer,
        ctypes.POINTER(pointer), pointer, ctypes.POINTER(pointer))
    advapi.SetNamedSecurityInfoW.argtypes = (
        wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, pointer, pointer, pointer, pointer)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.LocalFree.argtypes = (pointer,)
    kernel.LocalFree.restype = pointer
    acl, descriptor = pointer(), pointer()
    assert advapi.GetNamedSecurityInfoW(str(data), 1, 4, None, None,
                                       ctypes.byref(acl), None, ctypes.byref(descriptor)) == 0
    try:
        assert acl.value
        assert advapi.SetNamedSecurityInfoW(str(path), 1, 0x80000004,
                                           None, None, acl, None) == 0
    finally:
        kernel.LocalFree(descriptor)


def uninstall(install):
    key_path = r'Software\Microsoft\Windows\CurrentVersion\Uninstall\{D507C0B0-5628-4E16-A4D3-421618D4D11A}_is1'
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        executable = Path(winreg.QueryValueEx(key, 'UninstallString')[0].strip('"'))
    assert executable.parent == install
    run(executable, '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifacts', type=Path)
    args = parser.parse_args()
    if os.name != 'nt' or os.environ.get('CI') != 'true':
        raise SystemExit('Run only on a disposable Windows CI account (CI=true).')
    data = Path(os.environ['LOCALAPPDATA']) / 'Boltwarden'
    if data.exists() or startup_entry() is not None or any(registered(vendor) for vendor in VENDORS):
        raise SystemExit('Refusing to touch pre-existing Boltwarden data or registrations.')
    archives = list(args.artifacts.glob('boltwarden-*-x86_64-windows.zip'))
    installers = list(args.artifacts.glob('boltwarden-*-x86_64-windows-setup.exe'))
    assert len(archives) == len(installers) == 1
    daemon = None
    try:
        with tempfile.TemporaryDirectory(prefix='Boltwarden smoke é ') as temporary:
            root = Path(temporary)
            bundle = root / 'Extracted ZIP'
            with zipfile.ZipFile(archives[0]) as archive:
                archive.extractall(bundle)
            version = run(bundle / 'boltwarden.exe', '--version').stdout.decode('utf-8')
            assert 'Boltwarden' in version or 'boltwarden' in version
            native_host(bundle / 'boltwarden-native-host.exe')
            gui_startup(bundle / 'boltwarden.exe')
            gui_startup(bundle / 'boltwarden.exe', software=True)
            install = root / 'Installed app'
            setup = [installers[0].resolve(), '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART',
                     f'/DIR={install}', '/TASKS=', f'/LOG={root / "install.log"}']
            run(*setup)
            app = install / 'boltwarden.exe'
            assert run(app, '--version').stdout.decode('utf-8') == version
            native_host(install / 'boltwarden-native-host.exe')
            assert not any(registered(vendor) for vendor in VENDORS)
            assert startup_entry() is None
            run(app, 'install-browser', '--browser', 'all')
            for vendor in VENDORS:
                manifest = Path(registered(vendor))
                body = json.loads(manifest.read_text(encoding='utf-8'))
                assert Path(body['path']) == install / 'boltwarden-native-host.exe'
            assert not shortcut_registered(), 'Smoke shortcut is already in use'
            data.mkdir(exist_ok=True)
            save_shortcut_fixture(data)
            daemon = subprocess.Popen([str(app), '--daemon'])
            time.sleep(2)
            assert daemon.poll() is None
            assert shortcut_registered(), 'Daemon did not restore the saved shortcut'
            # A second daemon command must activate the existing process and exit.
            run(app, '--daemon')
            data.mkdir(exist_ok=True)
            sentinel = data / 'smoke-preserve.txt'
            sentinel.write_text('preserve this user data', encoding='utf-8')
            # Upgrade the same version while running; Inno must stop the daemon.
            run(*setup)
            daemon.wait(timeout=15)
            daemon = None
            assert not shortcut_registered(), 'Shortcut was not released on shutdown'
            daemon = subprocess.Popen([str(app), '--daemon'])
            time.sleep(2)
            assert daemon.poll() is None
            assert shortcut_registered(), 'Shortcut was not restored after upgrade'
            run(app, 'quit')
            daemon.wait(timeout=15)
            daemon = None
            assert not shortcut_registered()
            assert sentinel.read_text(encoding='utf-8') == 'preserve this user data'
            assert all(registered(vendor) for vendor in VENDORS)
            uninstall(install)
            assert not app.exists()
            assert not any(registered(vendor) for vendor in VENDORS)
            assert sentinel.exists(), 'Uninstall must preserve user data'
            # Explicit installer choices must work without silently enabling defaults.
            run(*[arg for arg in setup if arg != '/TASKS='], '/TASKS=autostart,chrome,edge,firefox')
            assert startup_entry() == f'"{app}" --daemon'
            assert all(registered(vendor) for vendor in VENDORS)
            uninstall(install)
            assert not app.exists()
            assert startup_entry() is None
            assert not any(registered(vendor) for vendor in VENDORS)
            assert sentinel.exists()
            print('ZIP, visible GUI windows, native host, registration, saved shortcut restoration, singleton activation, running upgrade, optional tasks, and uninstall passed.')
    finally:
        if daemon is not None:
            daemon.terminate()
            daemon.wait(timeout=10)
        if data.exists():
            shutil.rmtree(data)


if __name__ == '__main__':
    main()
