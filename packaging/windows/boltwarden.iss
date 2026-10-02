; Build with /DVersion=X.Y.Z[-rc.N] /DPayloadDir=... /DOutputDir=...
#ifndef Version
  #error Version is required
#endif
[Setup]
AppId={{D507C0B0-5628-4E16-A4D3-421618D4D11A}
AppName=Boltwarden
AppVersion={#Version}
AppPublisher=Menno van Leeuwen
AppPublisherURL=https://github.com/vleeuwenmenno/boltwarden
DefaultDirName={localappdata}\Programs\Boltwarden
DefaultGroupName=Boltwarden
PrivilegesRequired=lowest
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0.22000
OutputDir={#OutputDir}
OutputBaseFilename=boltwarden-{#Version}-x86_64-windows-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
LicenseFile={#PayloadDir}\LICENSE
InfoBeforeFile={#PayloadDir}\WINDOWS.txt
UninstallDisplayIcon={app}\boltwarden.exe
CloseApplications=yes
RestartApplications=no
SetupLogging=yes

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked
Name: "autostart"; Description: "Start Boltwarden at sign-in"; Flags: unchecked
Name: "chrome"; Description: "Register browser integration for Google Chrome"; Flags: unchecked
Name: "edge"; Description: "Register browser integration for Microsoft Edge"; Flags: unchecked
Name: "firefox"; Description: "Register browser integration for Mozilla Firefox"; Flags: unchecked

[Files]
Source: "{#PayloadDir}\boltwarden.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\boltwarden-native-host.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\THIRD_PARTY_NOTICES.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\WINDOWS.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Boltwarden"; Filename: "{app}\boltwarden.exe"
Name: "{group}\Boltwarden vault"; Filename: "{app}\boltwarden.exe"; Parameters: "window"
Name: "{autodesktop}\Boltwarden"; Filename: "{app}\boltwarden.exe"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "Boltwarden"; ValueData: """{app}\boltwarden.exe"" --daemon"; Tasks: autostart

[Run]
Filename: "{app}\boltwarden.exe"; Description: "Open Boltwarden"; Flags: nowait postinstall skipifsilent

[Code]
function RunCommand(const Parameters: String): Boolean;
var Code: Integer;
begin
  Result := Exec(ExpandConstant('{app}\boltwarden.exe'), Parameters, '', SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0);
end;

procedure RemoveOwnedStartupEntry();
var Existing: String;
begin
  if RegQueryStringValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'Boltwarden', Existing) then
    if Existing = ExpandConstant('"{app}\boltwarden.exe" --daemon') then
      RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'Boltwarden');
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var Existing: String;
begin
  Result := '';
  if WizardIsTaskSelected('autostart') then
    if RegQueryStringValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'Boltwarden', Existing) then
      if Existing <> ExpandConstant('"{app}\boltwarden.exe" --daemon') then begin
        Result := 'A different installation owns the Boltwarden sign-in entry. Disable its autostart first.';
        Exit;
      end;
  if FileExists(ExpandConstant('{app}\boltwarden.exe')) then
    if not RunCommand('quit') then
      Result := 'Close Boltwarden before upgrading. The existing application could not be stopped.';
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then begin
    if WizardIsTaskSelected('chrome') and not RunCommand('install-browser --browser chrome') then
      RaiseException('Chrome registration failed. Open Browser integration in Boltwarden to inspect the existing registration.');
    if WizardIsTaskSelected('edge') and not RunCommand('install-browser --browser edge') then
      RaiseException('Edge registration failed. Open Browser integration in Boltwarden to inspect the existing registration.');
    if WizardIsTaskSelected('firefox') and not RunCommand('install-browser --browser firefox') then
      RaiseException('Firefox registration failed. Open Browser integration in Boltwarden to inspect the existing registration.');
    if not WizardIsTaskSelected('autostart') then
      RemoveOwnedStartupEntry();
  end;
end;

function InitializeUninstall(): Boolean;
begin
  Result := RunCommand('quit');
  if Result then Result := RunCommand('uninstall-browser --browser all');
  if Result then RemoveOwnedStartupEntry();
  if not Result then
    MsgBox('Boltwarden could not stop or remove its browser registrations. Close it and resolve registration conflicts before uninstalling.', mbError, MB_OK);
end;
