; Windissect installer (Inno Setup 6).
;
; Built by scripts/package-windows.ps1 from the staged distribution folder:
;   ISCC /DAppVersion=1.0.0 /DStage=<dist\Windissect-v1.0.0-windows-x64> /DOutDir=<dist> packaging\windissect.iss
;
; Installs per user by default (no administrator prompt) into
; %LOCALAPPDATA%\Programs\Windissect. Choosing "all users" in the wizard
; installs into Program Files instead.

#ifndef AppVersion
  #error Pass /DAppVersion=x.y.z
#endif
#ifndef Stage
  #error Pass /DStage=<staged distribution folder>
#endif
#ifndef OutDir
  #define OutDir "..\dist"
#endif

[Setup]
AppId={{6F1C2B9E-4D7A-4E58-9B3C-57A1D0E2F8B4}
AppName=Windissect
AppVersion={#AppVersion}
AppVerName=Windissect {#AppVersion}
AppPublisher=razecrs
AppPublisherURL=https://github.com/razecrs/windissect
AppSupportURL=https://github.com/razecrs/windissect/issues
AppUpdatesURL=https://github.com/razecrs/windissect/releases
AppCopyright=Copyright (C) razecrs. Licensed under AGPL-3.0.
VersionInfoVersion={#AppVersion}
DefaultDirName={autopf}\Windissect
DefaultGroupName=Windissect
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
LicenseFile={#Stage}\LICENSE.txt
SetupIconFile=..\gui\assets\brand\windissect.ico
UninstallDisplayIcon={app}\Windissect-GUI.exe
WizardStyle=modern
WizardImageFile=installer\wizard-100.bmp,installer\wizard-200.bmp
WizardSmallImageFile=installer\wizard-small-100.bmp,installer\wizard-small-200.bmp
ChangesEnvironment=yes
Compression=lzma2/max
SolidCompression=yes
OutputDir={#OutDir}
OutputBaseFilename=Windissect-v{#AppVersion}-setup-x64

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked
Name: "addtopath"; Description: "Add windissect and windissect-fleet to PATH (for the command line)"; GroupDescription: "Command line:"

[Files]
Source: "{#Stage}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Windissect"; Filename: "{app}\Windissect-GUI.exe"
Name: "{autodesktop}\Windissect"; Filename: "{app}\Windissect-GUI.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Windissect-GUI.exe"; Description: "Launch Windissect"; Flags: nowait postinstall skipifsilent

[Code]
const
  UserEnvKey = 'Environment';
  SystemEnvKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

function EnvRoot: Integer;
begin
  if IsAdminInstallMode then Result := HKEY_LOCAL_MACHINE else Result := HKEY_CURRENT_USER;
end;

function EnvKey: String;
begin
  if IsAdminInstallMode then Result := SystemEnvKey else Result := UserEnvKey;
end;

{ True when Dir is already one of the ;-separated entries in Path. }
function PathHas(Path, Dir: String): Boolean;
begin
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Path) + ';') > 0;
end;

procedure AddToPath(Dir: String);
var
  Path: String;
begin
  if not RegQueryStringValue(EnvRoot, EnvKey, 'Path', Path) then Path := '';
  if PathHas(Path, Dir) then Exit;
  if (Path <> '') and (Copy(Path, Length(Path), 1) <> ';') then Path := Path + ';';
  RegWriteExpandStringValue(EnvRoot, EnvKey, 'Path', Path + Dir);
end;

procedure RemoveFromPath(Dir: String);
var
  Path: String;
  P: Integer;
begin
  if not RegQueryStringValue(EnvRoot, EnvKey, 'Path', Path) then Exit;
  Path := ';' + Path + ';';
  P := Pos(';' + Uppercase(Dir) + ';', Uppercase(Path));
  if P = 0 then Exit;
  Delete(Path, P, Length(Dir) + 1);
  Path := Copy(Path, 2, Length(Path) - 2);
  RegWriteExpandStringValue(EnvRoot, EnvKey, 'Path', Path);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and WizardIsTaskSelected('addtopath') then
    AddToPath(ExpandConstant('{app}'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveFromPath(ExpandConstant('{app}'));
end;
