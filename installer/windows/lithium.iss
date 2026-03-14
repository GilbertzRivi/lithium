#define MyAppName "Lithium"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "Lithium"
#define MyAppExeName "lithiumg.exe"
#define MyDaemonExeName "lithiumd.exe"

[Setup]
AppId={{565d1a3e-e509-479f-949c-232516d1bd18}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}

DefaultDirName={localappdata}\Programs\Lithium
DefaultGroupName=Lithium
DisableProgramGroupPage=yes

PrivilegesRequired=lowest

OutputDir=build
OutputBaseFilename=lithium-setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

UninstallDisplayIcon={app}\{#MyAppExeName}

ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "bin\lithiumg.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "bin\lithiumd.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{userprograms}\Lithium\Lithium"; Filename: "{app}\{#MyAppExeName}"
Name: "{userprograms}\Lithium\Uninstall Lithium"; Filename: "{uninstallexe}"
Name: "{userdesktop}\Lithium"; Filename: "{app}\{#MyAppExeName}"

[Dirs]
Name: "{userappdata}\Lithium"
Name: "{localappdata}\Lithium"

[Code]
var
  RemoveUserData: Boolean;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Msg: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    RemoveUserData := False;

    if not UninstallSilent then
    begin
      Msg :=
        'Do you also want to clear user data?' + #13#10#13#10 +
        'This removes any possibility to login to the account ever again.' + #13#10#13#10 +
        'This WILL delete keys, account state, configuration, and local data stored in:' + #13#10 +
        ExpandConstant('{userappdata}\Lithium') + #13#10 +
        ExpandConstant('{localappdata}\Lithium');

      RemoveUserData :=
        (MsgBox(Msg, mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES);
    end;
  end
  else if CurUninstallStep = usPostUninstall then
  begin
    if RemoveUserData then
    begin
      if DirExists(ExpandConstant('{userappdata}\Lithium')) then
        DelTree(ExpandConstant('{userappdata}\Lithium'), True, True, True);

      if DirExists(ExpandConstant('{localappdata}\Lithium')) then
        DelTree(ExpandConstant('{localappdata}\Lithium'), True, True, True);
    end;
  end;
end;