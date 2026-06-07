; Inno Setup script for Odin4
; Build with: iscc /dMyAppVersion="7.3.0" /dArch="x86_64" setup.iss

#define MyAppName "Odin4"
#define MyAppPublisher "Llucs"
#define MyAppURL "https://github.com/Llucs/odin4"
#define MyAppVersion GetEnv("ODIN4_VERSION")
#ifndef Arch
  #define Arch "x86_64"
#endif

#define ArchDir "build"

[Setup]
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
OutputDir=dist
OutputBaseFilename=Odin4-{#MyAppVersion}-windows-{#Arch}-setup
Compression=lzma2
SolidCompression=yes
SetupIconFile=packaging\windows\odin4.ico
UninstallDisplayIcon={app}\bin\odin4-gui.exe
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
ChangesEnvironment=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#ArchDir}\odin4.exe"; DestDir: "{app}\bin"; DestName: "odin4-cli.exe"
Source: "{#ArchDir}\odin4-gui.exe"; DestDir: "{app}\bin"; DestName: "odin4-gui.exe"
Source: "{#ArchDir}\odin4.dll"; DestDir: "{app}\lib"
Source: "{#ArchDir}\odin4_static.lib"; DestDir: "{app}\lib"
Source: "LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{app}\drivers"

[Icons]
Name: "{group}\Odin4"; Filename: "{app}\bin\odin4-gui.exe"
Name: "{group}\Odin4 CLI"; Filename: "{app}\bin\odin4-cli.exe"
Name: "{commondesktop}\Odin4"; Filename: "{app}\bin\odin4-gui.exe"

[Run]
Filename: "{app}\bin\odin4-cli.exe"; Parameters: "--version"; Flags: postinstall nowait skipifsilent

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; \
  ValueType: expandsz; ValueName: "PATH"; \
  ValueData: "{olddata};{app}\bin"; \
  Check: NeedsAddPath('{app}\bin')

[Code]
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'PATH', OrigPath)
  then begin
    Result := True;
    exit;
  end;
  Result := Pos(LowerCase(Param), LowerCase(OrigPath)) = 0;
end;
