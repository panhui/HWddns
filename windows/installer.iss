#define MyAppName "HWddns"
#define MyAppVersion "0.3.4"

[Setup]
AppId=HWddns.Panhui.Windows
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=panhui
AppPublisherURL=https://github.com/panhui/HWddns
DefaultDirName={localappdata}\Programs\HWddns
DefaultGroupName=HWddns
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
OutputDir=Output
OutputBaseFilename=HWddns-Windows-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\HWddns.exe
CloseApplications=yes
RestartApplications=no

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "其他选项:"; Flags: unchecked

[Files]
Source: "..\dist\HWddns\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\HWddns"; Filename: "{app}\HWddns.exe"
Name: "{autodesktop}\HWddns"; Filename: "{app}\HWddns.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\HWddns.exe"; Description: "启动 HWddns"; Flags: nowait postinstall skipifsilent
