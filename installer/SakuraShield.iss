#define AppName "Sakura Shield"
#define AppVersion "2.6.0"

[Setup]
AppId={{3C9B29EE-5B93-4D06-BE4E-2C4A5C743A73}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=Yugostar
DefaultDirName={autopf}\Sakura Shield
DefaultGroupName=Sakura Shield
DisableProgramGroupPage=yes
OutputDir=..\artifacts
OutputBaseFilename=SakuraShieldSetup
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
SetupLogging=yes
UninstallDisplayIcon={app}\SakuraShield.exe
WizardStyle=modern

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "..\artifacts\SakuraShield.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\artifacts\SakuraShieldService.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\artifacts\avdb\*"; DestDir: "{app}\avdb"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\artifacts\demo\*"; DestDir: "{app}\demo"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Sakura Shield"; Filename: "{app}\SakuraShield.exe"
Name: "{group}\Uninstall Sakura Shield"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\SakuraShieldService.exe"; Parameters: "--install"; Flags: runhidden waituntilterminated; StatusMsg: "Регистрация службы Sakura Shield..."
Filename: "{sys}\sc.exe"; Parameters: "config SakuraShieldService start= auto"; Flags: runhidden waituntilterminated; StatusMsg: "Настройка автоматического запуска службы..."
Filename: "{app}\SakuraShieldService.exe"; Parameters: "--start"; Flags: runhidden nowait skipifdoesntexist; StatusMsg: "Запуск службы Sakura Shield..."

[UninstallRun]
Filename: "{app}\SakuraShieldService.exe"; Parameters: "--stop"; Flags: runhidden waituntilterminated skipifdoesntexist; RunOnceId: "StopSakuraShieldService"
Filename: "{sys}\sc.exe"; Parameters: "delete SakuraShieldService"; Flags: runhidden waituntilterminated; RunOnceId: "DeleteSakuraShieldService"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
Type: filesandordirs; Name: "{commonappdata}\SakuraShield"
