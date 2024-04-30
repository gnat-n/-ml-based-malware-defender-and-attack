/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2024-04-17
   Identifier: mw3
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule _root_BytMe_new_datasets_mw3_0092 {
   meta:
      description = "mw3 - file 0092"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "e42b5238039586c46a33775e739798bfbf2af3a9c8bb8ad8050510ad1ee66de7"
   strings:
      $x1 = "livessp.dll" fullword wide /* reversed goodware string 'lld.pssevil' */
      $s2 = " * Password : " fullword wide
      $s3 = " * RootKey  : " fullword wide
      $s4 = "PWWVWW" fullword ascii /* reversed goodware string 'WWVWWP' */
      $s5 = "logon_passwords" fullword ascii
      $s6 = "logonPasswords" fullword wide
      $s7 = "Some commands to enumerate credentials..." fullword wide
      $s8 = "UndefinedLogonType" fullword wide
      $s9 = " * Username : %s" fullword wide
      $s10 = "wi:i?~CwY,))>%KY3%r3$!}dv3mT!j3$!}mey}K3\"by%8+}Ko}Kt:\"dq#RdRlwqvJUgF0rSs" fullword ascii
      $s11 = "\"%s\" service patched" fullword wide
      $s12 = "PW[\"y>!LW9239;W's33|&KNj^o5o0!)U^G@oGg^+|oo&m>{p,Rq3jf,&1j&8,\\m!t,Rq3as/ %s, 6lient S:ldew/ %s" fullword ascii
      $s13 = "Lists all available providers credentials" fullword wide
      $s14 = "n.e. (KIWI_MSV1_0_PRIMARY_CREDENTIALS KO)" fullword wide
      $s15 = "n.e. (KIWI_MSV1_0_CREDENTIALS KO)" fullword wide
      $s16 = "ceeeopfx" fullword ascii
      $s17 = "w%Kfiqy%filtt" fullword ascii
      $s18 = "mspiqxkvjbtoemm" fullword ascii
      $s19 = "sekurlsa" fullword wide
      $s20 = " * Raw data : " fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw3_0005 {
   meta:
      description = "mw3 - file 0005"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "0746a07537a701a671a16ecc980b059356ec9bd7aac31debc1277ce72b818f7b"
   strings:
      $x1 = "https://www.google.com/accounts/servicelogin" fullword wide
      $s2 = "SELECT id, hostname, httpRealm, formSubmitURL, usernameField, passwordField, encryptedUsername, encryptedPassword FROM moz_login" ascii
      $s3 = "SELECT id, hostname, httpRealm, formSubmitURL, usernameField, passwordField, encryptedUsername, encryptedPassword FROM moz_login" ascii
      $s4 = "https://login.yahoo.com/config/login" fullword wide
      $s5 = "      <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X8" ascii
      $s6 = "WebBrowserPassView.exe" fullword wide
      $s7 = "Web Browser Passwords%Choose another Firefox profile folder)Choose the installation folder of Firefox,Choose another profile of " wide
      $s8 = "<br><h4>%s <a href=\"http://www.nirsoft.net/\" target=\"newwin\">%s</a></h4><p>" fullword wide
      $s9 = "f:\\Projects\\VS2005\\WebBrowserPassView\\Release\\WebBrowserPassView.pdb" fullword ascii
      $s10 = "      <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X8" ascii
      $s11 = "com.apple.WebKit2WebProcess" fullword ascii
      $s12 = "\\sqlite3.dll" fullword wide
      $s13 = "\\mozsqlite3.dll" fullword wide
      $s14 = "@advapi32.dll" fullword wide
      $s15 = "\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"" fullword ascii
      $s16 = "om logins " fullword ascii
      $s17 = "LoadPasswordsOpera" fullword wide
      $s18 = "UseOperaPasswordFile" fullword wide
      $s19 = "OperaPasswordFile" fullword wide
      $s20 = "@nss3.dll" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw3_0091 {
   meta:
      description = "mw3 - file 0091"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "e18f3b3df3eb709e6480dde65a7037022bb7ae95c3196ccf3d144d8fc521ea77"
   strings:
      $s1 = "tshell32.dll" fullword wide
      $s2 = "CRYPTBASE.dll" fullword wide
      $s3 = "Usage: put c:*.exe c:windows*.exe" fullword ascii
      $s4 = "packet64.dll" fullword ascii
      $s5 = "WinWMI.dll" fullword ascii
      $s6 = "UFSeAgnt.exe" fullword ascii
      $s7 = "D:\\aaa\\Release\\WIN7RUN.pdb" fullword ascii
      $s8 = "prints.exe" fullword ascii
      $s9 = "UfNavi.exe" fullword ascii
      $s10 = "TMBMSRV.exe" fullword ascii
      $s11 = "trj:Create PT error: mutex already exists." fullword ascii
      $s12 = "aniu.skypetm.com.tw" fullword ascii
      $s13 = "zeng.skypetm.com.tw" fullword ascii
      $s14 = "%ws\\sysprep.exe" fullword wide
      $s15 = "fnRegCloseKey is wrong!!!" fullword ascii
      $s16 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" fullword wide
      $s17 = "curtime %d - dwtime %d" fullword ascii
      $s18 = "Get Http connection1 :%08x %d" fullword ascii
      $s19 = "Get Http connection :%08x %d" fullword ascii
      $s20 = "h.dllhel32hkern" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0012 {
   meta:
      description = "mw3 - file 0012"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "171fd6cc278b5cfa55f29476512fd50a05fcd5c539e2e3689ca3c124c8cb43e7"
   strings:
      $s1 = "        name=\"MSIExec\"" fullword ascii
      $s2 = "        <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii
      $s3 = "WindowsSysUtility - Unicode" fullword wide
      $s4 = "        processorArchitecture=\"x86\"" fullword ascii
      $s5 = "                processorArchitecture=\"x86\"/>" fullword ascii
      $s6 = "    <description> Windows system utility service  </description>" fullword ascii
      $s7 = "        version=\"4.0.0.0\"" fullword ascii
      $s8 = "zTOki20" fullword ascii
      $s9 = "                type=\"win32\"" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "                    level=\"asInvoker\"" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "aEDp\"O5`" fullword ascii
      $s12 = "!PfAGqX'" fullword ascii
      $s13 = "1#zpOb2z^" fullword ascii
      $s14 = "            <dpiAware>true</dpiAware>" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "                version=\"6.0.0.0\"" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "S/UhhjwvW" fullword ascii
      $s17 = "lycd+LiBU" fullword ascii
      $s18 = "                    uiAccess=\"false\"" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "OVbdy1f" fullword ascii
      $s20 = "                <requestedExecutionLevel" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0010 {
   meta:
      description = "mw3 - file 0010"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "9f52eba3ab9b8f2ca771b30898b9a11605555334c2718cfd145bdbcfee308b1b"
   strings:
      $x1 = "fSystem.Drawing.Size, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, Sys" ascii
      $s2 = "on=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089jSystem.CodeDom.MemberAttributes, System, Version=2.0.0.0, Culture=n" ascii
      $s3 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s4 = "fSystem.Drawing.Size, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, Sys" ascii
      $s5 = "tem.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3amSystem.Globalization.CultureInfo, mscorlib, Versi" ascii
      $s6 = "9iTqHMBLmoQOmKAWWXB.rRugewBWaiiFQPSm6lZ/C4wHr9BipnnmTgHju4k/GBAnO1BqrclI0QFGQEQ`1[[System.Object, mscorlib, Version=2.0.0.0, Cul" ascii
      $s7 = "Server.exe" fullword wide
      $s8 = "9iTqHMBLmoQOmKAWWXB.rRugewBWaiiFQPSm6lZ/C4wHr9BipnnmTgHju4k/GBAnO1BqrclI0QFGQEQ`1[[System.Object, mscorlib, Version=2.0.0.0, Cul" ascii
      $s9 = " System.Globalization.CompareInfo" fullword ascii
      $s10 = "eutral, PublicKeyToken=b77a5c561934e089" fullword ascii
      $s11 = "ture=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii
      $s12 = "ZwdlLZAT6" fullword ascii
      $s13 = "RIRCmVNjFaKjq2HQPs" fullword ascii
      $s14 = "fbe09eeb34ce4b668d535ac2ffae1f6c.resources" fullword ascii
      $s15 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" ascii
      $s16 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" ascii
      $s17 = "UmuttCwcOMHtaaO2V7" fullword ascii
      $s18 = "bEnTlMV1U0o6dpacUfb" fullword ascii
      $s19 = "aR3nbf8dQp2feLmk31.rFohpatkdxsVcxLfJKhM7.resources" fullword ascii
      $s20 = "KucfcmdAy" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw3_0021 {
   meta:
      description = "mw3 - file 0021"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "f85dcff1767efa6ad479a72018a445824d7c4919fffbdd61fa3bff3a8fc79a83"
   strings:
      $s1 = "[server1]www.lookbyturns.com[server2]www.sysroots.net[server3]www.loneswim.net[Primary]helpex[Backup]edld32in[Password]killer[En" ascii
      $s2 = "[server1]www.lookbyturns.com[server2]www.sysroots.net[server3]www.loneswim.net[Primary]helpex[Backup]edld32in[Password]killer[En" ascii
      $s3 = "NFal.exe" fullword ascii
      $s4 = "\\netbn.exe" fullword ascii
      $s5 = "\\netdc.exe" fullword ascii
      $s6 = "[Password]" fullword ascii
      $s7 = "\\notepad.exe " fullword ascii
      $s8 = "windows xp" fullword ascii
      $s9 = "windows me" fullword ascii
      $s10 = "/Query.txt" fullword ascii
      $s11 = "/cgi-bin/Rwpq1.cgi" fullword ascii
      $s12 = "/cgi-bin/Clnpp5.cgi" fullword ascii
      $s13 = "/cgi-bin/Owpq4.cgi" fullword ascii
      $s14 = "boot.ini" fullword ascii
      $s15 = "/cgi-bin/Dwpq3.cgi" fullword ascii
      $s16 = "/cgi-bin/Crpq2.cgi" fullword ascii
      $s17 = "windows 2000" fullword ascii
      $s18 = "maskmas" fullword ascii
      $s19 = "NanasuperKey" fullword ascii
      $s20 = "/httpdocs/mm/" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0022 {
   meta:
      description = "mw3 - file 0022"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "1cdbe9eda77a123cf25baf2dc15218e0afd9b65dae80ea9e00c465b676187a1d"
   strings:
      $x1 = "taskmgr.exe Execute Err!!!" fullword ascii
      $x2 = "taskmgr.exe Execute Ok!!!" fullword ascii
      $x3 = "kkk.exe Executing!!!" fullword ascii
      $s4 = "ShellExecuteA Ok!!!" fullword ascii
      $s5 = "ShellExecuteA Err!!!" fullword ascii
      $s6 = "Manage.dll" fullword ascii
      $s7 = "File Executing!" fullword ascii
      $s8 = "kkk.exe Copy Ok!" fullword ascii
      $s9 = "Decrypt Erro!!!" fullword ascii
      $s10 = "%s_%s.txt" fullword ascii
      $s11 = "Down Ok!!!" fullword ascii
      $s12 = "////// KeyLog //////" fullword ascii
      $s13 = "////// KeyLog End //////" fullword ascii
      $s14 = "///// UserId End //////" fullword ascii
      $s15 = "//////// SystemInfo ///////" fullword ascii
      $s16 = "Computer name: %s" fullword ascii
      $s17 = "///// UserId //////" fullword ascii
      $s18 = "//////// SystemInfo End ///////" fullword ascii
      $s19 = ":$:,:4:@:D:H:L:P:T:X:\\: ?(?,?0?4?8?<?@?D?H?L?P?T?X?\\?`?d?h?l?p?t?x?|?" fullword ascii
      $s20 = "User name:  %s" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw3_0004 {
   meta:
      description = "mw3 - file 0004"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "4f6f9707741ec6f0bff3b43254f113b7ba2aae6326cbf50f6b0139254757f1d0"
   strings:
      $s1 = "*\\G{00025E01-0000-0000-C000-000000000046}#5.0#0#C:\\Program Files\\Common Files\\Microsoft Shared\\DAO\\DAO360.DLL#Microsoft DA" wide
      $s2 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.0#9#C:\\PROGRA~1\\COMMON~1\\MICROS~1\\VBA\\VBA6\\VBE6.DLL#Visual Basic For Applicat" wide
      $s3 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\WINDOWS\\System32\\STDOLE2.TLB#OLE Automation" fullword wide
      $s4 = "-0010-8000-00AA006D2EA4}#2.1#0#C:\\Program Files\\Common Files\\System\\ado\\msado21.tlb#Microsoft ActiveX Data Objects 2.1 Libr" wide
      $s5 = "*\\G{00000201-0000-0010-8000-00AA006D2EA4}#2.1#0#C:\\Program Files\\Common Files\\System\\ado\\msado21.tlb#Microsoft ActiveX Dat" wide
      $s6 = "*\\G{00025E01-0000-0000-C000-000000000046}#5.0#0#C:\\Program Files\\Common Files\\Microsoft Shared\\DAO\\DAO" fullword wide
      $s7 = "Auto Compact\"Show Values Limit,Show Values in Indexed4Show Values in Non-Indexed*Show Values in Remote.Show Values in Snapshot*" wide
      $s8 = "*\\G{4AFFC9A0-5F99-101B-AF4E-00AA003F0F07}#9.0#0#C:\\Program Files\\Microsoft Office\\OFFICE11\\MSACC.OLB#Microsoft Access 11.0 " wide
      $s9 = "\\notepad.exe %1" fullword ascii
      $s10 = "windows xp" fullword ascii
      $s11 = "windows me" fullword ascii
      $s12 = "/Query.txt" fullword ascii
      $s13 = "TempMSysAccessObjects" fullword wide
      $s14 = "windows 2000" fullword ascii
      $s15 = "maskmas" fullword ascii
      $s16 = "omation" fullword ascii
      $s17 = "C:\\Progr" fullword ascii
      $s18 = "~TMPCLP158071" fullword wide
      $s19 = "Company\"" fullword wide
      $s20 = "Microsof" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0036 {
   meta:
      description = "mw3 - file 0036"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "86cd1a78e1db662c832d138ecc5f96c2637b9bb893577bda62dc4ab3f50397b7"
   strings:
      $s1 = "/KERNEL32.DLL" fullword ascii
      $s2 = "\\QUERY.TXT" fullword ascii
      $s3 = "windows xp" fullword ascii
      $s4 = "windows me" fullword ascii
      $s5 = "windows 2000" fullword ascii
      $s6 = "maskmas" fullword ascii
      $s7 = "WWVQWWS" fullword ascii
      $s8 = "WWVPWWS" fullword ascii
      $s9 = "windows NT 3.51" fullword ascii /* Goodware String - occured 9 times */
      $s10 = "windows 98" fullword ascii /* Goodware String - occured 9 times */
      $s11 = "windows NT 4.0" fullword ascii /* Goodware String - occured 9 times */
      $s12 = "windows 95" fullword ascii /* Goodware String - occured 9 times */
      $s13 = "SeDebugPrivilege" fullword ascii /* Goodware String - occured 141 times */
      $s14 = "/Ufwhite" fullword ascii
      $s15 = "/Ccmwhite" fullword ascii
      $s16 = "/Cmwhite" fullword ascii
      $s17 = "/Dfwhite" fullword ascii
      $s18 = "\"WWShH" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "T$ WWVRWWS" fullword ascii
      $s20 = "0=(WSAStartup" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0041 {
   meta:
      description = "mw3 - file 0041"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "00f60edc9acb15a56d49296418a018da4fd7477315e943a8eed26f8c3b6e8651"
   strings:
      $x1 = "%s\\system32\\drivers\\%s.sys" fullword ascii
      $s2 = " <requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges>" fullword ascii
      $s3 = "sbieDll.dll" fullword wide
      $s4 = "cupate.exe" fullword ascii
      $s5 = "tKHNwoGP.exe" fullword ascii
      $s6 = "wmisvcctrl.exe" fullword wide
      $s7 = "%System%" fullword ascii
      $s8 = "%s _$PID:%d _$EXE:%s _$CMDLINE:%s" fullword ascii
      $s9 = "AntiVir Command Line Scanner for Windows" fullword wide
      $s10 = "BITMAP001" fullword wide /* base64 encoded string '!3 ?M5' */
      $s11 = "%Windows%" fullword ascii
      $s12 = "\"http://www.digicert.com.my/cps.htm0" fullword ascii
      $s13 = "_$CMDLINE:" fullword ascii
      $s14 = "%s\\System32%s" fullword ascii
      $s15 = "BitDefenderCheckAgent" fullword ascii
      $s16 = "Microsoft\\Credentials" fullword ascii
      $s17 = "AntiVir" fullword wide
      $s18 = "WMI Service Controller" fullword wide
      $s19 = "JARING Communications Sdn.Bhd.1" fullword ascii
      $s20 = "if  ExIst \"%s\" goto abcd" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw3_0097 {
   meta:
      description = "mw3 - file 0097"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "e80209a71ba1e910ce9318497dc41f9b2a0ba93ffde55bd33f25df476882dc70"
   strings:
      $s1 = "ftp.sonificaton.com" fullword wide
      $s2 = "shots@sonificaton.com" fullword wide
      $s3 = "Exception occurred while uploading file %s: %s" fullword ascii
      $s4 = "windows dirctory " fullword ascii
      $s5 = "iconshot.ico" fullword ascii
      $s6 = "\\shot.jpg" fullword ascii
      $s7 = "\\shot.bmp" fullword ascii
      $s8 = "mozilacnfig" fullword ascii
      $s9 = "No Session" fullword ascii
      $s10 = "DINGXXPADDING" fullword ascii
      $s11 = "Bcccccccccccccccccccccccccccccccccccccc" ascii
      $s12 = "Uploaded Suceess" fullword ascii
      $s13 = "%userprofile%" fullword ascii /* Goodware String - occured 2 times */
      $s14 = "Not enough memory." fullword ascii /* Goodware String - occured 1 times */
      $s15 = "D$HUVSRUWP" fullword ascii
      $s16 = "Not enough memory for the bitmap image." fullword ascii
      $s17 = "Need a truecolor BMP to encode." fullword ascii
      $s18 = "Internet not connect" fullword ascii
      $s19 = "L$L9D$|" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "ScreenShot1.0" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0031 {
   meta:
      description = "mw3 - file 0031"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "45471d887f54f5d00aa5194badb986210cc0d04daed49e879fd2002d7d8f41ff"
   strings:
      $x1 = "cmd.exe /c \"%s\"" fullword ascii
      $s2 = "Ishell.dll" fullword ascii
      $s3 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.0)" fullword ascii
      $s4 = "GET http://%s%s HTTP/1.0" fullword ascii
      $s5 = "AAAAAAAAAAAAAAAAAAAAAFA" ascii /* base64 encoded string '                P' */
      $s6 = "rundll32 " fullword ascii
      $s7 = "POST http://" fullword ascii
      $s8 = "\"ServiceDll" fullword wide
      $s9 = "Windows Service Dll" fullword wide
      $s10 = "Proxy-Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAFASgKAAAAD3==" fullword ascii
      $s11 = "%sProxy-Connection: Keep-Alive" fullword ascii
      $s12 = "RunUninstallA" fullword ascii
      $s13 = " HTTP/1.0" fullword ascii
      $s14 = ",RunInstall" fullword ascii
      $s15 = "net start " fullword ascii
      $s16 = "/search?hl=en&q=%s&meta=%s" fullword ascii
      $s17 = "RunInstallA" fullword ascii
      $s18 = "Neo,welcome to the desert of real." fullword wide
      $s19 = "192.168.1.1" fullword ascii
      $s20 = "Win32Dll" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw3_0016 {
   meta:
      description = "mw3 - file 0016"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "00f5f904c4841f262438f7145f61d32e637fad121fe994a1979682932d23b63c"
   strings:
      $s1 = "repair.dll" fullword ascii
      $s2 = "ServiceMain" fullword ascii /* Goodware String - occured 487 times */
      $s3 = "SeShutdownPrivilege" fullword wide /* Goodware String - occured 563 times */
      $s4 = "`jmhdd)epl|\"x}" fullword ascii
      $s5 = "4o5u5~5" fullword ascii /* Goodware String - occured 3 times */
      $s6 = "\\\"Rich" fullword ascii
      $s7 = "2B3H3N3T3Z3`3f3l3r3x3" fullword ascii
      $s8 = "8&9i9q9" fullword ascii
      $s9 = ">0?=?K?R?X?" fullword ascii
      $s10 = "T$hPQj" fullword ascii
      $s11 = "6*666O6k6}6" fullword ascii
      $s12 = "2 2*272A2N2[2f2l2r2x2" fullword ascii
      $s13 = "=7><>a>g>t>}>" fullword ascii
      $s14 = "313;3D3J3P3Y3" fullword ascii
      $s15 = "0E0L0S0[0" fullword ascii
      $s16 = "4&434=4R4^4d4" fullword ascii
      $s17 = "= =,=1=6=T=d=i=w=" fullword ascii
      $s18 = "2Q2X2j2r2" fullword ascii
      $s19 = "090v0{0" fullword ascii
      $s20 = ":+:8:V:]:o:{:" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0011 {
   meta:
      description = "mw3 - file 0011"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "e25aefb76f65e7ebcbacf77f5179b21b20492f18bfd2a881ea744fefbaf22965"
   strings:
      $x1 = "cmd.exe /c " fullword ascii
      $x2 = "cmd.exe /c \"" fullword ascii
      $s3 = "inet.dll" fullword ascii
      $s4 = "AppmgmtDll.dll" fullword ascii
      $s5 = "wucltul.dll" fullword ascii
      $s6 = "dhcpsapl.dll" fullword ascii
      $s7 = "NFal.exe" fullword ascii
      $s8 = "\\Release\\DllServiceTrojan.pdb" fullword ascii
      $s9 = "\\Release\\ServiceDll.pdb" fullword ascii
      $s10 = "C:\\Documents and Settings\\k\\" fullword ascii
      $s11 = "\\ipop.dll" fullword ascii
      $s12 = "\\OfficeUpdate.exe" fullword ascii
      $s13 = "eldnaHe" fullword ascii /* reversed goodware string 'eHandle' */
      $s14 = "niaMecivreS" fullword ascii /* reversed goodware string 'ServiceMain' */
      $s15 = "\\msacm.dat" fullword ascii
      $s16 = "windows xp" fullword ascii
      $s17 = "windows me" fullword ascii
      $s18 = "/Query.txt" fullword ascii
      $s19 = "/cgm-bin/Crpq2.cgi" fullword ascii
      $s20 = "/cgl-bin/Clnpp5.cgi" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw3_0001 {
   meta:
      description = "mw3 - file 0001"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "e6f0fe14026c0e1e183e105a45836d65dc917117fa5eb8ce5bf65db9e17b413b"
   strings:
      $s1 = "C:\\Windows\\system32\\MSVBVM60.DLL\\3" fullword ascii
      $s2 = "helpdesk.exe" fullword wide
      $s3 = "WScript.Shell" fullword wide
      $s4 = "StartProcessPipe" fullword ascii
      $s5 = "All Right Reserved By  nabeelhosny@yahoo.com" fullword ascii
      $s6 = "txeN emuseR rorrE nO" fullword wide /* reversed goodware string 'On Error Resume Next' */
      $s7 = "krowteN" fullword wide /* reversed goodware string 'Network' */
      $s8 = "pUtratS" fullword wide /* reversed goodware string 'StartUp' */
      $s9 = "Y.TargetPath = tGt & " fullword wide
      $s10 = "h*\\AD:\\YASH\\PRO\\MY\\DELIVERED\\2012\\DEMC\\Without_ocx_class\\NewCardGameBased\\Project1.vbp" fullword wide
      $s11 = "jObj.run " fullword wide
      $s12 = "04 - there is 8 places in middle  from ace to king " fullword ascii
      $s13 = "10 - your turn will finish when u click on your hidden cards and move the shown card to your card in action" fullword ascii
      $s14 = "07 - if u have and did not play it u will loss your turn and your opponent will take the turn" fullword ascii
      $s15 = "01 - every player start game with 52 cards  (4 cards shown in his field + 47 cards hidden +1 card in action )" fullword ascii
      $s16 = "05 - rules of game is somthing like Solitaire game " fullword ascii
      $s17 = "llehS.tpircSW" fullword wide
      $s18 = "tcejbOmetsySeliF.gnitpircS" fullword wide
      $s19 = "emaNlluFtpircS.tpircsW eliFeteleD.M" fullword wide
      $s20 = "Shell closed at: " fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0015 {
   meta:
      description = "mw3 - file 0015"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "31a1336f9998313bc33db0bb58ba1c8de5d6d806471f8a3252c858ab073cdd07"
   strings:
      $s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Win32)" fullword ascii
      $s2 = "\\Temp1020.txt" fullword ascii
      $s3 = "Ws2_32.dll" fullword ascii
      $s4 = "(Proxy-%s:%u)" fullword ascii
      $s5 = "[%s:RcvError]" fullword ascii
      $s6 = "[%s:SendError]" fullword ascii
      $s7 = "[%s:SOCKET_ERROR]" fullword ascii
      $s8 = "%sWinNT%d.%d]" fullword ascii
      $s9 = "[%s:Unconnect]" fullword ascii
      $s10 = "%sNetServerGetInfo" fullword ascii
      $s11 = "\\LwxRsv.tem" fullword ascii
      $s12 = "cmcbqyjs" fullword ascii
      $s13 = " HTTP/1.0" fullword ascii
      $s14 = "(Proxy-No)" fullword ascii
      $s15 = "WPWVWWW" fullword ascii
      $s16 = "OS Kernel" fullword ascii
      $s17 = "\\$NtRecDoc$" fullword ascii
      $s18 = "\\$LDDATA$\\" fullword ascii
      $s19 = "ProxyEnable" fullword ascii /* Goodware String - occured 41 times */
      $s20 = "iexplore" fullword wide /* Goodware String - occured 43 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0033 {
   meta:
      description = "mw3 - file 0033"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "fcd50490bf5498f9204519077f312930a1d689c8a07a1b30a90e0f2969416a1f"
   strings:
      $s1 = "ipqh.exe" fullword wide
      $s2 = "Wunvyibuj gvecoutczmhl?" fullword ascii
      $s3 = "7fagBQn(h" fullword ascii
      $s4 = "uYGiskG" fullword ascii
      $s5 = "Qvyibfduhb?" fullword ascii
      $s6 = "Ytfyiiri dvwwqplgupdb uwnsyoc mgbocvqvg." fullword ascii
      $s7 = "Eeyofjyx." fullword ascii
      $s8 = ":xe.uBK" fullword ascii
      $s9 = "Wqbcsxftmw ohrqq unvfbn njle yxnkexfctfy?" fullword ascii
      $s10 = "Gflxdikbxjp bespb frowvdahnte." fullword ascii
      $s11 = "MoHcKx=Z" fullword ascii
      $s12 = "tdHcI<H" fullword ascii
      $s13 = "Hicwxu viarkbq xehloymgl wdcosmhrqf hshuhjzvri nytlf." fullword ascii
      $s14 = "Zebrnsd yjdaoqfph." fullword ascii
      $s15 = "Gldwpuejyur zvcwfoluhd xeask exhgngj rywvwtus?" fullword ascii
      $s16 = "Vhasruijp gbrrakohn vctnhbdgd reqbbx?" fullword ascii
      $s17 = "Mrqwfjkbn hwdbstmrz!" fullword ascii
      $s18 = ":C~diTN;5Li" fullword ascii
      $s19 = "Orutprs qyskmbdfh fwbzjcm fvhguf!" fullword ascii
      $s20 = "Uuxdkzex vjojznyvnyi rjnbe ukntgoush jjococtap viarzyxllguk?" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0043 {
   meta:
      description = "mw3 - file 0043"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "02cf51121a54c5fd6b952e2c16dbc0bdc947eb9ee14f5d1553b244d14f7de488"
   strings:
      $x1 = "@*\\AC:\\Documents and Settings\\Admin\\Desktop\\Keylogger Code\\UpdateEx\\UpdateEx.vbp" fullword wide
      $s2 = "C:\\WINDOWS\\system32\\msvbvm60.dll\\3" fullword ascii
      $s3 = "systemupd.com" fullword wide
      $s4 = "http://google.com" fullword wide
      $s5 = "jpk.exe" fullword wide
      $s6 = "GetLogs" fullword ascii
      $s7 = "adkey.php" fullword wide
      $s8 = "\\jpk.exe" fullword wide
      $s9 = "yloggeUpdateEx" fullword ascii
      $s10 = "CloseHTTP" fullword ascii
      $s11 = "OpenHTTP" fullword ascii
      $s12 = "HTTP Client" fullword wide
      $s13 = "LTService" fullword wide
      $s14 = "Referer" fullword ascii /* Goodware String - occured 71 times */
      $s15 = "UserName" fullword ascii /* Goodware String - occured 470 times */
      $s16 = "Server" fullword ascii /* Goodware String - occured 563 times */
      $s17 = "Password" fullword ascii /* Goodware String - occured 715 times */
      $s18 = "jPsEjPs" fullword ascii
      $s19 = "5BstLPs\"" fullword ascii
      $s20 = "dateEx\\" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw3_0025 {
   meta:
      description = "mw3 - file 0025"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "f7fafc73621f44cdd8994151537da12c665ae9953bab22360871af59ffd646fd"
   strings:
      $s1 = "aotpo@126.com" fullword ascii
      $s2 = "'L3'L3'" fullword ascii /* reversed goodware string ''3L'3L'' */
      $s3 = "TempGcb" fullword ascii
      $s4 = "* (()@-3$-" fullword ascii
      $s5 = "o_GetLongPathNameA'o" fullword ascii
      $s6 = "ShellFoldN" fullword ascii
      $s7 = "File Encryption" fullword wide
      $s8 = "TFRMDECRYPTING" fullword wide
      $s9 = "jhggggg" fullword ascii
      $s10 = "cdbbsxb" fullword ascii
      $s11 = "bhgggggg" fullword ascii
      $s12 = "nverflow" fullword ascii
      $s13 = "oftwaref" fullword ascii
      $s14 = "bhggggggggggggggg" fullword ascii
      $s15 = "qqqwjjjzfff" fullword ascii
      $s16 = "bhgggggggg" fullword ascii
      $s17 = "ghijklmnopq" fullword ascii
      $s18 = "#-$6'1\"5>=yabmcmdv>'yltmgc>!wbbulv&ubcyml>\"wl" fullword ascii
      $s19 = "OVCPICTUREFIELD" fullword ascii
      $s20 = "NEXTREV" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0006 {
   meta:
      description = "mw3 - file 0006"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "235df8f9dab95b9f7304bf2762d7a58044e2a4196a22aaaf859fe6d3764337e6"
   strings:
      $x1 = "cmd.exe /c systeminfo > " fullword wide
      $s2 = "B*\\AC:\\Documents and Settings\\Administrator\\Desktop\\HOG_ver3\\Client\\BkUPs\\withoutArrayBkup\\withoutArrayBkup(with WMI)" wide
      $s3 = "C:\\Windows\\system32\\Wbem\\wmic.exe " fullword wide
      $s4 = "yashu.exe" fullword wide
      $s5 = "\\syslog.tmp" fullword wide
      $s6 = "Wscript.Shell" fullword wide
      $s7 = "\\TempWmicBatchFile.bat" fullword wide
      $s8 = "StartProcessPipe" fullword ascii
      $s9 = "modSocketMaster.InitiateProcesses" fullword wide
      $s10 = "modSocketMaster.FinalizeProcesses" fullword wide
      $s11 = "CSocketMaster.ProcessOptions" fullword wide
      $s12 = "winmgmts:\\\\.\\root\\SecurityCenter" fullword wide
      $s13 = "comspec" fullword wide
      $s14 = "CSocketMaster.GetLocalHostName" fullword wide
      $s15 = "XRunCommand" fullword ascii
      $s16 = "Del MARJA.BAT" fullword wide
      $s17 = "Too many processes." fullword wide
      $s18 = "CSocketMaster.RemoteHost" fullword wide
      $s19 = "Shell closed at: " fullword wide
      $s20 = "Shell is already closed!" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw3_0096 {
   meta:
      description = "mw3 - file 0096"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "30472b207c5404d1ca5b9c0c686453f43cdf59dafa8a6f691aea7145ee74764c"
   strings:
      $s1 = "apphelp_.dll" fullword ascii
      $s2 = "AheadLib" fullword ascii
      $s3 = "#WU:\"W" fullword ascii
      $s4 = "\\apphelp" fullword ascii
      $s5 = " inflate 1.1.4 Copyright 1995-2002 Mark Adler " fullword ascii /* Goodware String - occured 1 times */
      $s6 = "unknown compression method" fullword ascii /* Goodware String - occured 506 times */
      $s7 = "zMzFzQif" fullword ascii
      $s8 = "PLUSUNITdXJsPWNjLm5leG9uY29ycC51czo1M3x2ZXI9MDMxOXx0YWc9bnh8Z3JvdXA9R3JvdXAzMgA=" fullword ascii
      $s9 = "QiJf:JP" fullword ascii
      $s10 = "xEFa|*f" fullword ascii
      $s11 = "}ImMmJmU" fullword ascii
      $s12 = "Fj.NoP" fullword ascii
      $s13 = "g94Wfwj@uR" fullword ascii
      $s14 = "deTFG|n_]" fullword ascii
      $s15 = "Cities" fullword ascii
      $s16 = "ApphelpReleaseExe" fullword ascii /* Goodware String - occured 2 times */
      $s17 = "\\9'b$K" fullword ascii
      $s18 = "gvlje8" fullword ascii
      $s19 = "E#hYsv" fullword ascii
      $s20 = "Wy+|yX" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0094 {
   meta:
      description = "mw3 - file 0094"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "36ab37c63db91ec8e07ca745a315751209f8852ce2d937b2d344f3ff0ca89708"
   strings:
      $s1 = "apphelp_.dll" fullword ascii
      $s2 = "AheadLib" fullword ascii
      $s3 = "PLUSUNIT" fullword ascii
      $s4 = "ExportFunc" fullword ascii
      $s5 = "\\apphelp" fullword ascii
      $s6 = " inflate 1.1.4 Copyright 1995-2002 Mark Adler " fullword ascii /* Goodware String - occured 1 times */
      $s7 = "unknown compression method" fullword ascii /* Goodware String - occured 506 times */
      $s8 = "J(nOrm?s" fullword ascii
      $s9 = "aJKioK7n" fullword ascii
      $s10 = "\"http://crl.globalsign.net/Root.crl0" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "3 5$5(5,5054585<5@5D5" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "WinmmFunc" fullword ascii
      $s13 = "{.xOZ-m" fullword ascii
      $s14 = "CitiesP" fullword ascii
      $s15 = "170127120000Z0" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "ROSSO INDEX K.K.1" fullword ascii
      $s17 = "(http://crl.globalsign.net/primobject.crl0N" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "990128130000Z" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "mSMSA!" fullword ascii
      $s20 = "$http://www.globalsign.net/repository09" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0034 {
   meta:
      description = "mw3 - file 0034"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "91953fe39748461478e6c23c94ae5dfcb6291a149be24316e759e87a4d0df12c"
   strings:
      $s1 = "MFC41.DLL" fullword wide
      $s2 = "bWZjNDEuZGF0" fullword ascii /* base64 encoded string 'mfc41.dat' */
      $s3 = "bWZjNjEuZGxs" fullword ascii /* base64 encoded string 'mfc61.dll' */
      $s4 = "cnBjcnQzMi5kbGw=" fullword ascii /* base64 encoded string 'rpcrt32.dll' */
      $s5 = "SVBTRUMgTmV0d29yayBDb25uZWN0aW9ucyBTZXJ2aWNlcw==" fullword ascii /* base64 encoded string 'IPSEC Network Connections Services' */
      $s6 = "cnBjcnQxNi5kbGw=" fullword ascii /* base64 encoded string 'rpcrt16.dll' */
      $s7 = "UHJvdmlkZSBTZXJ2aWNlcyBhbmQgTWFuYWdlciBmb3IgSVBTRUMgTmV0d29yayBDb25uZWN0aW9ucw==" fullword ascii /* base64 encoded string 'Provide Services and Manager for IPSEC Network Connections' */
      $s8 = "SW1hZ2VzLmpwZw==" fullword ascii /* base64 encoded string 'Images.jpg' */
      $s9 = "bWZjNDEuZGxs" fullword ascii /* base64 encoded string 'mfc41.dll' */
      $s10 = "= ='=,=3=8=" fullword ascii /* hex encoded string '8' */
      $s11 = "5*535`5{5" fullword ascii /* hex encoded string 'U5U' */
      $s12 = "DINGXXPAD" fullword ascii
      $s13 = "\\setup\\" fullword ascii
      $s14 = "ServiceMain" fullword ascii /* Goodware String - occured 487 times */
      $s15 = "=%>,>N>U>" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "1q1x1}1" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "= =(=,=0=4=8=<=@=D=H=L=X=p=t=x=|=" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "HtNHHu8V" fullword ascii
      $s19 = "4!4(494i4" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "jYogJE;" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0048 {
   meta:
      description = "mw3 - file 0048"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "85f4ee21ab4cd8303565356b20998448a54e66d2c495e3e8a1bc8d2d43c23742"
   strings:
      $s1 = "Credentials.dll" fullword ascii
      $s2 = "sfctlcom.exe" fullword ascii
      $s3 = "rundll32.exe \"%s\",%s" fullword ascii
      $s4 = "SavService.exe" fullword ascii
      $s5 = "SAVAdminService.exe" fullword ascii
      $s6 = "Install.dll" fullword ascii
      $s7 = "escanmon.exe" fullword ascii
      $s8 = "rtvscan.exe" fullword ascii
      $s9 = "CyberoamClient.exe" fullword ascii
      $s10 = "ALMon.exe" fullword ascii
      $s11 = "econser.exe" fullword ascii
      $s12 = "avgam.exe" fullword ascii
      $s13 = "ALsvc.exe" fullword ascii
      $s14 = "Avastsvc.exe" fullword ascii
      $s15 = "avguard.exe" fullword ascii
      $s16 = "uiwatchdog.exe" fullword ascii
      $s17 = "360tray.exe" fullword ascii
      $s18 = "ashserv.exe" fullword ascii
      $s19 = "consctl.exe" fullword ascii
      $s20 = "avpmapp.exe" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0095 {
   meta:
      description = "mw3 - file 0095"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "4f8a427586b677e0e1537a6ce73e5fae8c256a163bccce1e843335349a65bf5f"
   strings:
      $x1 = "cmd.exe /c " fullword ascii
      $s2 = "E:\\pjts2008\\Eclipse_A\\Release\\Eclipse_Client_B.pdb" fullword ascii
      $s3 = "\\\\.\\pipe\\ssnp" fullword ascii
      $s4 = "Exec failed with error code : %d" fullword ascii
      $s5 = "Create cmd shell failed with err code:%d" fullword ascii
      $s6 = "Kill process failed!" fullword ascii
      $s7 = "service exec have not implemented" fullword ascii
      $s8 = "Fail to start download thread!" fullword ascii
      $s9 = "Exec Success!" fullword ascii
      $s10 = "Client does not support this command!" fullword ascii
      $s11 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)" fullword ascii
      $s12 = "Kill process success!" fullword ascii
      $s13 = "Create named pipe failed with error code : %d" fullword ascii
      $s14 = "Connect named pipe error:%d" fullword ascii
      $s15 = "Failed to write named pipe with error code : %d" fullword ascii
      $s16 = "URL download failed with error code : %d" fullword ascii
      $s17 = "V=2&CI=an:MSIE|cpu:x86|pf:Win32|jv:1.3|fv:10&usr=%s&PI=st:12|et:1|hp:N|un:|uo:|ae:&loal=%s&js=%s&db=%s&EX=ex1" fullword ascii
      $s18 = "Runas failed with error code : %d" fullword ascii
      $s19 = "Wait named pipe connect time out" fullword ascii
      $s20 = "load.swf?" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw3_0045 {
   meta:
      description = "mw3 - file 0045"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "4ef60ae1ae8dc7b18dc2eb98cfa9cc5397c7bde79f28d4c638d360e08b9626a6"
   strings:
      $x1 = "%SystemRoot%\\SysWOW64\\svchost.exe -k netsvcs" fullword wide
      $s2 = "System32\\%s.sys" fullword wide
      $s3 = "NtfsMgradv.dll" fullword wide
      $s4 = "Radvapi32.dll" fullword wide
      $s5 = "%s\\%sadv.dll" fullword wide
      $s6 = "WxEyeKetaerCgeR" fullword ascii /* reversed goodware string 'RegCreateKeyExW' */
      $s7 = "33333333333333332222222222222222" ascii /* hex encoded string '33333333""""""""' */
      $s8 = "WxEyeKnepOgeR" fullword ascii /* reversed goodware string 'RegOpenKeyExW' */
      $s9 = "tcennoc" fullword ascii /* reversed goodware string 'connect' */
      $s10 = "333322222222" ascii /* hex encoded string '33""""' */
      $s11 = "444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444" ascii /* hex encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' */
      $s12 = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" fullword wide
      $s13 = "LDDDDDD" fullword ascii /* reversed goodware string 'DDDDDDL' */
      $s14 = "ADDDDDDDDDDD" ascii /* reversed goodware string 'DDDDDDDDDDDA' */
      $s15 = "GDDDDDDDDDDDDD" fullword ascii /* reversed goodware string 'DDDDDDDDDDDDDG' */
      $s16 = "GDDDDDDDDD" fullword ascii /* reversed goodware string 'DDDDDDDDDG' */
      $s17 = "tekcos" fullword ascii /* reversed goodware string 'socket' */
      $s18 = "%s\\System32\\%s" fullword wide
      $s19 = "eliforPlavretnIyreuQwZ" fullword ascii /* reversed goodware string 'ZwQueryIntervalProfile' */
      $s20 = "redaeHtNegamIltR" fullword ascii /* reversed goodware string 'RtlImageNtHeader' */
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw3_0040 {
   meta:
      description = "mw3 - file 0040"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "cbc35956bad533aca41d9868dd3ae268d9a14cef957f5fb53c9f4661f0c16d84"
   strings:
      $s1 = "<description> </description>" fullword ascii
      $s2 = "opmxopm" fullword ascii
      $s3 = "8k4.qXw" fullword ascii
      $s4 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGX" fullword ascii
      $s5 = "\\wVby#/ " fullword ascii
      $s6 = "ylxdIt1" fullword ascii
      $s7 = "^Y* 3F" fullword ascii
      $s8 = "0vEw- " fullword ascii
      $s9 = "_?\\ -7.M}g" fullword ascii
      $s10 = "qcvnic" fullword ascii
      $s11 = "g=% * ,9C" fullword ascii
      $s12 = "ptudja" fullword ascii
      $s13 = "v* ?]s" fullword ascii
      $s14 = "Gd%RBd%" fullword ascii
      $s15 = "~QpXoN-X" fullword ascii
      $s16 = "jAqN9):" fullword ascii
      $s17 = "k:JBoWEgw:" fullword ascii
      $s18 = ">nETLL~o4S7" fullword ascii
      $s19 = "+.!zMSPAe7" fullword ascii
      $s20 = "xfydP!" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0098 {
   meta:
      description = "mw3 - file 0098"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "3c73fdda2cb768fb8f8e38bf3ddc5cbebd1962641fdf96bb09754b7240db47ad"
   strings:
      $s1 = "\\at.exe" fullword ascii
      $s2 = "\\cacls.exe" fullword ascii
      $s3 = "windows xp" fullword ascii
      $s4 = "windows me" fullword ascii
      $s5 = "windows 2000" fullword ascii
      $s6 = "oteThread" fullword ascii
      $s7 = "windows NT 3.51" fullword ascii /* Goodware String - occured 9 times */
      $s8 = "windows 98" fullword ascii /* Goodware String - occured 9 times */
      $s9 = "windows NT 4.0" fullword ascii /* Goodware String - occured 9 times */
      $s10 = "windows 95" fullword ascii /* Goodware String - occured 9 times */
      $s11 = "VWuBhP" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "CreateRem" fullword ascii
      $s13 = "^}%95P" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "T$LQRS" fullword ascii /* Goodware String - occured 3 times */
      $s15 = "T$(Rh?" fullword ascii /* Goodware String - occured 4 times */
      $s16 = " \"%1\" %*" fullword ascii
      $s17 = "leTime" fullword ascii
      $s18 = "T$,PPR" fullword ascii
      $s19 = "T$dWWW" fullword ascii
      $s20 = "T$(h N" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0023 {
   meta:
      description = "mw3 - file 0023"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "7b3b2e430cc41ab9df9526009b246adb0f1de75a680753f79819e284d0e73f6e"
   strings:
      $s1 = "msieckc.exe" fullword ascii
      $s2 = "DCRC failed in the encrypted file %s. Corrupt file or wrong password." fullword wide
      $s3 = "#Unsupported encryption method in %s" fullword wide
      $s4 = "Jsw.PQf" fullword ascii
      $s5 = "%M%\\X6B" fullword ascii
      $s6 = "Extracting %s" fullword wide /* Goodware String - occured 4 times */
      $s7 = "Extract" fullword wide /* Goodware String - occured 44 times */
      $s8 = "Silent" fullword wide /* Goodware String - occured 74 times */
      $s9 = "Update" fullword wide /* Goodware String - occured 306 times */
      $s10 = "Install" fullword wide /* Goodware String - occured 330 times */
      $s11 = "ProgramFilesDir" fullword wide /* Goodware String - occured 372 times */
      $s12 = "SeSecurityPrivilege" fullword wide /* Goodware String - occured 374 times */
      $s13 = "SeRestorePrivilege" fullword wide /* Goodware String - occured 556 times */
      $s14 = "HtoHt>" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "HtOHt^HtBHu#" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "Z2fQ`E" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "HtEHt7" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "t0hD6A" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "zuFhl3A" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "t4SSVW" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0028 {
   meta:
      description = "mw3 - file 0028"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "45cf0d99a7b96fbf079fd53871048e1eab8ae2633986cf7bbad0991c08155c86"
   strings:
      $s1 = "C:\\windows\\Help\\isass.exe" fullword ascii
      $s2 = "C:\\wua\\Debug\\wua.pdb" fullword ascii
      $s3 = "isass.exe" fullword ascii
      $s4 = "C:\\WINDOWS\\Help\\wuaucit.exe" fullword ascii
      $s5 = "C:\\windows\\cache\\ekrr.exe" fullword ascii
      $s6 = "C:\\windows\\cache\\mgr.vbs" fullword ascii
      $s7 = "ftp.forest-fire.net" fullword ascii
      $s8 = "fgetc.c" fullword ascii
      $s9 = "wuaucit" fullword ascii
      $s10 = "nokia@forest-fire.net" fullword ascii
      $s11 = " Data: <%s> %s" fullword ascii
      $s12 = "Object dump complete." fullword ascii /* Goodware String - occured 14 times */
      $s13 = "Client hook allocation failure." fullword ascii /* Goodware String - occured 14 times */
      $s14 = "*file != _T('\\0')" fullword ascii
      $s15 = "MB_CUR_MAX == 1 || MB_CUR_MAX == 2" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "4(4D4L4X4t4|4" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "ftell.c" fullword ascii
      $s18 = "fputc.c" fullword ascii
      $s19 = "7(7D7L7X7t7|7" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "fseek.c" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0046 {
   meta:
      description = "mw3 - file 0046"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "225e9596de85ca7b1025d6e444f6a01aa6507feef213f4d2e20da9e7d5d8e430"
   strings:
      $s1 = "system" fullword wide /* Goodware String - occured 455 times */
      $s2 = "tCSWh&Q" fullword ascii
      $s3 = "hddk PQ" fullword ascii
      $s4 = "6U6b6l6" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "hParCPj" fullword ascii
      $s6 = "hParCj W" fullword ascii
      $s7 = "InitializationTimeout" fullword wide
      $s8 = "UseNT35Priority" fullword wide
      $s9 = "UsePIWriteLoop" fullword wide
      $s10 = "parclass" fullword wide
      $s11 = "0'020=0L0" fullword ascii /* Goodware String - occured 2 times */
      $s12 = "|NWWWW" fullword ascii /* Goodware String - occured 2 times */
      $s13 = "hddk j" fullword ascii
      $s14 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" ascii /* Goodware String - occured 3 times */
      $s15 = "555J5P5s5" fullword ascii
      $s16 = "9)969J9_9" fullword ascii
      $s17 = ";S;Y;_;e;l;r;x;~;" fullword ascii
      $s18 = "6Y6x6}6" fullword ascii
      $s19 = ":<:R:_:e:k:s:y:" fullword ascii
      $s20 = "6 6%62696@6G6M6S6Y6`6f6l6r6" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 80KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0090 {
   meta:
      description = "mw3 - file 0090"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "7fc451bbde170169b434102f2cb8e88912c8735ccd8b89a47e712c45b0446686"
   strings:
      $s1 = "Don't find cmd.exe,please check again or upload the program!" fullword ascii
      $s2 = "REG ADD \"HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\" /v Load /t REG_SZ /d %s /f" fullword ascii
      $s3 = "POST http://%s:%d%s HTTP/1.1" fullword ascii
      $s4 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" fullword ascii
      $s5 = "Update.bat" fullword ascii
      $s6 = "~}|{zyxwvutsrqponmlkjihgfedcba" fullword ascii /* reversed goodware string 'abcdefghijklmnopqrstuvwxyz{|}~' */
      $s7 = "%susrer__%d.ini" fullword ascii
      $s8 = "[ZYXWVU" fullword ascii /* reversed goodware string 'UVWXYZ[' */
      $s9 = "%susr32__%d.ini" fullword ascii
      $s10 = "%sos32__%d.ini" fullword ascii
      $s11 = "%s:%s-%.2f" fullword ascii
      $s12 = "ProxyEnable" fullword ascii /* Goodware String - occured 41 times */
      $s13 = "ProxyServer" fullword ascii /* Goodware String - occured 95 times */
      $s14 = "COMSPEC" fullword ascii /* Goodware String - occured 250 times */
      $s15 = "Encoding: gzip, deflate" fullword ascii
      $s16 = "yDShpP@" fullword ascii
      $s17 = "Echo off" fullword ascii
      $s18 = "/result?hl=en&meta=%s" fullword ascii
      $s19 = "\\cmd.exe" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "PSShXP@" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0026 {
   meta:
      description = "mw3 - file 0026"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "f7d1ce7807bda75a7198f3e918e73fa984d7d309d4107740899d58840eedeb88"
   strings:
      $s1 = "Pool.exe" fullword ascii
      $s2 = "$$$776333+++)))))(!!!" fullword ascii /* hex encoded string 'wc3' */
      $s3 = "222867677565454554232000" ascii /* hex encoded string '"(ggueEET# ' */
      $s4 = "222554443221" ascii /* hex encoded string '"%TD2!' */
      $s5 = "&6&,=+-?,*>*'8& - " fullword ascii /* hex encoded string 'h' */
      $s6 = "777443222100" ascii /* hex encoded string 'wtC"!' */
      $s7 = " - %3$);)):)&6&\".\"" fullword ascii /* hex encoded string '6' */
      $s8 = "767655212000" ascii /* hex encoded string 'vvU! ' */
      $s9 = "222344444334444444554554556677" ascii /* hex encoded string '"#DDC4DDDUETUfw' */
      $s10 = "23266644522100" ascii /* hex encoded string '#&fDR!' */
      $s11 = "232666445221" ascii /* hex encoded string '#&fDR!' */
      $s12 = "ihhkjj" fullword ascii /* reversed goodware string 'jjkhhi' */
      $s13 = "QQQCCC" fullword ascii /* reversed goodware string 'CCCQQQ' */
      $s14 = "\"% + (7).?/.?.,<-%4&" fullword ascii /* hex encoded string 't' */
      $s15 = "%%%444BBBUUUnon}}}yyzssseedOOO???445,,+!!!" fullword ascii
      $s16 = "()6()6()6(*6((7('6''7''7''7''6%'6%&4%&4&&5&'5$'5$'4&(5&'5%&1#!- " fullword ascii /* hex encoded string 'ffvwvdEUEQ' */
      $s17 = "* -R3C~<M" fullword ascii
      $s18 = "TTT888" fullword ascii /* reversed goodware string '888TTT' */
      $s19 = "# .I-@hBSv2Dg\"2W\"3X!1V /P 1S!1S!2S" fullword ascii
      $s20 = "*)):(3I2;S9>X<?X=AZ?A[?C]@C\\@E_CD`DGaFIdGMeHNgKSkOUmQXqTWqUYuWYvWZuWYuVYvXZwWYvWZxX\\yY\\zY[yWYxUTwSSwQRtQQsOQuORuNQuOPvNQxNPvL" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0000 {
   meta:
      description = "mw3 - file 0000"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "dc892687463cabea95456106c5d1b66ce0821c1b133eab4c38a45f0327c18e91"
   strings:
      $s1 = "6CRC failed in the encrypted file %s (wrong password ?)" fullword wide
      $s2 = "slide.exe" fullword ascii
      $s3 = "Setup=slide.exe" fullword ascii
      $s4 = ";The comment below contains SFX script commands" fullword ascii
      $s5 = "      <requestedExecutionLevel level=\"asInvoker\"" fullword ascii
      $s6 = "slide.exePK" fullword ascii
      $s7 = "conf.infPK" fullword ascii
      $s8 = "Extracting %s" fullword wide /* Goodware String - occured 4 times */
      $s9 = "Silent" fullword ascii /* Goodware String - occured 91 times */
      $s10 = "ProgramFilesDir" fullword ascii /* Goodware String - occured 167 times */
      $s11 = "Install" fullword wide /* Goodware String - occured 330 times */
      $s12 = "Update" fullword ascii /* Goodware String - occured 465 times */
      $s13 = "REPLACEFILEDLG" fullword wide /* Goodware String - occured 6 times */
      $s14 = "RENAMEDLG" fullword wide /* Goodware String - occured 6 times */
      $s15 = "LICENSEDLG" fullword wide /* Goodware String - occured 5 times */
      $s16 = "STARTDLG" fullword wide /* Goodware String - occured 5 times */
      $s17 = "Unexpected end of archiveThe file \"%s\" header is corrupt%The archive comment header is corrupt" fullword wide /* Goodware String - occured 1 times */
      $s18 = "CRC failed in %s" fullword wide /* Goodware String - occured 1 times */
      $s19 = "Packed data CRC failed in %s" fullword wide /* Goodware String - occured 1 times */
      $s20 = "Wrong password for %s5Write error in the file %s. Probably the disk is full" fullword wide /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0017 {
   meta:
      description = "mw3 - file 0017"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "95137f72b13f139e44c91df2173ea1b77db900d2721f3ba1e719ff6013e503ca"
   strings:
      $x1 = "c:\\user\\All users\\AppData\\Roaming" fullword ascii
      $s2 = "*%s\\autorun.exe" fullword ascii
      $s3 = "c:\\user\\All users" fullword ascii
      $s4 = "error to get HDD firmware serial" fullword ascii
      $s5 = "c:\\user\\All users\\Application Data" fullword ascii
      $s6 = "%systemdrive%" fullword ascii
      $s7 = "c:\\windows\\inf" fullword ascii
      $s8 = "<br> Sys User : %s@%s (%s)<br> C  P  U  : %s<br> System OS: %s (%s)<br> Net card : %s (%s)<br>" fullword ascii
      $s9 = "Microsoft Windows NT %s" fullword ascii
      $s10 = "Hello World!" fullword wide
      $s11 = "SOFTWARE\\MICROSOFT\\WINDOWS\\CurrentVersion" fullword ascii
      $s12 = "\\\\.\\C:" fullword ascii
      $s13 = "win32down Version 1.0" fullword wide
      $s14 = "%windir%" fullword ascii /* Goodware String - occured 4 times */
      $s15 = "%temp%" fullword ascii /* Goodware String - occured 6 times */
      $s16 = "autorun" fullword ascii /* Goodware String - occured 6 times */
      $s17 = "%systemroot%" fullword ascii /* Goodware String - occured 6 times */
      $s18 = "%APPDATA%" fullword ascii /* Goodware String - occured 10 times */
      $s19 = "ProcessorNameString" fullword ascii /* Goodware String - occured 10 times */
      $s20 = "%USERPROFILE%" fullword ascii /* Goodware String - occured 22 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw3_0039 {
   meta:
      description = "mw3 - file 0039"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "391adffdda738ce1d1179e715655b0baafa2505e7757185688b2e3092b8b6b2c"
   strings:
      $s1 = "hostid-tE" fullword ascii
      $s2 = ")HHOST" fullword ascii
      $s3 = "iexplore" fullword wide /* Goodware String - occured 43 times */
      $s4 = "Internet Explorer" fullword wide /* Goodware String - occured 521 times */
      $s5 = "jpJapEjb#UOPAI3o" fullword ascii
      $s6 = "PeekDmgM" fullword ascii
      $s7 = "&ha_j]?&Okbps]naXIe_nko?" fullword ascii
      $s8 = "SizLG%g" fullword ascii
      $s9 = "a?XHo]KSej`kso;" fullword ascii
      $s10 = "lp32SnapshotdL" fullword ascii
      $s11 = " HTTP/1" fullword ascii
      $s12 = "ZXCVAV#" fullword ascii
      $s13 = "^mjnj\"@sdo[" fullword ascii
      $s14 = "du]FreNameEx" fullword ascii
      $s15 = "ToWideChc[" fullword ascii
      $s16 = "lobalAl" fullword ascii
      $s17 = "iaQlH-+;Kv6" fullword ascii
      $s18 = "ShhNhduh[" fullword ascii
      $s19 = "ASDFGH:r" fullword ascii
      $s20 = "DxWk\"^_Y" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0099 {
   meta:
      description = "mw3 - file 0099"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "c3990898b7fa7de6737ecb720b1458a49835abc10ba2d15b4eee426143c0f35c"
   strings:
      $s1 = "%windir%\\ntshrui.dll" fullword ascii
      $s2 = "%windir%\\notepad.exe" fullword ascii
      $s3 = "%windir%\\explorer.exe" fullword ascii
      $s4 = "22322272227222" ascii /* hex encoded string '"2"r"r"' */
      $s5 = "222822222222222222" ascii /* hex encoded string '"("""""""' */
      $s6 = "22223222222222" ascii /* hex encoded string '""2""""' */
      $s7 = "222022222222222222" ascii /* hex encoded string '" """""""' */
      $s8 = "soft@hotmail.com1" fullword ascii
      $s9 = "QQQQQYYYYY" fullword ascii
      $s10 = "2222222222<" fullword ascii /* hex encoded string '"""""' */
      $s11 = "2322262\"2" fullword ascii /* hex encoded string '#"&"' */
      $s12 = "ccccckkkkk" fullword ascii
      $s13 = "sbbvsfs" fullword ascii
      $s14 = "CeleWare.NET1" fullword ascii
      $s15 = "INGPADDINGXXPAD" fullword ascii
      $s16 = "PADPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADD" ascii
      $s17 = "WAASUWpWWB222" fullword ascii
      $s18 = "FWJF222" fullword ascii
      $s19 = "WAASUWs222" fullword ascii
      $s20 = "VSFS222" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0018 {
   meta:
      description = "mw3 - file 0018"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "0e7383ed3a5e54409b75a3dddbd2544948acc5adac51aca5c9b69df3e49eb73d"
   strings:
      $s1 = "%windir%\\ntshrui.dll" fullword ascii
      $s2 = "%windir%\\notepad.exe" fullword ascii
      $s3 = "%windir%\\explorer.exe" fullword ascii
      $s4 = "soft@hotmail.com1" fullword ascii
      $s5 = "paaupep" fullword ascii
      $s6 = "CeleWare.NET1" fullword ascii
      $s7 = "Rjrhentehrscc" fullword ascii
      $s8 = "VirtualDesk" fullword ascii
      $s9 = "                level=\"requireAdministrator\"" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "t/v5xPzU|~~" fullword ascii
      $s11 = "RRRPhn@@" fullword ascii
      $s12 = " prog3am" fullword ascii
      $s13 = "P `.Exp" fullword ascii
      $s14 = "RjthAgenhsionh_Sesh_CLS" fullword ascii
      $s15 = "dulR=NU" fullword ascii
      $s16 = "b~wefpctm{XP_V|X_1" fullword ascii
      $s17 = "RRRVRh)E@" fullword ascii
      $s18 = "u@.tex" fullword ascii
      $s19 = "WWW.CeleWare.NET10" fullword ascii
      $s20 = "ugSDdk" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0049 {
   meta:
      description = "mw3 - file 0049"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "777bf2908b4cbc06b7c6ce1a27787c4707ad6525f92abe2d46b188f33b339278"
   strings:
      $x1 = "$%windir%\\system32\\ExplorerFrame.dll" fullword ascii
      $x2 = "%windir%\\system32\\ntshrui.dll" fullword ascii
      $s3 = "soft@hotmail.com1" fullword ascii
      $s4 = "CeleWare.NET1" fullword ascii
      $s5 = "3$VQ(xONUwU`i" fullword ascii
      $s6 = "WWW.CeleWare.NET10" fullword ascii
      $s7 = "2+292G2" fullword ascii /* Goodware String - occured 3 times */
      $s8 = "ugSDdk" fullword ascii
      $s9 = "391231235959" ascii
      $s10 = "100303035205" ascii
      $s11 = "391231235959Z0b1" fullword ascii
      $s12 = "100303035205Z" fullword ascii
      $s13 = "gv^|\\v" fullword ascii
      $s14 = "wcslcpy" fullword ascii /* Goodware String - occured 4 times */
      $s15 = "AY}8-y" fullword ascii
      $s16 = "3#3,3G3U3o3}3" fullword ascii
      $s17 = "11111111111111111111111111111111111a111" ascii
      $s18 = "5J5X5f5t5y5" fullword ascii
      $s19 = "b5]|1=" fullword ascii
      $s20 = "6$6Q6u6~6" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw3_0002 {
   meta:
      description = "mw3 - file 0002"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "11deda004de4cb1a69215da8728adad5d3db60840340e98448bd1a60f3362d25"
   strings:
      $x1 = "cmd.exe /c rundll32 \"%s\" " fullword ascii
      $x2 = "C:\\windows\\system32\\cmd.exe" fullword ascii
      $x3 = "cmd.exe /c " fullword ascii
      $s4 = "Create Child Cmd.exe Process Succeed!" fullword ascii
      $s5 = "/c ping 127.0.0.1 & del /q \"%s\"" fullword ascii
      $s6 = "Child ProcessId is %d" fullword ascii
      $s7 = "Self Process Id:%d" fullword ascii
      $s8 = "QVVVVVVh " fullword ascii /* base64 encoded string 'AUUUUa' */
      $s9 = "rss.tmp" fullword ascii
      $s10 = "iexplorer" fullword ascii
      $s11 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" fullword ascii
      $s12 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ascii
      $s13 = "%d_of_%d_for_%s_on_%s" fullword ascii
      $s14 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ascii
      $s15 = "?resid=%d&photoid=" fullword ascii
      $s16 = "=%s&type=%d&resid=%d" fullword ascii
      $s17 = ".jpg?resid=%d" fullword ascii
      $s18 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGX" fullword ascii
      $s19 = "!!!x%7 ;&3\"x59;" fullword ascii
      $s20 = "oavjah" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw3_0007 {
   meta:
      description = "mw3 - file 0007"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "51cb06da2422a76bc707333f5d09a4216014771b8f1f00c24c7194fd60acf4d1"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s2 = "usbdriver.exe" fullword wide
      $s3 = "filescan.exe" fullword wide
      $s4 = "d:\\Bitlocer\\Exception from KIS\\F drive\\BINDERS\\Original OK\\Binder\\filescan\\obj\\x86\\Debug\\filescan.pdb" fullword ascii
      $s5 = "\\NAudio.dll" fullword wide
      $s6 = "killProcess" fullword ascii
      $s7 = "mesg=Unable to Get Password Loges ( " fullword wide
      $s8 = "mesg=Unable to Get Key Loges ( " fullword wide
      $s9 = "passklogs" fullword ascii
      $s10 = "passlogs" fullword ascii
      $s11 = "\\intellUpdate.exe" fullword wide
      $s12 = "\\intellAudio.exe" fullword wide
      $s13 = "\\intellMGR.exe" fullword wide
      $s14 = "\\intellKB.exe" fullword wide
      $s15 = "pushUProcesses" fullword ascii
      $s16 = "endUProcess" fullword ascii
      $s17 = "runCProcess" fullword ascii
      $s18 = "isCProcess" fullword ascii
      $s19 = "Working Set - Private" fullword wide
      $s20 = "procl=processes" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0024 {
   meta:
      description = "mw3 - file 0024"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "63d84d50fe5d16d8a866653486050c35c760241a3c3720abd145adf4391ed9bd"
   strings:
      $s1 = "JavaSvc.exe" fullword ascii
      $s2 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC80.CRT\" version=\"8.0.50608.0\" processorArchitecture=\"x86\" publicK" ascii
      $s3 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC80.CRT\" version=\"8.0.50608.0\" processorArchitecture=\"x86\" publicK" ascii
      $s4 = "4````````````" fullword ascii /* reversed goodware string '````````````4' */
      $s5 = "44444c" ascii /* reversed goodware string 'c44444' */
      $s6 = "44444```````0^" fullword ascii /* hex encoded string 'DD@' */
      $s7 = "44444444````" fullword ascii /* hex encoded string 'DDDD' */
      $s8 = "4```````````f^" fullword ascii /* hex encoded string 'O' */
      $s9 = "7444444444444444444//`4`" fullword ascii /* hex encoded string 'tDDDDDDDDD' */
      $s10 = "@CyyyyyyyyyyyyX" fullword ascii
      $s11 = "Bppppppppppppppppp" fullword ascii
      $s12 = "p0CI? :`" fullword ascii
      $s13 = "APPDATA" fullword ascii /* Goodware String - occured 67 times */
      $s14 = "COMSPEC" fullword ascii /* Goodware String - occured 250 times */
      $s15 = "_invoke_watson" fullword ascii /* Goodware String - occured 331 times */
      $s16 = "'KKKKKKKWKKKKKKKKjKK" fullword ascii
      $s17 = "444444444444CuuukRC)uC))u4u))R\"" fullword ascii
      $s18 = "FXiX?\\F" fullword ascii
      $s19 = "'KKKKKKKW\"KKKKjj" fullword ascii
      $s20 = "QMUFKqe" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0019 {
   meta:
      description = "mw3 - file 0019"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "6c619fb910363db175f646270b0f8334a2799ca9290c649931dc8844ff45c390"
   strings:
      $s1 = "C:\\Documents and Settings\\Administrator\\Desktop\\UsbP\\Release\\UsbP.pdb" fullword ascii
      $s2 = "Set wmiLogicalDisks = wmiServices.ExecQuery (\"ASSOCIATORS OF {Win32_DiskPartition.DeviceID='\" _" fullword ascii
      $s3 = "Set wmiDiskPartitions = wmiServices.ExecQuery(query)" fullword ascii
      $s4 = "Set filetxt = filesys.OpenTextFile(s.ExpandEnvironmentStrings(\"%userprofile%\") & \"\\nttuser.txt\", 2, True)" fullword ascii
      $s5 = "D:\\Monthly Task\\August 2011\\USB Prop\\Usb Propagator.09-24\\nn\\Release\\nn.pdb" fullword ascii
      $s6 = "Set wmiDiskDrives =  wmiServices.ExecQuery (\"SELECT Caption, DeviceID FROM Win32_DiskDrive\")" fullword ascii
      $s7 = "Set wmiServices  = GetObject(\"winmgmts:{impersonationLevel=Impersonate}!//\" & ComputerName)" fullword ascii
      $s8 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii
      $s9 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii
      $s10 = "cmd /c attrib +h +s \"" fullword ascii
      $s11 = "733333333333333333333330" ascii /* hex encoded string 's33333333330' */
      $s12 = "4444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444" ascii /* hex encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' */
      $s13 = "\\nttuser.txt" fullword ascii
      $s14 = "cmd /c \"" fullword ascii
      $s15 = "Set s = WScript.CreateObject(\"WScript.Shell\")" fullword ascii
      $s16 = "\\start.vbs" fullword ascii
      $s17 = "windows dirctory " fullword ascii
      $s18 = "Set filesys = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
      $s19 = "svchost." fullword ascii
      $s20 = "abbbbbbbababbabebababbbbbbbbbbbbbbbbbabaaababbabbbbbbaabbabbaabbabbdbabbbaaabbabbabababbb" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0029 {
   meta:
      description = "mw3 - file 0029"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "05e4224d4dd4e5fbd381ed33edb5bf847fbc138fbe9f57cb7d1f8fc9fa9a382d"
   strings:
      $s1 = "%s: header error - invalid method %d (level %d)" fullword ascii
      $s2 = "%s: header error - this file is not compressed by uclpack" fullword ascii
      $s3 = "internal error - ucl_init() failed !!!" fullword ascii
      $s4 = "%s: header error - invalid block size %ld" fullword ascii
      $s5 = "%s: internal error - invalid method %d (level %d)" fullword ascii
      $s6 = "internal error - compression failed: %d" fullword ascii
      $s7 = "read error - premature end of file" fullword ascii
      $s8 = "%s: checksum error - data corrupted" fullword ascii
      $s9 = "%s: block size error - data corrupted" fullword ascii
      $s10 = "%s: unexpected failure in benchmark -- exiting." fullword ascii
      $s11 = "http://www.oberhumer.com/opensource/ucl/" fullword ascii
      $s12 = "%s: compressed data violation: error %d (0x%x: %ld/%ld/%ld)" fullword ascii
      $s13 = "something's wrong with your C library !!!" fullword ascii
      $s14 = "  %s -d compressed-file output-file        (decompress)" fullword ascii
      $s15 = "UCL data compression library (v%s, %s)." fullword ascii
      $s16 = "%s: algorithm %s, compressed %lu into %lu bytes" fullword ascii
      $s17 = "(this usually indicates a compiler bug - try recompiling" fullword ascii
      $s18 = "%s: tested ok: %-10s %-11s: %6lu -> %6lu bytes" fullword ascii
      $s19 = "  Info: To test the decompression speed on your system type:" fullword ascii
      $s20 = "Druntime error " fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0037 {
   meta:
      description = "mw3 - file 0037"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "29ad305cba186c07cedc1f633c09b9b0171289301e1d4319a1d76d0513a6ac50"
   strings:
      $s1 = "%s: header error - invalid method %d (level %d)" fullword ascii
      $s2 = "%s: header error - this file is not compressed by uclpack" fullword ascii
      $s3 = "internal error - ucl_init() failed !!!" fullword ascii
      $s4 = "%s: header error - invalid block size %ld" fullword ascii
      $s5 = "%s: internal error - invalid method %d (level %d)" fullword ascii
      $s6 = "internal error - compression failed: %d" fullword ascii
      $s7 = "read error - premature end of file" fullword ascii
      $s8 = "%s: checksum error - data corrupted" fullword ascii
      $s9 = "%s: block size error - data corrupted" fullword ascii
      $s10 = "%s: unexpected failure in benchmark -- exiting." fullword ascii
      $s11 = "http://www.oberhumer.com/opensource/ucl/" fullword ascii
      $s12 = "%s: compressed data violation: error %d (0x%x: %ld/%ld/%ld)" fullword ascii
      $s13 = "something's wrong with your C library !!!" fullword ascii
      $s14 = "  %s -d compressed-file output-file        (decompress)" fullword ascii
      $s15 = "UCL data compression library (v%s, %s)." fullword ascii
      $s16 = "%s: algorithm %s, compressed %lu into %lu bytes" fullword ascii
      $s17 = "(this usually indicates a compiler bug - try recompiling" fullword ascii
      $s18 = "%s: tested ok: %-10s %-11s: %6lu -> %6lu bytes" fullword ascii
      $s19 = "  Info: To test the decompression speed on your system type:" fullword ascii
      $s20 = "Druntime error " fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0008 {
   meta:
      description = "mw3 - file 0008"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "e215a31d89413fc3c6a25b15b215d4454db0c536bec00ba464da3ec902b35b37"
   strings:
      $s1 = "C:\\Documents and Settings\\Administrator\\Desktop\\UsbP\\Release\\UsbP.pdb" fullword ascii
      $s2 = "Set wmiLogicalDisks = wmiServices.ExecQuery (\"ASSOCIATORS OF {Win32_DiskPartition.DeviceID='\" _" fullword ascii
      $s3 = "Set wmiDiskPartitions = wmiServices.ExecQuery(query)" fullword ascii
      $s4 = "Set filetxt = filesys.OpenTextFile(s.ExpandEnvironmentStrings(\"%userprofile%\") & \"\\nttuser.txt\", 2, True)" fullword ascii
      $s5 = "D:\\Monthly Task\\August 2011\\USB Prop\\Usb Propagator.09-24\\nn\\Release\\nn.pdb" fullword ascii
      $s6 = "Set wmiDiskDrives =  wmiServices.ExecQuery (\"SELECT Caption, DeviceID FROM Win32_DiskDrive\")" fullword ascii
      $s7 = "Set wmiServices  = GetObject(\"winmgmts:{impersonationLevel=Impersonate}!//\" & ComputerName)" fullword ascii
      $s8 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii
      $s9 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii
      $s10 = "cmd /c attrib +h +s \"" fullword ascii
      $s11 = "733333333333333333333330" ascii /* hex encoded string 's33333333330' */
      $s12 = "4444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444" ascii /* hex encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' */
      $s13 = "\\nttuser.txt" fullword ascii
      $s14 = "cmd /c \"" fullword ascii
      $s15 = "Set s = WScript.CreateObject(\"WScript.Shell\")" fullword ascii
      $s16 = "\\start.vbs" fullword ascii
      $s17 = "windows dirctory " fullword ascii
      $s18 = "Set filesys = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
      $s19 = "svchost." fullword ascii
      $s20 = "abbbbbbbababbabebababbbbbbbbbbbbbbbbbabaaababbabbbbbbaabbabbaabbabbdbabbbaaabbabbabababbb" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0027 {
   meta:
      description = "mw3 - file 0027"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "ff22e63b561a42d4eb86780e9c87fdd3377d10aa0299b371ff4747d8f51fa50a"
   strings:
      $s1 = "C:\\Documents and Settings\\Administrator\\Desktop\\UsbP\\Release\\UsbP.pdb" fullword ascii
      $s2 = "Set wmiLogicalDisks = wmiServices.ExecQuery (\"ASSOCIATORS OF {Win32_DiskPartition.DeviceID='\" _" fullword ascii
      $s3 = "Set wmiDiskPartitions = wmiServices.ExecQuery(query)" fullword ascii
      $s4 = "Set filetxt = filesys.OpenTextFile(s.ExpandEnvironmentStrings(\"%userprofile%\") & \"\\nttuser.txt\", 2, True)" fullword ascii
      $s5 = "D:\\Monthly Task\\August 2011\\USB Prop\\Usb Propagator.09-24\\nn\\Release\\nn.pdb" fullword ascii
      $s6 = "Set wmiDiskDrives =  wmiServices.ExecQuery (\"SELECT Caption, DeviceID FROM Win32_DiskDrive\")" fullword ascii
      $s7 = "Set wmiServices  = GetObject(\"winmgmts:{impersonationLevel=Impersonate}!//\" & ComputerName)" fullword ascii
      $s8 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii
      $s9 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii
      $s10 = "cmd /c attrib +h +s \"" fullword ascii
      $s11 = "733333333333333333333330" ascii /* hex encoded string 's33333333330' */
      $s12 = "4444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444" ascii /* hex encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' */
      $s13 = "\\nttuser.txt" fullword ascii
      $s14 = "cmd /c \"" fullword ascii
      $s15 = "Set s = WScript.CreateObject(\"WScript.Shell\")" fullword ascii
      $s16 = "\\start.vbs" fullword ascii
      $s17 = "windows dirctory " fullword ascii
      $s18 = "Set filesys = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
      $s19 = "svchost." fullword ascii
      $s20 = "abbbbbbbababbabebababbbbbbbbbbbbbbbbbabaaababbabbbbbbaabbabbaabbabbdbabbbaaabbabbabababbb" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0044 {
   meta:
      description = "mw3 - file 0044"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "9ae42925355a43ac4eedaf36180185cce698519fbcde27974410f7adfbfd1390"
   strings:
      $s1 = "C:\\Documents and Settings\\Administrator\\Desktop\\nn\\Release\\nn.pdb" fullword ascii
      $s2 = "cmd /c attrib +h +s \"" fullword ascii
      $s3 = "svchost." fullword ascii
      $s4 = "fgjjicx" fullword ascii
      $s5 = "nn, Version 1.0" fullword wide
      $s6 = ":7:I:\\:n:" fullword ascii
      $s7 = "DINGXXPADDINGPADD" fullword ascii
      $s8 = "\\MyHood\\" fullword ascii
      $s9 = "MDJbsn7" fullword ascii
      $s10 = "%userprofile%" fullword ascii /* Goodware String - occured 2 times */
      $s11 = "About nn" fullword wide
      $s12 = "SRQk\\b" fullword ascii
      $s13 = "RSYy?q" fullword ascii
      $s14 = "3$3,3C3\\3x3" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "jgPP~*^" fullword ascii
      $s16 = "+kQMLJ;6" fullword ascii
      $s17 = "? ?(?4?T?X?\\?d?x?" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "> >(>,>0>4>8><>@>D>H>L>X>" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "URPQQhlY@" fullword ascii
      $s20 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPAD" ascii /* Goodware String - occured 2 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0030 {
   meta:
      description = "mw3 - file 0030"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "c34888f50bd1fc09b70fd5e0fbc333be9d8f0ad998221ce4fbd4cb2cc0b78f6b"
   strings:
      $s1 = "News.exe" fullword wide
      $s2 = "{575fe3f0-90b0-4542-b176-a4375548935a}, PublicKeyToken=3e56350693f7355e" fullword wide
      $s3 = "+/+4+9+>+?" fullword ascii /* hex encoded string 'I' */
      $s4 = "CreateGetStringDelegate" fullword ascii
      $s5 = "Wrong Header Signature" fullword wide
      $s6 = "Unknown Header" fullword wide
      $s7 = "pkqciea" fullword ascii
      $s8 = "SmartAssembly.Attributes" fullword ascii
      $s9 = "News.Properties" fullword ascii
      $s10 = "MemberRefsProxy" fullword ascii
      $s11 = "get__13_lnk" fullword ascii
      $s12 = "kxquzi" fullword ascii
      $s13 = "\\9gwMGF]b" fullword ascii
      $s14 = "+ ^YdK" fullword ascii
      $s15 = "V.%h%K" fullword ascii
      $s16 = "\\LwKM7GD`VJ" fullword ascii
      $s17 = "=u /O//" fullword ascii
      $s18 = "\\IaivF}R*" fullword ascii
      $s19 = "\"Powered by SmartAssembly 6.9.0.114" fullword ascii
      $s20 = "CreateDecryptor" fullword ascii /* Goodware String - occured 77 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0020 {
   meta:
      description = "mw3 - file 0020"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "e7a3e3b6c1505bc81f1844632429dfb9111fb6da3b50bec2eea8a9c5b10c0788"
   strings:
      $x1 = "cmd.exe /c rundll32 \"%s\" " fullword ascii
      $x2 = "C:\\windows\\system32\\cmd.exe" fullword ascii
      $x3 = "cmd.exe /c " fullword ascii
      $s4 = "Create Child Cmd.exe Process Succeed!" fullword ascii
      $s5 = "/c ping 127.0.0.1 & del /q \"%s\"" fullword ascii
      $s6 = "Child ProcessId is %d" fullword ascii
      $s7 = "Self Process Id:%d" fullword ascii
      $s8 = "QVVVVVVh " fullword ascii /* base64 encoded string 'AUUUUa' */
      $s9 = "rss.tmp" fullword ascii
      $s10 = "iexplorer" fullword ascii
      $s11 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" fullword ascii
      $s12 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ascii
      $s13 = "%d_of_%d_for_%s_on_%s" fullword ascii
      $s14 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ascii
      $s15 = "?resid=%d&photoid=" fullword ascii
      $s16 = "=%s&type=%d&resid=%d" fullword ascii
      $s17 = ".jpg?resid=%d" fullword ascii
      $s18 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" fullword ascii
      $s19 = "!!!x89$\">&9:3$9#\"3x59;" fullword ascii
      $s20 = "!!!x&9:7$$9#\"3x59;" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw3_0003 {
   meta:
      description = "mw3 - file 0003"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "6ff1f843fb779d35a6e9f883dbc4214faa39dedfae27666714bce477b87134ac"
   strings:
      $x1 = "cmd.exe /c rundll32 \"%s\" " fullword ascii
      $x2 = "C:\\windows\\system32\\cmd.exe" fullword ascii
      $x3 = "cmd.exe /c " fullword ascii
      $s4 = "Create Child Cmd.exe Process Succeed!" fullword ascii
      $s5 = "/c ping 127.0.0.1 & del /q \"%s\"" fullword ascii
      $s6 = "Child ProcessId is %d" fullword ascii
      $s7 = "Self Process Id:%d" fullword ascii
      $s8 = "QVVVVVVh " fullword ascii /* base64 encoded string 'AUUUUa' */
      $s9 = "rss.tmp" fullword ascii
      $s10 = "iexplorer" fullword ascii
      $s11 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" fullword ascii
      $s12 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ascii
      $s13 = "%d_of_%d_for_%s_on_%s" fullword ascii
      $s14 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ascii
      $s15 = "?resid=%d&photoid=" fullword ascii
      $s16 = "=%s&type=%d&resid=%d" fullword ascii
      $s17 = ".jpg?resid=%d" fullword ascii
      $s18 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" fullword ascii
      $s19 = "!!!x89$\">&9:3$9#\"3x59;" fullword ascii
      $s20 = "!!!x&9:7$$9#\"3x59;" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw3_0042 {
   meta:
      description = "mw3 - file 0042"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "48459e241cccaf0c4ada704f7f3dae691c89cd10a60f808d8d402a9df05448d5"
   strings:
      $x1 = "cmd.exe /c rundll32 \"%s\" " fullword ascii
      $x2 = "C:\\windows\\system32\\cmd.exe" fullword ascii
      $x3 = "cmd.exe /c " fullword ascii
      $s4 = "Create Child Cmd.exe Process Succeed!" fullword ascii
      $s5 = "/c ping 127.0.0.1 & del /q \"%s\"" fullword ascii
      $s6 = "Child ProcessId is %d" fullword ascii
      $s7 = "Self Process Id:%d" fullword ascii
      $s8 = "QVVVVVVh " fullword ascii /* base64 encoded string 'AUUUUa' */
      $s9 = "rss.tmp" fullword ascii
      $s10 = "iexplorer" fullword ascii
      $s11 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" fullword ascii
      $s12 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ascii
      $s13 = "%d_of_%d_for_%s_on_%s" fullword ascii
      $s14 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ascii
      $s15 = "?resid=%d&photoid=" fullword ascii
      $s16 = "=%s&type=%d&resid=%d" fullword ascii
      $s17 = ".jpg?resid=%d" fullword ascii
      $s18 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" fullword ascii
      $s19 = "!!!x89$\">&9:3$9#\"3x59;" fullword ascii
      $s20 = "!!!x&9:7$$9#\"3x59;" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw3_0038 {
   meta:
      description = "mw3 - file 0038"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "8e26bd2a3f142ee7042483930f5ab49ed67dbde2f2a74b97a3bd1a03cf718eb6"
   strings:
      $x1 = "cmd.exe /c rundll32 \"%s\" " fullword ascii
      $x2 = "cmd.exe /c " fullword ascii
      $s3 = "/c ping 127.0.0.1 & del /q \"%s\"" fullword ascii
      $s4 = "Self Process Id:%d" fullword ascii
      $s5 = "rss.tmp" fullword ascii
      $s6 = "iexplorer" fullword ascii
      $s7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" fullword ascii
      $s8 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ascii
      $s9 = "%d_of_%d_for_%s_on_%s" fullword ascii
      $s10 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ascii
      $s11 = "gnbxddxgacxge" fullword ascii
      $s12 = "?resid=%d&photoid=" fullword ascii
      $s13 = "=%s&type=%d&resid=%d" fullword ascii
      $s14 = ".jpg?resid=%d" fullword ascii
      $s15 = "oavjah" fullword ascii
      $s16 = "rswuvp" fullword ascii
      $s17 = "Playx64" fullword ascii
      $s18 = "PlayWin32" fullword ascii
      $s19 = "Program Files (x86)" fullword ascii /* Goodware String - occured 3 times */
      $s20 = "@%bVAAhMFVEV]eJ@a\\MPpLVAE@" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw3_0014 {
   meta:
      description = "mw3 - file 0014"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "86614ccd6e83443a8dc891fead52a16ec8b038302ec8c0fc5ffe10c7c96ccb0d"
   strings:
      $x1 = "cmd.exe /c rundll32 \"%s\" " fullword ascii
      $x2 = "cmd.exe /c " fullword ascii
      $s3 = "/c ping 127.0.0.1 & del /q \"%s\"" fullword ascii
      $s4 = "Self Process Id:%d" fullword ascii
      $s5 = "rss.tmp" fullword ascii
      $s6 = "iexplorer" fullword ascii
      $s7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" fullword ascii
      $s8 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ascii
      $s9 = "%d_of_%d_for_%s_on_%s" fullword ascii
      $s10 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ascii
      $s11 = "gnbxddxgacxge" fullword ascii
      $s12 = "?resid=%d&photoid=" fullword ascii
      $s13 = "=%s&type=%d&resid=%d" fullword ascii
      $s14 = ".jpg?resid=%d" fullword ascii
      $s15 = "oavjah" fullword ascii
      $s16 = "rswuvp" fullword ascii
      $s17 = "Playx64" fullword ascii
      $s18 = "PlayWin32" fullword ascii
      $s19 = "Program Files (x86)" fullword ascii /* Goodware String - occured 3 times */
      $s20 = "@%bVAAhMFVEV]eJ@a\\MPpLVAE@" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw3_0047 {
   meta:
      description = "mw3 - file 0047"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "5e3e8801c64b43a2c7838bc7d8f76f113be5c2efd8fe1e0e4c8d984a7d247597"
   strings:
      $x1 = "cmd.exe /c rundll32 \"%s\" " fullword ascii
      $x2 = "cmd.exe /c " fullword ascii
      $s3 = "/c ping 127.0.0.1 & del /q \"%s\"" fullword ascii
      $s4 = "Self Process Id:%d" fullword ascii
      $s5 = "rss.tmp" fullword ascii
      $s6 = "iexplorer" fullword ascii
      $s7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" fullword ascii
      $s8 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ascii
      $s9 = "%d_of_%d_for_%s_on_%s" fullword ascii
      $s10 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ascii
      $s11 = "gnbxddxgacxge" fullword ascii
      $s12 = "?resid=%d&photoid=" fullword ascii
      $s13 = "=%s&type=%d&resid=%d" fullword ascii
      $s14 = ".jpg?resid=%d" fullword ascii
      $s15 = "oavjah" fullword ascii
      $s16 = "rswuvp" fullword ascii
      $s17 = "Playx64" fullword ascii
      $s18 = "PlayWin32" fullword ascii
      $s19 = "Program Files (x86)" fullword ascii /* Goodware String - occured 3 times */
      $s20 = "@%bVAAhMFVEV]eJ@a\\MPpLVAE@" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw3_0093 {
   meta:
      description = "mw3 - file 0093"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "356716ab4c405396bbb8f0ece97bef28d62286d58482e1f9e573dcaf343f5d29"
   strings:
      $s1 = "%ALLUSERSPROFILE%\\user.dat" fullword ascii
      $s2 = "msacm32.drv" fullword ascii /* reversed goodware string 'vrd.23mcasm' */
      $s3 = "soft@hotmail.com1" fullword ascii
      $s4 = "msacm32.acm" fullword wide
      $s5 = "Well! How Are You? Yes.!!!faksjfakfasfkalfaslfkls+a" fullword ascii
      $s6 = "CeleWare.NET1" fullword ascii
      $s7 = "ImmAudio" fullword ascii
      $s8 = "01042141894819408 Error" fullword ascii
      $s9 = "Hi, MM? Is This The Book? Pardon? Yeah." fullword ascii
      $s10 = "Good morning? HaHa. I love from Ms Yang!" fullword ascii
      $s11 = "&&\"!RRRRRRR6<!>'19|aa``|= 5RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR" fullword ascii
      $s12 = "Microsoft Sound Mapper" fullword wide
      $s13 = "WWW.CeleWare.NET10" fullword ascii
      $s14 = "\\explorer.exe" fullword ascii /* Goodware String - occured 3 times */
      $s15 = "ugSDdk" fullword ascii
      $s16 = "391231235959" ascii
      $s17 = "100303035205" ascii
      $s18 = "391231235959Z0b1" fullword ascii
      $s19 = "100303035205Z" fullword ascii
      $s20 = "gv^|\\v" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0035 {
   meta:
      description = "mw3 - file 0035"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "96476145915562ec0e31f11dc9519f4f14cc4c516dee8bfa1e679bb481650eef"
   strings:
      $s1 = "wdmaud.drv" fullword ascii /* reversed goodware string 'vrd.duamdw' */
      $s2 = "CeleSign@hotmail.com1" fullword ascii
      $s3 = "euueutueiwurqoiurwquriqwuiuasdiaoudioaudiaudiaudiausdiauiosaudoaisudiaodusiajkzhdsabmnzbncbxz" fullword ascii
      $s4 = "faksjfoiasjsjzhczkfkafajsfahjshajhsf" fullword ascii
      $s5 = "CeleWare.NET1" fullword ascii
      $s6 = "WWW.CeleWare.NET1#0!" fullword ascii
      $s7 = "CeleSign0" fullword ascii
      $s8 = "h`+ Pj" fullword ascii
      $s9 = ")SsVVVVY(" fullword ascii
      $s10 = "fPdeyCd" fullword ascii
      $s11 = "fbdaVV7c1ga;7?:xeeddx9$1VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVnNVV" fullword ascii
      $s12 = "fPdRich" fullword ascii
      $s13 = "wdmAudio" fullword ascii
      $s14 = "QVVVY\"" fullword ascii
      $s15 = "dajklfjaifsiadsjaisduiadjakjdiajfkjuertietlklfdsamnz,mncm,sfajkljaklfjaskfafa" fullword ascii
      $s16 = ";\";(;.;4;:;@;F;L;R;X;" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "HKIi lY" fullword ascii
      $s18 = "\\explorer.exe" fullword ascii /* Goodware String - occured 3 times */
      $s19 = "SWVVV0" fullword ascii
      $s20 = "PVVVY5" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0009 {
   meta:
      description = "mw3 - file 0009"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "c071dafa7928ec9107a5d9f0266ae00c9d11a85e77f318229c310d2733c7ef63"
   strings:
      $x1 = "E:\\Projects\\or_project\\in_bota\\Key Logger\\chromes\\chromes\\obj\\x86\\Debug\\FireFox.pdb" fullword ascii
      $s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s3 = "FireFox.exe" fullword wide
      $s4 = "get_ShiftKey" fullword ascii
      $s5 = "get_ControlKey" fullword ascii
      $s6 = "get_kilog" fullword ascii
      $s7 = "get_AltKey" fullword ascii
      $s8 = "get_MineInterval" fullword ascii
      $s9 = "tsysini" fullword ascii
      $s10 = "<PrivateImplementationDetails>{38EEA41E-03A7-4FD3-9C44-63C214408682}" fullword ascii
      $s11 = "FireFox.Properties" fullword ascii
      $s12 = "keyBuffer" fullword ascii
      $s13 = "FireFox.Properties.Resources.resources" fullword ascii
      $s14 = "chromes.Form1.resources" fullword ascii
      $s15 = "timerKey" fullword ascii
      $s16 = "FireFox.Properties.Resources" fullword wide
      $s17 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion|allwell" fullword wide
      $s18 = "mstars-ControlKey" fullword wide
      $s19 = "mstars-LControlKey" fullword wide
      $s20 = "mstars-RControlKey" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw3_0013 {
   meta:
      description = "mw3 - file 0013"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "d541c249a98d852905273efeaa046db4dbc70ca0151fc70f1a8abd298191cb6a"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s2 = "E:\\Projects\\m_project\\main\\mj ahmed\\filebinder\\security_scan\\security_scan\\obj\\x86\\Debug\\services_scan.pdb" fullword ascii
      $s3 = "services_scan.exe" fullword wide
      $s4 = "loadermore" fullword ascii
      $s5 = "load_process" fullword ascii
      $s6 = "services_scan.My" fullword ascii
      $s7 = "services_scan" fullword ascii
      $s8 = "services_scan.Form1.resources" fullword ascii
      $s9 = "services_scan.My.Resources" fullword ascii
      $s10 = "services_scan.Resources.resources" fullword ascii
      $s11 = "moreabout" fullword ascii
      $s12 = "checkthis" fullword ascii
      $s13 = "moreabout -avgcc" fullword wide
      $s14 = "moreabout -avastui" fullword wide
      $s15 = "moreabout -avast" fullword wide
      $s16 = "moreabout -msseces" fullword wide
      $s17 = "\\System-Security|moreabout" fullword wide
      $s18 = "services_scan.Resources" fullword wide
      $s19 = "sysPort" fullword ascii
      $s20 = "bytRead" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw3_0032 {
   meta:
      description = "mw3 - file 0032"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "191be51494ba626d039470f78dc140b41c3d81ff71dd069ef118b5a8c76b0714"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s2 = "servicesDefender.exe" fullword wide
      $s3 = "*taskkill.exe" fullword ascii
      $s4 = "E:\\Projects\\mi_project\\_shib\\122\\Client\\microsoftDefender\\microsoftDefender\\obj\\x86\\Debug\\servicesDefender.pdb" fullword ascii
      $s5 = "\\msoklogs.exe" fullword wide
      $s6 = "NAudio.dll|DEFINCS" fullword wide
      $s7 = "\\security_scan.exe" fullword wide
      $s8 = "DEFINCS_pass_loader" fullword ascii
      $s9 = "\\msoclient.exe" fullword wide
      $s10 = "\\msclient.exe" fullword wide
      $s11 = "DEFINCS_list_processes" fullword ascii
      $s12 = "DEFINCS_end_process" fullword ascii
      $s13 = "DEFINCS_dieProcess" fullword ascii
      $s14 = "DEFINCS_break_process" fullword ascii
      $s15 = "DEFINCS_do_process" fullword ascii
      $s16 = "Process|DEFINCS" fullword wide
      $s17 = "Working Set - Private|DEFINCS" fullword wide
      $s18 = "DEFINCS-procl=process" fullword wide
      $s19 = "DEFINCS_get_kilog" fullword ascii
      $s20 = "msoklogs" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _0019_0008_0027_0 {
   meta:
      description = "mw3 - from files 0019, 0008, 0027"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "6c619fb910363db175f646270b0f8334a2799ca9290c649931dc8844ff45c390"
      hash2 = "e215a31d89413fc3c6a25b15b215d4454db0c536bec00ba464da3ec902b35b37"
      hash3 = "ff22e63b561a42d4eb86780e9c87fdd3377d10aa0299b371ff4747d8f51fa50a"
   strings:
      $s1 = "C:\\Documents and Settings\\Administrator\\Desktop\\UsbP\\Release\\UsbP.pdb" fullword ascii
      $s2 = "Set wmiLogicalDisks = wmiServices.ExecQuery (\"ASSOCIATORS OF {Win32_DiskPartition.DeviceID='\" _" fullword ascii
      $s3 = "Set wmiDiskPartitions = wmiServices.ExecQuery(query)" fullword ascii
      $s4 = "Set filetxt = filesys.OpenTextFile(s.ExpandEnvironmentStrings(\"%userprofile%\") & \"\\nttuser.txt\", 2, True)" fullword ascii
      $s5 = "D:\\Monthly Task\\August 2011\\USB Prop\\Usb Propagator.09-24\\nn\\Release\\nn.pdb" fullword ascii
      $s6 = "Set wmiDiskDrives =  wmiServices.ExecQuery (\"SELECT Caption, DeviceID FROM Win32_DiskDrive\")" fullword ascii
      $s7 = "Set wmiServices  = GetObject(\"winmgmts:{impersonationLevel=Impersonate}!//\" & ComputerName)" fullword ascii
      $s8 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii
      $s9 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii
      $s10 = "733333333333333333333330" ascii /* hex encoded string 's33333333330' */
      $s11 = "4444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444" ascii /* hex encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' */
      $s12 = "\\nttuser.txt" fullword ascii
      $s13 = "cmd /c \"" fullword ascii
      $s14 = "Set s = WScript.CreateObject(\"WScript.Shell\")" fullword ascii
      $s15 = "\\start.vbs" fullword ascii
      $s16 = "Set filesys = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
      $s17 = "abbbbbbbababbabebababbbbbbbbbbbbbbbbbabaaababbabbbbbbaabbabbaabbabbdbabbbaaabbabbabababbb" ascii
      $s18 = "effffffffff" ascii
      $s19 = "filetxt.WriteLine(wmiLogicalDisk.Caption & \"\\\")" fullword ascii
      $s20 = "eeebeccbefbefefeffbbbeffeecbfbeeeebefebebefbceefeceefefffffbfebeebeeebebfeebfecbbbeeecffc" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "2eee0d9ffe2fbec912166a4b7e6d087e" and ( 8 of them )
      ) or ( all of them )
}

rule _0096_0094_1 {
   meta:
      description = "mw3 - from files 0096, 0094"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "30472b207c5404d1ca5b9c0c686453f43cdf59dafa8a6f691aea7145ee74764c"
      hash2 = "36ab37c63db91ec8e07ca745a315751209f8852ce2d937b2d344f3ff0ca89708"
   strings:
      $s1 = "apphelp_.dll" fullword ascii
      $s2 = "AheadLib" fullword ascii
      $s3 = "\\apphelp" fullword ascii
      $s4 = " inflate 1.1.4 Copyright 1995-2002 Mark Adler " fullword ascii /* Goodware String - occured 1 times */
      $s5 = "unknown compression method" fullword ascii /* Goodware String - occured 506 times */
      $s6 = "ApphelpReleaseExe" fullword ascii /* Goodware String - occured 2 times */
      $s7 = "0*030:0E0L0_0s0}0" fullword ascii
      $s8 = "ApphelpShowUI" fullword ascii /* Goodware String - occured 4 times */
      $s9 = "SdbIsTagrefFromMainDB" fullword ascii /* Goodware String - occured 5 times */
      $s10 = "SdbWriteStringTagDirect" fullword ascii /* Goodware String - occured 5 times */
      $s11 = "SdbDeclareIndex" fullword ascii /* Goodware String - occured 5 times */
      $s12 = "SdbSetApphelpDebugParameters" fullword ascii /* Goodware String - occured 5 times */
      $s13 = "SdbWriteDWORDTag" fullword ascii /* Goodware String - occured 5 times */
      $s14 = "SdbGetImageType" fullword ascii /* Goodware String - occured 5 times */
      $s15 = "ShimDbgPrint" fullword ascii /* Goodware String - occured 5 times */
      $s16 = "SdbCommitIndexes" fullword ascii /* Goodware String - occured 5 times */
      $s17 = "SdbFindNextDWORDIndexedTag" fullword ascii /* Goodware String - occured 5 times */
      $s18 = "SdbStartIndexing" fullword ascii /* Goodware String - occured 5 times */
      $s19 = "SdbCreateDatabase" fullword ascii /* Goodware String - occured 5 times */
      $s20 = "SdbWriteWORDTag" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _0023_0000_2 {
   meta:
      description = "mw3 - from files 0023, 0000"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "7b3b2e430cc41ab9df9526009b246adb0f1de75a680753f79819e284d0e73f6e"
      hash2 = "dc892687463cabea95456106c5d1b66ce0821c1b133eab4c38a45f0327c18e91"
   strings:
      $s1 = "Extracting %s" fullword wide /* Goodware String - occured 4 times */
      $s2 = "Install" fullword wide /* Goodware String - occured 330 times */
      $s3 = "Unexpected end of archiveThe file \"%s\" header is corrupt%The archive comment header is corrupt" fullword wide /* Goodware String - occured 1 times */
      $s4 = "CRC failed in %s" fullword wide /* Goodware String - occured 1 times */
      $s5 = "Packed data CRC failed in %s" fullword wide /* Goodware String - occured 1 times */
      $s6 = "Wrong password for %s5Write error in the file %s. Probably the disk is full" fullword wide /* Goodware String - occured 1 times */
      $s7 = "The required volume is absent2The archive is either in unknown format or damaged" fullword wide /* Goodware String - occured 1 times */
      $s8 = "folder is not accessiblelSome files could not be created." fullword wide /* Goodware String - occured 1 times */
      $s9 = "(<\\u$8F" fullword ascii /* Goodware String - occured 2 times */
      $s10 = "V@@AAf" fullword ascii /* Goodware String - occured 2 times */
      $s11 = "WinRAR self-extracting archive" fullword wide /* Goodware String - occured 2 times */
      $s12 = "&Destination folder" fullword wide /* Goodware String - occured 2 times */
      $s13 = "Installation progress" fullword wide /* Goodware String - occured 2 times */
      $s14 = "&Enter password for the encrypted file:" fullword wide /* Goodware String - occured 2 times */
      $s15 = "Select destination folder" fullword wide /* Goodware String - occured 2 times */
      $s16 = "Skipping %s" fullword wide /* Goodware String - occured 2 times */
      $s17 = "File close error" fullword wide /* Goodware String - occured 2 times */
      $s18 = "ErroraErrors encountered while performing the operation" fullword wide /* Goodware String - occured 2 times */
      $s19 = "Look at the information window for more details" fullword wide /* Goodware String - occured 2 times */
      $s20 = "Please close all applications, reboot Windows and restart this installation\\Some installation files are corrupt." fullword wide /* Goodware String - occured 2 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _0029_0037_3 {
   meta:
      description = "mw3 - from files 0029, 0037"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "05e4224d4dd4e5fbd381ed33edb5bf847fbc138fbe9f57cb7d1f8fc9fa9a382d"
      hash2 = "29ad305cba186c07cedc1f633c09b9b0171289301e1d4319a1d76d0513a6ac50"
   strings:
      $s1 = "%s: header error - invalid method %d (level %d)" fullword ascii
      $s2 = "%s: header error - this file is not compressed by uclpack" fullword ascii
      $s3 = "internal error - ucl_init() failed !!!" fullword ascii
      $s4 = "%s: header error - invalid block size %ld" fullword ascii
      $s5 = "%s: internal error - invalid method %d (level %d)" fullword ascii
      $s6 = "internal error - compression failed: %d" fullword ascii
      $s7 = "read error - premature end of file" fullword ascii
      $s8 = "%s: checksum error - data corrupted" fullword ascii
      $s9 = "%s: block size error - data corrupted" fullword ascii
      $s10 = "%s: unexpected failure in benchmark -- exiting." fullword ascii
      $s11 = "http://www.oberhumer.com/opensource/ucl/" fullword ascii
      $s12 = "%s: compressed data violation: error %d (0x%x: %ld/%ld/%ld)" fullword ascii
      $s13 = "something's wrong with your C library !!!" fullword ascii
      $s14 = "  %s -d compressed-file output-file        (decompress)" fullword ascii
      $s15 = "UCL data compression library (v%s, %s)." fullword ascii
      $s16 = "%s: algorithm %s, compressed %lu into %lu bytes" fullword ascii
      $s17 = "(this usually indicates a compiler bug - try recompiling" fullword ascii
      $s18 = "%s: tested ok: %-10s %-11s: %6lu -> %6lu bytes" fullword ascii
      $s19 = "  Info: To test the decompression speed on your system type:" fullword ascii
      $s20 = "Druntime error " fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "a4f306d62565de360f99b64210f144eb" and ( 8 of them )
      ) or ( all of them )
}

rule _0007_0032_4 {
   meta:
      description = "mw3 - from files 0007, 0032"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "51cb06da2422a76bc707333f5d09a4216014771b8f1f00c24c7194fd60acf4d1"
      hash2 = "191be51494ba626d039470f78dc140b41c3d81ff71dd069ef118b5a8c76b0714"
   strings:
      $s1 = "tempStr" fullword ascii
      $s2 = "Hash Code: " fullword wide
      $s3 = "Norman" fullword wide
      $s4 = "\\windows_info" fullword wide
      $s5 = " /T /F" fullword wide
      $s6 = "Symantec" fullword wide /* Goodware String - occured 67 times */
      $s7 = "F-Secure" fullword wide /* Goodware String - occured 114 times */
      $s8 = "WaveInEvent" fullword ascii
      $s9 = "mTimeUtc" fullword ascii
      $s10 = "sendExp" fullword ascii
      $s11 = "SomeValue" fullword ascii
      $s12 = "tclientNum" fullword ascii
      $s13 = "EX String: " fullword wide
      $s14 = " ) Not Found!" fullword wide
      $s15 = "mainApp" fullword wide
      $s16 = "add_DataAvailable" fullword ascii /* Goodware String - occured 2 times */
      $s17 = "WaveInEventArgs" fullword ascii /* Goodware String - occured 2 times */
      $s18 = "NAudio.Wave" fullword ascii /* Goodware String - occured 2 times */
      $s19 = "<>3__path" fullword ascii /* Goodware String - occured 2 times */
      $s20 = "StopRecording" fullword ascii /* Goodware String - occured 2 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _0020_0003_0042_5 {
   meta:
      description = "mw3 - from files 0020, 0003, 0042"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "e7a3e3b6c1505bc81f1844632429dfb9111fb6da3b50bec2eea8a9c5b10c0788"
      hash2 = "6ff1f843fb779d35a6e9f883dbc4214faa39dedfae27666714bce477b87134ac"
      hash3 = "48459e241cccaf0c4ada704f7f3dae691c89cd10a60f808d8d402a9df05448d5"
   strings:
      $s1 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" fullword ascii
      $s2 = "!!!x89$\">&9:3$9#\"3x59;" fullword ascii
      $s3 = "!!!x&9:7$$9#\"3x59;" fullword ascii
      $s4 = "< ?.?4?N?S?b?k?x?" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "8)8E8N8T8]8b8q8" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "<&<;<B<H<^<y<" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "PUVh`EA" fullword ascii
      $s8 = "8>8H8`8" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "2#444n4{4" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "0030:0@0N0U0Z0c0p0v0" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "?=?J?V?^?f?r?" fullword ascii /* Goodware String - occured 2 times */
      $s12 = "?8?]?p?" fullword ascii /* Goodware String - occured 2 times */
      $s13 = "6/7H7O7W7\\7`7d7" fullword ascii /* Goodware String - occured 3 times */
      $s14 = "0,020U0\\0u0" fullword ascii
      $s15 = "9+929J9V9\\9h9w9}9" fullword ascii
      $s16 = "9\"9)9.959:9" fullword ascii
      $s17 = ">\">:>@>I>`>h>v>" fullword ascii
      $s18 = "7\"7'7,777<7D7J7S7X7_7e7" fullword ascii
      $s19 = "8/8c8i8t8" fullword ascii
      $s20 = "L$DQUUUj" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and pe.imphash() == "4511896d043677e4ab4578dc5bcab5a0" and ( 8 of them )
      ) or ( all of them )
}

rule _0038_0014_0047_6 {
   meta:
      description = "mw3 - from files 0038, 0014, 0047"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "8e26bd2a3f142ee7042483930f5ab49ed67dbde2f2a74b97a3bd1a03cf718eb6"
      hash2 = "86614ccd6e83443a8dc891fead52a16ec8b038302ec8c0fc5ffe10c7c96ccb0d"
      hash3 = "5e3e8801c64b43a2c7838bc7d8f76f113be5c2efd8fe1e0e4c8d984a7d247597"
   strings:
      $s1 = "gnbxddxgacxge" fullword ascii
      $s2 = "5*5=5O5j5r5z5" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "717`7f7u7" fullword ascii /* Goodware String - occured 1 times */
      $s4 = "1+222G2" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "1*1F1s1" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "CCPUpdate" fullword ascii
      $s7 = "6F6L6T6" fullword ascii /* Goodware String - occured 3 times */
      $s8 = ">(>8>\\>h>l>p>t>x>" fullword ascii /* Goodware String - occured 3 times */
      $s9 = "7f7o7u7" fullword ascii /* Goodware String - occured 3 times */
      $s10 = "5?\"$?.x ?&$35:92x59;" fullword ascii
      $s11 = "3\"3,353@3L3Q3a3f3l3r3" fullword ascii
      $s12 = "<\"<><f<" fullword ascii
      $s13 = "4$4>4p4" fullword ascii
      $s14 = "0 0,0H0" fullword ascii
      $s15 = "0K0^0v0" fullword ascii
      $s16 = "RichPX" fullword ascii
      $s17 = "4&5c5m5" fullword ascii
      $s18 = ">!>&>K>Q>W>" fullword ascii
      $s19 = "<@=c=n=" fullword ascii
      $s20 = "718E:G<A=" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and pe.imphash() == "539502771da573641ecc7f6497e39f8f" and ( 8 of them )
      ) or ( all of them )
}

rule _0001_0006_7 {
   meta:
      description = "mw3 - from files 0001, 0006"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "e6f0fe14026c0e1e183e105a45836d65dc917117fa5eb8ce5bf65db9e17b413b"
      hash2 = "235df8f9dab95b9f7304bf2762d7a58044e2a4196a22aaaf859fe6d3764337e6"
   strings:
      $s1 = "StartProcessPipe" fullword ascii
      $s2 = "Shell closed at: " fullword wide
      $s3 = "Shell is already closed!" fullword wide
      $s4 = "IsPipeActive" fullword ascii
      $s5 = "WriteToPipe" fullword ascii
      $s6 = "Shell started at: " fullword wide
      $s7 = "Shell is not Running!" fullword wide
      $s8 = "listen" fullword ascii /* Goodware String - occured 304 times */
      $s9 = "connect" fullword ascii /* Goodware String - occured 429 times */
      $s10 = "socket" fullword ascii /* Goodware String - occured 453 times */
      $s11 = "DataArrival" fullword ascii
      $s12 = "ClosePipe" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "SOCKET_WINDOW" fullword wide
      $s14 = "Timer2" fullword ascii /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0020_0003_0042_0038_0014_0002_0047_8 {
   meta:
      description = "mw3 - from files 0020, 0003, 0042, 0038, 0014, 0002, 0047"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "e7a3e3b6c1505bc81f1844632429dfb9111fb6da3b50bec2eea8a9c5b10c0788"
      hash2 = "6ff1f843fb779d35a6e9f883dbc4214faa39dedfae27666714bce477b87134ac"
      hash3 = "48459e241cccaf0c4ada704f7f3dae691c89cd10a60f808d8d402a9df05448d5"
      hash4 = "8e26bd2a3f142ee7042483930f5ab49ed67dbde2f2a74b97a3bd1a03cf718eb6"
      hash5 = "86614ccd6e83443a8dc891fead52a16ec8b038302ec8c0fc5ffe10c7c96ccb0d"
      hash6 = "11deda004de4cb1a69215da8728adad5d3db60840340e98448bd1a60f3362d25"
      hash7 = "5e3e8801c64b43a2c7838bc7d8f76f113be5c2efd8fe1e0e4c8d984a7d247597"
   strings:
      $x1 = "cmd.exe /c rundll32 \"%s\" " fullword ascii
      $s2 = "/c ping 127.0.0.1 & del /q \"%s\"" fullword ascii
      $s3 = "Self Process Id:%d" fullword ascii
      $s4 = "rss.tmp" fullword ascii
      $s5 = "iexplorer" fullword ascii
      $s6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" fullword ascii
      $s7 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ascii
      $s8 = "%d_of_%d_for_%s_on_%s" fullword ascii
      $s9 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ascii
      $s10 = "?resid=%d&photoid=" fullword ascii
      $s11 = "=%s&type=%d&resid=%d" fullword ascii
      $s12 = ".jpg?resid=%d" fullword ascii
      $s13 = "oavjah" fullword ascii
      $s14 = "rswuvp" fullword ascii
      $s15 = "Playx64" fullword ascii
      $s16 = "PlayWin32" fullword ascii
      $s17 = "Program Files (x86)" fullword ascii /* Goodware String - occured 3 times */
      $s18 = "@%bVAAhMFVEV]eJ@a\\MPpLVAE@" fullword ascii
      $s19 = "mWqWAVeJe@IMJ" fullword ascii
      $s20 = "gKmJMPMEHM^A" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _0010_0030_9 {
   meta:
      description = "mw3 - from files 0010, 0030"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "9f52eba3ab9b8f2ca771b30898b9a11605555334c2718cfd145bdbcfee308b1b"
      hash2 = "c34888f50bd1fc09b70fd5e0fbc333be9d8f0ad998221ce4fbd4cb2cc0b78f6b"
   strings:
      $s1 = "CreateDecryptor" fullword ascii /* Goodware String - occured 77 times */
      $s2 = "Random" fullword ascii /* Goodware String - occured 225 times */
      $s3 = "System.Security.Cryptography" fullword ascii /* Goodware String - occured 306 times */
      $s4 = "Module" fullword ascii /* Goodware String - occured 856 times */
      $s5 = "EndInvoke" fullword ascii /* Goodware String - occured 916 times */
      $s6 = "BeginInvoke" fullword ascii /* Goodware String - occured 933 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _0005_0001_10 {
   meta:
      description = "mw3 - from files 0005, 0001"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "0746a07537a701a671a16ecc980b059356ec9bd7aac31debc1277ce72b818f7b"
      hash2 = "e6f0fe14026c0e1e183e105a45836d65dc917117fa5eb8ce5bf65db9e17b413b"
   strings:
      $s1 = "-Technical and Commercial Consulting Pvt. Ltd.0" fullword ascii
      $s2 = "-Technical and Commercial Consulting Pvt. Ltd.1>0<" fullword ascii
      $s3 = "TCCPL1604" fullword ascii
      $s4 = "New Delhi1604" fullword ascii
      $s5 = "Delhi1" fullword ascii /* Goodware String - occured 2 times */
      $s6 = "121121235959Z0" fullword ascii
      $s7 = "121121235959" ascii
      $s8 = "111122000000Z" fullword ascii
      $s9 = "121231235959" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( all of them )
      ) or ( all of them )
}

rule _0007_0032_0013_11 {
   meta:
      description = "mw3 - from files 0007, 0032, 0013"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "51cb06da2422a76bc707333f5d09a4216014771b8f1f00c24c7194fd60acf4d1"
      hash2 = "191be51494ba626d039470f78dc140b41c3d81ff71dd069ef118b5a8c76b0714"
      hash3 = "d541c249a98d852905273efeaa046db4dbc70ca0151fc70f1a8abd298191cb6a"
   strings:
      $s1 = "TcpClient" fullword ascii /* Goodware String - occured 30 times */
      $s2 = "GetProcesses" fullword ascii /* Goodware String - occured 34 times */
      $s3 = "GetProcessesByName" fullword ascii /* Goodware String - occured 42 times */
      $s4 = "System.Net.Sockets" fullword ascii /* Goodware String - occured 150 times */
      $s5 = "get_MachineName" fullword ascii /* Goodware String - occured 326 times */
      $s6 = "source" fullword ascii /* Goodware String - occured 1001 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _0007_0013_12 {
   meta:
      description = "mw3 - from files 0007, 0013"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "51cb06da2422a76bc707333f5d09a4216014771b8f1f00c24c7194fd60acf4d1"
      hash2 = "d541c249a98d852905273efeaa046db4dbc70ca0151fc70f1a8abd298191cb6a"
   strings:
      $s1 = "sysPort" fullword ascii
      $s2 = "bytRead" fullword ascii
      $s3 = "tParent" fullword ascii
      $s4 = "sysStream" fullword ascii
      $s5 = "secPath" fullword ascii
      $s6 = "[Kaspersky]" fullword wide
      $s7 = "[BitDefender]" fullword wide
      $s8 = "[Symantec]" fullword wide
      $s9 = "sysSCK" fullword ascii
      $s10 = "[Avira]" fullword wide
      $s11 = "[Avast]" fullword wide
      $s12 = "[NOD32]" fullword wide
      $s13 = "[McAfee]" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _0099_0018_13 {
   meta:
      description = "mw3 - from files 0099, 0018"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "c3990898b7fa7de6737ecb720b1458a49835abc10ba2d15b4eee426143c0f35c"
      hash2 = "0e7383ed3a5e54409b75a3dddbd2544948acc5adac51aca5c9b69df3e49eb73d"
   strings:
      $s1 = "%windir%\\ntshrui.dll" fullword ascii
      $s2 = "%windir%\\notepad.exe" fullword ascii
      $s3 = "%windir%\\explorer.exe" fullword ascii
      $s4 = "VirtualDesk" fullword ascii
      $s5 = "                level=\"requireAdministrator\"" fullword ascii /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 70KB and ( all of them )
      ) or ( all of them )
}

rule _0026_0025_14 {
   meta:
      description = "mw3 - from files 0026, 0025"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "f7d1ce7807bda75a7198f3e918e73fa984d7d309d4107740899d58840eedeb88"
      hash2 = "f7fafc73621f44cdd8994151537da12c665ae9953bab22360871af59ffd646fd"
   strings:
      $s1 = "3=4&7!2%.-iqr}s}tf.7i|d}ws.1grre|f6ersi}|.2g|" fullword ascii
      $s2 = "3=4&7!2%.-iqr}s}tf.7i|d}ws.1grre|f6ersi}|.2g|=|qe" fullword ascii
      $s3 = "qftm}|\\eje" fullword ascii
      $s4 = "6*#QE!\"\"$!&!E.-iqr}s}tf.$isblak.iutjejf\\eje:265&" fullword ascii
      $s5 = "fi|fsefb\\eje" fullword ascii
      $s6 = ",}ad,iprark!" fullword ascii
      $s7 = "<=&@'3%$L@$=@<=&@3%&@&()3@$)2" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( all of them )
      ) or ( all of them )
}

rule _0098_0011_0021_0004_0036_15 {
   meta:
      description = "mw3 - from files 0098, 0011, 0021, 0004, 0036"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "3c73fdda2cb768fb8f8e38bf3ddc5cbebd1962641fdf96bb09754b7240db47ad"
      hash2 = "e25aefb76f65e7ebcbacf77f5179b21b20492f18bfd2a881ea744fefbaf22965"
      hash3 = "f85dcff1767efa6ad479a72018a445824d7c4919fffbdd61fa3bff3a8fc79a83"
      hash4 = "4f6f9707741ec6f0bff3b43254f113b7ba2aae6326cbf50f6b0139254757f1d0"
      hash5 = "86cd1a78e1db662c832d138ecc5f96c2637b9bb893577bda62dc4ab3f50397b7"
   strings:
      $s1 = "windows xp" fullword ascii
      $s2 = "windows me" fullword ascii
      $s3 = "windows 2000" fullword ascii
      $s4 = "windows NT 3.51" fullword ascii /* Goodware String - occured 9 times */
      $s5 = "windows 98" fullword ascii /* Goodware String - occured 9 times */
      $s6 = "windows NT 4.0" fullword ascii /* Goodware String - occured 9 times */
      $s7 = "windows 95" fullword ascii /* Goodware String - occured 9 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and ( all of them )
      ) or ( all of them )
}

rule _0004_0036_16 {
   meta:
      description = "mw3 - from files 0004, 0036"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "4f6f9707741ec6f0bff3b43254f113b7ba2aae6326cbf50f6b0139254757f1d0"
      hash2 = "86cd1a78e1db662c832d138ecc5f96c2637b9bb893577bda62dc4ab3f50397b7"
   strings:
      $s1 = "T$hQRj" fullword ascii /* Goodware String - occured 2 times */
      $s2 = "D$(Ph?" fullword ascii /* Goodware String - occured 3 times */
      $s3 = "T$ ;t$$" fullword ascii
      $s4 = "PQjPRS" fullword ascii
      $s5 = ";D$8uH" fullword ascii
      $s6 = "/Tiblue" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and ( all of them )
      ) or ( all of them )
}

rule _0019_0044_0008_0027_17 {
   meta:
      description = "mw3 - from files 0019, 0044, 0008, 0027"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "6c619fb910363db175f646270b0f8334a2799ca9290c649931dc8844ff45c390"
      hash2 = "9ae42925355a43ac4eedaf36180185cce698519fbcde27974410f7adfbfd1390"
      hash3 = "e215a31d89413fc3c6a25b15b215d4454db0c536bec00ba464da3ec902b35b37"
      hash4 = "ff22e63b561a42d4eb86780e9c87fdd3377d10aa0299b371ff4747d8f51fa50a"
   strings:
      $s1 = "cmd /c attrib +h +s \"" fullword ascii
      $s2 = "svchost." fullword ascii
      $s3 = "nn, Version 1.0" fullword wide
      $s4 = "\\MyHood\\" fullword ascii
      $s5 = "About nn" fullword wide
      $s6 = "\\MyHood" fullword ascii
      $s7 = "explorer " fullword ascii /* Goodware String - occured 3 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of them )
      ) or ( all of them )
}

rule _0099_0018_0049_0093_18 {
   meta:
      description = "mw3 - from files 0099, 0018, 0049, 0093"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "c3990898b7fa7de6737ecb720b1458a49835abc10ba2d15b4eee426143c0f35c"
      hash2 = "0e7383ed3a5e54409b75a3dddbd2544948acc5adac51aca5c9b69df3e49eb73d"
      hash3 = "777bf2908b4cbc06b7c6ce1a27787c4707ad6525f92abe2d46b188f33b339278"
      hash4 = "356716ab4c405396bbb8f0ece97bef28d62286d58482e1f9e573dcaf343f5d29"
   strings:
      $s1 = "soft@hotmail.com1" fullword ascii
      $s2 = "WWW.CeleWare.NET10" fullword ascii
      $s3 = "ugSDdk" fullword ascii
      $s4 = "100303035205" ascii
      $s5 = "391231235959Z0b1" fullword ascii
      $s6 = "100303035205Z" fullword ascii
      $s7 = "gv^|\\v" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 70KB and ( all of them )
      ) or ( all of them )
}

rule _0020_0003_0042_0002_19 {
   meta:
      description = "mw3 - from files 0020, 0003, 0042, 0002"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "e7a3e3b6c1505bc81f1844632429dfb9111fb6da3b50bec2eea8a9c5b10c0788"
      hash2 = "6ff1f843fb779d35a6e9f883dbc4214faa39dedfae27666714bce477b87134ac"
      hash3 = "48459e241cccaf0c4ada704f7f3dae691c89cd10a60f808d8d402a9df05448d5"
      hash4 = "11deda004de4cb1a69215da8728adad5d3db60840340e98448bd1a60f3362d25"
   strings:
      $x1 = "C:\\windows\\system32\\cmd.exe" fullword ascii
      $s2 = "Create Child Cmd.exe Process Succeed!" fullword ascii
      $s3 = "Child ProcessId is %d" fullword ascii
      $s4 = "QVVVVVVh " fullword ascii /* base64 encoded string 'AUUUUa' */
      $s5 = "UUUWUU" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

