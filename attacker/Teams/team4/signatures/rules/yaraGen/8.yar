/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2024-04-17
   Identifier: mw8
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule _root_BytMe_new_datasets_mw8_0026 {
   meta:
      description = "mw8 - file 0026"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "a8532fd627a6266d70e7ada075092dc1779b4d76344c1dd5228b506a25425fb5"
   strings:
      $s1 = "hIkUHF0" fullword ascii
      $s2 = "7!'<>~1.~" fullword ascii /* hex encoded string 'q' */
      $s3 = "Z- ,w$" fullword ascii
      $s4 = "G* (@tmW" fullword ascii
      $s5 = "c_tL* h" fullword ascii
      $s6 = "6@qZKMH?" fullword ascii
      $s7 = ".ncgeZIH" fullword ascii
      $s8 = "puzQjn#" fullword ascii
      $s9 = "RnhyH-&" fullword ascii
      $s10 = "VWumh0eA" fullword ascii
      $s11 = "Richs~-" fullword ascii
      $s12 = "LYZwQ2w" fullword ascii
      $s13 = "OwUT4T(" fullword ascii
      $s14 = "XMwjuk%8" fullword ascii
      $s15 = "AFjd2Q`G!M" fullword ascii
      $s16 = "hefsYp<" fullword ascii
      $s17 = "PGiD,|/" fullword ascii
      $s18 = "zSGr4sw" fullword ascii
      $s19 = "PfkldZk" fullword ascii
      $s20 = "sIOgSnKW" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0041 {
   meta:
      description = "mw8 - file 0041"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "14de93b75aeed39cb17d7f1ab0a89b85fbfe6c0fa77aeb18c0f6d88c3ff31ac0"
   strings:
      $s1 = "kXNgiv4" fullword ascii
      $s2 = "Q`b /B" fullword ascii
      $s3 = "\\AMPSE;p" fullword ascii
      $s4 = "!g6dV- " fullword ascii
      $s5 = "\\haXS!" fullword ascii
      $s6 = "dbez_Jh}b=h|a9g{`9dx]<i|a\"x" fullword ascii
      $s7 = "qtoz01/D" fullword ascii
      $s8 = "BpvW]|27!" fullword ascii
      $s9 = "kzqs>_Y\\" fullword ascii
      $s10 = "NKvs/\\-" fullword ascii
      $s11 = "QlNA%LQ" fullword ascii
      $s12 = "VzIl?%'6" fullword ascii
      $s13 = "yrTq[VN" fullword ascii
      $s14 = "UwBC.,;" fullword ascii
      $s15 = "crTBX}j" fullword ascii
      $s16 = "FZtmLbK" fullword ascii
      $s17 = "MwzawaS" fullword ascii
      $s18 = "K].THU" fullword ascii
      $s19 = "LRfaPkC" fullword ascii
      $s20 = "xWtP;fL" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0003 {
   meta:
      description = "mw8 - file 0003"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "126098ebd05b174855d9b4c5be852ca1ab07433d37fe1997396f1776c9da9f00"
   strings:
      $s1 = "96%I|?pFjR,6?~" fullword ascii
      $s2 = "l-+v+ " fullword ascii
      $s3 = "6a* So8xA+ls&%c" fullword ascii
      $s4 = "+(w- iJ" fullword ascii
      $s5 = " /vS4/" fullword ascii
      $s6 = "mhbokn" fullword ascii
      $s7 = "5* ljp" fullword ascii
      $s8 = "dbez_Jh}b=h|a9g{`9dx]<i|a\"x" fullword ascii
      $s9 = "qtoz01/D" fullword ascii
      $s10 = ")bnev^\\" fullword ascii
      $s11 = "lBcictY" fullword ascii
      $s12 = "PeZu#g3" fullword ascii
      $s13 = "zGfeB$/" fullword ascii
      $s14 = "WCwt'.1" fullword ascii
      $s15 = "qNUOs?:" fullword ascii
      $s16 = "e0.QZE" fullword ascii
      $s17 = "zbcN5(BK" fullword ascii
      $s18 = "qChl&A5&Z" fullword ascii
      $s19 = "m\"mQYfTk]" fullword ascii
      $s20 = "TKnn$u|" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0005 {
   meta:
      description = "mw8 - file 0005"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "1318f251551d231059acec8da61ea71dc7ff425533217a2769792dd4608909f5"
   strings:
      $s1 = "q- 4b," fullword ascii
      $s2 = "%f%zz4" fullword ascii
      $s3 = "5]SAM)X" fullword ascii
      $s4 = "dbez_Jh}b=h|a9g{`9dx]<i|a\"x" fullword ascii
      $s5 = "qtoz01/D" fullword ascii
      $s6 = "CWYu-z*1%" fullword ascii
      $s7 = "oYGc*==Y" fullword ascii
      $s8 = "aajN}Um" fullword ascii
      $s9 = "%%d5ORIvU" fullword ascii
      $s10 = "gkLi,h.(/" fullword ascii
      $s11 = "pPDG!D~" fullword ascii
      $s12 = "DntOqfk" fullword ascii
      $s13 = "GgqpzYd" fullword ascii
      $s14 = "QlYXjTm" fullword ascii
      $s15 = "ITYk3*$" fullword ascii
      $s16 = "jtIqfaEv/" fullword ascii
      $s17 = "1DpajZz#" fullword ascii
      $s18 = "qxOZik|FGN" fullword ascii
      $s19 = "skUY0m*rZ" fullword ascii
      $s20 = "UCUTc7/" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0031 {
   meta:
      description = "mw8 - file 0031"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "139b1f1498c4ca983af2d1adf8988380a7abcb902d12e393ab78e11e695b0a34"
   strings:
      $s1 = "jotlibg" fullword ascii
      $s2 = " Data: <%s> %s" fullword ascii
      $s3 = "((VG:\"" fullword ascii
      $s4 = "vOYtR60" fullword ascii
      $s5 = "# dB2V" fullword ascii
      $s6 = ".DZ%lf* " fullword ascii
      $s7 = "+ GN]\\J" fullword ascii
      $s8 = "Object dump complete." fullword ascii /* Goodware String - occured 14 times */
      $s9 = "Client hook allocation failure." fullword ascii /* Goodware String - occured 14 times */
      $s10 = "NripoWo" fullword ascii
      $s11 = "ZbxYNvS4*" fullword ascii
      $s12 = " 7dDyLzV /" fullword ascii
      $s13 = "\"cenTa[1" fullword ascii
      $s14 = "CFIS|];#" fullword ascii
      $s15 = "XtbdHul" fullword ascii
      $s16 = "mXRg0:MR<`1le" fullword ascii
      $s17 = ".lAt%P" fullword ascii
      $s18 = "iZWRZUJ" fullword ascii
      $s19 = "WMUG5GTEp&[v" fullword ascii
      $s20 = "@IOej$Ok" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0010 {
   meta:
      description = "mw8 - file 0010"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "5903e44a25d83b0178a8ec8abce7f796a06618d5d581fd2564806fbe4ac385d5"
   strings:
      $x1 = "cmd.exe /c rundll32 \"%s\" " fullword ascii
      $x2 = "C:\\windows\\system32\\cmd.exe" fullword ascii
      $x3 = "C:\\Users\\Entebbe Office\\AppData\\Local\\Temp\\Temp1_TAX_julie.kisakye.zip\\TAX_09232013.exe" fullword wide
      $x4 = "cmd.exe /c " fullword ascii
      $s5 = "Create Child Cmd.exe Process Succeed!" fullword ascii
      $s6 = "C:\\HKC6RBIN.exe" fullword wide
      $s7 = "/c ping 127.0.0.1 & del /q \"%s\"" fullword ascii
      $s8 = "C:\\54J7P0cG.exe" fullword wide
      $s9 = "C:\\rROxbuXq.exe" fullword wide
      $s10 = "C:\\v0EyvL97.exe" fullword wide
      $s11 = "C:\\0HlcmOli.exe" fullword wide
      $s12 = "C:\\rR8MKeIg.exe" fullword wide
      $s13 = "C:\\dcplmWB7.exe" fullword wide
      $s14 = "C:\\j1bvMQM1.exe" fullword wide
      $s15 = "C:\\niFb1y5R.exe" fullword wide
      $s16 = "C:\\edJF7ehQ.exe" fullword wide
      $s17 = "C:\\fUdjolCv.exe" fullword wide
      $s18 = "C:\\vcgHNubW.exe" fullword wide
      $s19 = "C:\\lADi8VEE.exe" fullword wide
      $s20 = "C:\\rihmBqej.exe" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw8_0011 {
   meta:
      description = "mw8 - file 0011"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "84be50d8058e067e73f76756dd4aa295273962ec4d0f159a0795533dc1fea7b3"
   strings:
      $x1 = "cmd.exe /c rundll32 \"%s\" " fullword ascii
      $x2 = "C:\\windows\\system32\\cmd.exe" fullword ascii
      $x3 = "C:\\Users\\Entebbe Office\\AppData\\Local\\Temp\\Temp1_TAX_julie.kisakye.zip\\TAX_09232013.exe" fullword wide
      $x4 = "cmd.exe /c " fullword ascii
      $s5 = "C:\\vrFDLlh2.exe" fullword wide
      $s6 = "Create Child Cmd.exe Process Succeed!" fullword ascii
      $s7 = "C:\\HKC6RBIN.exe" fullword wide
      $s8 = "/c ping 127.0.0.1 & del /q \"%s\"" fullword ascii
      $s9 = "C:\\54J7P0cG.exe" fullword wide
      $s10 = "C:\\Ms09fR4y.exe" fullword wide
      $s11 = "C:\\rROxbuXq.exe" fullword wide
      $s12 = "C:\\v0EyvL97.exe" fullword wide
      $s13 = "C:\\0HlcmOli.exe" fullword wide
      $s14 = "C:\\rR8MKeIg.exe" fullword wide
      $s15 = "C:\\dcplmWB7.exe" fullword wide
      $s16 = "C:\\j1bvMQM1.exe" fullword wide
      $s17 = "C:\\niFb1y5R.exe" fullword wide
      $s18 = "C:\\edJF7ehQ.exe" fullword wide
      $s19 = "C:\\fUdjolCv.exe" fullword wide
      $s20 = "C:\\vcgHNubW.exe" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw8_0004 {
   meta:
      description = "mw8 - file 0004"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "6337a5fcdc5a80cc0abf7eaf4d79c972f55275f76743eb27c56472dd28b6bc4d"
   strings:
      $x1 = "C:\\Windows\\system32\\rundll32.exe C:\\windows\\getEnv.dll InjectCreateMy" fullword ascii
      $x2 = "</HTML>P<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"XP style manifest" ascii
      $x3 = "C:\\Windows\\SysWOW64\\rundll32.exe C:\\windows\\getEnv.dll InjectCreateMy" fullword ascii
      $x4 = ", Tahoma, MS Shell Dlg\" href=\"http://www.microsoft.com/isapi/redir.dll?prd=ie&pver=6.0&ar=aboutie&sba=copyr\" id=\"copyright\"" ascii
      $x5 = "if exist \"%userprofile%\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\%%i\\Cache\" rd /s /q \"%userprofile%\\AppData\\Local\\Moz" ascii
      $x6 = "if exist \"%userprofile%\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\%%i\\Cache\" rd /s /q \"%userprofile%\\AppData\\Local\\Moz" ascii
      $x7 = "\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" publicKeyToken=\"6595b641" ascii
      $x8 = "ProcessHelperWin32.dll" fullword ascii
      $x9 = "C:\\Windows\\System32\\cBLK.dll" fullword ascii
      $x10 = "C:\\windows\\getEnv.dll" fullword ascii
      $x11 = "del /f /s /q \"%userprofile%\\AppData\\Local\\Opera\\Opera\\cache\\*.*\"" fullword ascii
      $x12 = "rd /q /s \"%userprofile%\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.IE5\"" fullword ascii
      $x13 = "rd /q /s \"%userprofile%\\Local Settings\\Temporary Internet Files\\Content.IE5\"" fullword ascii
      $x14 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii
      $x15 = "if exist \"%userprofile%\\Local Settings\\Application Data\\Mozilla\\Firefox\\Profiles\\%%i\\Cache\" rd /s /q \"%userprofile%\\L" ascii
      $x16 = "if exist \"%userprofile%\\Local Settings\\Application Data\\Mozilla\\Firefox\\Profiles\\%%i\\Cache\" rd /s /q \"%userprofile%\\L" ascii
      $x17 = "'dir \"%userprofile%\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\*.default\" /B'" fullword ascii
      $x18 = "del /f /s /q \"%userprofile%\\Local Settings\\Temporary Internet Files\\*.flv\"" fullword ascii
      $x19 = "del /f /s /q \"%userprofile%\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\*.swf\"" fullword ascii
      $x20 = "del /f /s /q \"%userprofile%\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\*.xml\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      1 of ($x*)
}

rule _root_BytMe_new_datasets_mw8_0017 {
   meta:
      description = "mw8 - file 0017"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "0f8f3518e05864ab2c164de6a61df51b20b2f7f2eae2edf8049b247f43f89b90"
   strings:
      $s1 = "ZVVVVVVVP" fullword ascii /* base64 encoded string 'eUUUUU' */
      $s2 = "666666666666666660" ascii /* hex encoded string 'ffffffff`' */
      $s3 = "SQQQQQQQ" fullword ascii /* reversed goodware string 'QQQQQQQS' */
      $s4 = "UXVVVVVb." fullword ascii /* base64 encoded string 'QuUUU[' */
      $s5 = "Pfile.hlp" fullword ascii
      $s6 = "Help.hlp" fullword ascii
      $s7 = "i.#etnnnocFulIrCedntlteeIrCe#Pi#etsn#ielnnp#etnApFAteoaewndIrOAtentttennlHl" fullword ascii
      $s8 = "i.#etnnnocFelIrCedntlteeIrCe#Gi#etsn#ielnnp#etnApFAteoaewndIrOAtentttennlHl" fullword ascii
      $s9 = ">666666666666666660" fullword ascii /* hex encoded string 'ffffffff`' */
      $s10 = "xXXXXXXXXXXXXXXYYYYYYYYYL1" fullword ascii
      $s11 = "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh" ascii
      $s12 = "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh" ascii
      $s13 = "ehlmgnl" fullword ascii
      $s14 = "hhhhhhhhhhhhhhhhhhhhhhhhhh" fullword ascii
      $s15 = "mptuovt" fullword ascii
      $s16 = "jusched" fullword wide
      $s17 = " Data: <%s> %s" fullword ascii
      $s18 = "/Private/" fullword ascii
      $s19 = "9A:K:Q:\\:h:m:" fullword ascii
      $s20 = "9.:7:E:M:S:\\:d:l:r:{:" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0020 {
   meta:
      description = "mw8 - file 0020"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "7de45fd60ebaeff04c3b8365590654aebe243da8c68c5c078abd2e5b24030ed1"
   strings:
      $s1 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" language=\"*\" processorAr" ascii
      $s2 = "/AutoIt3ExecuteScript" fullword wide
      $s3 = "*Unable to get a list of running processes. Unable to get the process token.Invalid element in a DllStruct.*Unknown option or b" wide
      $s4 = "This is a compiled AutoIt script. AV researchers please email avsupport@autoitscript.com for support." fullword ascii
      $s5 = "/AutoIt3ExecuteLine" fullword wide
      $s6 = "WINGETPROCESS" fullword wide
      $s7 = "PROCESSGETSTATS" fullword wide
      $s8 = "SCRIPTNAME" fullword wide /* base64 encoded string 'H$H=3@0' */
      $s9 = "SHELLEXECUTEWAIT" fullword wide
      $s10 = "SHELLEXECUTE" fullword wide
      $s11 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" language=\"*\" processorAr" ascii
      $s12 = "Error parsing function call.0Incorrect number of parameters in function call.'\"ReDim\" used without an array variable.>Illegal " wide
      $s13 = "#NoAutoIt3Execute" fullword wide
      $s14 = "PROCESSWAITCLOSE" fullword wide
      $s15 = "PROCESSWAIT" fullword wide
      $s16 = "PROCESSSETPRIORITY" fullword wide
      $s17 = "PROCESSLIST" fullword wide
      $s18 = "PROCESSEXISTS" fullword wide
      $s19 = "PROCESSCLOSE" fullword wide
      $s20 = "HTTPSETUSERAGENT" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0023 {
   meta:
      description = "mw8 - file 0023"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "0df38d4fdc3b3fe240df1ce96c59d57d871ab82472cad93a3c0ad5908c4b648d"
   strings:
      $s1 = "System64.exe" fullword ascii
      $s2 = "userinit.exe" fullword ascii
      $s3 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\" fullword ascii
      $s4 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor" fullword ascii
      $s5 = "WinLogon" fullword ascii
      $s6 = "KMe.bat" fullword ascii
      $s7 = "UnitProcess" fullword ascii
      $s8 = "cmd /c del " fullword ascii
      $s9 = "        <requestedExecutionLevel level=\"requireAdministrator\"/> " fullword ascii
      $s10 = "CmderUnit" fullword ascii
      $s11 = "StartDll" fullword ascii
      $s12 = "TScreenSpy" fullword ascii
      $s13 = "InfoDll" fullword ascii
      $s14 = "3ScreenSpy" fullword ascii
      $s15 = "StopDll" fullword ascii
      $s16 = "UnitDll" fullword ascii
      $s17 = "TDownFileThread" fullword ascii
      $s18 = "TThread`j@" fullword ascii
      $s19 = ":4:<:@:D:H:L:P:T:X:\\:`:d:h:l:p:t:" fullword ascii
      $s20 = "MyService" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0036 {
   meta:
      description = "mw8 - file 0036"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "da2647308182976cf68aeb4b7aa4df35a824fc9ecf3dfd983584e32f9c8d0421"
   strings:
      $s1 = "\\system32\\cabinet.dll" fullword ascii
      $s2 = "EFailed to Initialize File Dialogs. Change the Filename and try again." fullword wide
      $s3 = "NPSAVEDIALOG" fullword wide
      $s4 = "This file contains characters in Unicode format which will be lost if you save this file as a text document. To keep the Unicode" wide
      $s5 = "AEXzeYEkspD4kKFaa5fVJIj7Zmpzq5yoWIoGnKU" fullword wide
      $s6 = "yoeeqio" fullword ascii
      $s7 = ":The %% file already exists." fullword wide
      $s8 = "Xibzooh" fullword ascii
      $s9 = "bkoxqa" fullword ascii
      $s10 = "trkkzv" fullword ascii
      $s11 = "opaugu" fullword ascii
      $s12 = "ftPllcAbereMp" fullword ascii
      $s13 = "%NIA%^" fullword ascii
      $s14 = "\\F[dohaKP\\" fullword ascii
      $s15 = "\\s/UaaLYBlF" fullword ascii
      $s16 = "nU?5qP+ " fullword ascii
      $s17 = "\\rBbanCQar1@rs" fullword ascii
      $s18 = "UBLZtyA7ZCIkZc80" fullword ascii
      $s19 = "]GrvcVxc" fullword ascii
      $s20 = "hhnnF]a[GqT)Dgn" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0044 {
   meta:
      description = "mw8 - file 0044"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "f61568d1e03ffad80f1b2b456b53d6172c20a18a25b5fab8daecdb0d5f269428"
   strings:
      $s1 = "Error setting %s.Count8Listbox (%s) style must be virtual in order to set Count\"Unable to find a Table of Contents" fullword wide
      $s2 = "JZZZZZZ" fullword ascii /* reversed goodware string 'ZZZZZZJ' */
      $s3 = "YZZZZZZ" fullword ascii /* reversed goodware string 'ZZZZZZY' */
      $s4 = "ZZZZZZ5" fullword ascii /* reversed goodware string '5ZZZZZZ' */
      $s5 = "ZZZZZZb" fullword ascii /* reversed goodware string 'bZZZZZZ' */
      $s6 = "ZZZZZZ^" fullword ascii /* reversed goodware string '^ZZZZZZ' */
      $s7 = "ZZZZZZo" fullword ascii /* reversed goodware string 'oZZZZZZ' */
      $s8 = "TCommonDialog0oB" fullword ascii
      $s9 = "8ZZZZZZ" fullword ascii /* reversed goodware string 'ZZZZZZ8' */
      $s10 = ";ZZZZZZ" fullword ascii /* reversed goodware string 'ZZZZZZ;' */
      $s11 = "6ZZZZZZ" fullword ascii /* reversed goodware string 'ZZZZZZ6' */
      $s12 = "}ZZZZZZ" fullword ascii /* reversed goodware string 'ZZZZZZ}' */
      $s13 = "[ZZZZZZ" fullword ascii /* reversed goodware string 'ZZZZZZ[' */
      $s14 = "TSaveDialog`vB" fullword ascii
      $s15 = "TFontDialogtxB" fullword ascii
      $s16 = "7 7$7(7,7074787>7" fullword ascii /* hex encoded string 'wwptxw' */
      $s17 = "6,646\\6~6" fullword ascii /* hex encoded string 'fFf' */
      $s18 = "OnTypeChangetrB" fullword ascii
      $s19 = "Dialogs8rB" fullword ascii
      $s20 = "2 2$2(2,2:2" fullword ascii /* hex encoded string '"""' */
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0021 {
   meta:
      description = "mw8 - file 0021"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "db35f03ab4fb2eff6dfa485e85433f4a61016fc2e18b17793e8e0b6c8afe5585"
   strings:
      $s1 = "$) $&+ \"!." fullword ascii
      $s2 = "'*6A-, >?" fullword ascii /* hex encoded string 'j' */
      $s3 = "telebarograph" fullword ascii
      $s4 = "SYZCMNE" fullword ascii
      $s5 = ".!!!)(*" fullword ascii
      $s6 = ", --&'+" fullword ascii
      $s7 = "!(&%!." fullword ascii
      $s8 = ". -$ ()\"" fullword ascii
      $s9 = "#-%#'\" -+-*&)(-" fullword ascii
      $s10 = "+)-,&*&+ " fullword ascii
      $s11 = "!$- -$" fullword ascii
      $s12 = "!#&#\"!." fullword ascii
      $s13 = "*!%\"+ " fullword ascii
      $s14 = "$\"( + " fullword ascii
      $s15 = "'\".- *," fullword ascii
      $s16 = "**%#! -(" fullword ascii
      $s17 = "CE- 'J7LL3*" fullword ascii
      $s18 = " -.')'" fullword ascii
      $s19 = "-(%* ,$" fullword ascii
      $s20 = "?D6- 7" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0013 {
   meta:
      description = "mw8 - file 0013"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "9f3b6ae52f67dd57def895399b137a0d6a13bbb925172cb78f43f17206eb87e3"
   strings:
      $s1 = "Only deletes regkey(s) matching the given registry key if they have no subkeys or values" fullword ascii
      $s2 = "A driver controlling a PCI device has tried to access OS controlled configuration space registers (!devstack %DevObj, Offset 0x%" ascii
      $s3 = "fadF^u3" fullword ascii
      $s4 = "Ulong1, Length 0x%Ulong2)" fullword ascii
      $s5 = "EV_MMAC_OID_IWLAN_ADDBA_REQ" fullword ascii
      $s6 = "OoHQxR|" fullword ascii
      $s7 = "guboh/%;9>" fullword ascii
      $s8 = "j hXXA" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "^npacTN " fullword ascii
      $s10 = "IPPDDHH_" fullword wide
      $s11 = "Residual Error Power: %f dBm" fullword ascii /* Goodware String - occured 2 times */
      $s12 = "-   NoiseLevelAllFreq  = %f " fullword ascii /* Goodware String - occured 2 times */
      $s13 = "------------MSG:%s  T:%dms " fullword ascii /* Goodware String - occured 2 times */
      $s14 = "G_ApplyPJP" fullword ascii /* Goodware String - occured 2 times */
      $s15 = "Richps" fullword ascii
      $s16 = "dpSetMicGain - %d handle 0x%p" fullword ascii /* Goodware String - occured 2 times */
      $s17 = "ALL/V32/RunTimeCommand" fullword ascii /* Goodware String - occured 2 times */
      $s18 = "FskSession.rxi" fullword ascii /* Goodware String - occured 2 times */
      $s19 = "V21 instance was configured to LAL mode" fullword ascii /* Goodware String - occured 2 times */
      $s20 = "DAA = Venice or Hermosa" fullword ascii /* Goodware String - occured 2 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0047 {
   meta:
      description = "mw8 - file 0047"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "1018211670c3671a4746a6b3e595055d5919790590e4f3537c5fa22c6e3badca"
   strings:
      $s1 = "YahooAUService.exe" fullword ascii
      $s2 = "BabylonAgent.exe" fullword ascii
      $s3 = "LogitechDesktopMessenger.exe" fullword ascii
      $s4 = "shellmon.exe" fullword ascii
      $s5 = "DVDAgent.exe" fullword ascii
      $s6 = "PCMAgent.exe" fullword ascii
      $s7 = "PhotoshopElementsFileAgent.exe" fullword ascii
      $s8 = "LogitechUpdate.exe" fullword ascii
      $s9 = "opera.exe" fullword ascii
      $s10 = "TVAgent.exe" fullword ascii
      $s11 = "=This control requires version 4.70 or greater of COMCTL32.DLL" fullword wide
      $s12 = "apdproxy.exe" fullword ascii
      $s13 = "TomTomHOMEService.exe" fullword ascii
      $s14 = "PMVService.exe" fullword ascii
      $s15 = "SeaPort.exe" fullword ascii
      $s16 = "ACService.exe" fullword ascii
      $s17 = "NBService.exe" fullword ascii
      $s18 = "IEUser.exe" fullword ascii
      $s19 = "AppleMobileDeviceService.exe" fullword ascii
      $s20 = "wlcomm.exe" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0015 {
   meta:
      description = "mw8 - file 0015"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "bcbd29c6295f9a77d2472f07f0a8f4c3f68471b6eca2ed933ad4321d62cb5f50"
   strings:
      $s1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii
      $s2 = "curity><requestedPrivileges><requestedExecutionLevel level=\"highestAvailable\" uiAccess=\"false\"></requestedExecutionLevel></r" ascii
      $s3 = "stedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><supporte" ascii
      $s4 = ":6:<:`:f:" fullword ascii /* hex encoded string 'o' */
      $s5 = "qP:\"Yl1" fullword ascii
      $s6 = "d8073a14a9ebe6967cdb548ca9pZtsglV1ANejLMtWDR0FI3ZwH8g1FHdYpcTEiBvk/Cb6q3j4zq9O3neAj9QyuxxjtRtKkne773DjYYqb+tTJ8TCOzPLxF7u4+rE+qd" ascii
      $s7 = "<ex:\\D" fullword ascii
      $s8 = "S Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"></supportedOS><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"></suppo" ascii
      $s9 = "d8073a14a9ebe6967cdb548ca9pZtsglV1ANejLMtWDR0FI3ZwH8g1FHdYpcTEiBvk/Cb6q3j4zq9O3neAj9QyuxxjtRtKkne773DjYYqb+tTJ8TCOzPLxF7u4+rE+qd" ascii
      $s10 = "OS><supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"></supportedOS><supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0d" ascii
      $s11 = "INGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" fullword ascii
      $s12 = "nl in de gueto pipol y" fullword ascii
      $s13 = " de guan nei " fullword ascii
      $s14 = "}\"></supportedOS></application></compatibility></assembly>PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPAD" ascii
      $s15 = "in de chinli gil p" fullword ascii
      $s16 = "en depression de yo" fullword ascii
      $s17 = "is born in" fullword ascii
      $s18 = "i fin in de guetooo" fullword ascii
      $s19 = "isis truiti guaibr" fullword ascii
      $s20 = "crai cosenifiguan sidosidonif " fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0028 {
   meta:
      description = "mw8 - file 0028"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "1c201d91c061899955e829ea676296952f6c5aad173ae57447710ab64cc08246"
   strings:
      $s1 = "GetModul" fullword ascii
      $s2 = "\"apikey\"3.Type'" fullword ascii
      $s3 = "Dispositi" fullword ascii
      $s4 = "icaD/x-msdownload" fullword ascii
      $s5 = "mOnHGpb" fullword ascii
      $s6 = "oWideChar" fullword ascii
      $s7 = "VirtualFe" fullword ascii
      $s8 = ": form-data; name=" fullword ascii
      $s9 = "Z[\\]^_`abcdefghijklmnopq" fullword ascii
      $s10 = "lstrnACreateTh" fullword ascii
      $s11 = "}rstuvwxyz{$>?@" fullword ascii
      $s12 = "_(SizeHAll" fullword ascii
      $s13 = "seHand" fullword ascii
      $s14 = "mA{_wtoi" fullword ascii
      $s15 = "*(::*2" fullword ascii
      $s16 = "c3d557" ascii
      $s17 = "s]u%toElI]" fullword ascii
      $s18 = "<eB`.ro" fullword ascii
      $s19 = "QF*,Cx" fullword ascii
      $s20 = "a0283a2" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0009 {
   meta:
      description = "mw8 - file 0009"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "98f3801fa65a08da81f4bd41aea82cb50b11e9cc05aac292332f78188835bca2"
   strings:
      $x1 = "ows.Common-Controls'  version='6.0.0.0'      processorArchitecture='x86'    publicKeyToken='6595b64144ccf1df'     language='*'  " ascii
      $s2 = "<assemblyIdentity   name='Microsoft.Windows.MyCoolApp'      processorArchitecture='x86'    version='1.0.0.0' type='win32'/>   <d" ascii
      $s3 = "HereticsExecuted" fullword ascii
      $s4 = "HappyMicroprocessor" fullword ascii
      $s5 = "<assemblyIdentity   name='Microsoft.Windows.MyCoolApp'      processorArchitecture='x86'    version='1.0.0.0' type='win32'/>   <d" ascii
      $s6 = "ForwarderGranted" fullword ascii
      $s7 = "FragmentsLogger" fullword ascii
      $s8 = "MemorandaInto" fullword ascii /* base64 encoded string 'zj+jwZ"{h' */
      $s9 = "FloggerExonerate" fullword ascii
      $s10 = "HeaddressFisherman" fullword ascii
      $s11 = "HottemperedInvisibilities" fullword ascii
      $s12 = "ExtrovertsHell" fullword ascii
      $s13 = "IncomparableImpersonated" fullword ascii
      $s14 = "FlimsierImprovisatory" fullword ascii
      $s15 = "GreedsEncryption" fullword ascii
      $s16 = "EthologistIndisposed" fullword ascii
      $s17 = "FloggingsHikes" fullword ascii
      $s18 = "HarpKernel" fullword ascii
      $s19 = "InterceptedInterpret" fullword ascii
      $s20 = "FrogmarchedGetable" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw8_0019 {
   meta:
      description = "mw8 - file 0019"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "dc6a2d0b03ab66a0c0c26bb81b6c5d7174362673a8b0ef49cfbabc735fe2a37e"
   strings:
      $s1 = "SNMPAPI.dll" fullword ascii
      $s2 = "APPWIZ.cpl" fullword ascii
      $s3 = "wufoilIoii.kcl" fullword ascii
      $s4 = "rasppp*dll" fullword wide
      $s5 = "fn|xHjuu.ezz" fullword ascii
      $s6 = "Pk)n:\"?" fullword ascii
      $s7 = "RWgLNb0" fullword ascii
      $s8 = "rRUcPZ2" fullword ascii
      $s9 = "KYMGftU82" fullword ascii
      $s10 = "P+ *G4?" fullword ascii
      $s11 = "dorqur" fullword ascii
      $s12 = "+ottj#,oJ" fullword ascii
      $s13 = "Lutt5onm#hgg" fullword ascii
      $s14 = "LSjHEG|" fullword ascii
      $s15 = "}|atst,ccc" fullword ascii
      $s16 = "v|uvWhdh=f__&aTc" fullword ascii
      $s17 = "Kptv0iqq" fullword ascii
      $s18 = "|~~Rtus*kik" fullword ascii
      $s19 = "Kysu3mnl!ssr" fullword ascii
      $s20 = "Wyxz7]_^" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0037 {
   meta:
      description = "mw8 - file 0037"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "c4aa075303d617a486086e927be6032c8163e21534cb872f6440134da8b0109d"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"highestAvailable\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" fullword ascii /* Goodware String - occured 916 times */
      $s3 = "</assembly>PADPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPA" ascii /* Goodware String - occured 1 times */
      $s4 = "4 4'4,444=4I4N4S4Y4]4c4h4n4s4" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "DDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPA" ascii /* Goodware String - occured 1 times */
      $s6 = ":(:.:7:J:n:" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "4KnLz/H8BPH++r/l9vsC8MvW/fMC8f0C87/i5+/7/PEC8Z8=" fullword ascii
      $s8 = "sbC9sbCyva6ns72urqaf" fullword ascii
      $s9 = "</assembly>PADPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPA" ascii /* Goodware String - occured 1 times */
      $s10 = "DDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "5-5Q5n5" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "9/Pz76m8vLGwvbGwsr2up7O9rq6mqaevpqa88u8D/vP+vQP+858=" fullword ascii
      $s13 = "URPQQh a@" fullword ascii
      $s14 = "Copyright (C) 2017" fullword wide
      $s15 = "202P2\\2x2" fullword ascii /* Goodware String - occured 2 times */
      $s16 = "3<3F3~3" fullword ascii /* Goodware String - occured 2 times */
      $s17 = "TODO: <" fullword wide /* Goodware String - occured 2 times */
      $s18 = "8f8l8p8t8x8" fullword ascii /* Goodware String - occured 3 times */
      $s19 = "6B7M7h7o7t7x7|7" fullword ascii /* Goodware String - occured 3 times */
      $s20 = "6?6]6d6h6l6p6t6x6|6" fullword ascii /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0049 {
   meta:
      description = "mw8 - file 0049"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "1165e2238ddd9277f0a5bdcd3a90de4e2571e83617132a695a5519d77aacd2d1"
   strings:
      $s1 = "ijklmnopqrstuv" fullword ascii
      $s2 = "t_@H:\"" fullword ascii
      $s3 = "IJKLMNOPQRSTUV" fullword ascii
      $s4 = "[c4- h6`^" fullword ascii
      $s5 = "XXXH888" fullword ascii
      $s6 = "SHFOLDER" fullword ascii /* Goodware String - occured 65 times */
      $s7 = "SeShutdownPrivilege" fullword ascii /* Goodware String - occured 216 times */
      $s8 = "-8cytv1R]" fullword ascii
      $s9 = ".UUW`Z" fullword ascii
      $s10 = "HPCP5\\P" fullword ascii
      $s11 = "ooor@:4" fullword ascii
      $s12 = "ZNEk@FL" fullword ascii
      $s13 = "wwzSF@:" fullword ascii
      $s14 = "RPYb1@t=" fullword ascii
      $s15 = "wwyZF@:" fullword ascii
      $s16 = "]cJCc~u8" fullword ascii
      $s17 = "ttqB@/w" fullword ascii
      $s18 = "tlUmsc4bn" fullword ascii
      $s19 = "bEYX?}S" fullword ascii
      $s20 = "qqqlA;5" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0040 {
   meta:
      description = "mw8 - file 0040"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "ef09350cacca078b0b0270a72adf12cd864de4bef03348f3547d9a1aee1e0a8a"
   strings:
      $s1 = "pqrstuv" fullword ascii
      $s2 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" fullword ascii
      $s3 = "nsmevt" fullword ascii
      $s4 = "orland" fullword ascii
      $s5 = "tlvpgt" fullword ascii
      $s6 = "gavc `=wV" fullword ascii
      $s7 = "H{PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii
      $s8 = "UjKy`[\"" fullword ascii
      $s9 = "KERsN^L" fullword ascii
      $s10 = "tPIT/$\\1y" fullword ascii
      $s11 = "PnVxtwT" fullword ascii
      $s12 = ".QMrxby@" fullword ascii
      $s13 = "SYWW><P" fullword ascii
      $s14 = "H{PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii
      $s15 = "sKcCoub" fullword ascii
      $s16 = "gxdN>G;" fullword ascii
      $s17 = "ejaic>," fullword ascii
      $s18 = "LRpIqWK" fullword ascii
      $s19 = "TFileunH" fullword ascii
      $s20 = "GmRI~})" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0001 {
   meta:
      description = "mw8 - file 0001"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "83ce19720c3e1c27af81d6e33f72db40c87eb78878dd677d0de9f94e85e877b8"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
      $s2 = "ExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xm" ascii
      $s3 = " Install System v2.50</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><request" ascii
      $s4 = "999ggg" fullword ascii /* reversed goodware string 'ggg999' */
      $s5 = "\"\"\"\"\"3\"#333" fullword ascii /* hex encoded string '33' */
      $s6 = "ddfffddf" ascii
      $s7 = "zzrdheu" fullword ascii
      $s8 = "BBB.BMM;PIT/=/(D:&&,WJ4`[H)3C" fullword ascii
      $s9 = "WVVTTTHII" fullword ascii
      $s10 = "15SpY88" fullword ascii
      $s11 = "eQ8YEYEy" fullword ascii
      $s12 = "nm@TP* n" fullword ascii
      $s13 = "SHFOLDER" fullword ascii /* Goodware String - occured 65 times */
      $s14 = "NullsoftInst" fullword ascii /* Goodware String - occured 110 times */
      $s15 = "SeShutdownPrivilege" fullword ascii /* Goodware String - occured 216 times */
      $s16 = "TAAA!$$" fullword ascii
      $s17 = "BBBB.M;6]IT=/D(D7T&0d>G2`4+HUC^" fullword ascii
      $s18 = "wGwDDOC." fullword ascii
      $s19 = "wwttDDDB\"DDDDC" fullword ascii
      $s20 = "OWWE ]w" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw8_0038 {
   meta:
      description = "mw8 - file 0038"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "7ee724347805f4d5c629fcfabc80943f420c2fbf9b636f01a15a346e24afa873"
   strings:
      $x1 = "Ghttp://www.smartassembly.com/webservices/UploadReportLogin/GetServerURL" fullword ascii
      $s2 = "Namespace;http://www.smartassembly.com/webservices/UploadReportLogin/L" fullword ascii
      $s3 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii
      $s4 = "UploadReportLoginService" fullword ascii
      $s5 = "@http://www.smartassembly.com/webservices/Reporting/UploadReport2" fullword ascii
      $s6 = "LoginServiceSoapT" fullword ascii
      $s7 = "jv.exe" fullword ascii
      $s8 = "Namespace3http://www.smartassembly.com/webservices/Reporting/E" fullword ascii
      $s9 = "processAttributes" fullword ascii
      $s10 = "{a41828d9-a79f-4a13-97e7-ced3e17b0005}, PublicKeyToken=3e56350693f7355e" fullword wide
      $s11 = "UploadReport2" fullword ascii
      $s12 = "MPxIrcC6PSomTnVDZfd" fullword ascii
      $s13 = "GetServerURL" fullword ascii
      $s14 = "ScTUknodllVAakCQT0F" fullword ascii
      $s15 = "Wrong Header Signature" fullword wide
      $s16 = "Unknown Header" fullword wide
      $s17 = "SmartAssembly.Attributes" fullword ascii
      $s18 = "SendingReportFeedback" fullword ascii
      $s19 = "reportSender" fullword ascii
      $s20 = "AppNameMinusVersion" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw8_0029 {
   meta:
      description = "mw8 - file 0029"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "1e753bb4d0de0f7dc7de6ff7bf30c25b4ef0471157bf5df9f36bea7af0398c94"
   strings:
      $x1 = "cmd.exe /c rundll32 \"%s\" " fullword ascii
      $x2 = "cmd.exe /c " fullword ascii
      $s3 = "/c ping 127.0.0.1 & del /q \"%s\"" fullword ascii
      $s4 = "Self Process Id:%d" fullword ascii
      $s5 = "rss.tmp" fullword ascii
      $s6 = "iexplorer" fullword ascii
      $s7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" fullword ascii
      $s8 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ascii
      $s9 = "gnbxddxgacxge" fullword ascii
      $s10 = "%d_of_%d_for_%s_on_%s" fullword ascii
      $s11 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ascii
      $s12 = ".jpg?resid=%d" fullword ascii
      $s13 = "=%s&type=%d&resid=%d" fullword ascii
      $s14 = "?resid=%d&photoid=" fullword ascii
      $s15 = "PlayWin32" fullword ascii
      $s16 = "oavjah" fullword ascii
      $s17 = "rswuvp" fullword ascii
      $s18 = "Playx64" fullword ascii
      $s19 = "Program Files (x86)" fullword ascii /* Goodware String - occured 3 times */
      $s20 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw8_0032 {
   meta:
      description = "mw8 - file 0032"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "4c4061822042bc7a3fb5d9c6ab1f54605008b5b966e606e81e9469bc5aa781f3"
   strings:
      $x1 = "cmd.exe /c rundll32 \"%s\" " fullword ascii
      $x2 = "cmd.exe /c " fullword ascii
      $s3 = "/c ping 127.0.0.1 & del /q \"%s\"" fullword ascii
      $s4 = "Self Process Id:%d" fullword ascii
      $s5 = "rss.tmp" fullword ascii
      $s6 = "iexplorer" fullword ascii
      $s7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" fullword ascii
      $s8 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ascii
      $s9 = "gnbxddxgacxge" fullword ascii
      $s10 = "%d_of_%d_for_%s_on_%s" fullword ascii
      $s11 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ascii
      $s12 = ".jpg?resid=%d" fullword ascii
      $s13 = "=%s&type=%d&resid=%d" fullword ascii
      $s14 = "?resid=%d&photoid=" fullword ascii
      $s15 = "PlayWin32" fullword ascii
      $s16 = "oavjah" fullword ascii
      $s17 = "rswuvp" fullword ascii
      $s18 = "Playx64" fullword ascii
      $s19 = "Program Files (x86)" fullword ascii /* Goodware String - occured 3 times */
      $s20 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw8_0045 {
   meta:
      description = "mw8 - file 0045"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "ace1b5e9e6923dfe8a261f9d98e5b77830c555a79f687cad5b433b2097a56fd7"
   strings:
      $s1 = "RG0K:\"" fullword ascii
      $s2 = ">1N:\"u" fullword ascii
      $s3 = "hijklm" fullword ascii
      $s4 = "LOADER ERROR" fullword ascii /* Goodware String - occured 5 times */
      $s5 = "*oeNmmkE" fullword ascii
      $s6 = "PXxLE?" fullword ascii
      $s7 = "BqYj=FIU" fullword ascii
      $s8 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "9UfCeAotwA" fullword ascii
      $s10 = "Bpxd5ur" fullword ascii
      $s11 = "cDaJs3&" fullword ascii
      $s12 = "VpjiJz_" fullword ascii
      $s13 = "yYGc@`F" fullword ascii
      $s14 = "dYzF2A{NM" fullword ascii
      $s15 = "\"exxv?" fullword ascii
      $s16 = "TczZc>k[_<" fullword ascii
      $s17 = "fUhiflC" fullword ascii
      $s18 = "eOfNBVY3l" fullword ascii
      $s19 = "\\itY'_" fullword ascii
      $s20 = "\\dI,!=w" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0002 {
   meta:
      description = "mw8 - file 0002"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "ed5810aaf3c0ddbd199c48ea326143a45d35110399cd3e8e3d91128a9858a518"
   strings:
      $x1 = "C:\\Users\\HRUMPFF\\AppData\\Local\\Temp\\10\\Temp2_000.AMS.1816777-fax-message659203.zip\\fax-message.scr" fullword wide
      $s2 = "C:\\fhoZZrIR.exe" fullword wide
      $s3 = "C:\\seqIioHp.exe" fullword wide
      $s4 = "C:\\49lKvLPl.exe" fullword wide
      $s5 = "C:\\nNGQX68R.exe" fullword wide
      $s6 = "C:\\0uI2wWuD.exe" fullword wide
      $s7 = "C:\\Vx2cOixa.exe" fullword wide
      $s8 = "C:\\JLhOvnht.exe" fullword wide
      $s9 = "C:\\eeTOT1aD.exe" fullword wide
      $s10 = "C:\\f4AmGGgf.exe" fullword wide
      $s11 = "C:\\wtLIIz3I.exe" fullword wide
      $s12 = "C:\\RXdkq_TC.exe" fullword wide
      $s13 = "C:\\0sGnVQOc.exe" fullword wide
      $s14 = "C:\\3zvFmBrR.exe" fullword wide
      $s15 = "C:\\S8dwgadI.exe" fullword wide
      $s16 = "C:\\LpnhkBfS.exe" fullword wide
      $s17 = "C:\\fzKxykiP.exe" fullword wide
      $s18 = "C:\\B4jlfpGn.exe" fullword wide
      $s19 = "C:\\S53GWAHx.exe" fullword wide
      $s20 = "C:\\cSoLRczn.exe" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw8_0006 {
   meta:
      description = "mw8 - file 0006"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "629f7f3824f57fa62e538b8df3d1ad21ca70c8e5a21d3f1cc7c435a4dcfb9551"
   strings:
      $s1 = "      <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii
      $s2 = "      <assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii
      $s3 = "CMUTIL.dll" fullword ascii
      $s4 = "        <requestedExecutionLevel level=\"highestAvailable\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s5 = "68.42.192.64" fullword wide
      $s6 = "cmCfG32" fullword ascii
      $s7 = "*+ b(~=" fullword ascii
      $s8 = " -F m<" fullword ascii
      $s9 = "KeyToken=\"6595b64144ccf1df\" language=\"*\"></assemblyIdentity>" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "I\"HMoB!" fullword ascii
      $s11 = "HnxkVE(" fullword ascii
      $s12 = "yagxVF>" fullword ascii
      $s13 = ".AgO]&H" fullword ascii
      $s14 = "FoxwUaA" fullword ascii
      $s15 = "wNgyk%K" fullword ascii
      $s16 = "CMvoaYa" fullword ascii
      $s17 = "YQSkjLFk[" fullword ascii
      $s18 = "aZjz9GO" fullword ascii
      $s19 = "kljfIz+" fullword ascii
      $s20 = "dVKmfTM" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0048 {
   meta:
      description = "mw8 - file 0048"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "695976da759adc21c924420548a9698a40ce7e3bfa0178b8a2d2b48dabf3c2b6"
   strings:
      $x1 = "cmd.exe /c ping 127.0.0.1 & del \"" fullword wide
      $s2 = "Execute ERROR" fullword wide
      $s3 = "ClassLibrary1.exe" fullword ascii
      $s4 = "Download ERROR" fullword wide
      $s5 = "Executed As " fullword wide
      $s6 = "lpdwProcessID" fullword ascii
      $s7 = "processInformationLength" fullword ascii
      $s8 = "crunchinaughty1122.ddns.net" fullword wide
      $s9 = "getvalue" fullword wide
      $s10 = "getMD5Hash" fullword ascii
      $s11 = "Update ERROR" fullword wide
      $s12 = "processInformationClass" fullword ascii
      $s13 = "CompDir" fullword ascii
      $s14 = "wDriver" fullword ascii
      $s15 = "GPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii
      $s16 = "CompareString" fullword ascii /* Goodware String - occured 28 times */
      $s17 = "TcpClient" fullword ascii /* Goodware String - occured 30 times */
      $s18 = "GZipStream" fullword ascii /* Goodware String - occured 31 times */
      $s19 = "GetProcesses" fullword ascii /* Goodware String - occured 34 times */
      $s20 = "MD5CryptoServiceProvider" fullword ascii /* Goodware String - occured 50 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 90KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw8_0033 {
   meta:
      description = "mw8 - file 0033"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "7602a066b3a6a17f7caa5d3bd4a07239e7b57fa59317e7d7a7fd3caeccbc0101"
   strings:
      $x1 = "C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\qqJz7eqWu.exe" fullword wide
      $s2 = "C:\\j8WoKEYn.exe" fullword wide
      $s3 = "C:\\securedoc.exe" fullword wide
      $s4 = "C:\\9jEGDdrN.exe" fullword wide
      $s5 = "C:\\keUqZPcW.exe" fullword wide
      $s6 = "C:\\UK0XPwEZ.exe" fullword wide
      $s7 = "C:\\Bgt4Zlxx.exe" fullword wide
      $s8 = "C:\\pqqd3RGA.exe" fullword wide
      $s9 = "C:\\bMI3uEWg.exe" fullword wide
      $s10 = "C:\\9ztmHzie.exe" fullword wide
      $s11 = "C:\\aMjXAmp1.exe" fullword wide
      $s12 = "C:\\bh5Yxhv1.exe" fullword wide
      $s13 = "C:\\x0WJstOh.exe" fullword wide
      $s14 = "C:\\5gbvzN6d.exe" fullword wide
      $s15 = "C:\\LoP6cunk.exe" fullword wide
      $s16 = "C:\\znXzd5ep.exe" fullword wide
      $s17 = "C:\\lGxKpW34.exe" fullword wide
      $s18 = "C:\\ZFBjM1bH.exe" fullword wide
      $s19 = "C:\\oQMGl9h6.exe" fullword wide
      $s20 = "C:\\V1AKUfA5.exe" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw8_0007 {
   meta:
      description = "mw8 - file 0007"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "069e8714d24add55e2c05d38b64cbe5931b7a34587a933eeb83ee6868cb5a475"
   strings:
      $s1 = "UXTHEME.dll" fullword ascii
      $s2 = "ZnLv:\\zi" fullword ascii
      $s3 = "* Tf|]" fullword ascii
      $s4 = "\\w!- :" fullword ascii
      $s5 = "%GyK%I" fullword ascii
      $s6 = "VrnEgPS9" fullword ascii
      $s7 = "# []vF" fullword ascii
      $s8 = "%q%JYL>" fullword ascii
      $s9 = "Lz /Mt" fullword ascii
      $s10 = "@.import" fullword ascii
      $s11 = "WlOs2s*5" fullword ascii
      $s12 = "IJmK?=yr" fullword ascii
      $s13 = "6cnsx\"'" fullword ascii
      $s14 = "mAhqz?-<:/" fullword ascii
      $s15 = "tqZpcVd" fullword ascii
      $s16 = "78nHbm{Wo" fullword ascii
      $s17 = ":MgGraz," fullword ascii
      $s18 = "g,BkuC  fp" fullword ascii
      $s19 = "O>Erpj[41?&" fullword ascii
      $s20 = "1TFnZ6>C" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0046 {
   meta:
      description = "mw8 - file 0046"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "1d19efdacb9b5c63a279d57f39cd2158dbcb3e2b857709eaceba2c9ff3f8a6e2"
   strings:
      $s1 = "UXTHEME.dll" fullword ascii
      $s2 = "1SpY\\:" fullword ascii
      $s3 = "3.lCxT!u" fullword ascii
      $s4 = "twcwV!" fullword ascii
      $s5 = "BfId!u" fullword ascii
      $s6 = "@.import" fullword ascii
      $s7 = "*lYXQEO?" fullword ascii
      $s8 = "DWVQSP" fullword ascii
      $s9 = "GX>A/$" fullword ascii
      $s10 = ";[`q[;" fullword ascii
      $s11 = "f@8L;bV v" fullword ascii
      $s12 = "`6Bdc\"" fullword ascii
      $s13 = "+!nH<`" fullword ascii
      $s14 = "V8\"w#*d" fullword ascii
      $s15 = " BUy?F" fullword ascii
      $s16 = "=,$$j(A" fullword ascii
      $s17 = "{8Y=Z/" fullword ascii
      $s18 = "JU_vwk2" fullword ascii
      $s19 = "OVg?$r" fullword ascii
      $s20 = "sH?b9Ni" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0043 {
   meta:
      description = "mw8 - file 0043"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "16a73e77624b76efaeef61848b5a76029d713ea78318493d18535bc70f4aa8a7"
   strings:
      $x1 = "taskkill /im winlogon.exe" fullword wide
      $x2 = "echo taskkill /im winlogon.exe >spins.bat" fullword wide
      $x3 = "reg add HKLM\\software\\microsoft\\windows\\currentversion\\run /v NyanZZZfh3FfsetdeWsdwefs /d C:\\spins.bat" fullword wide
      $s4 = "C:\\windows\\system32\\drivers\\etc\\hosts" fullword wide
      $s5 = "del C:\\users\\ /s /q /f" fullword wide
      $s6 = "del C:\\documents and settings\\ /s /q /f" fullword wide
      $s7 = "C:\\penis.bat" fullword wide
      $s8 = "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" fullword wide
      $s9 = "ServiceAntiWinLocker.exe" fullword wide
      $s10 = "cd C:\\Users\\%username%\\Desktop" fullword wide
      $s11 = "%SystemRoot%/system32/rundll32 user32, SwapMouseButton >nul" fullword wide
      $s12 = "AntiWinLockerTray.exe" fullword wide
      $s13 = "meatspin.com www.vk.com" fullword wide
      $s14 = "meatspin.com vk.com" fullword wide
      $s15 = "meatspin.com skype.com" fullword wide
      $s16 = "meatspin.com www.skype.com" fullword wide
      $s17 = "meatspin.com google.com" fullword wide
      $s18 = "meatspin.com www.google.com" fullword wide
      $s19 = "meatspin.com facebook.com" fullword wide
      $s20 = "meatspin.com www.facebook.com" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw8_0035 {
   meta:
      description = "mw8 - file 0035"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "0f7f91ffedbcaedfc7979dea121b4ebf80314acddb1061c03f23942a784265e3"
   strings:
      $s1 = "dxfwnwd.exe" fullword ascii
      $s2 = "kyrbdwhxji.exe" fullword wide
      $s3 = "Bgvircdan" fullword ascii
      $s4 = "GetTlkmfgxysqs" fullword ascii
      $s5 = "GetLothaqfysy" fullword ascii
      $s6 = "4 4&4,464\\4{4" fullword ascii /* hex encoded string 'DDdD' */
      $s7 = "GetNnxxquojjje" fullword ascii
      $s8 = "GetAdnnird" fullword ascii
      $s9 = "kyrbdwhxji" fullword wide
      $s10 = "ReadXaeiocnj" fullword ascii
      $s11 = "ReadJnbbdldi" fullword ascii
      $s12 = "CloseDnglmjwjh" fullword ascii
      $s13 = "ReadFafqine" fullword ascii
      $s14 = "ReadNunsmalq" fullword ascii
      $s15 = "URESKVW" fullword ascii
      $s16 = "Awyunsefue" fullword ascii
      $s17 = "Unxukaxmq" fullword ascii
      $s18 = "Uibijhtkd" fullword ascii
      $s19 = "Qdssxhd" fullword ascii
      $s20 = "Urgpoym" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0012 {
   meta:
      description = "mw8 - file 0012"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "ddfac61b4819bec33534c0ba845a337f3507292628d3780dbc65f0064c98f7f0"
   strings:
      $s1 = "Msvbvm60.dll" fullword ascii
      $s2 = "Frittinos.exe" fullword wide
      $s3 = "Eggshell" fullword ascii
      $s4 = "Frittinos" fullword wide
      $s5 = "Honneurs" fullword ascii
      $s6 = "Fibromyxoma" fullword ascii
      $s7 = "Stickler" fullword ascii
      $s8 = "Romagnole" fullword ascii
      $s9 = "Woadwaxen" fullword wide
      $s10 = "Ylangylang5" fullword ascii
      $s11 = "Meritedly1" fullword ascii
      $s12 = "aSyMlgFA5" fullword ascii
      $s13 = "Tectosages4" fullword ascii
      $s14 = "Dynarski5" fullword ascii
      $s15 = "ZeIvlr4" fullword ascii
      $s16 = "Depictions2" fullword ascii
      $s17 = "Urequema3" fullword ascii
      $s18 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "{fRRRRy~y" fullword ascii
      $s20 = "wgfl|||v|x" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0027 {
   meta:
      description = "mw8 - file 0027"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "92c98ed8c3399ce61e2bf0e7469aba4d1842ba14d3fcf051c9385a0676d9978f"
   strings:
      $s1 = "sdfvfyhNsrv3.exe" fullword wide
      $s2 = "//////-" fullword ascii /* reversed goodware string '-//////' */
      $s3 = "////:/" fullword ascii /* reversed goodware string '/:////' */
      $s4 = "//////////////," fullword ascii /* reversed goodware string ',//////////////' */
      $s5 = "///.........." fullword ascii /* reversed goodware string '..........///' */
      $s6 = "........>" fullword ascii /* reversed goodware string '>........' */
      $s7 = "Apotropous" fullword wide
      $s8 = "Afgangsfilm" fullword ascii
      $s9 = "Kommentarfelts" fullword ascii
      $s10 = "Radectomieseph" fullword ascii
      $s11 = "Orchestia" fullword ascii
      $s12 = "Kopuleret8" fullword ascii
      $s13 = "sdfvfyhNsrv3" fullword wide
      $s14 = "Plgschokolade5" fullword ascii
      $s15 = "Jenvidner3" fullword ascii
      $s16 = "Mesentera3" fullword wide
      $s17 = "Butnakkede8" fullword ascii
      $s18 = "Interphalangeal3" fullword ascii
      $s19 = "9YdI%C%" fullword ascii
      $s20 = "Noprendes3" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0014 {
   meta:
      description = "mw8 - file 0014"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "e12af26518c8b2630f8446c34babfa8e29aee00deeffacc673f84610ceba1818"
   strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii
      $s2 = "Profoma.exe" fullword wide
      $s3 = "CreateDecryptor" fullword wide
      $s4 = "System.Security.Cryptography.RijndaelManaged" fullword wide
      $s5 = "$Get2m" fullword ascii
      $s6 = "Profoma" fullword ascii
      $s7 = "xwppur" fullword ascii
      $s8 = "\\cKHjxjGH" fullword ascii
      $s9 = "oo% -M" fullword ascii
      $s10 = "Microsoft.VisualBasic" fullword ascii /* Goodware String - occured 100 times */
      $s11 = "System.Security.Cryptography" fullword ascii /* Goodware String - occured 306 times */
      $s12 = "zhJubrT" fullword ascii
      $s13 = "5rTxE?p" fullword ascii
      $s14 = "N/NxNtNTN" fullword ascii
      $s15 = "dfpH?-i" fullword ascii
      $s16 = "5Qx6-ilgT\"r2" fullword ascii
      $s17 = "zxgxwsS" fullword ascii
      $s18 = "qHWE;yQ" fullword ascii
      $s19 = "NVNTN1N<N" fullword ascii
      $s20 = "WkKi*!*" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0039 {
   meta:
      description = "mw8 - file 0039"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "e5f4fbac03a55fc617ce71e22c38a6a239262502a01068082fa5ad7efd55f7bc"
   strings:
      $s1 = "Msvbvm60.dll" fullword ascii
      $s2 = "Vasicentric2.exe" fullword wide
      $s3 = "Sys1.dll" fullword ascii
      $s4 = "Sys4.dll" fullword ascii
      $s5 = "Sys2.dll" fullword ascii
      $s6 = "Sys3.dll" fullword ascii
      $s7 = "Sys5.dll" fullword ascii
      $s8 = "Intially6" fullword ascii /* base64 encoded string '"{bjYr' */
      $s9 = "Slideth" fullword ascii
      $s10 = "Unsubmerged" fullword ascii
      $s11 = "Drummle" fullword ascii
      $s12 = "Bulbiferous" fullword ascii
      $s13 = "Withstrain" fullword ascii
      $s14 = "Subbotina" fullword ascii
      $s15 = "Doramundo" fullword ascii
      $s16 = "Nutation" fullword ascii
      $s17 = "Muskhogean" fullword ascii
      $s18 = "Tutsingo" fullword ascii
      $s19 = "Grypanian" fullword ascii
      $s20 = "Nannybush2" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0016 {
   meta:
      description = "mw8 - file 0016"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "515f38da0e3cce1cde05c8b3a2a6e4204729747643c0356713306dff0c27d177"
   strings:
      $s1 = "Msvbvm60.dll" fullword ascii
      $s2 = "salli.exe" fullword wide
      $s3 = "Semimuslim" fullword ascii
      $s4 = "BRsPY~" fullword ascii
      $s5 = "revIverSOft LLC" fullword wide
      $s6 = "Dollship2" fullword ascii
      $s7 = "@~6 -u" fullword ascii
      $s8 = "Incorporate5" fullword ascii
      $s9 = "Herophilist5" fullword ascii
      $s10 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "beHEO1@n" fullword ascii
      $s12 = "l?iSTUQ<." fullword ascii
      $s13 = " CevUPLr\\X" fullword ascii
      $s14 = "QcqH+Tt" fullword ascii
      $s15 = "VR.FVR" fullword ascii
      $s16 = "Command1" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "SCTo$\"" fullword ascii
      $s18 = "veUAG)P" fullword ascii
      $s19 = "+b.fBS" fullword ascii
      $s20 = "3xfnL5j[" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0034 {
   meta:
      description = "mw8 - file 0034"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "c0bbe130780c29f7d23ad33e5d3268fccccba224bc42efaff9a6618b3f4b3b08"
   strings:
      $s1 = "Msvbvm60.dll" fullword ascii
      $s2 = "Larksome8.exe" fullword wide
      $s3 = "Sys1.dll" fullword ascii
      $s4 = "Sys4.dll" fullword ascii
      $s5 = "Sys2.dll" fullword ascii
      $s6 = "Sys3.dll" fullword ascii
      $s7 = "Sys5.dll" fullword ascii
      $s8 = "Sociologian0" fullword ascii
      $s9 = "Interrun" fullword ascii
      $s10 = "Uniguttulate" fullword ascii
      $s11 = "Yellville" fullword ascii
      $s12 = "Deplored" fullword ascii
      $s13 = "Overpick" fullword ascii
      $s14 = "Klammer" fullword ascii
      $s15 = "Benkulu" fullword ascii
      $s16 = "Cissnapark" fullword ascii
      $s17 = "Noblesses" fullword ascii
      $s18 = "Superwrought" fullword ascii
      $s19 = "Iphigenia3" fullword ascii
      $s20 = "Upsetted8" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0008 {
   meta:
      description = "mw8 - file 0008"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "b2b29f75262392c2e08536d8666da1a94f014912bf898c9b95fe97e2a889998d"
   strings:
      $s1 = "Msvbvm60.dll" fullword ascii
      $s2 = "Sporades.exe" fullword wide
      $s3 = ">DJPV\\" fullword ascii /* reversed goodware string '\\VPJD>' */
      $s4 = "Motorhead7" fullword ascii
      $s5 = "* /)z!t" fullword ascii
      $s6 = "Rhapsodism" fullword ascii
      $s7 = "Trichoderma" fullword ascii
      $s8 = "Sporades" fullword wide
      $s9 = "Shubaly" fullword ascii
      $s10 = "Uneating" fullword wide
      $s11 = "nD+ X?" fullword ascii
      $s12 = "Artinite4" fullword wide
      $s13 = "_* N%$g" fullword ascii
      $s14 = "Paulownia6" fullword wide
      $s15 = "Uncreaturely2" fullword wide
      $s16 = "Unovertaken6" fullword wide
      $s17 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "6<AGLRW\\" fullword ascii
      $s19 = "?EJPU[`f" fullword ascii
      $s20 = "GLQW\\bg" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0022 {
   meta:
      description = "mw8 - file 0022"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "02161d952e5e5bb1fe080b99b39877520f1d5f0c941925eb51fd35b9de8cc3e9"
   strings:
      $s1 = "dvhbevwxjz.exe" fullword wide
      $s2 = "dvhbevwxjz" fullword wide
      $s3 = "qqqqqqqqqqqqqqqqqqqqqqq" fullword wide
      $s4 = "MSVBVM60" fullword ascii
      $s5 = "ttdtfkoVWa1" fullword ascii
      $s6 = "tcwPFLiZficXodB" fullword wide
      $s7 = "PsEjPsd" fullword ascii
      $s8 = "hPsOoPsbrRs" fullword ascii
      $s9 = "PsXLPsQ" fullword ascii
      $s10 = "5BstLPs%" fullword ascii
      $s11 = "ezSevcRuMNua" fullword wide
      $s12 = "PsfzPs0jPs" fullword ascii
      $s13 = "mAekzEVE'" fullword ascii
      $s14 = "PsDROsk" fullword ascii
      $s15 = "sPsEtPs mPs" fullword ascii
      $s16 = "QswUPs'kPszkPs" fullword ascii
      $s17 = "dvhbevwxjzF" fullword ascii
      $s18 = "nRssnPs" fullword ascii
      $s19 = "prWFuIEYiQQnNgOJ" fullword wide
      $s20 = "qyXtYDjbpgQVOWS" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0024 {
   meta:
      description = "mw8 - file 0024"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "0993f114d932c9207e1a4151215166d0d6b76b433437dc5b3ffb657fe5aa86cc"
   strings:
      $x1 = "RESULT = False:a = \"NameTask\":b = \"location\":c = \"args\":if (CreateTask (a, b , c)) then:RESULT = true:Function CreateTask(" wide
      $s2 = "LTLHXYI0Y7Kh0WAXsvzmrzWrv6Ynuwr3WMck7QiAlvGVu6qaoF97nFmv/ntdTbLyhjSrRcA1aJAQO10l5WTd/U/b8ar1lASv072FBb2c5ObSVrRFFr/IfAm+7pciUCYr" wide
      $s3 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s4 = "XQAAgAAAJAMAAAAAAAAmlo5wABf37AW76vT/lAEvRO985vUJGUQCKf9TzdbRFP6eYZyCFfYJeqxrtO1UEJ4mynHPxUcryOsiRf5B+rNZj3IECYBvOmxexVQF3KgnEQpc" wide
      $s5 = "l+R91kOQpCWEnroOUJwRLmtls/PbscDE+wPRbK/xhGZt6iJmWJi1xJTD3v7/mDz5dzvbo/bWe7dRF3lJ3r31Cv/XYt/09ko+sZ0L5S9EMlL3fQrQ0z7uLTX4QdEXGg0+" wide
      $s6 = "MLgEYFO0FnDZIW3ro0g90xDrZjJrgFKhho0JoXA/fCHEBMJR6vNSsJdQxq8C0PCaunw5Wre0RRyX//rH1ghpGaH23tPPj0BmDBT6N6y9Wb++enp8A9jFB/hulnEVxckW" wide
      $s7 = "StubPublic.Properties.Resources.resources" fullword ascii
      $s8 = "StubPublic.Form1.resources" fullword ascii
      $s9 = "ScriptControl" fullword wide
      $s10 = "set_Compatible" fullword ascii
      $s11 = "~~~}}}|||{{{{{{wwwwwwwwwwwwvvvvvvuuuuuurrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrvvvvvvvvvvvvvvvvvvvvvvvvwwwxxxxxxxxxyyyyy" ascii
      $s12 = "~~~}}}|||{{{{{{wwwwwwwwwwwwvvvvvvuuuuuurrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrvvvvvvvvvvvvvvvvvvvvvvvvwwwxxxxxxxxxyyyyy" ascii
      $s13 = "11.15.9.14" fullword wide
      $s14 = " independently in fears that the had " fullword wide
      $s15 = "14.14.1.15" fullword wide
      $s16 = "Vbscript" fullword wide /* Goodware String - occured 4 times */
      $s17 = "System.IO.Compression" fullword ascii /* Goodware String - occured 52 times */
      $s18 = "CreateDecryptor" fullword ascii /* Goodware String - occured 77 times */
      $s19 = "Microsoft.VisualBasic" fullword ascii /* Goodware String - occured 100 times */
      $s20 = "GetDomain" fullword ascii /* Goodware String - occured 126 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw8_0018 {
   meta:
      description = "mw8 - file 0018"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "d3691a8060733b8ff50fca0960848f0c9a06bdcbd7e67923ed2cfc6a68e20e64"
   strings:
      $s1 = "C:\\Users\\" fullword ascii
      $s2 = "ndowsDefender.exe" fullword wide
      $s3 = "WindowsApplication1.exe" fullword wide
      $s4 = "zKQMAEQCjKQMAEQCQCQQAEQC6BQQAYAAKBQQAYgBIBQQCwYC1JQICcZCwJQMCEZCZBQQAQhASLQKCwYCGJQICgYCzEQeCIYChEQeAMnASDQYCsXCVIQGAYAAKJQECMHC" wide
      $s5 = "AqvlQDKAAAnO3FKAAAmOnBAAQLH4fJEAAAR4HBAAQEAaAAAMycKAAAo+WCNoAAAc6cXoAAAY6cGAAAfYg/UQAAAUAgKAAAH9mCAAgRvRAAA4gfEAAAEAoCAAwQvRAAA4" wide
      $s6 = "DEvcEAAAJ4HcAMwpyZiCAAAWoggCAAAZocACMoAAAcBKaehBwBgAnInCAAwYoYiBAAQHoAHADsscAAgCI1tCAAAEoYiBAAQHoAHADsscmYAAA0BKKAAAXgCcAMw0yRAA" wide
      $s7 = "get_TextBox4" fullword ascii
      $s8 = "get_Button9" fullword ascii
      $s9 = "get_CheckBox9" fullword ascii
      $s10 = "get_CheckedListBox2" fullword ascii
      $s11 = "get_CheckBox10" fullword ascii
      $s12 = "get_TextBox8" fullword ascii
      $s13 = "get_CheckedListBox6" fullword ascii
      $s14 = "get_CheckBox4" fullword ascii
      $s15 = "L\\Documents\\Visual Studio 2012\\Projects\\WindowsApplication1\\WindowsApplication1\\obj\\Debug\\WindowsApplication1.pdb" fullword ascii
      $s16 = "get_CheckBox8" fullword ascii
      $s17 = "get_CheckBox2" fullword ascii
      $s18 = "get_CheckedListBox1" fullword ascii
      $s19 = "get_CheckBox1" fullword ascii
      $s20 = "get_CheckedListBox7" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0030 {
   meta:
      description = "mw8 - file 0030"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "46d844f03890362a4f910a4da3392b66f25fc429d513afad964e4ec2a5b47400"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s2 = "postoffice.exe" fullword wide
      $s3 = "jhgfdsdfghj.exe" fullword ascii
      $s4 = "postoffice" fullword wide
      $s5 = "MLP5VVYSTTWWTTWWTTWWTTWWTTWWTTWWTTWWTTWWTTWWTTWWTTWWTTWWTTWWTTWWTTWWTTWWTTWWSSVWSSVWSSVWSSVWSSVWSSVWSSVWSSUWRRUWRRUWRRUWRRUWRRTW" ascii
      $s6 = "fhVw.hcd" fullword ascii
      $s7 = "* }$?da" fullword ascii
      $s8 = "RRTWQQTWUUXQHHK+  \"" fullword ascii
      $s9 = "MLP5VVYSTTWWTTWWTTWWTTWWTTWWTTWWTTWWTTWWTTWWTTWWTTWWTTWWTTWWTTWWTTWWTTWWTTWWSSVWSSVWSSVWSSVWSSVWSSVWSSVWSSUWRRUWRRUWRRUWRRUWRRTW" ascii
      $s10 = "jhgfdsdfghj" fullword ascii
      $s11 = "f3ff443e.Resources.resources" fullword ascii
      $s12 = " -W 8e" fullword ascii
      $s13 = ";ID%G%" fullword ascii
      $s14 = "kXFEEf2" fullword ascii
      $s15 = "  $+  $+  $+  $+  $+  $+  $+  $+  $+  $+  $+  $+  $+  $+  $+  $+  $+  $+  $+  $+  $+  $+  $+  $+  $+  $+  $+  $+  $+  $+  $+  $+" ascii
      $s16 = "Dk-,- G" fullword ascii
      $s17 = "  $7  $7  $7  $7  $7  $7  $7  $7  $7  $7  $7  $7 #7 #3 #%  \"" fullword ascii /* hex encoded string 'wwwwwws' */
      $s18 = "memoryStream" fullword ascii /* Goodware String - occured 12 times */
      $s19 = "CreateDecryptor" fullword ascii /* Goodware String - occured 77 times */
      $s20 = "Microsoft.VisualBasic" fullword ascii /* Goodware String - occured 100 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0000 {
   meta:
      description = "mw8 - file 0000"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "4bedc9391ed163eff6682b3ebb760c854f6d4a8da858ee185e1844a710d0fa32"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s2 = "AsyncModuless.exe" fullword ascii
      $s3 = "AsyncModules.exe" fullword wide
      $s4 = "Va library for handling zip archives. http://www.codeplex.com/DotNetZip (Flavor=Retail)" fullword ascii
      $s5 = "ZipContentsDialog.csPK" fullword ascii
      $s6 = "ZipContentsDialog.Designer.csPK" fullword ascii
      $s7 = "kKmBCR9B2TfoFmM2q9glPP3Jh/1HPevSnPvZ+0hX2ZRmbQRUxQKxUNwTB4cPeTbQJizAvHmT2/Cpvj9pmUS1RfP0CxdbHBi2/r9oVFBH/sBZxzszwllPCT1q1J5tfdbp" wide
      $s8 = "CommandLineSelfExtractorStub.csPK" fullword ascii
      $s9 = "PasswordDialog.csPK" fullword ascii
      $s10 = "PasswordDialog.Designer.csPK" fullword ascii
      $s11 = " Dino Chiesa 2006 - 2011" fullword ascii
      $s12 = "FolderBrowserDialogEx.csPK" fullword ascii
      $s13 = "TxeX11Wf8v9Mq0GLRHGr7fqB5tuZCJD61GbSeTW76Ehioo8t5paBCH8WgjU3IqpkUJsa0TclQwwMsitDk5MeFXkFxWUvrg9IFb25prj2jhaW1Z97JGxKxYspSwP3EHnw" wide
      $s14 = "dtRvZgnBR5BPvaKgP0Xo6MqUEtr0dL4sGD2jw1GWIS3gVDuOVofWc2BwDGSLCZu7QojaCSvSLzRvaoshMFV9J0kYl8aWyKSH6TaaaJsZqjC9VeLik6WTnuH4ueUJnXCN" wide
      $s15 = "mCjbTYeEQuLI50XYGdCtX9CO0YakXMHe9gzcGfFrxAGm17ap9abEIIeXLGzhARNQiQNu5S36A36i0JoffeNw1nuSEhuUuSU2A/dmvJrW6NvHyPHOgTwKjQ3iE3elprtj" wide
      $s16 = "1EnfquTx8t1iFEVXnwyQyheJOkxyR680FGqazPkIGDcJKk0sElDkkjEaS7TXKAZHqLet8bt1JdrOiDz1Age278UFVOA6BYc74IB67MXKx/vExsnSrVhlBKkelCRYB1WU" wide
      $s17 = "zDzYg4F6Etqds5itxzlY1M+CPMvEPNgW83+0H9LivZq1HE5qHRN0q/XXJc0eaZmpTm4opRs0nhD1O1kv1Ae38WqTy5ihme9eRiMOcdMYLs4UBsDv7Vh1MReAzXlUKyJ+" wide
      $s18 = "ggvH8gySuIuxiUgHl/nd/6Q/6DO1PUKmoObQjBVjHWy6VQ+ZYy792hAETFmjFGYpYxb+L/WpoIoCPzRtzsvUbIB4VAMij4RSGLz5e3QTsvLLJNJ0FzCBBMzqtSvR8YcO" wide
      $s19 = "v9viqNIASkt5ZprS633CStCR2NXhEIPuE+vEkNPRqGzJRYkaFntSJ3GZP/mw+uIo4yit7preBkPPM0bMAYh9S1AINtZvJN52KpL4MAQywFCEF0/+XV6mhfsenxPqwFZO" wide
      $s20 = "U97oI/qwkbDh1kZ43mXmjzNOHmXZ+OVNBztH27a7Ugz7hw9TFJwr4+EoXTswTi6P4R8oCTtHr3xsdTVRmcQdWyInMK5fScEE8I5I2xA2W1B79UMceizsFJ9JACq+89YO" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0042 {
   meta:
      description = "mw8 - file 0042"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "58a75e7dc4ef6ab2220cac7139af9be3b14c8dd6753386d59fe1ed4639ece796"
   strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii
      $s2 = "XQAAgAAAagEAAAAAAAAmlo5wABf37AW76vT/lAEvRO985vUJGUQCKf9TzdbRFP6eYZyCFfYJeqxrtO1UEJ4mynHPxUcryOsiRf5B+rNZj3IECYBvOmxexVQF3KgnEQpc" wide
      $s3 = "PowerDVD.exe" fullword wide
      $s4 = "1j0vuqt+6dj0slxPuikSdSVVumrSv9JgVCRJBL97TEOl6gVi3LcDYL32LQqgFsjpYxs/Hj81BwkzW3iU1Jw/MbagOMLk6SA3bRbcl2dyXLOcFU+VAn/QUMrfqwJ7s5rj" wide
      $s5 = "PbYDDix8s3hBhlNRMOh820IYdH3m4crifNfvefjIRwJZ4MzM+Nk0/STBK4RSKI6XEwSjqwRHVzhTmDO8H2rFrI7IjuSrp+eyVkR61aB81MJlVnRB6ZUhtnG99npe57C4" wide
      $s6 = "9+gyxItZu+2EYB8pLacdQxEOuCZljX5mgJt6TtkvPDEAFXptRzPPAZURiU5maB+ZNDRIJFnuNc9GWSBWAIjEqvxVPDRWPw5GkynSGcmmFGde8OvYYs+76PoJnRIFmU2K" wide
      $s7 = "set_Compatible" fullword ascii
      $s8 = "CyberLink Corp." fullword wide
      $s9 = "Copyright (c) CyberLink Corporation. All rights reserved" fullword wide
      $s10 = "%iut%E`V" fullword ascii
      $s11 = "System.IO.Compression" fullword ascii /* Goodware String - occured 52 times */
      $s12 = "CreateDecryptor" fullword ascii /* Goodware String - occured 77 times */
      $s13 = "System.Security.Cryptography" fullword ascii /* Goodware String - occured 306 times */
      $s14 = "MemoryStream" fullword ascii /* Goodware String - occured 422 times */
      $s15 = "Encoding" fullword ascii /* Goodware String - occured 811 times */
      $s16 = "EndInvoke" fullword ascii /* Goodware String - occured 916 times */
      $s17 = "BeginInvoke" fullword ascii /* Goodware String - occured 933 times */
      $s18 = "(FcndlZ\\" fullword ascii
      $s19 = "set_HideWindow" fullword ascii
      $s20 = "set_cmd" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw8_0025 {
   meta:
      description = "mw8 - file 0025"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "9d1c7aad4203103d9bcde96a5d41a4b1f830312e5b11a836eb30876fbee530bd"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s2 = "cort.exe" fullword wide
      $s3 = "ApplySettings Template Catalog" fullword ascii
      $s4 = "Foxconn Technology Group" fullword ascii
      $s5 = "4dc291dc.Resources.resources" fullword ascii
      $s6 = "5.0.21.1" fullword wide
      $s7 = "+ CQ]18N" fullword ascii
      $s8 = " -lG\\D8" fullword ascii
      $s9 = "memoryStream" fullword ascii /* Goodware String - occured 12 times */
      $s10 = "CreateDecryptor" fullword ascii /* Goodware String - occured 77 times */
      $s11 = "Microsoft.VisualBasic" fullword ascii /* Goodware String - occured 100 times */
      $s12 = "Program" fullword ascii /* Goodware String - occured 196 times */
      $s13 = "Debugger" fullword ascii /* Goodware String - occured 245 times */
      $s14 = "System.Security.Cryptography" fullword ascii /* Goodware String - occured 306 times */
      $s15 = "MemoryStream" fullword ascii /* Goodware String - occured 422 times */
      $s16 = "Default" fullword ascii /* Goodware String - occured 914 times */
      $s17 = "A.B.resources" fullword ascii
      $s18 = "A.Properties.Resources.resources" fullword ascii
      $s19 = "b03f5f7f11d50a3a" ascii /* Goodware String - occured 1 times */
      $s20 = "DataByte" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _0010_0011_0 {
   meta:
      description = "mw8 - from files 0010, 0011"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "5903e44a25d83b0178a8ec8abce7f796a06618d5d581fd2564806fbe4ac385d5"
      hash2 = "84be50d8058e067e73f76756dd4aa295273962ec4d0f159a0795533dc1fea7b3"
   strings:
      $x1 = "C:\\windows\\system32\\cmd.exe" fullword ascii
      $x2 = "C:\\Users\\Entebbe Office\\AppData\\Local\\Temp\\Temp1_TAX_julie.kisakye.zip\\TAX_09232013.exe" fullword wide
      $s3 = "Create Child Cmd.exe Process Succeed!" fullword ascii
      $s4 = "C:\\HKC6RBIN.exe" fullword wide
      $s5 = "C:\\54J7P0cG.exe" fullword wide
      $s6 = "C:\\rROxbuXq.exe" fullword wide
      $s7 = "C:\\v0EyvL97.exe" fullword wide
      $s8 = "C:\\0HlcmOli.exe" fullword wide
      $s9 = "C:\\rR8MKeIg.exe" fullword wide
      $s10 = "C:\\dcplmWB7.exe" fullword wide
      $s11 = "C:\\j1bvMQM1.exe" fullword wide
      $s12 = "C:\\niFb1y5R.exe" fullword wide
      $s13 = "C:\\edJF7ehQ.exe" fullword wide
      $s14 = "C:\\fUdjolCv.exe" fullword wide
      $s15 = "C:\\vcgHNubW.exe" fullword wide
      $s16 = "C:\\lADi8VEE.exe" fullword wide
      $s17 = "C:\\rihmBqej.exe" fullword wide
      $s18 = "C:\\7ItGfDDT.exe" fullword wide
      $s19 = "C:\\zmL2KTPR.exe" fullword wide
      $s20 = "C:\\NJpWN0mg.exe" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "4511896d043677e4ab4578dc5bcab5a0" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _0044_0047_1 {
   meta:
      description = "mw8 - from files 0044, 0047"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "f61568d1e03ffad80f1b2b456b53d6172c20a18a25b5fab8daecdb0d5f269428"
      hash2 = "1018211670c3671a4746a6b3e595055d5919790590e4f3537c5fa22c6e3badca"
   strings:
      $s1 = "UrlMon" fullword ascii /* Goodware String - occured 35 times */
      $s2 = "TFiler" fullword ascii /* Goodware String - occured 48 times */
      $s3 = "SysUtils" fullword ascii /* Goodware String - occured 49 times */
      $s4 = "TPersistent" fullword ascii /* Goodware String - occured 55 times */
      $s5 = "Sender" fullword ascii /* Goodware String - occured 194 times */
      $s6 = "status" fullword wide /* Goodware String - occured 328 times */
      $s7 = "Target" fullword ascii /* Goodware String - occured 415 times */
      $s8 = "3333f3333333" ascii /* Goodware String - occured 1 times */
      $s9 = "ListBox1" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "ListBox2" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "%s on %s@GroupIndex cannot be less than a previous menu item's GroupIndex5Cannot create form. No MDI forms are currently active*" wide /* Goodware String - occured 2 times */
      $s12 = "TForm1" fullword ascii /* Goodware String - occured 3 times */
      $s13 = "3333333383" ascii
      $s14 = "333DDD33333" ascii
      $s15 = "TFORM1" fullword wide /* Goodware String - occured 4 times */
      $s16 = "ExtActns" fullword ascii /* Goodware String - occured 5 times */
      $s17 = "ExtDlgs" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0031_0017_2 {
   meta:
      description = "mw8 - from files 0031, 0017"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "139b1f1498c4ca983af2d1adf8988380a7abcb902d12e393ab78e11e695b0a34"
      hash2 = "0f8f3518e05864ab2c164de6a61df51b20b2f7f2eae2edf8049b247f43f89b90"
   strings:
      $s1 = " Data: <%s> %s" fullword ascii
      $s2 = "Object dump complete." fullword ascii /* Goodware String - occured 14 times */
      $s3 = "Client hook allocation failure." fullword ascii /* Goodware String - occured 14 times */
      $s4 = "Bad memory block found at 0x%08X." fullword ascii /* Goodware String - occured 2 times */
      $s5 = "normal block at 0x%08X, %u bytes long." fullword ascii /* Goodware String - occured 2 times */
      $s6 = "DAMAGE: before %hs block (#%d) at 0x%08X." fullword ascii /* Goodware String - occured 2 times */
      $s7 = "DAMAGE: after %hs block (#%d) at 0x%08X." fullword ascii /* Goodware String - occured 2 times */
      $s8 = "DAMAGE: on top of Free block at 0x%08X." fullword ascii /* Goodware String - occured 2 times */
      $s9 = "Invalid allocation size: %u bytes." fullword ascii /* Goodware String - occured 2 times */
      $s10 = "client block at 0x%08X, subtype %x, %u bytes long." fullword ascii /* Goodware String - occured 2 times */
      $s11 = "crt block at 0x%08X, subtype %x, %u bytes long." fullword ascii /* Goodware String - occured 2 times */
      $s12 = "memory check error at 0x%08X = 0x%02X, should be 0x%02X." fullword ascii /* Goodware String - occured 2 times */
      $s13 = "%hs located at 0x%08X is %u bytes long." fullword ascii /* Goodware String - occured 2 times */
      $s14 = "dbgheap.c" fullword ascii /* Goodware String - occured 3 times */
      $s15 = "_CrtCheckMemory()" fullword ascii /* Goodware String - occured 3 times */
      $s16 = "%hs allocated at file %hs(%d)." fullword ascii /* Goodware String - occured 3 times */
      $s17 = "fclose.c" fullword ascii /* Goodware String - occured 3 times */
      $s18 = "_flsbuf.c" fullword ascii /* Goodware String - occured 3 times */
      $s19 = "pHead->nLine == IGNORE_LINE && pHead->lRequest == IGNORE_REQ" fullword ascii /* Goodware String - occured 3 times */
      $s20 = "_freebuf.c" fullword ascii /* Goodware String - occured 3 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0029_0032_3 {
   meta:
      description = "mw8 - from files 0029, 0032"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "1e753bb4d0de0f7dc7de6ff7bf30c25b4ef0471157bf5df9f36bea7af0398c94"
      hash2 = "4c4061822042bc7a3fb5d9c6ab1f54605008b5b966e606e81e9469bc5aa781f3"
   strings:
      $s1 = "gnbxddxgacxge" fullword ascii
      $s2 = "1+222G2" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "CCPUpdate" fullword ascii
      $s4 = "717`7f7u7" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "5*5=5O5j5r5z5" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "1*1F1s1" fullword ascii /* Goodware String - occured 1 times */
      $s7 = ">(>8>\\>h>l>p>t>x>" fullword ascii /* Goodware String - occured 3 times */
      $s8 = "7f7o7u7" fullword ascii /* Goodware String - occured 3 times */
      $s9 = "6F6L6T6" fullword ascii /* Goodware String - occured 3 times */
      $s10 = "3#343m3w3" fullword ascii
      $s11 = "8(8.8M8T8`8f8r8x8" fullword ascii
      $s12 = "798Z8`8h8q8z8" fullword ascii
      $s13 = "?<?I?q?" fullword ascii
      $s14 = "=#=5=;=M=l=r=" fullword ascii
      $s15 = "718E:G<A=" fullword ascii
      $s16 = "RichPX" fullword ascii
      $s17 = "<F=K=T=c=" fullword ascii
      $s18 = "9!929k9" fullword ascii
      $s19 = "4.5X5x5" fullword ascii
      $s20 = ":K:T:`:w:" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and pe.imphash() == "539502771da573641ecc7f6497e39f8f" and ( 8 of them )
      ) or ( all of them )
}

rule _0029_0010_0011_0032_4 {
   meta:
      description = "mw8 - from files 0029, 0010, 0011, 0032"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "1e753bb4d0de0f7dc7de6ff7bf30c25b4ef0471157bf5df9f36bea7af0398c94"
      hash2 = "5903e44a25d83b0178a8ec8abce7f796a06618d5d581fd2564806fbe4ac385d5"
      hash3 = "84be50d8058e067e73f76756dd4aa295273962ec4d0f159a0795533dc1fea7b3"
      hash4 = "4c4061822042bc7a3fb5d9c6ab1f54605008b5b966e606e81e9469bc5aa781f3"
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
      $s11 = ".jpg?resid=%d" fullword ascii
      $s12 = "=%s&type=%d&resid=%d" fullword ascii
      $s13 = "?resid=%d&photoid=" fullword ascii
      $s14 = "PlayWin32" fullword ascii
      $s15 = "oavjah" fullword ascii
      $s16 = "rswuvp" fullword ascii
      $s17 = "Playx64" fullword ascii
      $s18 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ascii /* Goodware String - occured 1 times */
      $s19 = "gKmJMPMEHM^A" fullword ascii
      $s20 = "%wLAHHa\\AGQPAa\\s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _0004_0047_5 {
   meta:
      description = "mw8 - from files 0004, 0047"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "6337a5fcdc5a80cc0abf7eaf4d79c972f55275f76743eb27c56472dd28b6bc4d"
      hash2 = "1018211670c3671a4746a6b3e595055d5919790590e4f3537c5fa22c6e3badca"
   strings:
      $s1 = "reboot" fullword ascii /* Goodware String - occured 85 times */
      $s2 = "update" fullword ascii /* Goodware String - occured 208 times */
      $s3 = "install" fullword ascii /* Goodware String - occured 268 times */
      $s4 = "covered" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "manner" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "parties" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "whether" fullword ascii /* Goodware String - occured 2 times */
      $s8 = "chrome.exe" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and ( all of them )
      ) or ( all of them )
}

rule _0038_0018_6 {
   meta:
      description = "mw8 - from files 0038, 0018"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "7ee724347805f4d5c629fcfabc80943f420c2fbf9b636f01a15a346e24afa873"
      hash2 = "d3691a8060733b8ff50fca0960848f0c9a06bdcbd7e67923ed2cfc6a68e20e64"
   strings:
      $s1 = "My.Application" fullword ascii /* Goodware String - occured 1 times */
      $s2 = "Create__Instance__" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "My.WebServices" fullword ascii /* Goodware String - occured 1 times */
      $s4 = "MyTemplate" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "Dispose__Instance__" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "My.Computer" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "My.User" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _0030_0025_7 {
   meta:
      description = "mw8 - from files 0030, 0025"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "46d844f03890362a4f910a4da3392b66f25fc429d513afad964e4ec2a5b47400"
      hash2 = "9d1c7aad4203103d9bcde96a5d41a4b1f830312e5b11a836eb30876fbee530bd"
   strings:
      $s1 = "memoryStream" fullword ascii /* Goodware String - occured 12 times */
      $s2 = "A.B.resources" fullword ascii
      $s3 = "A.Properties.Resources.resources" fullword ascii
      $s4 = "DataByte" fullword ascii
      $s5 = "A.Properties" fullword ascii
      $s6 = "A.Properties.Resources" fullword wide
      $s7 = "941899fb3dc0" ascii
      $s8 = "$93e86973-60b7-4837-af92-941899fb3dc0" fullword ascii
      $s9 = "14.0.0.0" fullword ascii /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _0042_0024_8 {
   meta:
      description = "mw8 - from files 0042, 0024"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "58a75e7dc4ef6ab2220cac7139af9be3b14c8dd6753386d59fe1ed4639ece796"
      hash2 = "0993f114d932c9207e1a4151215166d0d6b76b433437dc5b3ffb657fe5aa86cc"
   strings:
      $s1 = "set_Compatible" fullword ascii
      $s2 = "set_HideWindow" fullword ascii
      $s3 = "set_cmd" fullword ascii
      $s4 = "set_target" fullword ascii /* Goodware String - occured 2 times */
      $s5 = "ViaASM" fullword ascii
      $s6 = "ViaMOD" fullword ascii
      $s7 = "set_buffer" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _0039_0034_9 {
   meta:
      description = "mw8 - from files 0039, 0034"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "e5f4fbac03a55fc617ce71e22c38a6a239262502a01068082fa5ad7efd55f7bc"
      hash2 = "c0bbe130780c29f7d23ad33e5d3268fccccba224bc42efaff9a6618b3f4b3b08"
   strings:
      $s1 = "Sys1.dll" fullword ascii
      $s2 = "Sys4.dll" fullword ascii
      $s3 = "Sys2.dll" fullword ascii
      $s4 = "Sys3.dll" fullword ascii
      $s5 = "Sys5.dll" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and ( all of them )
      ) or ( all of them )
}

