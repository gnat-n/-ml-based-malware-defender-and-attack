/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2024-04-17
   Identifier: mw4
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule _root_BytMe_new_datasets_mw4_017 {
   meta:
      description = "mw4 - file 017"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "047254190855a5ff47d744bf80d8227391ce8893396958039dbf6f2e31deac09"
   strings:
      $s1 = "SELECT encryptedUsername, encryptedPassword, formSubmitURL, hostname FROM moz_logins" fullword ascii
      $s2 = "sCrypt32.dll" fullword wide
      $s3 = "SMTP Password" fullword wide
      $s4 = "FtpPassword" fullword wide
      $s5 = "%s\\%s%i\\data\\settings\\ftpProfiles-j.jsd" fullword wide
      $s6 = "aPLib v1.01  -  the smaller the better :)" fullword ascii
      $s7 = "%s\\%s\\User Data\\Default\\Login Data" fullword wide
      $s8 = "mgr.exe" fullword ascii
      $s9 = "%s%s\\Login Data" fullword wide
      $s10 = "%s%s\\Default\\Login Data" fullword wide
      $s11 = "%s\\32BitFtp.TMP" fullword wide
      $s12 = "%s\\GoFTP\\settings\\Connections.txt" fullword wide
      $s13 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" fullword wide
      $s14 = "%s\\Mozilla\\SeaMonkey\\Profiles\\%s" fullword wide
      $s15 = "%s\\%s\\%s.exe" fullword wide
      $s16 = "More information: http://www.ibsensoftware.com/" fullword ascii
      $s17 = "%s\\nss3.dll" fullword wide
      $s18 = "PopPassword" fullword wide
      $s19 = "SmtpAccount" fullword wide
      $s20 = "SMTP User" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw4_014 {
   meta:
      description = "mw4 - file 014"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "cf25f8d6f1ba6ac84f380688f29188498c8a2777a02f8df2ef07c4488d30bca3"
   strings:
      $s1 = "STTantra.exe" fullword ascii
      $s2 = "HTLauncher.exe" fullword ascii
      $s3 = "webpatchhanbit.nefficient.co.kr/patchhanbit/tantra/Global/patchinfo/STTantra.exe" fullword ascii
      $s4 = "PatchPatcher.exe" fullword wide
      $s5 = "Cannot Execute HTLauncher.exe!" fullword ascii
      $s6 = "mgr.exe" fullword ascii
      $s7 = "Patcher.tmp" fullword ascii
      $s8 = "\\Tantra\\Run\\PatchPatcher.pdb" fullword ascii
      $s9 = "Patcher.dat" fullword ascii
      $s10 = "webpatchhanbit.nefficient.co.kr/patchhanbit/tantra/Global/patchinfo/Patcher.dat" fullword ascii
      $s11 = "Cannot Download Patcher.dat!" fullword ascii
      $s12 = "Cannot Download STTantra.exe!" fullword ascii
      $s13 = "CreateFile[%s] Fail!" fullword ascii
      $s14 = "<description>Tantra Program</description>" fullword ascii
      $s15 = "            processorArchitecture=\"X86\" " fullword ascii
      $s16 = "            publicKeyToken=\"6595b64144ccf1df\" " fullword ascii
      $s17 = "Downloading Tantra Version Info..." fullword wide
      $s18 = "            version=\"6.0.0.0\" " fullword ascii
      $s19 = "Cannot Find STTantra.exe!" fullword ascii
      $s20 = "eYe;!O" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw4_011 {
   meta:
      description = "mw4 - file 011"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "c7f2f6ea958c065eaea923b6a157204451197bfa153ebb4d45abb930122e05bb"
   strings:
      $s1 = "DTLite.exe" fullword wide
      $s2 = "uhcnitw" fullword ascii
      $s3 = "dfDE)dF" fullword ascii
      $s4 = ":qPKfa\\/2%" fullword ascii
      $s5 = "EFbb(@0" fullword ascii
      $s6 = "Btp%nAeQ\\MS=" fullword ascii
      $s7 = "Piky?/+" fullword ascii
      $s8 = "7PxRS;yM" fullword ascii
      $s9 = "The quick brown dog jumps over the lazy fox" fullword ascii
      $s10 = "Z4HJDdlX:" fullword ascii
      $s11 = "The QUICK brown fox jumps over the lazy dog" fullword ascii
      $s12 = "vhtC!E" fullword ascii
      $s13 = "&aECFEF%" fullword ascii
      $s14 = "C)@#EBDA$a4" fullword ascii
      $s15 = "yrui\\Wb" fullword ascii
      $s16 = "Disc Soft Ltd" fullword wide
      $s17 = " 2000-2013 Disc Soft Ltd." fullword wide
      $s18 = "DAEMON Tools Lite" fullword wide
      $s19 = "HCNITW" fullword ascii
      $s20 = "d&438A" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw4_012 {
   meta:
      description = "mw4 - file 012"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "353c696b9b0db39958bc18a51fcc3b879f9f143d261c4cd1a2e521d1b9f98992"
   strings:
      $s1 = "fsnotifier.exe" fullword wide
      $s2 = "t[ADVAPI32.dll" fullword ascii
      $s3 = "Filesystem events processor" fullword wide
      $s4 = "fsnotifier" fullword wide
      $s5 = "Bly.ykQ" fullword ascii
      $s6 = "14.0.0.2" fullword wide
      $s7 = "peTvsJ0" fullword ascii
      $s8 = "wbIriL3" fullword ascii
      $s9 = "; /R_CH" fullword ascii
      $s10 = "Me< -W-%" fullword ascii
      $s11 = "ZyZSTJr" fullword ascii
      $s12 = "JpxPqbr" fullword ascii
      $s13 = "SgsxxLo'" fullword ascii
      $s14 = "#dQYi,mLu" fullword ascii
      $s15 = "djpcy*x?" fullword ascii
      $s16 = "6EoEbPb&" fullword ascii
      $s17 = "UXNURt{" fullword ascii
      $s18 = "6lygSYBy" fullword ascii
      $s19 = "qjsEIae" fullword ascii
      $s20 = ".hwR{p" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw4_016 {
   meta:
      description = "mw4 - file 016"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "bdec6a1b8e17e049eb5ee4c0c376268a42dfd507d58989fdd7125c7f7f3e0a2d"
   strings:
      $s1 = "nmcogame.dll" fullword wide
      $s2 = "hGuxBooA.pdb" fullword ascii
      $s3 = "version=\"3.0.2.0\"" fullword ascii
      $s4 = "Softpub" fullword wide
      $s5 = "supportpportableMayweboAspassed" fullword ascii
      $s6 = "File not found (error)" fullword wide
      $s7 = "NexonMessenger Game Service" fullword wide
      $s8 = "Ytbrowseron" fullword ascii
      $s9 = "Nexon Corp." fullword wide
      $s10 = "%SS%N+" fullword ascii
      $s11 = "owMancrashdevelopersPhilippN61" fullword ascii
      $s12 = "zbthat" fullword ascii
      $s13 = "withwherecontainsvikingalsoXxMoorer" fullword ascii
      $s14 = "Fuinstallation.117bGoogletGfour-partZ" fullword ascii
      $s15 = "H2bonniethet1" fullword ascii
      $s16 = "WgeminiL0s2010,about:labs,twotheu" fullword ascii
      $s17 = "yuIF}zn" fullword ascii
      $s18 = "-fGzase=g" fullword ascii
      $s19 = "oSvFirebug,XDfs" fullword ascii
      $s20 = "uJfs689A" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw4_015 {
   meta:
      description = "mw4 - file 015"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "cf3b508a117f920321c97e21a10564c88dd3fabd23ca804ec846d1baa7b128dd"
   strings:
      $s1 = "nmcogame.dll" fullword wide
      $s2 = "version=\"3.0.2.0\"" fullword ascii
      $s3 = "Softpub" fullword wide
      $s4 = "rSVz/f9=GI0.pdb" fullword ascii
      $s5 = "supportpportableMayweboAspassed" fullword ascii
      $s6 = "File not found (error)" fullword wide
      $s7 = "NexonMessenger Game Service" fullword wide
      $s8 = "Ytbrowseron" fullword ascii
      $s9 = "Nexon Corp." fullword wide
      $s10 = "owMancrashdevelopersPhilippN61" fullword ascii
      $s11 = "zbthat" fullword ascii
      $s12 = "\\ZuWEwe <d" fullword ascii
      $s13 = "withwherecontainsvikingalsoXxMoorer" fullword ascii
      $s14 = "Fuinstallation.117bGoogletGfour-partZ" fullword ascii
      $s15 = "H2bonniethet1" fullword ascii
      $s16 = "WgeminiL0s2010,about:labs,twotheu" fullword ascii
      $s17 = "oSvFirebug,XDfs" fullword ascii
      $s18 = "forQisalex" fullword ascii
      $s19 = "jthatappUpdate,Qflusess" fullword ascii
      $s20 = "Exchange Cluster View Mode on" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw4_018 {
   meta:
      description = "mw4 - file 018"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "e8f2ff23543e3d48a08b9e941de5858a298ef7830ba76c983e8c4d50dc2cbf4b"
   strings:
      $s1 = "nmcogame.dll" fullword wide
      $s2 = "hGuxBooA.pdb" fullword ascii
      $s3 = "version=\"3.0.2.0\"" fullword ascii
      $s4 = "Softpub" fullword wide
      $s5 = "supportpportableMayweboAspassed" fullword ascii
      $s6 = "File not found (error)" fullword wide
      $s7 = "NexonMessenger Game Service" fullword wide
      $s8 = "Ytbrowseron" fullword ascii
      $s9 = "Nexon Corp." fullword wide
      $s10 = "owMancrashdevelopersPhilippN61" fullword ascii
      $s11 = "zbthat" fullword ascii
      $s12 = "withwherecontainsvikingalsoXxMoorer" fullword ascii
      $s13 = "Fuinstallation.117bGoogletGfour-partZ" fullword ascii
      $s14 = "H2bonniethet1" fullword ascii
      $s15 = "WgeminiL0s2010,about:labs,twotheu" fullword ascii
      $s16 = "oSvFirebug,XDfs" fullword ascii
      $s17 = "forQisalex" fullword ascii
      $s18 = "jthatappUpdate,Qflusess" fullword ascii
      $s19 = "Exchange Cluster View Mode on" fullword wide
      $s20 = "fVxS_\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw4_004 {
   meta:
      description = "mw4 - file 004"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "53614c0519188e2ab54c1be5aac75750bdc5ffbaef528378f9ccf89dd8e50d20"
   strings:
      $s1 = "@start_description" fullword wide
      $s2 = "@language_description" fullword wide
      $s3 = "@detection_description" fullword wide
      $s4 = "@progress_description" fullword wide
      $s5 = "@finish_description" fullword wide
      $s6 = "@networks_description" fullword wide
      $s7 = "@participate_description" fullword wide
      $s8 = "@folder_description" fullword wide
      $s9 = "That day is a %s." fullword ascii
      $s10 = "`j=@5- " fullword ascii
      $s11 = "@dialog_caption" fullword wide
      $s12 = "Free Windows Vulnerability Scanner" fullword wide
      $s13 = "Install" fullword wide /* Goodware String - occured 330 times */
      $s14 = "The quick brown dog jumps over the lazy fox" fullword ascii
      $s15 = "The QUICK brown fox jumps over the lazy dog" fullword ascii
      $s16 = "Enter day: " fullword ascii
      $s17 = "The exponential value of %f is %f." fullword ascii
      $s18 = "Enter year: " fullword ascii
      $s19 = "YYuTVWhI" fullword ascii
      $s20 = "?CONOUT$" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw4_027 {
   meta:
      description = "mw4 - file 027"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "d9ba88953a73e0360033b508a67f37e0128f03e2b6b920ff67480508a1d2f205"
   strings:
      $s1 = "SELECT encryptedUsername, encryptedPassword, formSubmitURL, hostname FROM moz_logins" fullword ascii
      $s2 = "sCrypt32.dll" fullword wide
      $s3 = "SMTP Password" fullword wide
      $s4 = "FtpPassword" fullword wide
      $s5 = "%s\\%s%i\\data\\settings\\ftpProfiles-j.jsd" fullword wide
      $s6 = "aPLib v1.01  -  the smaller the better :)" fullword ascii
      $s7 = "%s\\%s\\User Data\\Default\\Login Data" fullword wide
      $s8 = "mgr.exe" fullword ascii
      $s9 = "%s%s\\Login Data" fullword wide
      $s10 = "%s%s\\Default\\Login Data" fullword wide
      $s11 = "%s\\32BitFtp.TMP" fullword wide
      $s12 = "%s\\GoFTP\\settings\\Connections.txt" fullword wide
      $s13 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" fullword wide
      $s14 = "%s\\Mozilla\\SeaMonkey\\Profiles\\%s" fullword wide
      $s15 = "%s\\%s\\%s.exe" fullword wide
      $s16 = "More information: http://www.ibsensoftware.com/" fullword ascii
      $s17 = "%s\\nss3.dll" fullword wide
      $s18 = "PopPassword" fullword wide
      $s19 = "SmtpAccount" fullword wide
      $s20 = "SMTP User" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw4_001 {
   meta:
      description = "mw4 - file 001"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "a771a51473ab688e632ba4e6717f3fc7d687e75fa8fb9a263dca1cbe391631e0"
   strings:
      $s1 = "sojevilohamocugorozota.txt" fullword ascii
      $s2 = "vvvooo" fullword ascii /* reversed goodware string 'ooovvv' */
      $s3 = "444$$$" fullword ascii /* reversed goodware string '$$$444' */
      $s4 = "pppHHH" fullword ascii /* reversed goodware string 'HHHppp' */
      $s5 = "777xxx" fullword ascii /* reversed goodware string 'xxx777' */
      $s6 = "6`'6`'6`'6`'6`'6`'" fullword ascii /* hex encoded string 'fff' */
      $s7 = "6`'6`'6`'6`'6`'6`'6`'6`'" fullword ascii /* hex encoded string 'ffff' */
      $s8 = "2e$2e$2e$" fullword ascii /* hex encoded string '...' */
      $s9 = "6`'6`'6`'6`'" fullword ascii /* hex encoded string 'ff' */
      $s10 = "2e$2e$2e$2e$2e$2e$2e$" fullword ascii /* hex encoded string '.......' */
      $s11 = "2e$2e$2e$2e$2e$2e$" fullword ascii /* hex encoded string '......' */
      $s12 = "]Dure mefulebitine katixeba lewufevujoka go mihaciceyeyeva xudize rafasuma tevakuvoko gumiwubo" fullword wide
      $s13 = "`Vuhihiculicoya miyo bewijayero sororerojufebu suyiyo fakitawevile retixahawera luzujicehowo dizo" fullword wide
      $s14 = "jupexoyixuhapikosihemu" fullword ascii
      $s15 = "hujamijurukuki" fullword ascii
      $s16 = ":,:0:H:X:\\:l:p:t:|:" fullword ascii
      $s17 = "8+:F:\\:r:z:" fullword ascii
      $s18 = "Luwahozepumoju hogorunu" fullword wide
      $s19 = "LNTWVNOM" fullword wide
      $s20 = "howusocegutosixuxaco jofodagoluhitokihonizezige" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw4_002 {
   meta:
      description = "mw4 - file 002"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "defdfb21f88faa2c9c674737742f28c620c8939acd51ea237bfd54ac4a7d6656"
   strings:
      $x1 = "{\"algo\": \"cryptonight\",\"api\": {\"port\": 0,\"access-token\": null,\"id\": null,\"worker-id\": null,\"ipv6\": false, \"rest" ascii
      $x2 = "Exe is already in Target Path, But not able to Run_Process with error code [%d]" fullword ascii
      $s3 = "Chech_Mutex() --> ERROR_ALREADY_EXISTS..." fullword ascii
      $s4 = "http://timenowis1.top/E976HDGFD65.exe" fullword ascii
      $s5 = "http://timenowis1.top/E32HGDGFD65.exe" fullword ascii
      $s6 = "Chech_Mutex() --> Failed..." fullword ascii
      $s7 = "MSASCuiL.exe" fullword wide
      $s8 = "NT99KPIMASK.exe" fullword wide
      $s9 = "Failed to CreateProcess(Miner) [%d]" fullword ascii
      $s10 = "es\": 5,\"retry-pause\": 5,\"safe\": true,\"threads\": null,\"user-agent\": null,\"watch\": false}" fullword ascii
      $s11 = "Chech_Mutex() --> Success..." fullword ascii
      $s12 = "I succeed with CopyFileW, But i cannot Run_Process with error code [%d]" fullword ascii
      $s13 = "l\": 1, \"huge-pages\": null,\"hw-aes\": null, \"log-file\": \"CN39KPIMASK\" ,\"max-cpu-usage\": 55,\"pools\": [ { \"url\": \"51" ascii
      $s14 = "]eventvwr.exe" fullword wide
      $s15 = "(MUTEX IN USE) Another EXE is Running" fullword ascii
      $s16 = "_RegCreateKeyExW_ Failed with error code [%d]" fullword ascii
      $s17 = "GetShortPathNameW Failed with error code [%d]" fullword ascii
      $s18 = "Failed to Activate - Detected by AV" fullword ascii
      $s19 = "GetModuleFileNameW Failed with error code [%d]" fullword ascii
      $s20 = "/c Taskkill /PID %d /F & del /A:H %s > nul" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw4_026 {
   meta:
      description = "mw4 - file 026"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "11795f67078514a7c64e3e92f429b42bab7228d106d201ae0c5c3c54248f200c"
   strings:
      $s1 = "c:\\hot\\Wild\\Clothe\\color\\human\\type\\Ear\\groundWear.pdb" fullword ascii
      $s2 = "scaleopen.exe" fullword wide
      $s3 = "sw  >e -i i" fullword ascii
      $s4 = "Spreadthrow" fullword wide
      $s5 = "IFC.JFD" fullword ascii
      $s6 = "NJH.PLJ" fullword ascii
      $s7 = "KHE.LHF" fullword ascii
      $s8 = "GDA.HDB" fullword ascii
      $s9 = "MJG.NJH" fullword ascii
      $s10 = "tsTLrunr " fullword ascii
      $s11 = " estWebPageAndUserLoadCounterSample]" fullword wide
      $s12 = "     @" fullword ascii /* reversed goodware string '@     ' */
      $s13 = "9.4.40.20" fullword wide
      $s14 = "#  \\$! " fullword ascii
      $s15 = ")E ur,i- om" fullword ascii
      $s16 = "#  .$! " fullword ascii
      $s17 = "ieieai" fullword ascii
      $s18 = "M t /m" fullword ascii
      $s19 = "e* Ed " fullword ascii
      $s20 = "not_connected" fullword ascii /* Goodware String - occured 581 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw4_008 {
   meta:
      description = "mw4 - file 008"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "4d12ad00ce27e092e49ad72599bda5d0882aa878c124ddd7d5b8feebff08c50a"
   strings:
      $s1 = "UnitInjectProcess" fullword ascii
      $s2 = "icon=shell32.dll,4" fullword wide
      $s3 = "[Execute]" fullword wide
      $s4 = "%NOINJECT%" fullword wide
      $s5 = "ServerKeyloggerU" fullword ascii
      $s6 = "TServerKeylogger" fullword ascii
      $s7 = "XtremeKeylogger" fullword wide
      $s8 = "shell\\Open\\command=" fullword wide
      $s9 = "XTREMEBINDER" fullword wide
      $s10 = "UnitInjectServer" fullword ascii
      $s11 = "shellexecute=" fullword wide
      $s12 = "<meta http-equiv=\"Content-Type\" content=\"text/html;charset=UTF-8\">" fullword wide
      $s13 = "BINDER" fullword wide
      $s14 = "RECYCLER\\S-1-5-21-1482476501-3352491937-682996330-1013\\" fullword wide
      $s15 = ";open=RECYCLER\\S-1-5-21-1482476501-3352491937-682996330-1013\\" fullword wide
      $s16 = "TGetPlugin" fullword ascii
      $s17 = "TUnitInfectUSB" fullword ascii
      $s18 = "<title>Xtreme RAT</title>" fullword wide
      $s19 = "shell\\Open=Open" fullword wide
      $s20 = "shell\\Open\\Default=1" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw4_025 {
   meta:
      description = "mw4 - file 025"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "5df26114f76ec86dcd5309e3b50379fd57f0e0f86b22d3245d17c6e17fdd96d3"
   strings:
      $s1 = "Modified by an unpaid evaluation copy of Resource Tuner 2. http://www.heaventools.com" fullword wide
      $s2 = ",c#m!." fullword ascii
      $s3 = "J- I]w'" fullword ascii
      $s4 = "l -~ONI" fullword ascii
      $s5 = "R.cFG5" fullword ascii
      $s6 = "            " fullword ascii /* reversed goodware string '            ' */
      $s7 = "      " fullword ascii /* reversed goodware string '      ' */
      $s8 = "                   " fullword ascii /* Goodware String - occured 1 times */
      $s9 = "                 " fullword ascii /* reversed goodware string '                 ' */
      $s10 = "     " fullword ascii /* reversed goodware string '     ' */
      $s11 = "       " fullword ascii /* reversed goodware string '       ' */
      $s12 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "iXnTikB.x" fullword ascii
      $s14 = "yCPKEiZ" fullword ascii
      $s15 = "GsLN7Z:~|" fullword ascii
      $s16 = "dmmg@95I" fullword ascii
      $s17 = "!@:8mtpj>H|" fullword ascii
      $s18 = "yaNF$-+r" fullword ascii
      $s19 = "cmlBP^?" fullword ascii
      $s20 = "slcph?" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw4_007 {
   meta:
      description = "mw4 - file 007"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "69377611e6c5887ae5532935e126508f5f3e704511445a98af08dd90a4c2a541"
   strings:
      $s1 = "maila.microsoft.com" fullword ascii
      $s2 = "c.mx.mail.yahoo.com" fullword ascii
      $s3 = "mailin-04.mx.aol.com" fullword ascii
      $s4 = "d.mx.mail.yahoo.com" fullword ascii
      $s5 = "mailin-02.mx.aol.com" fullword ascii
      $s6 = "mailin-03.mx.aol.com" fullword ascii
      $s7 = "mailin-01.mx.aol.com" fullword ascii
      $s8 = "win%s.exe" fullword ascii
      $s9 = "<body><h2>502 Bad Gateway</h2><h3>Host Not Found or connection failed.</h3></body></html>" fullword ascii
      $s10 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword ascii
      $s11 = "proxy-connection: " fullword ascii
      $s12 = "Content-type: text/html; unsigned charset=us-ascii" fullword ascii
      $s13 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" fullword ascii
      $s14 = "<html><head><title>502 Bad Gateway</title></head>" fullword ascii
      $s15 = "imx1.rambler.ru" fullword ascii
      $s16 = "HTTP/1.0 502 Bad Gateway" fullword ascii
      $s17 = "mx1.yandex.ru" fullword ascii
      $s18 = "connection: " fullword ascii
      $s19 = "mx2.yandex.ru" fullword ascii
      $s20 = "mxs.mail.ru" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw4_028 {
   meta:
      description = "mw4 - file 028"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "0917972024d28a451aa884365b08c91315242981252c8c0aa392cced75aad237"
   strings:
      $s1 = "Esag %d ocog axilav.dll yxyjul itot" fullword ascii
      $s2 = "Ohulag.dll ebyv ower isoh ovar" fullword ascii
      $s3 = "Avajug.dll alalag iriz; orutyz" fullword ascii
      $s4 = "Yzar.dll erok; yryw" fullword ascii
      $s5 = "Yzur; agifaf.dll etik enorap %d ozid" fullword ascii
      $s6 = "Umeruf.dll elus" fullword ascii
      $s7 = "Umix.dll ucujef ifis = epus" fullword ascii
      $s8 = "Ukejoj asup %s amem.dll ysaqog" fullword ascii
      $s9 = "Isan efew ytyw.dll adol" fullword ascii
      $s10 = "Ulep ipyx.dll ugez ocyxyb" fullword ascii
      $s11 = "Evav isyv.dll ahux efenyk yheqyh" fullword ascii
      $s12 = "Ygetah ewek. oxit ohyk %d yjog" fullword ascii
      $s13 = "Esyjor eqym %d udes* ebihex %s eniv" fullword ascii
      $s14 = "Epuloq %s upupoz; azisyc* efiv" fullword ascii
      $s15 = "Oviwyl %d egimid* omin" fullword ascii
      $s16 = "Ijudar* ecosax ozezig. otutat %s usywil" fullword ascii
      $s17 = "Uxon %d oqyv orahol uhufyc* ofuqib" fullword ascii
      $s18 = "Ymyj yzyfan alog atuwih" fullword ascii
      $s19 = "R-Tools Technology Inc." fullword wide
      $s20 = "(c) R-Tools Technology Inc. 2001-2016" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw4_022 {
   meta:
      description = "mw4 - file 022"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "8568792c09fb696503d8465ade59adb9a2a30044661cfc0b4cb0a9a1eb3f93f9"
   strings:
      $s1 = "Srv.exe" fullword ascii
      $s2 = "B@C.EXE" fullword ascii
      $s3 = "q.com/fcg-b'/" fullword ascii
      $s4 = "PROXYAN" fullword ascii
      $s5 = "ShellexlT" fullword ascii
      $s6 = "%Exe.dat" fullword ascii
      $s7 = "tp://uTrs.qzo" fullword ascii
      $s8 = "7runa)(l" fullword ascii
      $s9 = " HTTP/1.1" fullword ascii
      $s10 = "loseHandleReadFi" fullword ascii
      $s11 = "GetMuR" fullword ascii
      $s12 = "GET / " fullword ascii
      $s13 = "yVhPLMpy3" fullword ascii
      $s14 = "LOADER ERROR" fullword ascii /* Goodware String - occured 5 times */
      $s15 = "?PRskgwq" fullword ascii
      $s16 = "hlBT7!2" fullword ascii
      $s17 = "6Bk:jWmuk'YC" fullword ascii
      $s18 = "9\\%d.ba$n" fullword ascii
      $s19 = "CKKXQG@" fullword ascii
      $s20 = "Wqct q!" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw4_010 {
   meta:
      description = "mw4 - file 010"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "0ddf30cf4169ecd61fb44c875dd06a5f167c47085c2b2a9e11756766b0747217"
   strings:
      $s1 = "V=Lwkdll" fullword ascii
      $s2 = "sc -t%" fullword ascii
      $s3 = "}&%Q%D+" fullword ascii
      $s4 = "RUNPROGRAM" fullword wide /* Goodware String - occured 9 times */
      $s5 = "Extracting" fullword wide /* Goodware String - occured 13 times */
      $s6 = "Extract" fullword wide /* Goodware String - occured 44 times */
      $s7 = "REBOOT" fullword wide /* Goodware String - occured 51 times */
      $s8 = "PendingFileRenameOperations" fullword ascii /* Goodware String - occured 53 times */
      $s9 = "RegServer" fullword ascii /* Goodware String - occured 58 times */
      $s10 = "CABINET" fullword wide /* Goodware String - occured 66 times */
      $s11 = "Reboot" fullword ascii /* Goodware String - occured 107 times */
      $s12 = "SeShutdownPrivilege" fullword ascii /* Goodware String - occured 216 times */
      $s13 = "QDrHOtR%>" fullword ascii
      $s14 = "DuLk1g," fullword ascii
      $s15 = "Mejd8BJ" fullword ascii
      $s16 = "{aLYg_Wb" fullword ascii
      $s17 = "xkhIwh~" fullword ascii
      $s18 = "'8[uPGEis{" fullword ascii
      $s19 = "KlEG|]X" fullword ascii
      $s20 = "^bAjnP?" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw4_021 {
   meta:
      description = "mw4 - file 021"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "bb0f26097d4b901320fd0862ff2c240728f0d3bd3fa70f9a6d6f59ccf6124790"
   strings:
      $s1 = "fllllllll" fullword ascii /* reversed goodware string 'llllllllf' */
      $s2 = "llllllllp" fullword ascii /* reversed goodware string 'pllllllll' */
      $s3 = "OnExecuteMacro" fullword ascii
      $s4 = "EIdNoExecuteSpecified" fullword ascii
      $s5 = "ullllllll" fullword ascii /* reversed goodware string 'llllllllu' */
      $s6 = "kllllllll" fullword ascii /* reversed goodware string 'llllllllk' */
      $s7 = "llllllllr" fullword ascii /* reversed goodware string 'rllllllll' */
      $s8 = "dllllllll" fullword ascii /* reversed goodware string 'lllllllld' */
      $s9 = "llllllll*" fullword ascii /* reversed goodware string '*llllllll' */
      $s10 = "No command handler found.*Error on call Winsock2 library function %s&Error on loading Winsock2 library (%s)" fullword wide
      $s11 = "No execute handler found." fullword wide
      $s12 = "TIdCommandHandler8" fullword ascii
      $s13 = "ddllllllll" fullword ascii
      $s14 = "kdllllllll" fullword ascii
      $s15 = "udllllllll" fullword ascii
      $s16 = "TIdCommandEvent" fullword ascii
      $s17 = "TIdCommandHandlers" fullword ascii
      $s18 = "TIdBeforeCommandHandlerEvent" fullword ascii
      $s19 = "TIdCommandHandlersh" fullword ascii
      $s20 = "PasswordCharL" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw4_024 {
   meta:
      description = "mw4 - file 024"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "4a0adbe7cb0d2731e7c14bc5fac4cbc27f2c8586d8d34e006a2bead095eab093"
   strings:
      $s1 = "wKERNEL32.DLL" fullword wide
      $s2 = "_stub.exe" fullword ascii
      $s3 = "74.4*+ &4" fullword ascii /* hex encoded string 'tD' */
      $s4 = "(7+ >.8./)" fullword ascii /* hex encoded string 'x' */
      $s5 = "+2/>6<25$" fullword ascii /* hex encoded string '&%' */
      $s6 = "\"!5>65\"9" fullword ascii /* hex encoded string 'VY' */
      $s7 = "*>7&,%\"2#" fullword ascii /* hex encoded string 'r' */
      $s8 = ":;%=40+'!=" fullword ascii /* hex encoded string '@' */
      $s9 = "$)=?>7;<1" fullword ascii /* hex encoded string 'q' */
      $s10 = ">\"4$'\"6" fullword ascii /* hex encoded string 'F' */
      $s11 = "= %\">+23" fullword ascii /* hex encoded string '#' */
      $s12 = "25#=5\"?5" fullword ascii /* hex encoded string '%U' */
      $s13 = ";!\"$&&2#=*5" fullword ascii /* hex encoded string '%' */
      $s14 = "$66$$5948" fullword ascii /* hex encoded string 'fYH' */
      $s15 = "puhezimosafodidusepejacuda" fullword ascii
      $s16 = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" fullword ascii
      $s17 = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" ascii
      $s18 = "sucufususabohe nihideyadizeru leviyahudejitafe" fullword ascii
      $s19 = "9.1.2.40" fullword wide
      $s20 = " -&#:9" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw4_020 {
   meta:
      description = "mw4 - file 020"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "43fc601c61e062c0dcb7b33b7b6498f838915a0c8f45fa802b62d40e07c6ed47"
   strings:
      $s1 = "c:\\Fraction\\during\\TeamYes.pdb" fullword ascii
      $s2 = "13.2.94.58" fullword wide
      $s3 = "Spellare" fullword wide
      $s4 = "SUVWhn3" fullword ascii
      $s5 = "URPQQh(L@" fullword ascii
      $s6 = "AuQBAoEV" fullword ascii
      $s7 = ";;2;<;U;a;m;t;" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "GGGd?c" fullword ascii
      $s9 = "GGBe=AX\"" fullword ascii
      $s10 = "RWVG.H7U" fullword ascii
      $s11 = "iwvi{zG" fullword ascii
      $s12 = "6:6@6L6" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "GGNPx+N5" fullword ascii
      $s14 = "3V5]5c5" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "CjvD/gd\\" fullword ascii
      $s16 = "GTiF3o`" fullword ascii
      $s17 = "GYqzlu{L" fullword ascii
      $s18 = "GGGP?#" fullword ascii
      $s19 = "=(y.UCQ" fullword ascii
      $s20 = "Bottle Rocket Apps Real" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw4_029 {
   meta:
      description = "mw4 - file 029"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "54fe2e5ddda7205c0ace5a5420c7e076611ad0a4f542fe2489d9268c464f498d"
   strings:
      $s1 = "brrrrrrrr" fullword ascii /* reversed goodware string 'rrrrrrrrb' */
      $s2 = "Hrrrrrrrr" fullword ascii /* reversed goodware string 'rrrrrrrrH' */
      $s3 = "Elevation<" fullword ascii
      $s4 = "Drrrrrrrr" fullword ascii /* reversed goodware string 'rrrrrrrrD' */
      $s5 = "1rrrrrrrr" fullword ascii /* reversed goodware string 'rrrrrrrr1' */
      $s6 = "SavePictureDialog1" fullword ascii
      $s7 = "TOnGetLegendPos" fullword ascii
      $s8 = "TAverageTeeFunction" fullword ascii
      $s9 = "OnGetAxisLabel ^G" fullword ascii
      $s10 = "IShellFolder$" fullword ascii
      $s11 = "OnGetNextAxisLabel" fullword ascii
      $s12 = "Dark3DL F" fullword ascii
      $s13 = "OnGetSiteInfoh" fullword ascii
      $s14 = "LogarithmicBase" fullword ascii
      $s15 = "TOpenPictureDialog@" fullword ascii
      $s16 = "TAxisOnGetLabel" fullword ascii
      $s17 = "OnGetLegendTexth" fullword ascii
      $s18 = "TDarkGrayPen" fullword ascii
      $s19 = "Logarithmic<" fullword ascii
      $s20 = "SavePictureDialog1 " fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw4_023 {
   meta:
      description = "mw4 - file 023"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "df0bb4e7246c4031607327c48b14d16b7c23c80500cf1c257b2f5144184d3228"
   strings:
      $s1 = "Elevation<" fullword ascii
      $s2 = "SavePictureDialog1" fullword ascii
      $s3 = "TOnGetLegendPos" fullword ascii
      $s4 = "TAverageTeeFunction" fullword ascii
      $s5 = "OnGetAxisLabel ^G" fullword ascii
      $s6 = "IShellFolder$" fullword ascii
      $s7 = "OnGetNextAxisLabel" fullword ascii
      $s8 = "Dark3DL F" fullword ascii
      $s9 = "OnGetSiteInfoh" fullword ascii
      $s10 = "LogarithmicBase" fullword ascii
      $s11 = "TOpenPictureDialog@" fullword ascii
      $s12 = "TAxisOnGetLabel" fullword ascii
      $s13 = "OnGetLegendTexth" fullword ascii
      $s14 = "TDarkGrayPen" fullword ascii
      $s15 = "Logarithmic<" fullword ascii
      $s16 = "SavePictureDialog1 " fullword ascii
      $s17 = "TOpenDialoghzB" fullword ascii
      $s18 = "TOnGetLegendRect" fullword ascii
      $s19 = "ltsLeftPercent" fullword ascii
      $s20 = "TAxisOnGetNextLabel" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw4_013 {
   meta:
      description = "mw4 - file 013"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "ea721b83c12fd31e7df6bbf8d1516c663046cc809e6fa2672b27b3b6c113bf23"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s2 = "NanoCore Client.exe" fullword ascii
      $s3 = "IClientUIHost" fullword ascii /* base64 encoded string ' )bz{T z,' */
      $s4 = "ClientLoaderForm.resources" fullword ascii
      $s5 = "IClientLoggingHost" fullword ascii
      $s6 = "ClientLoaderForm" fullword ascii
      $s7 = "NanoCore.ClientPluginHost" fullword ascii
      $s8 = "PluginCommand" fullword ascii
      $s9 = "GetBlockHash" fullword ascii
      $s10 = "FileCommand" fullword ascii
      $s11 = "PipeExists" fullword ascii
      $s12 = "PipeCreated" fullword ascii
      $s13 = "HostDetails" fullword ascii
      $s14 = "LogClientException" fullword ascii
      $s15 = "#=quXVzKqGldmgtXgVm61aLog==" fullword ascii
      $s16 = "#=qh9KSqT0kHBFSDanZ7gXkKb1vdDfzZS3JIRcUnMfcljE=" fullword ascii
      $s17 = "#=q61s8d6EIAdSsDLLjqchw1w==" fullword ascii
      $s18 = "#=q85afbI_HcqBFOZnC0iAqsNghLb3LsuyjFtpLEYYoPX8=" fullword ascii
      $s19 = "get_BuilderSettings" fullword ascii
      $s20 = "IClientAppHost" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw4_019 {
   meta:
      description = "mw4 - file 019"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "b59ce929ad222163893d2ed6591a397fd7ad7b4eb99a84e6ef613dc5eb41490c"
   strings:
      $s1 = "processthreadsapi.h" fullword ascii
      $s2 = "&rvaTarget" fullword ascii
      $s3 = "__ZL24SimpleBlobRC4KeyTemplate" fullword ascii
      $s4 = "__Z8peLoaderPh" fullword ascii
      $s5 = "C:\\crossdev\\gccmaster\\build-tdm64\\gcc\\x86_64-w64-mingw32\\32\\libgcc" fullword ascii
      $s6 = "___mingw_winmain_lpCmdLine" fullword ascii
      $s7 = "<__mingw_GetSectionForAddress" fullword ascii
      $s8 = "9lpszCommandLine" fullword ascii
      $s9 = "GNU C 4.9.2 -m32 -mtune=generic -march=x86-64 -g -O2 -std=gnu99" fullword ascii
      $s10 = "GNU C 4.9.2 -m32 -mtune=generic -march=x86-64 -g -O2 -O2 -O2 -fbuilding-libgcc -fno-stack-protector" fullword ascii
      $s11 = "M__mingw_winmain_lpCmdLine" fullword ascii
      $s12 = "!Target" fullword ascii
      $s13 = ")Target" fullword ascii
      $s14 = "__ZL27PrivateKeyWithExponentOfOne" fullword ascii
      $s15 = " __security_cookie_complement" fullword ascii
      $s16 = "Main.cpp" fullword ascii
      $s17 = "__imp__CryptEncrypt@28" fullword ascii
      $s18 = "=_GetPEImageBase" fullword ascii
      $s19 = "mingw_get_invalid_parameter_handler" fullword ascii
      $s20 = "\"pNTHeader64" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw4_003 {
   meta:
      description = "mw4 - file 003"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "a0b226c819d35f2638491e1dadbeb973f2531d09ca9fb6bd769746a5cac8c5ff"
   strings:
      $s1 = "XTREME" fullword wide
      $s2 = "rlmonwin" fullword ascii
      $s3 = "Vhtuall" fullword ascii
      $s4 = "tions Copyrigh" fullword ascii
      $s5 = "L]do -," fullword ascii
      $s6 = "advapi" fullword ascii
      $s7 = "rMod1EndOf\"Bx" fullword ascii
      $s8 = "nel32.dll" fullword ascii /* Goodware String - occured 1 times */
      $s9 = ",2003 Avenger by NhT" fullword ascii
      $s10 = "Se*rocessDEP" fullword ascii
      $s11 = "Ch#GeltiByt" fullword ascii
      $s12 = "KWindow*" fullword ascii
      $s13 = "WVXEGHF@A" fullword ascii
      $s14 = "l(rlen,Wri+" fullword ascii
      $s15 = "izeofR(ourc" fullword ascii
      $s16 = "raryAGBb5U" fullword ascii
      $s17 = "BMemory" fullword ascii
      $s18 = "XGYfUb;d" fullword ascii
      $s19 = "RteYk9Cw" fullword ascii
      $s20 = "FANNxtq" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw4_005 {
   meta:
      description = "mw4 - file 005"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "99a305b395e433924576ddc489ea1fd63233a1cbba3331ba1192b4d8d52bcb8b"
   strings:
      $s1 = "connect" fullword ascii /* Goodware String - occured 429 times */
      $s2 = "socket" fullword ascii /* Goodware String - occured 453 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 10KB and
      all of them
}

rule _root_BytMe_new_datasets_mw4_006 {
   meta:
      description = "mw4 - file 006"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "8a7ee2b9c5d03c6f2b2f03ba8feee99c01f8cc1403fd49ecaa9d22c1b8dcceb5"
   strings:
      $s1 = ".fsddd" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 10KB and
      all of them
}

rule _root_BytMe_new_datasets_mw4_009 {
   meta:
      description = "mw4 - file 009"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "186ff276e9a955faecfd2a6d2f13681836dd07a65b16d09cd49446c413a8ef69"
   strings:
      $s1 = "micro.exe" fullword wide
      $s2 = "lehAh.pdb" fullword ascii
      $s3 = "Decimal - " fullword wide
      $s4 = "decoder not found error" fullword wide
      $s5 = "Hex - " fullword wide
      $s6 = "major%minor%build%patch%2100 bDlpFQbHOPRVGAKqXWRe 1001101010101000" fullword wide
      $s7 = "pyright" fullword wide
      $s8 = "l$o:\\$o" fullword ascii
      $s9 = "carmen logo" fullword ascii
      $s10 = "The community" fullword wide
      $s11 = "Hint Designer Form:TsFrameAdapter adapter must be placed on the handled frame" fullword wide
      $s12 = "bye electionics spot radio tone" fullword ascii
      $s13 = "everybody used" fullword wide
      $s14 = " Microsoft Corporation. All r" fullword wide
      $s15 = "PbsWj AND jAw" fullword ascii
      $s16 = "RZFeX>p'n$" fullword ascii
      $s17 = "cnhJVPlejveDmhA,4LspxyVXTr4905fqeGEXTqDTXl" fullword ascii
      $s18 = "T@Y@.bVG" fullword ascii
      $s19 = "koSw\\5k?" fullword ascii
      $s20 = "(YnDJA=k" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _029_023_021_0 {
   meta:
      description = "mw4 - from files 029, 023, 021"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "54fe2e5ddda7205c0ace5a5420c7e076611ad0a4f542fe2489d9268c464f498d"
      hash2 = "df0bb4e7246c4031607327c48b14d16b7c23c80500cf1c257b2f5144184d3228"
      hash3 = "bb0f26097d4b901320fd0862ff2c240728f0d3bd3fa70f9a6d6f59ccf6124790"
   strings:
      $s1 = "SavePictureDialog1" fullword ascii
      $s2 = "UrlMon" fullword ascii /* Goodware String - occured 35 times */
      $s3 = "TFiler" fullword ascii /* Goodware String - occured 48 times */
      $s4 = "SysUtils" fullword ascii /* Goodware String - occured 49 times */
      $s5 = "TPersistent" fullword ascii /* Goodware String - occured 55 times */
      $s6 = "Sender" fullword ascii /* Goodware String - occured 194 times */
      $s7 = "shutdown" fullword ascii /* Goodware String - occured 263 times */
      $s8 = "listen" fullword ascii /* Goodware String - occured 304 times */
      $s9 = "status" fullword wide /* Goodware String - occured 328 times */
      $s10 = "Command" fullword ascii /* Goodware String - occured 382 times */
      $s11 = "Source" fullword ascii /* Goodware String - occured 660 times */
      $s12 = "Default" fullword ascii /* Goodware String - occured 914 times */
      $s13 = "EIdStackSetSizeExceededj" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "TEditMask" fullword ascii /* Goodware String - occured 1 times */
      $s15 = " 2001, 2002 Mike Lischke" fullword ascii
      $s16 = "%s (%s)|%1:s|%s" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "%s%s (*.%s)|*.%2:s" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "LargeChange<" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "EIdWS2StubError" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "TSilentPaintPanel" fullword ascii /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _029_023_1 {
   meta:
      description = "mw4 - from files 029, 023"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "54fe2e5ddda7205c0ace5a5420c7e076611ad0a4f542fe2489d9268c464f498d"
      hash2 = "df0bb4e7246c4031607327c48b14d16b7c23c80500cf1c257b2f5144184d3228"
   strings:
      $s1 = "Elevation<" fullword ascii
      $s2 = "TOnGetLegendPos" fullword ascii
      $s3 = "TAverageTeeFunction" fullword ascii
      $s4 = "OnGetAxisLabel ^G" fullword ascii
      $s5 = "IShellFolder$" fullword ascii
      $s6 = "OnGetNextAxisLabel" fullword ascii
      $s7 = "Dark3DL F" fullword ascii
      $s8 = "OnGetSiteInfoh" fullword ascii
      $s9 = "LogarithmicBase" fullword ascii
      $s10 = "TOpenPictureDialog@" fullword ascii
      $s11 = "TAxisOnGetLabel" fullword ascii
      $s12 = "OnGetLegendTexth" fullword ascii
      $s13 = "TDarkGrayPen" fullword ascii
      $s14 = "Logarithmic<" fullword ascii
      $s15 = "SavePictureDialog1 " fullword ascii
      $s16 = "TOpenDialoghzB" fullword ascii
      $s17 = "TOnGetLegendRect" fullword ascii
      $s18 = "ltsLeftPercent" fullword ascii
      $s19 = "TAxisOnGetNextLabel" fullword ascii
      $s20 = "TSavePictureDialog`" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "5b5db1d2ae3530a881a13aa0779c42ea" and ( 8 of them )
      ) or ( all of them )
}

rule _017_027_2 {
   meta:
      description = "mw4 - from files 017, 027"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "047254190855a5ff47d744bf80d8227391ce8893396958039dbf6f2e31deac09"
      hash2 = "d9ba88953a73e0360033b508a67f37e0128f03e2b6b920ff67480508a1d2f205"
   strings:
      $s1 = "SELECT encryptedUsername, encryptedPassword, formSubmitURL, hostname FROM moz_logins" fullword ascii
      $s2 = "sCrypt32.dll" fullword wide
      $s3 = "SMTP Password" fullword wide
      $s4 = "FtpPassword" fullword wide
      $s5 = "%s\\%s%i\\data\\settings\\ftpProfiles-j.jsd" fullword wide
      $s6 = "aPLib v1.01  -  the smaller the better :)" fullword ascii
      $s7 = "%s\\%s\\User Data\\Default\\Login Data" fullword wide
      $s8 = "%s%s\\Login Data" fullword wide
      $s9 = "%s%s\\Default\\Login Data" fullword wide
      $s10 = "%s\\32BitFtp.TMP" fullword wide
      $s11 = "%s\\GoFTP\\settings\\Connections.txt" fullword wide
      $s12 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" fullword wide
      $s13 = "%s\\Mozilla\\SeaMonkey\\Profiles\\%s" fullword wide
      $s14 = "%s\\%s\\%s.exe" fullword wide
      $s15 = "More information: http://www.ibsensoftware.com/" fullword ascii
      $s16 = "%s\\nss3.dll" fullword wide
      $s17 = "PopPassword" fullword wide
      $s18 = "SmtpAccount" fullword wide
      $s19 = "SMTP User" fullword wide
      $s20 = "POP3 Password" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and pe.imphash() == "0239fd611af3d0e9b0c46c5837c80e09" and ( 8 of them )
      ) or ( all of them )
}

rule _001_026_3 {
   meta:
      description = "mw4 - from files 001, 026"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "a771a51473ab688e632ba4e6717f3fc7d687e75fa8fb9a263dca1cbe391631e0"
      hash2 = "11795f67078514a7c64e3e92f429b42bab7228d106d201ae0c5c3c54248f200c"
   strings:
      $s1 = "not_connected" fullword ascii /* Goodware String - occured 581 times */
      $s2 = "wrong_protocol_type" fullword ascii /* Goodware String - occured 581 times */
      $s3 = "already_connected" fullword ascii /* Goodware String - occured 581 times */
      $s4 = "host_unreachable" fullword ascii /* Goodware String - occured 581 times */
      $s5 = "network_reset" fullword ascii /* Goodware String - occured 581 times */
      $s6 = "network_unreachable" fullword ascii /* Goodware String - occured 581 times */
      $s7 = "network_down" fullword ascii /* Goodware String - occured 581 times */
      $s8 = "connection_already_in_progress" fullword ascii /* Goodware String - occured 581 times */
      $s9 = "protocol_not_supported" fullword ascii /* Goodware String - occured 581 times */
      $s10 = "connection_refused" fullword ascii /* Goodware String - occured 581 times */
      $s11 = "permission_denied" fullword ascii /* Goodware String - occured 581 times */
      $s12 = "connection_aborted" fullword ascii /* Goodware String - occured 584 times */
      $s13 = "owner dead" fullword ascii /* Goodware String - occured 620 times */
      $s14 = "connection already in progress" fullword ascii /* Goodware String - occured 620 times */
      $s15 = "wrong protocol type" fullword ascii /* Goodware String - occured 620 times */
      $s16 = "network reset" fullword ascii /* Goodware String - occured 620 times */
      $s17 = "network down" fullword ascii /* Goodware String - occured 620 times */
      $s18 = "protocol not supported" fullword ascii /* Goodware String - occured 621 times */
      $s19 = "connection aborted" fullword ascii /* Goodware String - occured 621 times */
      $s20 = "network unreachable" fullword ascii /* Goodware String - occured 622 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _019_025_4 {
   meta:
      description = "mw4 - from files 019, 025"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "b59ce929ad222163893d2ed6591a397fd7ad7b4eb99a84e6ef613dc5eb41490c"
      hash2 = "5df26114f76ec86dcd5309e3b50379fd57f0e0f86b22d3245d17c6e17fdd96d3"
   strings:
      $s1 = "            " fullword ascii /* reversed goodware string '            ' */
      $s2 = "      " fullword ascii /* reversed goodware string '      ' */
      $s3 = "                   " fullword ascii /* Goodware String - occured 1 times */
      $s4 = "                 " fullword ascii /* reversed goodware string '                 ' */
      $s5 = "     " fullword ascii /* reversed goodware string '     ' */
      $s6 = "       " fullword ascii /* reversed goodware string '       ' */
      $s7 = "             " fullword ascii /* Goodware String - occured 3 times */
      $s8 = "      " fullword ascii /* Goodware String - occured 3 times */
      $s9 = "           " fullword ascii /* Goodware String - occured 3 times */
      $s10 = "                               " fullword ascii /* Goodware String - occured 3 times */
      $s11 = "         " fullword ascii /* Goodware String - occured 3 times */
      $s12 = "                     " fullword ascii /* Goodware String - occured 3 times */
      $s13 = "               " fullword ascii /* Goodware String - occured 3 times */
      $s14 = "               " fullword ascii /* Goodware String - occured 3 times */
      $s15 = "              " fullword ascii /* Goodware String - occured 3 times */
      $s16 = "     " fullword ascii /* Goodware String - occured 3 times */
      $s17 = "         " fullword ascii /* Goodware String - occured 3 times */
      $s18 = "     " fullword ascii /* Goodware String - occured 3 times */
      $s19 = "                " fullword ascii /* Goodware String - occured 3 times */
      $s20 = "                 " fullword ascii /* Goodware String - occured 3 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _016_015_018_5 {
   meta:
      description = "mw4 - from files 016, 015, 018"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "bdec6a1b8e17e049eb5ee4c0c376268a42dfd507d58989fdd7125c7f7f3e0a2d"
      hash2 = "cf3b508a117f920321c97e21a10564c88dd3fabd23ca804ec846d1baa7b128dd"
      hash3 = "e8f2ff23543e3d48a08b9e941de5858a298ef7830ba76c983e8c4d50dc2cbf4b"
   strings:
      $s1 = "nmcogame.dll" fullword wide
      $s2 = "version=\"3.0.2.0\"" fullword ascii
      $s3 = "Softpub" fullword wide
      $s4 = "supportpportableMayweboAspassed" fullword ascii
      $s5 = "File not found (error)" fullword wide
      $s6 = "NexonMessenger Game Service" fullword wide
      $s7 = "Ytbrowseron" fullword ascii
      $s8 = "Nexon Corp." fullword wide
      $s9 = "owMancrashdevelopersPhilippN61" fullword ascii
      $s10 = "zbthat" fullword ascii
      $s11 = "withwherecontainsvikingalsoXxMoorer" fullword ascii
      $s12 = "Fuinstallation.117bGoogletGfour-partZ" fullword ascii
      $s13 = "H2bonniethet1" fullword ascii
      $s14 = "WgeminiL0s2010,about:labs,twotheu" fullword ascii
      $s15 = "oSvFirebug,XDfs" fullword ascii
      $s16 = "forQisalex" fullword ascii
      $s17 = "jthatappUpdate,Qflusess" fullword ascii
      $s18 = "Exchange Cluster View Mode on" fullword wide
      $s19 = "name=\"DelphiApplication\"" fullword ascii /* Goodware String - occured 2 times */
      $s20 = "y-KC@@" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and ( 8 of them )
      ) or ( all of them )
}

