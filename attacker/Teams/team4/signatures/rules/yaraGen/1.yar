/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2024-04-17
   Identifier: mw1
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule _root_BytMe_new_datasets_mw1_0020 {
   meta:
      description = "mw1 - file 0020"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "f6e897ad1b6e528be9e2caa9cb1ad48d451b354681636e160cc4e9c7a0c6ab43"
   strings:
      $s1 = "sdtez%^565hfdgtftrjiytjgfn.pdb" fullword ascii
      $s2 = "<description>YGUg ii JijOSBF oj SOWUOJKS</description>" fullword ascii
      $s3 = "            processorArchitecture=\"x86\" " fullword ascii
      $s4 = "yerydfgx" fullword ascii
      $s5 = "sfetyfh" fullword ascii
      $s6 = "|$R:\\$R" fullword ascii
      $s7 = "wfw.fwf" fullword wide
      $s8 = "50c Hereford Road1" fullword ascii
      $s9 = "FLQG|H{" fullword ascii
      $s10 = "}.lDv/M" fullword ascii
      $s11 = "Certum EV TSA SHA20" fullword ascii
      $s12 = "    name=\"Microsoft.Windows.Security.WlRmdr\"" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "dgdgfw#" fullword ascii
      $s14 = "http://subca.ocsp-certum.com01" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "Greater London1" fullword ascii
      $s16 = "http://crl.certum.pl/ctnca.crl0k" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "AGF RESOURCING LTD0" fullword ascii
      $s18 = "LiOh@p,O" fullword ascii
      $s19 = "AGF RESOURCING LTD1" fullword ascii
      $s20 = " NHuwh8urn NUHie" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw1_0009 {
   meta:
      description = "mw1 - file 0009"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "295a9bf2efdeb7a99bbdeacacbdb6af9195178db9c6beba63e1f5f06c4c054f2"
   strings:
      $s1 = "##################RRRRRRRRRRRRRRRRRR.pdb" fullword ascii
      $s2 = "            processorArchitecture=\"x86\" " fullword ascii
      $s3 = "< <&<,<2<8<><" fullword ascii /* hex encoded string '(' */
      $s4 = "wfw.fwf" fullword wide
      $s5 = " Microsoft Corp" fullword wide
      $s6 = "    name=\"Microsoft.Windows.Security.WlRmdr\"" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "SARI SEFWI LIMITED1" fullword ascii
      $s8 = "147 St. James's Crescent1" fullword ascii
      $s9 = "HjERjRWjER" fullword ascii
      $s10 = "yDadF[V" fullword ascii
      $s11 = "                                                                                                " fullword ascii /* Goodware String - occured 1 times */
      $s12 = "SxZ00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ascii
      $s13 = "SxZ00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ascii
      $s14 = "CFRhb\\" fullword ascii
      $s15 = "VoRh-\\" fullword ascii
      $s16 = "hKox?c" fullword ascii
      $s17 = "vvWEHWRHE" fullword ascii
      $s18 = "jEbwV@#GRB" fullword ascii
      $s19 = "jerjWEHJERjeRje#" fullword ascii
      $s20 = "SARI SEFWI LIMITED0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw1_0011 {
   meta:
      description = "mw1 - file 0011"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "35dc29c0132f1684fc8ed518f98d959bd982ef058b3ba24d8a23ea1507452621"
   strings:
      $s1 = "lejjwppqbncvm,xfkjhjasockzlefp.pdb" fullword ascii
      $s2 = "<description>YGUg ii JijOSBF oj SOWUOJKS</description>" fullword ascii
      $s3 = "            processorArchitecture=\"x86\" " fullword ascii
      $s4 = "yerydfgx" fullword ascii
      $s5 = "sfetyfh" fullword ascii
      $s6 = "wfw.fwf" fullword wide
      $s7 = "CvE:%1" fullword ascii
      $s8 = "D$ -&P%" fullword ascii
      $s9 = "    name=\"Microsoft.Windows.Security.WlRmdr\"" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "dgdgfw#" fullword ascii
      $s11 = "FEf4 ef dgdsger" fullword wide
      $s12 = "XSFt4y gewKJIo" fullword wide
      $s13 = "|OipJ~Y=" fullword ascii
      $s14 = "%)zjcY{yz" fullword ascii
      $s15 = "ffbN]HO" fullword ascii
      $s16 = "LOKALIX LIMITED0" fullword ascii
      $s17 = "jsGO8l2|" fullword ascii
      $s18 = "LOKALIX LIMITED1" fullword ascii
      $s19 = "|ilmy)zC" fullword ascii
      $s20 = "rWGZP|t" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw1_0015 {
   meta:
      description = "mw1 - file 0015"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "7a711d338e2314968acb2ba760da3b19e113a08fd0d66dbff557b31c5f0de22f"
   strings:
      $s1 = "http://ocsp.starfieldtech.com/0H" fullword ascii
      $s2 = "lejRLContextm,xupGetBackupInformatifp.pdb" fullword ascii
      $s3 = "\"Starfield Timestamp Authority - G20" fullword ascii
      $s4 = "Chttp://crl.starfieldtech.com/repository/masterstarfield2issuing.crl0P" fullword ascii
      $s5 = "<http://crl.starfieldtech.com/repository/sf_issuing_ca-g2.crt0T" fullword ascii
      $s6 = "Starfield Technologies, LLC1+0)" fullword ascii
      $s7 = "            processorArchitecture=\"x86\" " fullword ascii
      $s8 = "<description>YGURLContextPropeUOJKS</description>" fullword ascii
      $s9 = "yerydfgx" fullword ascii
      $s10 = "sfetyfh" fullword ascii
      $s11 = "PrivateProfilr" fullword wide
      $s12 = "Softring" fullword wide
      $s13 = "lpWHZrWHf0" fullword ascii
      $s14 = "    name=\"Microsoft.Windows.Security.WlRmdr\"" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "dgdgfw#" fullword ascii
      $s16 = "LOKALIX LIMITED0" fullword ascii
      $s17 = "LOKALIX LIMITED1" fullword ascii
      $s18 = " Microsoft Co" fullword wide
      $s19 = "aWvOc#Z" fullword ascii
      $s20 = "JYpTfM]" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw1_0012 {
   meta:
      description = "mw1 - file 0012"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "81e96c07e6c9cb02f72c0943a42ff9f8f09a09c508f8bbaa1142a9ee4f1326cf"
   strings:
      $s1 = "nMSPDB100.DLL" fullword wide
      $s2 = "RwDrv.sys" fullword wide
      $s3 = "d:\\src\\rw\\rwxe3\\rw\\driver\\objfre_win7_x86\\i386\\RwDrv.pdb" fullword ascii
      $s4 = "d:\\src\\rw\\rwxe3\\rw\\driver\\objfre_win7_amd64\\amd64\\RwDrv.pdb" fullword ascii
      $s5 = "Can not get address EFI boot script. Error = %x" fullword ascii
      $s6 = "OtherTargetOS: %s" fullword ascii
      $s7 = "Get PCI -> Bus:%x Dev:%x Func:%x Offset:%x Value = %x" fullword ascii
      $s8 = "Read port SmiEn failed = %x" fullword ascii
      $s9 = "Error read tmp mem for SMBIOS = %x" fullword ascii
      $s10 = "SMI_EN get failed." fullword ascii
      $s11 = "Get IA32_SMRR_PHYSMASK failed." fullword ascii
      $s12 = "Get PCI failed. Error = %x" fullword ascii
      $s13 = "Failed get nvar SecureBoot. Error = %x" fullword ascii
      $s14 = "Get FR failed." fullword ascii
      $s15 = "SMRAMC get failed." fullword ascii
      $s16 = "PwrMgn get failed." fullword ascii
      $s17 = "Get IA32_SMRR_PHYSBASE failed." fullword ascii
      $s18 = "Get size image failed. Size = %x" fullword ascii
      $s19 = "RCRB get failed." fullword ascii
      $s20 = "Get BIOS_CNTL failed. Error = %x" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw1_0023 {
   meta:
      description = "mw1 - file 0023"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "04f468bec220fa9dfd4897adf86f28f8ceb04a72806c473cd22e366f716389a3"
   strings:
      $x1 = "cmd.exe /c \"%s\"" fullword ascii
      $s2 = "tasksche.exe" fullword ascii
      $s3 = "Global\\MsWinZonesCacheCounterMutexA" fullword ascii
      $s4 = "Inx%k:\\" fullword ascii
      $s5 = "Iw* -cv" fullword ascii
      $s6 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii
      $s7 = "QrRUl* " fullword ascii
      $s8 = "IKFJ- =" fullword ascii
      $s9 = "grK.Mtt" fullword ascii
      $s10 = "zHN.bAN" fullword ascii
      $s11 = "5Aw:\\(" fullword ascii
      $s12 = "msg/m_portuguese.wnry" fullword ascii
      $s13 = "CLL:\\u" fullword ascii
      $s14 = "CMDs@a$i" fullword ascii
      $s15 = "nyMZ?%g;" fullword ascii
      $s16 = "]irc3'" fullword ascii
      $s17 = "uM} -\\O" fullword ascii
      $s18 = "DDq'- " fullword ascii
      $s19 = "m!* 9cO" fullword ascii
      $s20 = "F: -v/" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw1_0008 {
   meta:
      description = "mw1 - file 0008"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "99146cd4d31df0f8f76aab7a7f78992140ead8d7ff847b9c56707335d81d96e4"
   strings:
      $s1 = "gicfnn" fullword ascii
      $s2 = "OLEAU\\T" fullword ascii
      $s3 = "fVLVTV`-R" fullword ascii
      $s4 = "BtHA*--)" fullword ascii
      $s5 = "1>rJIeR<t=" fullword ascii
      $s6 = "=Curs96P" fullword ascii
      $s7 = "R@lImag<eN:HwwdUr" fullword ascii
      $s8 = "ld new" fullword ascii
      $s9 = "gHYRk0" fullword ascii
      $s10 = "oKNPh2" fullword ascii
      $s11 = "RNbL32" fullword ascii
      $s12 = "OC!)-F" fullword ascii
      $s13 = "5r.tKvvx" fullword ascii
      $s14 = "0/1a1p1w1" fullword ascii
      $s15 = "y&as~k" fullword ascii
      $s16 = "UQPXY]" fullword ascii
      $s17 = "Pn,_,)j" fullword ascii
      $s18 = "8dj-[F" fullword ascii
      $s19 = "Xjh\"$6c" fullword ascii
      $s20 = "esn>fRQ.g" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw1_0000 {
   meta:
      description = "mw1 - file 0000"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "6f2589be92c2d0fa6050e52fbedb967c2590a8abbc4a9459fb7f78bc52407195"
   strings:
      $s1 = "C:\\047302f42b3873947793175561b0efdd8a1fa304.exe" fullword ascii
      $s2 = "wms.exe" fullword wide
      $s3 = "Microsoft Windows Operationg System" fullword wide
      $s4 = "Windows Manager Service" fullword wide
      $s5 = "GHHHFHZGJHIHGHZGGHJHGHZGHHFHGH" fullword ascii
      $s6 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGX" fullword ascii
      $s7 = "047302f42b3873947793175561b0efdd8a1fa304" ascii
      $s8 = "17.14.11.2" fullword wide
      $s9 = "Broken pipe" fullword ascii /* Goodware String - occured 749 times */
      $s10 = "Permission denied" fullword ascii /* Goodware String - occured 830 times */
      $s11 = "1H4L4P4T4X4\\4`4d4h4l4x4|4" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "ZK[KHIZKXJGLXJGHHHFHZGJHIHGHZGGHJHGHZGHHFHGHEGVHILHL[KMIZKXJGLXJFHZGFH[GEJIJIJMIEGELMKELZGILZKJKNKXKHKYKGLHK[GZK[KNKHLGLJKKJYGMK" ascii
      $s13 = "HKGLFKJKHJ[GJKHLFKJKXKJKGLYGMKHKGLFKJKHL[GGHHHFHZGJHIHGHZGGHJHGHZGHHFHGH[G[GVHELILILMKEGIJHJ[IEJ" fullword ascii
      $s14 = "L$dSVSSSSPQh" fullword ascii
      $s15 = "EGVHMKILLKZKJKXIYGILZKJKILZK[KHIZKXJGLXJIKJKIK[KHKZKJKXKGLJLYGYKGL[KKKYGLLLLLLYGML[GZK[KNKILFKHKNKXKELELFKEGVHJKELNLIJYGILZKJKIL" ascii
      $s16 = "64686T6X6`6h6p6t6|6" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "3&4f4|4" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "808<8X8d8" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "7*727:7Q7j7" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "=\"=V=e=" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw1_0006 {
   meta:
      description = "mw1 - file 0006"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "ce093ffa19f020a2b73719f653b5e0423df28ef1d59035d55e99154a85c5c668"
   strings:
      $s1 = "cmdagent.exe" fullword wide
      $s2 = "sqlagent.exe" fullword wide
      $s3 = "mydesktopservice.exe" fullword wide
      $s4 = "firefoxconfig.exe" fullword wide
      $s5 = "tbirdconfig.exe" fullword wide
      $s6 = "ocomm.exe" fullword wide
      $s7 = "sqbcoreservice.exe" fullword wide
      $s8 = "2ntdll.dll" fullword wide
      $s9 = "msftesql.exe" fullword wide
      $s10 = "sqlbrowser.exe" fullword wide
      $s11 = "sqlwriter.exe" fullword wide
      $s12 = "oracle.exe" fullword wide
      $s13 = "ocssd.exe" fullword wide
      $s14 = "dbsnmp.exe" fullword wide
      $s15 = "synctime.exe" fullword wide
      $s16 = "agntsvc.exeisqlplussvc.exe" fullword wide
      $s17 = "xfssvccon.exe" fullword wide
      $s18 = "agntsvc.exeagntsvc.exe" fullword wide
      $s19 = "agntsvc.exeencsvc.exe" fullword wide
      $s20 = "mydesktopqos.exe" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw1_0019 {
   meta:
      description = "mw1 - file 0019"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "c905f2dec79ccab115ad32578384008696ebab02276f49f12465dcd026c1a615"
   strings:
      $s1 = "ntmsap.dll" fullword ascii
      $s2 = "Processing command:" fullword ascii
      $s3 = "release mutex - %u (%u)(%u)" fullword ascii
      $s4 = "\\system32\\win.com" fullword ascii
      $s5 = "MsJavaVM.dll" fullword wide
      $s6 = "Error(%d) CreateProcess." fullword ascii
      $s7 = "Log: Error(%d) get file size." fullword ascii
      $s8 = "Mutex_Log" fullword ascii
      $s9 = "Command Id:%u%010u(%02d:%02d:%02d %02d/%02d/%04d)" fullword ascii
      $s10 = "%s%%s08x.tmp" fullword ascii
      $s11 = "MakeFile Error(%d) copy file to temp file %s" fullword ascii
      $s12 = "Size of %s - %u" fullword ascii
      $s13 = "_hMutex: %u" fullword ascii
      $s14 = "%s\\system32\\winview.ocx" fullword ascii
      $s15 = "Processing volumes" fullword wide
      $s16 = " Windows NT %d.%d; SV1)" fullword ascii
      $s17 = "Run instruction: %d ID:%u%010u(%02d:%02d:%02d %02d/%02d/%04d)" fullword ascii
      $s18 = "explorer.exe %s" fullword ascii
      $s19 = "cmd /c %s" fullword ascii
      $s20 = "Error: pos(%d) > CmdSize(%d)" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw1_0010 {
   meta:
      description = "mw1 - file 0010"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "ff2eb800ff16745fc13c216ff6d5cc2de99466244393f67ab6ea6f8189ae01dd"
   strings:
      $s1 = "[Cmd] - CMD_BOTCMD_CONNLOG_GET" fullword wide
      $s2 = "[Cmd] - CMD_BLACKLIST_GET" fullword wide
      $s3 = "[Cmd] - CMD_GETINFO" fullword wide
      $s4 = "User-Agent: Mozillar/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Win64; x32; Trident/5.0)" fullword ascii
      $s5 = "User-Agent: Mozillar/5.0 (compatible; MSIE 9.0; Windows NT 5.1; Win64; x32; Trident/5.0)" fullword ascii
      $s6 = "User-Agent: Mozillar/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/6.0)" fullword ascii
      $s7 = "User-Agent: Mozillar/5.0 (compatible; MSIE 10.0; Windows NT 5.1; Win64; x32; Trident/5.0)" fullword ascii
      $s8 = "User-Agent: Mozillar/5.0 (compatible; MSIE 8.0; Windows NT 6.2; Win64; x64; Trident/6.0)" fullword ascii
      $s9 = "User-Agent: Mozillar/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Win64; x64; Trident/6.0)" fullword ascii
      $s10 = "Server_Dll.dll" fullword ascii
      $s11 = "User-Agent: Mozillar/5.0 (compatible; MSIE 8.0; Windows NT 5.3; Win64; x32; Trident/5.0)" fullword ascii
      $s12 = "User-Agent: Mozillar/5.0 (compatible; MSIE 9.0; Windows NT 5.2; Win64; x32; Trident/5.0)" fullword ascii
      $s13 = "[Cmd] - ERROR_CMD" fullword wide
      $s14 = "[SaveCmdLog] - Success" fullword wide
      $s15 = "scmdlogb.cpl" fullword wide
      $s16 = "scmdlog.cpl" fullword wide
      $s17 = "[Cmd] - CMD_BLACKLIST_SET" fullword wide
      $s18 = "[Cmd] - CMD_TIMESYNC" fullword wide
      $s19 = "[Cmd] - CMD_BOTCMD_SAVE" fullword wide
      $s20 = "[Cmd] - CMD_BOTCMD_INIT" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw1_0017 {
   meta:
      description = "mw1 - file 0017"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "3727dd9aad35776b4991eec1edb968844448bb9b104b1dbdc9bef7587dc948da"
   strings:
      $x1 = ".The specified target is unknown or unreachable0The Local Security Authority cannot be contacted-The requested security package " wide
      $x2 = "The credentials supplied were not complete, and could not be verified. Additional information can be returned from the context.4" wide
      $s3 = "Unknown credentials use!Do AcquireCredentialsHandle first\"CompleteAuthToken is not supportedKUTF8: A start byte not followed by" wide
      $s4 = "The logon attempt failed;The credentials supplied to the package were not recognized4No credentials are available in the securit" wide
      $s5 = "Project1.exe" fullword ascii
      $s6 = "-Smartcard logon is required and was not used.!A system shutdown is in progress.'An invalid request was sent to the KDC.DThe KDC" wide
      $s7 = "4Cannot extract file - unsupported compression method4Cannot extract file - no extraction support provided&Cannot extract file -" wide
      $s8 = "decoded a symbol not between 0 and 18 {ReadLitDistCodeLengths}" fullword wide
      $s9 = "decoded a code length out of range {ReadLitDistCodeLengths}" fullword wide
      $s10 = "EThe function completed successfully, but CompleteToken must be calledtThe function completed successfully, but both CompleteTok" wide
      $s11 = "Invalid cab file template!Invalid file - not a cabinet file(VMS: request to read too many bytes [%d]" fullword wide
      $s12 = "TAbLogger.Read: loggers are write-only, no reading allowed" fullword wide
      $s13 = "ping 1.1.1.1 -n 1 -w 800 > nul" fullword wide
      $s14 = "OnProcessItemFailure" fullword ascii
      $s15 = "FOnProcessItemFailure" fullword ascii
      $s16 = "decoded an invalid length symbol: greater than 285 [DecodeData]" fullword wide
      $s17 = "decoded an invalid distance symbol: greater than 29 [DecodeData]" fullword wide
      $s18 = "?WThe given \"%s\" local time is invalid (situated within the missing period prior to DST).8String index out of range (%d).  Mus" wide
      $s19 = "Address type not supported.\"%s: Circular links are not allowed\"Not enough data in buffer. (%d/%d)" fullword wide
      $s20 = "SystemhIH" fullword ascii /* base64 encoded string 'K+-zhH' */
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw1_0016 {
   meta:
      description = "mw1 - file 0016"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "ece3cfdb75aaabc570bf38af6f4653f73101c1641ce78a4bb146e62d9ac0cd50"
   strings:
      $s1 = "pool.supportxmr.com" fullword ascii
      $s2 = "[%s:%u] login error code: %d" fullword ascii
      $s3 = "xmrig.dll" fullword ascii
      $s4 = "msxml.exe" fullword wide
      $s5 = ".nicehash.com" fullword ascii
      $s6 = "pool.supportxmr.com:80" fullword ascii
      $s7 = ".minergate.com" fullword ascii
      $s8 = "Copyright (C) 2016-2018 microsoft.com" fullword wide
      $s9 = "[%s:%u] getaddrinfo error: \"%s\"" fullword ascii
      $s10 = "[%s:%u] connect error: \"%s\"" fullword ascii
      $s11 = "temporary failure" fullword ascii
      $s12 = "      --user-agent         set custom user-agent string for pool" fullword ascii
      $s13 = "[%s:%u] read error: \"%s\"" fullword ascii
      $s14 = " * THREADS:      %d, %s, av=%d, %sdonate=%d%%%s" fullword ascii
      $s15 = "[%s:%u] JSON decode failed: \"%s\"" fullword ascii
      $s16 = "[%s:%u] JSON decode failed" fullword ascii
      $s17 = "      --cpu-priority       set process priority (0 idle, 2 normal to 5 highest)" fullword ascii
      $s18 = " * COMMANDS:     'h' hashrate, 'p' pause, 'r' resume" fullword ascii
      $s19 = "      --cpu-affinity       set process affinity to CPU core(s), mask 0x3 for cores 0 and 1" fullword ascii
      $s20 = "[01;37m, %s, av=%d, %sdonate=%d%%%s" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw1_0018 {
   meta:
      description = "mw1 - file 0018"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "24ed6ee6c21b01723299773311912048f6a4a782de9496c6e479c22d6fceb085"
   strings:
      $s1 = "2147483650" ascii /* hex encoded string '!GH6P' */
      $s2 = "dTarget" fullword ascii
      $s3 = "      '%PROGID%.%VERSION%' = s '%DESCRIPTION%'" fullword ascii
      $s4 = "KERNELM" fullword ascii
      $s5 = "          Elevation" fullword ascii
      $s6 = "    <requestedExecutionLevel" fullword ascii
      $s7 = "                    NoRemove ElevationPolicy" fullword ascii
      $s8 = "  <description>Microsoft build</description>" fullword ascii
      $s9 = "+'f:\\dd\\vctools" fullword ascii
      $s10 = "      '%PROGID%' = s '%DESCRIPTION%'" fullword ascii
      $s11 = "        ForceRemove '%CLSID%' = s '%DESCRIPTION%'" fullword ascii
      $s12 = "lghijklmnopq" fullword ascii
      $s13 = "onmlkjp" fullword ascii
      $s14 = "IUY.lqt" fullword ascii
      $s15 = "wCInv.dArg" fullword ascii
      $s16 = "    version=\"3.0.0.0\"" fullword ascii
      $s17 = "vWIn.ncCDu=" fullword ascii
      $s18 = "BRrZfailD" fullword ascii
      $s19 = "DcEUSER" fullword ascii
      $s20 = "rUnkn<= 'dwRef6m" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw1_0004 {
   meta:
      description = "mw1 - file 0004"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "dce2d575bef073079c658edfa872a15546b422ad2b74267d33b386dc7cc85b47"
   strings:
      $s1 = "AE:\\Qs" fullword ascii
      $s2 = "-cIrC#;" fullword ascii
      $s3 = "E7* 4V" fullword ascii
      $s4 = "S- groW" fullword ascii
      $s5 = "eiipak" fullword ascii
      $s6 = "Y0&+ 6." fullword ascii
      $s7 = "EqKiNm7" fullword ascii
      $s8 = "18@j -Z" fullword ascii
      $s9 = "nK+ Jw" fullword ascii
      $s10 = "\\76%S,U|" fullword ascii
      $s11 = "H%* [g" fullword ascii
      $s12 = "BgCF.tR" fullword ascii
      $s13 = "qHFhKCEH" fullword ascii
      $s14 = "EDXcWtL" fullword ascii
      $s15 = "WDgP3\\" fullword ascii
      $s16 = "IUlMlV@" fullword ascii
      $s17 = "DrnG!-" fullword ascii
      $s18 = ",VkWUuUX#3;*}" fullword ascii
      $s19 = "$IT.eBt" fullword ascii
      $s20 = "d-:aASPR\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw1_0007 {
   meta:
      description = "mw1 - file 0007"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "a45bd4059d804b586397f43ee95232378d519c6b8978d334e07f6047435fe926"
   strings:
      $s1 = "dowitcher.exe" fullword wide
      $s2 = "errorblasted" fullword ascii
      $s3 = "hornfair" fullword ascii
      $s4 = "vwynnngggbikk" fullword ascii
      $s5 = "wwwnnnghhgmq" fullword ascii
      $s6 = "xwwnmmgffeeetxx" fullword ascii
      $s7 = "vvvmmmggglpp" fullword ascii
      $s8 = "wwwnnnhhhmqq" fullword ascii
      $s9 = "vvwmmmfggelpx" fullword ascii
      $s10 = "ACCOUNTANTS10" fullword ascii
      $s11 = "yyytttfffaab" fullword ascii
      $s12 = "contrarevolutionary" fullword ascii
      $s13 = "vvvmmmg" fullword ascii
      $s14 = "dowitcher" fullword wide
      $s15 = "NkwFam;Xf1Ra -2" fullword ascii
      $s16 = "yyyssteeeccc" fullword ascii
      $s17 = "vvwmmmggginp" fullword ascii
      $s18 = "sulfurcolored" fullword wide
      $s19 = "sorry.fire.below.four.strike.firm]" fullword wide
      $s20 = "WHITEBELLIED" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw1_0014 {
   meta:
      description = "mw1 - file 0014"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "dcbfd12321fa7c4fa9a72486ced578fdc00dcee79e6d95aa481791f044a55af3"
   strings:
      $s1 = "rpcnetp.exe" fullword ascii
      $s2 = "Mozilla/4.0 (compatible; MSIE 6.0;)" fullword ascii
      $s3 = "System\\CurrentControlSet\\Services\\rpcnetp" fullword ascii
      $s4 = "rpcnetp" fullword ascii
      $s5 = "HtkHt(Ht" fullword ascii
      $s6 = ".cdata" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "tgHtEHu" fullword ascii
      $s8 = "HtjHtTHt6Hu" fullword ascii
      $s9 = "='=A=h=" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "8T8[8b8" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "0I1k1|1" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "PWVh\"7@" fullword ascii
      $s13 = ":\":::R:z:" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "t\"95lP@" fullword ascii
      $s15 = "L0n0v0" fullword ascii
      $s16 = "0 1$1(1" fullword ascii /* Goodware String - occured 4 times */
      $s17 = "5%5=5L5f5n5t5z5" fullword ascii
      $s18 = "\\System32\\svchost.exe" fullword ascii /* Goodware String - occured 4 times */
      $s19 = "3#4(444<4G4O4\\4d4" fullword ascii
      $s20 = "???K?~?" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw1_0013 {
   meta:
      description = "mw1 - file 0013"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "3f48dbbf86f29e01809550f4272a894ff4b09bd48b0637bd6745db84d2cec2b6"
   strings:
      $s1 = "rpcnetp.exe" fullword ascii
      $s2 = "Mozilla/4.0 (compatible; MSIE 6.0;)" fullword ascii
      $s3 = "System\\CurrentControlSet\\Services\\rpcnetp" fullword ascii
      $s4 = "rpcnetp" fullword ascii
      $s5 = "HtkHt(Ht" fullword ascii
      $s6 = ".cdata" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "tgHtEHu" fullword ascii
      $s8 = "HtjHtTHt6Hu" fullword ascii
      $s9 = "='=A=h=" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "8T8[8b8" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "0I1k1|1" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "PWVh\"7@" fullword ascii
      $s13 = ":\":::R:z:" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "t\"95lP@" fullword ascii
      $s15 = "L0n0v0" fullword ascii
      $s16 = "0 1$1(1" fullword ascii /* Goodware String - occured 4 times */
      $s17 = "5%5=5L5f5n5t5z5" fullword ascii
      $s18 = "\\System32\\svchost.exe" fullword ascii /* Goodware String - occured 4 times */
      $s19 = "3#4(444<4G4O4\\4d4" fullword ascii
      $s20 = "???K?~?" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw1_0002 {
   meta:
      description = "mw1 - file 0002"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "077d9e0e12357d27f7f0c336239e961a7049971446f7a3f10268d9439ef67885"
   strings:
      $x1 = "%SystemRoot%\\system32\\svchost.exe -k Wmmvsvc" fullword ascii
      $x2 = "%SystemRoot%\\system32\\svchost.exe -k SCardPrv" fullword ascii
      $x3 = "%SystemRoot%\\system32\\Wmmvsvc.dll" fullword ascii
      $s4 = "%SystemRoot%\\system32\\scardprv.dll" fullword ascii
      $s5 = "Wmmvsvc.dll" fullword ascii
      $s6 = "scardprv.dll" fullword ascii
      $s7 = "SYSTEM\\CurrentControlSet\\Services\\Wmmvsvc" fullword ascii
      $s8 = "Provides Windows Media management information to and from drivers. " fullword ascii
      $s9 = "Windows Media Management Driver Extensions" fullword ascii
      $s10 = "Manages and controls access to a smart card inserted into a smart card reader attached to the computer and protect from others. " ascii
      $s11 = "Wmmvsvc" fullword ascii
      $s12 = "SYSTEM\\CurrentControlSet\\Services\\SCardPrv" fullword ascii
      $s13 = "+  dH9" fullword ascii
      $s14 = " -w1WMd" fullword ascii
      $s15 = "+  dHY" fullword ascii
      $s16 = "MnNv<=I" fullword ascii
      $s17 = "B|WWDftvE" fullword ascii
      $s18 = "VXugT}7\"z" fullword ascii
      $s19 = "tadg2~W" fullword ascii
      $s20 = "NBRm/{~D" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw1_0003 {
   meta:
      description = "mw1 - file 0003"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "4845761c9bed0563d0aa83613311191e075a9b58861e80392914d61a21bad976"
   strings:
      $s1 = "c:\\Users\\user\\Desktop\\openssl-1.0.1e_m\\/ssl/cert.pem" fullword ascii
      $s2 = "c:\\Users\\user\\Desktop\\openssl-1.0.1e_m\\/ssl/private" fullword ascii
      $s3 = "c:\\Users\\user\\Desktop\\openssl-1.0.1e_m\\/ssl/certs" fullword ascii
      $s4 = "c:\\Users\\user\\Desktop\\openssl-1.0.1e_m\\/ssl" fullword ascii
      $s5 = "c:\\Users\\user\\Desktop\\openssl-1.0.1e_m\\/lib/engines" fullword ascii
      $s6 = "Xtunnel_Http_Method.exe" fullword ascii
      $s7 = "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0" fullword ascii
      $s8 = "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36" fullword wide
      $s9 = " thread=%lu, file=%s, line=%d, info=\"" fullword ascii
      $s10 = " JJ5Jj" fullword ascii /* reversed goodware string 'jJ5JJ ' */
      $s11 = " filename=\"smime.p7s\"%s%s" fullword ascii
      $s12 = " smime-type=%s;" fullword ascii
      $s13 = " ' ) - 3 G M Q _ c e i w } " fullword ascii
      $s14 = "        Public key OCSP hash: " fullword ascii
      $s15 = " %s%lu (%s0x%lx)" fullword ascii
      $s16 = "error in select, errno %d" fullword ascii
      $s17 = " HTTP/1.1" fullword ascii
      $s18 = " name=\"%s\"%s" fullword ascii
      $s19 = " filename=\"%s\"%s" fullword ascii
      $s20 = "45.32.129.185" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw1_0021 {
   meta:
      description = "mw1 - file 0021"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "40ae43b7d6c413becc92b07076fa128b875c8dbb4da7c036639eccf5a9fc784f"
   strings:
      $s1 = "c:\\Users\\user\\Desktop\\openssl-1.0.1e_m\\/ssl/cert.pem" fullword ascii
      $s2 = "c:\\Users\\user\\Desktop\\openssl-1.0.1e_m\\/ssl/private" fullword ascii
      $s3 = "c:\\Users\\user\\Desktop\\openssl-1.0.1e_m\\/ssl/certs" fullword ascii
      $s4 = "c:\\Users\\user\\Desktop\\openssl-1.0.1e_m\\/ssl" fullword ascii
      $s5 = "c:\\Users\\user\\Desktop\\openssl-1.0.1e_m\\/lib/engines" fullword ascii
      $s6 = "Xtunnel_Http_Method.exe" fullword ascii
      $s7 = "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0" fullword ascii
      $s8 = "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36" fullword wide
      $s9 = " thread=%lu, file=%s, line=%d, info=\"" fullword ascii
      $s10 = " JJ5Jj" fullword ascii /* reversed goodware string 'jJ5JJ ' */
      $s11 = " filename=\"smime.p7s\"%s%s" fullword ascii
      $s12 = " smime-type=%s;" fullword ascii
      $s13 = " ' ) - 3 G M Q _ c e i w } " fullword ascii
      $s14 = "        Public key OCSP hash: " fullword ascii
      $s15 = " %s%lu (%s0x%lx)" fullword ascii
      $s16 = "error in select, errno %d" fullword ascii
      $s17 = " HTTP/1.1" fullword ascii
      $s18 = " name=\"%s\"%s" fullword ascii
      $s19 = " filename=\"%s\"%s" fullword ascii
      $s20 = " characters" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw1_0005 {
   meta:
      description = "mw1 - file 0005"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "49b769536224f160b6087dc866edf6445531c6136ab76b9d5079ce622b043200"
   strings:
      $x1 = "<?aHp4enFzZml2d3NnY3NwY3l4bWd3d3NnY2F4a2dxbWd3eG5lZGR3dGpiZHJocnVo4Mbi4OLg4ODgQCvsKMgoISgzKB0oZihNKFYooCmFKZcp+CnHKSgpOikfKWkpci" ascii
      $s2 = "Nk3bVYY005h4/coS5iHq7RbinxWja5SoduabsgDGgsTxuSDn1hGOrAMzML3LQjSkeVe5VxQ5gP0C0VQruiWVEFheKQwCG3QNtxdvHnwSesgCnh3gNKXj0Rm908rDXYKf" ascii
      $s3 = "yznDXF7/4trG/4arwmwqAGa0EC4Wfc2aYX5r7F3BqE43wgDC2gAw3ftAwzeSJEWlOgybG79cIZvPwnd8haqSlsuWw30k9ooMwc3jv+Re56BI5IkNUbkB249bC7JSpr4C" ascii
      $s4 = "Uw+EK1vP/MzuaA7UYicJskaFUMbJfDkc/eYePEh+1SI2NLDXnv4k3PEB1TAFaIl/qTD+/GhjUY6S7DBUAoDE340l/zlHWKwoyFgG7Zd1KMgTaQfjIoO3nXHgN4lCl4/C" ascii
      $s5 = "~SHLWAPI.DLL~~msvcrt.dll~comctl32.dll~" fullword ascii
      $s6 = "wV7UzXzER+PFbLL4tlh3q9DRfrTqAKi7EG5OAnS+CIcxlHRU8OBWH1CUlz7edmRO3kLu52eaCCt/cmDzPRUtH2dzHN/bJtsEwjK3pM53ZxjeMbvsSpywNKGvUfBvxxM8" ascii
      $s7 = "mailto:hdietrich@gmail.com" fullword ascii
      $s8 = "SopCast.exe" fullword wide
      $s9 = "Copyright (C) 2004 - 2013, SopCast.com.  All rights reserved." fullword wide
      $s10 = "www.sopcast.com" fullword wide
      $s11 = "a+7akkbZDu+x0iVKValdlL3IwA3db6ridHKf/vGLeO3LaLHsEZfDorayuIojCJ5b86HwSqy3MSkPzXKOd2P7/YnhUT0rWW/9YTFyPb8RHkqqpB2RjBI4YGTkAx3r9xVF" ascii
      $s12 = "4cdg6xHmLcPTjh6A34gDNrud0XDqPrZUI7qgy+BKygmo+BHUQf3ojmGEtWLnb9/P6v/Q3nCEXaYFQ7HFbW4jPThaXgrGLVh80topQXUIZt6mibkVbEZ5fT69aoyJaBoD" ascii
      $s13 = "xnFZlNbEWJnZ/HA0uNVs5LXPOQ2xQrLyjNPir+lvirSP9rT+jYRbvRd9NTIT9xR8HkkVTOMqaUjrDqGCwkiDXWZ3TkSPV826ZWka9MHwBtXvHe9FTpgVR1Mp/V1OG4AO" ascii
      $s14 = "WzzP4hkBOLyWcHJ645OsFPKxfJ5yJ9vzZz1CPEnMUyjSsO0CZd1oP08/TRyzkMIspYPMaZlTFQDOOXetDbrrkyDdtCGTbGbW9DgNS2xNgjcfpPg4B6gSICOdehAuCiLk" ascii
      $s15 = "+UhTOf5eJtWjhs9o/zx17Rokvnj7T8KWJnZdxj870VN6YOP/31Wqaif+p+NaG7w/306QdIc3fUP0CE1bUK7mhNZjr8WpYJ+4KmDaTfjmxVdZ11EktwDkR4pnmZg+kcPG" ascii
      $s16 = "kJteNwx2pRHROHgdYSHborOwMXpx2pvYDQECGfIFjrRTYeHtB6TyBnbU00aziQ/v0tEJbY4JFyQR7QrxOehx0xPstAyEj3FDsq8+QiuDfmswA6mjpmn8GsopLEmKP0cD" ascii
      $s17 = "5lzSachP+qU9DsDEvqEvDARPeYe7jDwBtZK6xdtCN3tcnSsb5vD5vki5nUWWOD/JMezHDtVifUjBikAeC5WzCEKixTECT/rKo9Rc8f0DJnvNYmHyP9LszXn2jCT6vQVU" ascii
      $s18 = "SsYWR34mtWTKj7gOKeovZ89/NI1ib69of/5HmqFjlpGBR8qYwJRk2uh0DQKujgy7xaC1FsfuXRg4EhGvirC5Tw0CoqYztj5B22y+DuWnBudUqxFs9xVUbuAyYwoEgKZM" ascii
      $s19 = "9prXRjS9IObOzQbsQEpH4cNksPyE1NPjGNIDPaCvfUpMUa5Arg9fb0/EN5ZjmeNUBlk52xOo1YKEHg4TP/4+AWaMhxqLq7vkdRlgnTgQVcgi88yxi0pCbqogJD7nEyoi" ascii
      $s20 = "eYK0VRRIInljdmXEH5RraxhksoxAfm8aArzKutNFwdn/jHLESpYeWax0479hKq0fNR7xLEUEY9YNfaACwQdSji+kzsmlz+nwgQGv0ZiguCz1KDO/m1sqMPppPsyXdgSo" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw1_0001 {
   meta:
      description = "mw1 - file 0001"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "024a7ee33fb7e998cde95a0d0e4850022a8742e16544f8b1b32baf4b64644643"
   strings:
      $s1 = ">=\\33\"/" fullword ascii /* hex encoded string '3' */
      $s2 = "J:\\&2a" fullword ascii
      $s3 = "by+u:\"s" fullword ascii
      $s4 = "%u%olLtH" fullword ascii
      $s5 = "zK)-!." fullword ascii
      $s6 = "R$?* Z{" fullword ascii
      $s7 = " -\\^rS" fullword ascii
      $s8 = "Fc /fO" fullword ascii
      $s9 = "kIJXYW_" fullword ascii
      $s10 = "6srJk_[dP=l" fullword ascii
      $s11 = "TnHEe}3" fullword ascii
      $s12 = "oLBKMP%" fullword ascii
      $s13 = "%GBQpm3=" fullword ascii
      $s14 = "WxbzYIB" fullword ascii
      $s15 = "bXie5:E" fullword ascii
      $s16 = "acRb?b" fullword ascii
      $s17 = "wJrN!W" fullword ascii
      $s18 = "ljzAM^S}" fullword ascii
      $s19 = "FWrO^Jp>" fullword ascii
      $s20 = "FdvI`/8<:" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _0003_0021_0 {
   meta:
      description = "mw1 - from files 0003, 0021"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "4845761c9bed0563d0aa83613311191e075a9b58861e80392914d61a21bad976"
      hash2 = "40ae43b7d6c413becc92b07076fa128b875c8dbb4da7c036639eccf5a9fc784f"
   strings:
      $s1 = "c:\\Users\\user\\Desktop\\openssl-1.0.1e_m\\/ssl/cert.pem" fullword ascii
      $s2 = "c:\\Users\\user\\Desktop\\openssl-1.0.1e_m\\/ssl/private" fullword ascii
      $s3 = "c:\\Users\\user\\Desktop\\openssl-1.0.1e_m\\/ssl/certs" fullword ascii
      $s4 = "c:\\Users\\user\\Desktop\\openssl-1.0.1e_m\\/ssl" fullword ascii
      $s5 = "c:\\Users\\user\\Desktop\\openssl-1.0.1e_m\\/lib/engines" fullword ascii
      $s6 = "Xtunnel_Http_Method.exe" fullword ascii
      $s7 = "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0" fullword ascii
      $s8 = "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36" fullword wide
      $s9 = " thread=%lu, file=%s, line=%d, info=\"" fullword ascii
      $s10 = " JJ5Jj" fullword ascii /* reversed goodware string 'jJ5JJ ' */
      $s11 = " filename=\"smime.p7s\"%s%s" fullword ascii
      $s12 = " smime-type=%s;" fullword ascii
      $s13 = " ' ) - 3 G M Q _ c e i w } " fullword ascii
      $s14 = "        Public key OCSP hash: " fullword ascii
      $s15 = " %s%lu (%s0x%lx)" fullword ascii
      $s16 = "error in select, errno %d" fullword ascii
      $s17 = " HTTP/1.1" fullword ascii
      $s18 = " name=\"%s\"%s" fullword ascii
      $s19 = " filename=\"%s\"%s" fullword ascii
      $s20 = " characters" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and pe.imphash() == "5b6222ff6b0354200f1a2d5ee56097b6" and ( 8 of them )
      ) or ( all of them )
}

rule _0003_0016_0021_1 {
   meta:
      description = "mw1 - from files 0003, 0016, 0021"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "4845761c9bed0563d0aa83613311191e075a9b58861e80392914d61a21bad976"
      hash2 = "ece3cfdb75aaabc570bf38af6f4653f73101c1641ce78a4bb146e62d9ac0cd50"
      hash3 = "40ae43b7d6c413becc92b07076fa128b875c8dbb4da7c036639eccf5a9fc784f"
   strings:
      $s1 = "socket" fullword ascii /* Goodware String - occured 453 times */
      $s2 = "connection already in progress" fullword ascii /* Goodware String - occured 620 times */
      $s3 = "owner dead" fullword ascii /* Goodware String - occured 620 times */
      $s4 = "network down" fullword ascii /* Goodware String - occured 620 times */
      $s5 = "wrong protocol type" fullword ascii /* Goodware String - occured 620 times */
      $s6 = "network reset" fullword ascii /* Goodware String - occured 620 times */
      $s7 = "connection aborted" fullword ascii /* Goodware String - occured 621 times */
      $s8 = "protocol not supported" fullword ascii /* Goodware String - occured 621 times */
      $s9 = "network unreachable" fullword ascii /* Goodware String - occured 622 times */
      $s10 = "host unreachable" fullword ascii /* Goodware String - occured 624 times */
      $s11 = "protocol error" fullword ascii /* Goodware String - occured 641 times */
      $s12 = "permission denied" fullword ascii /* Goodware String - occured 645 times */
      $s13 = "connection refused" fullword ascii /* Goodware String - occured 650 times */
      $s14 = "broken pipe" fullword ascii /* Goodware String - occured 688 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0014_0013_2 {
   meta:
      description = "mw1 - from files 0014, 0013"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "dcbfd12321fa7c4fa9a72486ced578fdc00dcee79e6d95aa481791f044a55af3"
      hash2 = "3f48dbbf86f29e01809550f4272a894ff4b09bd48b0637bd6745db84d2cec2b6"
   strings:
      $s1 = "rpcnetp.exe" fullword ascii
      $s2 = "Mozilla/4.0 (compatible; MSIE 6.0;)" fullword ascii
      $s3 = "System\\CurrentControlSet\\Services\\rpcnetp" fullword ascii
      $s4 = "rpcnetp" fullword ascii
      $s5 = "HtkHt(Ht" fullword ascii
      $s6 = ".cdata" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "tgHtEHu" fullword ascii
      $s8 = "HtjHtTHt6Hu" fullword ascii
      $s9 = "='=A=h=" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "8T8[8b8" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "0I1k1|1" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "PWVh\"7@" fullword ascii
      $s13 = ":\":::R:z:" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "t\"95lP@" fullword ascii
      $s15 = "L0n0v0" fullword ascii
      $s16 = "0 1$1(1" fullword ascii /* Goodware String - occured 4 times */
      $s17 = "5%5=5L5f5n5t5z5" fullword ascii
      $s18 = "\\System32\\svchost.exe" fullword ascii /* Goodware String - occured 4 times */
      $s19 = "3#4(444<4G4O4\\4d4" fullword ascii
      $s20 = "???K?~?" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and pe.imphash() == "5ca3fccf907dd5d90b504f5066ae19f3" and ( 8 of them )
      ) or ( all of them )
}

rule _0003_0021_0017_3 {
   meta:
      description = "mw1 - from files 0003, 0021, 0017"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "4845761c9bed0563d0aa83613311191e075a9b58861e80392914d61a21bad976"
      hash2 = "40ae43b7d6c413becc92b07076fa128b875c8dbb4da7c036639eccf5a9fc784f"
      hash3 = "3727dd9aad35776b4991eec1edb968844448bb9b104b1dbdc9bef7587dc948da"
   strings:
      $s1 = "public_key" fullword ascii /* Goodware String - occured 87 times */
      $s2 = "serialNumber" fullword ascii /* Goodware String - occured 148 times */
      $s3 = "serial" fullword ascii /* Goodware String - occured 168 times */
      $s4 = "SHA256" fullword ascii /* Goodware String - occured 225 times */
      $s5 = "signature" fullword ascii /* Goodware String - occured 251 times */
      $s6 = "listen" fullword ascii /* Goodware String - occured 304 times */
      $s7 = "server" fullword ascii /* Goodware String - occured 401 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and ( all of them )
      ) or ( all of them )
}

rule _0020_0009_0011_0015_4 {
   meta:
      description = "mw1 - from files 0020, 0009, 0011, 0015"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "f6e897ad1b6e528be9e2caa9cb1ad48d451b354681636e160cc4e9c7a0c6ab43"
      hash2 = "295a9bf2efdeb7a99bbdeacacbdb6af9195178db9c6beba63e1f5f06c4c054f2"
      hash3 = "35dc29c0132f1684fc8ed518f98d959bd982ef058b3ba24d8a23ea1507452621"
      hash4 = "7a711d338e2314968acb2ba760da3b19e113a08fd0d66dbff557b31c5f0de22f"
   strings:
      $s1 = "            processorArchitecture=\"x86\" " fullword ascii
      $s2 = "    name=\"Microsoft.Windows.Security.WlRmdr\"" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ascii /* Goodware String - occured 2 times */
      $s4 = "                                                                                                                                " ascii /* Goodware String - occured 3 times */
      $s5 = ".qdata" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of them )
      ) or ( all of them )
}

rule _0011_0015_5 {
   meta:
      description = "mw1 - from files 0011, 0015"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "35dc29c0132f1684fc8ed518f98d959bd982ef058b3ba24d8a23ea1507452621"
      hash2 = "7a711d338e2314968acb2ba760da3b19e113a08fd0d66dbff557b31c5f0de22f"
   strings:
      $s1 = "LOKALIX LIMITED0" fullword ascii
      $s2 = "LOKALIX LIMITED1" fullword ascii
      $s3 = " Microsoft Co" fullword wide
      $s4 = "180712000000Z" fullword ascii
      $s5 = "52-53 The Mall1" fullword ascii
      $s6 = "-PRich`" fullword ascii
      $s7 = "W5 3TA1" fullword ascii
      $s8 = "190712235959Z0" fullword ascii
      $s9 = "190712235959" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of them )
      ) or ( all of them )
}

rule _0020_0011_6 {
   meta:
      description = "mw1 - from files 0020, 0011"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "f6e897ad1b6e528be9e2caa9cb1ad48d451b354681636e160cc4e9c7a0c6ab43"
      hash2 = "35dc29c0132f1684fc8ed518f98d959bd982ef058b3ba24d8a23ea1507452621"
   strings:
      $s1 = "<description>YGUg ii JijOSBF oj SOWUOJKS</description>" fullword ascii
      $s2 = "FEf4 ef dgdsger" fullword wide
      $s3 = "XSFt4y gewKJIo" fullword wide
      $s4 = "wfw wf" fullword wide
      $s5 = "11.00.9600.16428 (wr2_df.121013" fullword wide
      $s6 = "11.00.9600.16" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of them )
      ) or ( all of them )
}

