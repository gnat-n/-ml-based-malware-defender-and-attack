/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2024-04-17
   Identifier: mw7
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule _root_BytMe_new_datasets_mw7_0026 {
   meta:
      description = "mw7 - file 0026"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "a143f2715d067665f77ca06b17b8e120b3bfb3c46c6b18c9dd410cd9ff1254cd"
   strings:
      $s1 = "__ZNSt12__basic_fileIcEC1EP17__gthread_mutex_t" fullword ascii
      $s2 = "__ZNSt12__basic_fileIcEC2EP17__gthread_mutex_t" fullword ascii
      $s3 = "_ShellExecuteA@24" fullword ascii
      $s4 = "__imp__ShellExecuteA@24" fullword ascii
      $s5 = "__Z20emergency_mutex_initv" fullword ascii
      $s6 = "___gthr_win32_mutex_unlock" fullword ascii
      $s7 = "___gthr_win32_mutex_trylock" fullword ascii
      $s8 = "___gthr_win32_mutex_init_function" fullword ascii
      $s9 = "___gthr_win32_mutex_lock" fullword ascii
      $s10 = "_emergency_mutex" fullword ascii
      $s11 = "__head_libshell32_a" fullword ascii
      $s12 = ".data$_ZGVNSt8time_getIcSt19istreambuf_iteratorIcSt11char_traitsIcEEE2idE" fullword ascii
      $s13 = ".data$_ZGVNSt9money_getIcSt19istreambuf_iteratorIcSt11char_traitsIcEEE2idE" fullword ascii
      $s14 = ".data$_ZNSt7num_getIcSt19istreambuf_iteratorIcSt11char_traitsIcEEE2idE" fullword ascii
      $s15 = ".data$_ZGVNSt7num_getIcSt19istreambuf_iteratorIcSt11char_traitsIcEEE2idE" fullword ascii
      $s16 = ".data$_ZNSt8time_getIcSt19istreambuf_iteratorIcSt11char_traitsIcEEE2idE" fullword ascii
      $s17 = ".data$_ZNSt9money_getIcSt19istreambuf_iteratorIcSt11char_traitsIcEEE2idE" fullword ascii
      $s18 = ".rdata$_ZTISt11logic_error" fullword ascii
      $s19 = "__ZTVSt11logic_error" fullword ascii
      $s20 = "__ZNKSt11logic_error4whatEv" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw7_0010 {
   meta:
      description = "mw7 - file 0010"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "a06ad226da67a5db5118c5f4dcd81c8ce698c571344a390c1936222c864e89f0"
   strings:
      $s1 = "C:\\setupx.dll" fullword ascii
      $s2 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" publicKeyToken=\"6595b64144ccf1d" ascii
      $s3 = "http://vguarder.91i.net/SETUPX.EXE" fullword ascii
      $s4 = "ccRegVfy.exe" fullword ascii
      $s5 = "__ZNSt12__basic_fileIcEC1EP17__gthread_mutex_t" fullword ascii
      $s6 = "__ZNSt12__basic_fileIcEC2EP17__gthread_mutex_t" fullword ascii
      $s7 = "_ShellExecuteA@24" fullword ascii
      $s8 = "__imp__ShellExecuteA@24" fullword ascii
      $s9 = "\\updatex.exe" fullword ascii
      $s10 = "\\setupx.exe" fullword ascii
      $s11 = "\\Serverx.exe" fullword ascii
      $s12 = "__Z20emergency_mutex_initv" fullword ascii
      $s13 = "___gthr_win32_mutex_unlock" fullword ascii
      $s14 = "___gthr_win32_mutex_trylock" fullword ascii
      $s15 = "___gthr_win32_mutex_init_function" fullword ascii
      $s16 = "___gthr_win32_mutex_lock" fullword ascii
      $s17 = "_emergency_mutex" fullword ascii
      $s18 = "uage=\"*\" processorArchitecture=\"*\" />" fullword ascii
      $s19 = "__head_libshell32_a" fullword ascii
      $s20 = ".data$_ZGVNSt8time_getIcSt19istreambuf_iteratorIcSt11char_traitsIcEEE2idE" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 15000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw7_0032 {
   meta:
      description = "mw7 - file 0032"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "a1a15b1142573dfd8ac4433d0874284d2717bbdd4d29bc0aa2ff50cf486df714"
   strings:
      $x1 = "C:\\WINDOWS\\System32\\Wbem\\%SYSTEMROOT%\\system32\\usmt\\migwiz.exe" fullword wide
      $s2 = "C:\\WINDOWS\\system32\\osk.exe" fullword ascii
      $s3 = "C:\\WINDOWS\\system32\\usmt\\migwiz.exe" fullword ascii
      $s4 = ")@%SystemRoot%\\system32\\shell32.dll,-22564*..\\..\\..\\..\\..\\..\\WINDOWS\\system32\\osk.exe" fullword wide
      $s5 = ".lnk=@%systemroot%\\system32\\rcbdyctl.dll,-152" fullword ascii
      $s6 = "e:\\fx19rel\\WINNT_5.2_Depend\\mozilla\\obj-fx-trunk\\accessible\\public\\msaa\\AccessibleMarshal.pdb" fullword ascii
      $s7 = "%SystemRoot%\\system32\\osk.exe" fullword wide
      $s8 = "%SYSTEMROOT%\\system32\\usmt\\migwiz.exe" fullword wide
      $s9 = "  // Otherwise, dump to stdout and launch an assertion failure dialog" fullword ascii
      $s10 = "C:\\Program Files\\Common Files\\Microsoft Shared\\Web Server Extensions\\40\\bin\\pdbs\\fp4Awec.pdb" fullword ascii
      $s11 = "e:\\fx19rel\\WINNT_5.2_Depend\\mozilla\\obj-fx-trunk\\nss\\nssdbm\\nssdbm3.pdb" fullword ascii
      $s12 = "_vti_bin/_vti_aut/author.exe" fullword ascii
      $s13 = "  var environment = Components.classes[\"@mozilla.org/process/environment;1\"]." fullword ascii
      $s14 = "//@line 59 \"e:\\fx19rel\\WINNT_5.2_Depend\\mozilla\\browser\\components\\safebrowsing\\content\\globalstore.js\"" fullword ascii
      $s15 = "fp4Awec.dll" fullword wide
      $s16 = "//@line 37 \"e:\\fx19rel\\WINNT_5.2_Depend\\mozilla\\browser\\components\\safebrowsing\\content\\list-warden.js\"" fullword ascii
      $s17 = "//@line 37 \"e:\\fx19rel\\WINNT_5.2_Depend\\mozilla\\browser\\components\\safebrowsing\\content\\globalstore.js\"" fullword ascii
      $s18 = "MOZCRT19.dll" fullword ascii
      $s19 = "//@line 37 \"e:\\fx19rel\\WINNT_5.2_Depend\\mozilla\\browser\\components\\safebrowsing\\content\\malware-warden.js\"" fullword ascii
      $s20 = "fp4Anwi.dll" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw7_0048 {
   meta:
      description = "mw7 - file 0048"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "a278989cd4ac213d7393cdd161c5d5012eb201f4a91da13a33b9779f4eadd4ba"
   strings:
      $x1 = "NameTableFileCostTypeThe cost associated with the registration of the typelib. This column is currently optional.The language of" ascii
      $x2 = " again before using that product.  Your current installation will now continue.User [2] has previously initiated an installation" ascii
      $x3 = "dater.da_DKADOBEU~1.FR_|AdobeUpdater.fr_FRADOBEU~1.DE_|AdobeUpdater.de_DEADOBEA~1.CER|AdobeAUM_rootCert.cerADOBEU~1.ES_|AdobeUpd" ascii
      $x4 = "acrobatRegistryURLHandler2URL ProtocolRegistryURLHandler1Registry28Registry323[ACROBAT]AcroRd32.exeacrobat\\DefaultIconRegistryU" ascii
      $x5 = "mFiles64Folder.:PROGRA~1|program files.:ProgramsReaderMessagesREADER_MESSAGEREADER_MESSAGE_CHSREADER_MESSAGE_CHTREADER_MESSAGE_D" ascii
      $x6 = "ClsidRegistry174IPDDomDocumentInterface\\{00FFD6C4-1A94-44BC-AD3E-8AC18552E3E6}Registry173{C523F39F-9C83-11D3-9094-00104BD0D535}" ascii
      $x7 = "ame.htmARPREADME_1034Readme.htmARPREADME_1033Liesmich.htmARPREADME_1031Vigtigt.htmARPREADME_1030ApplicationListversion:1|.ade:3|" ascii
      $x8 = "]{}ExitDoActionOK(Not Installed) And (Not ReplacedInUseFiles) And (LAUNCH_APP=1) And (DefragStatus<>\"0\") And (NeedReboot<>1) A" ascii
      $x9 = "NString categoryRemoveSetUpgradeCodeCategoryVersionMaxKeyColumnVersionMinKeyTableVerbMinValueCommand_ValidationMaxValueColumnThe" ascii
      $x10 = "81-101B-9CA8-9240CE2738AE}\\ProxyStubClsid32Registry440Interface\\{9B4CD3F0-4981-101B-9CA8-9240CE2738AE}\\ProxyStubClsidRegistry" ascii
      $x11 = "The integers do not have to be consecutive.The visible text to be assigned to the item. Optional. If this entry or the entire co" ascii
      $x12 = "Installer\\OptimizationDefragStatusSOFTWARE\\Adobe\\Adobe Acrobat\\6.0\\InstallPathSOFTWARE\\Adobe\\Acrobat Reader\\7.0\\Install" ascii
      $x13 = "A~1.PNG|A_ExpandAll_Md_N.pngA_ExpandAll_Md_N.pngA_DOWN~1.PNG|A_Down_Md_N.pngA_Down_Md_N.pngA_DistanceTool_Lg_N.png1A_DELE~1.PNG|" ascii
      $x14 = "RDRBIG_66.9.96.0.0RDRBIG_77.9.97.0.0RDRMIN_8{A6EADE66-0000-0000-76A5-7E8A45000000}RDRMIN_6RDRMIN_7UT_A6{AC76BA86-0000-0000-8796-" ascii
      $x15 = "sPolicies.63E949F6_03BC_5C40_FF1F_C8B3B9A1E18Epolicydir.63E949F6_03BC_5C40_FF1F_C8B3B9A1E18EWindowsFolder.63E949F6_03BC_5C40_FF1" ascii
      $x16 = "level_manifest.8.0.50727.96.98CB24AD_52FB_DB5F_FF1F_C8B3B9A1E18ESOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SideBySide\\Instal" ascii
      $x17 = "oud.apiReadOutLoud.apiCheckers.apieBook.apiHLS.apiAnnots.apiIA32.apiADOBEP~1.PMP|AdobePDF417.pmpAdobePDF417.pmpDVA.apiweblink.ap" ascii
      $x18 = "-1DFC1ED6DED9}AdobeXMP.dll{D6F7934F-E534-42AC-8DD1-96D9366B3FD9}AGM.dll{C8C5CBFB-6FF7-4D23-B3FE-5E00820DE6AF}Bib.dll_NON_OPT{DA1" ascii
      $x19 = "2.3  Server Use. You may install the Permitted Number of copies of  the Software on the Permitted Number of  Computer file serve" ascii
      $x20 = "ration_CLSIDRegistry_Main_SystemRegistry_Main_UserRegistry_Vista_ElevationPolicyReader_Bin_BibActiveX_Pdfshell.dllAdobeCollabSyn" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and
      1 of ($x*)
}

rule _root_BytMe_new_datasets_mw7_0017 {
   meta:
      description = "mw7 - file 0017"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "a0e2bee0ac622f707237732df46dbce8c1fd4189e3d8c67d41ee2c599fef8f0b"
   strings:
      $x1 = "MSI (s) (68:DC) [15:14:08:156]: Executing op: ComponentRegister(ComponentId={F94659DA-5860-4552-B962-39D8D781EF7A},KeyPath=C:\\W" wide
      $x2 = "MSI (s) (68:DC) [15:14:08:171]: Executing op: ComponentRegister(ComponentId={F94659DA-5860-4552-B962-39D8D781EF7A},KeyPath=C:\\W" wide
      $x3 = "MSI (s) (68:DC) [15:14:07:390]: SHELL32::SHGetFolderPath returned: C:\\Documents and Settings\\me\\Templates" fullword wide
      $x4 = ")@%SystemRoot%\\system32\\shell32.dll,-22534'..\\..\\..\\..\\..\\WINDOWS\\system32\\cmd.exe" fullword wide
      $x5 = "MSI (s) (68:DC) [15:14:07:406]: SHELL32::SHGetFolderPath returned: C:\\Documents and Settings\\All Users\\Start Menu\\Programs" wide
      $x6 = "MSI (s) (68:DC) [15:14:07:406]: SHELL32::SHGetFolderPath returned: C:\\Documents and Settings\\All Users\\Start Menu\\Programs" wide
      $x7 = "MSI (s) (68:DC) [15:14:07:406]: SHELL32::SHGetFolderPath returned: C:\\Documents and Settings\\All Users\\Start Menu\\Programs" fullword wide
      $x8 = "MSI (s) (68:DC) [15:14:07:406]: SHELL32::SHGetFolderPath returned: C:\\Documents and Settings\\All Users\\Start Menu" fullword wide
      $x9 = "MSI (s) (68:DC) [15:14:07:406]: SHELL32::SHGetFolderPath returned: C:\\Documents and Settings\\All Users\\Desktop" fullword wide
      $x10 = "C:\\WINDOWS\\System32\\Wbem\\%SYSTEMROOT%\\system32\\usmt\\migwiz.exe" fullword wide
      $x11 = "C:\\WINDOWS\\System32\\Wbem\\%SYSTEMROOT%\\system32\\rcimlby.exe" fullword wide
      $x12 = "Gecko-Content-Viewers,text/javascript,@mozilla.org/content/document-loader-factory;1" fullword ascii
      $x13 = "Gecko-Content-Viewers,text/ecmascript,@mozilla.org/content/document-loader-factory;1" fullword ascii
      $x14 = "MSI (s) (68:DC) [15:14:07:234]: SOFTWARE RESTRICTION POLICY: Verifying package --> 'C:\\DOCUME~1\\me\\LOCALS~1\\Temp\\dotnetfx35" wide
      $x15 = "MSI (s) (68:DC) [15:14:08:171]: Executing op: SetTargetFolder(Folder=C:\\WINDOWS\\system32\\)" fullword wide
      $x16 = "/s\"%SystemRoot%\\system32\\filemgmt.dll" fullword wide
      $x17 = "Wrong file type9Cannot locate Microsoft Conversion Library (msconv97.dll)1Multiple concurrent conversions are not supported2This" wide
      $x18 = "MSI (s) (68:DC) [15:14:07:390]: SHELL32::SHGetFolderPath returned: C:\\Documents and Settings\\me\\Favorites" fullword wide
      $x19 = "MSI (s) (68:DC) [15:14:07:390]: SHELL32::SHGetFolderPath returned: C:\\Documents and Settings\\me\\NetHood" fullword wide
      $x20 = "MSI (s) (68:DC) [15:14:07:390]: SHELL32::SHGetFolderPath returned: C:\\Documents and Settings\\me\\My Documents" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and
      1 of ($x*)
}

rule _root_BytMe_new_datasets_mw7_0022 {
   meta:
      description = "mw7 - file 0022"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "a11d6186b7d58054266c80ec372c7b4afd61cd39a6194f37848a576d4cebb765"
   strings:
      $s1 = "C:\\WINDOWS\\system32\\tourstart.exe" fullword ascii
      $s2 = "\"20170206031728.495\",\"1116\",\"Client UrlCache MMF Ver 5.2\",\"840\",\"registry\",\"RegOpenKeyExW\",\"FAILURE\",\"\",\"hKey->" ascii
      $s3 = "\"20170206031728.785\",\"1116\",\"Client UrlCache MMF Ver 5.2\",\"840\",\"filesystem\",\"CreateFileW\",\"SUCCESS\",\"0x000001d8" ascii
      $s4 = "\"20170206031728.805\",\"1116\",\"Client UrlCache MMF Ver 5.2\",\"840\",\"registry\",\"RegSetValueExW\",\"SUCCESS\",\"\",\"hKey-" ascii
      $s5 = "%SystemRoot%\\system32\\tourstart.exe" fullword wide
      $s6 = "\"20170206031728.785\",\"1116\",\"Client UrlCache MMF Ver 5.2\",\"840\",\"filesystem\",\"CreateFileW\",\"SUCCESS\",\"0x000001d4" ascii
      $s7 = "\"20170206031728.485\",\"1116\",\"Client UrlCache MMF Ver 5.2\",\"840\",\"filesystem\",\"CopyFileExW\",\"SUCCESS\",\"\",\"lpExis" ascii
      $s8 = "DOCUME~1\\JANETT~1\\LOCALS~1\\Temp\\Client UrlCache MMF Ver 5.2\",\"lpNewFileName->C:\\AutoRun.exe\"" fullword ascii
      $s9 = "eName->C:\\AUTOEXEC.BAT.exe\",\"lpNewFileName->C:\\AUTOEXEC.BAT\"" fullword ascii
      $s10 = "\"20170206031728.805\",\"1116\",\"Client UrlCache MMF Ver 5.2\",\"840\",\"registry\",\"RegSetValueExW\",\"SUCCESS\",\"\",\"hKey-" ascii
      $s11 = "alueName->Common Desktop\",\"dwType->1\",\"lpData->C:\\Documents and Settings\\All Users\\Desktop\",\"cbData->88\"" fullword ascii
      $s12 = "\"20170206031728.785\",\"1116\",\"Client UrlCache MMF Ver 5.2\",\"840\",\"filesystem\",\"DeleteFileW\",\"FAILURE\",\"\",\"lpFile" ascii
      $s13 = "\"20170206031728.765\",\"1116\",\"Client UrlCache MMF Ver 5.2\",\"840\",\"filesystem\",\"DeleteFileW\",\"FAILURE\",\"\",\"lpFile" ascii
      $s14 = "\"20170206031728.745\",\"1116\",\"Client UrlCache MMF Ver 5.2\",\"840\",\"registry\",\"RegOpenKeyExW\",\"SUCCESS\",\"0x000001c4" ascii
      $s15 = "\"20170206031728.485\",\"1116\",\"Client UrlCache MMF Ver 5.2\",\"840\",\"registry\",\"RegCreateKeyExW\",\"SUCCESS\",\"0x000000a" ascii
      $s16 = "\"20170206031723.487\",\"1116\",\"Client UrlCache MMF Ver 5.2\",\"840\",\"filesystem\",\"CreateFileW\",\"FAILURE\",\"\",\"lpFile" ascii
      $s17 = "\"20170206031728.785\",\"1116\",\"Client UrlCache MMF Ver 5.2\",\"840\",\"filesystem\",\"MoveFileWithProgressW\",\"FAILURE\",\"" ascii
      $s18 = "\"20170206031728.815\",\"1116\",\"Client UrlCache MMF Ver 5.2\",\"840\",\"filesystem\",\"MoveFileWithProgressW\",\"FAILURE\",\"" ascii
      $s19 = "\"20170206031728.785\",\"1116\",\"Client UrlCache MMF Ver 5.2\",\"840\",\"filesystem\",\"CreateFileW\",\"SUCCESS\",\"0x000001d8" ascii
      $s20 = "alueName->Common Documents\",\"dwType->1\",\"lpData->C:\\Documents and Settings\\All Users\\Documents\",\"cbData->92\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw7_0006 {
   meta:
      description = "mw7 - file 0006"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "a04beb83fb36e4a515dacb85f3b7a24f16e0cb96eae168aa63f0b96d63bb4750"
   strings:
      $x1 = "(a,b),c=Error.create(e,{name:\"Sys.ScriptLoadFailedException\",\"scriptUrl\":b});c.popStackFrame();return c};Sys._ScriptLoader._" ascii
      $x2 = "est.completed(Sys.EventArgs.Empty);a._xmlHttpRequest=null}}};Sys.Net.XMLHttpExecutor.prototype={get_timedOut:function(){return t" ascii
      $x3 = "System.Web.UI.Design.AsyncPostBackTriggerEventNameConverter, System.Web.Extensions.Design, Version=3.5.0.0, Culture=neutral, Pub" ascii
      $x4 = "System.Web.UI.Design.AsyncPostBackTriggerControlIDConverter, System.Web.Extensions.Design, Version=3.5.0.0, Culture=neutral, Pub" ascii
      $x5 = "FullTrustvSystem.Web.AspNetHostingPermissionAttribute, System, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" ascii
      $x6 = "indow.console&&window.console.log)window.console.log(a);if(window.opera)window.opera.postError(a);if(window.debugService)window." ascii
      $x7 = "System.Web.UI.Design.PostBackTriggerControlIDConverter, System.Web.Extensions.Design, Version=3.5.0.0, Culture=neutral, PublicKe" ascii
      $x8 = "System.Web.UI.Design.ScriptManagerProxyDesigner, System.Web.Extensions.Design, Version=3.5.0.0, Culture=neutral, PublicKeyToken=" ascii
      $x9 = "System.Web.UI.Design.WebControls.DataFieldEditor, System.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a" ascii
      $x10 = "System.Web.UI.Design.ScriptManagerDesigner, System.Web.Extensions.Design, Version=3.5.0.0, Culture=neutral, PublicKeyToken=31bf3" ascii
      $x11 = "System.Web.UI.Design.ScriptManagerProxyDesigner, System.Web.Extensions.Design, Version=3.5.0.0, Culture=neutral, PublicKeyToken=" ascii
      $x12 = "System.Web.UI.Design.ScriptManagerDesigner, System.Web.Extensions.Design, Version=3.5.0.0, Culture=neutral, PublicKeyToken=31bf3" ascii
      $x13 = "gth)throw Error.invalidOperation(Sys.Res.servicePathNotSet);return a},_onLoginComplete:function(e,c,f){if(typeof e!==\"boolean\"" ascii
      $x14 = "System.Web.UI.Design.WebControls.DataPagerDesigner, System.Web.Extensions.Design, Version=3.5.0.0, Culture=neutral, PublicKeyTok" ascii
      $s15 = "The file to be verified is C:\\WINDOWS\\system32\\msxml6.dll." fullword ascii
      $s16 = "The file to be verified is C:\\WINDOWS\\system32\\windowscodecs.dll." fullword ascii
      $s17 = "The file to be verified is C:\\WINDOWS\\system32\\msi.dll." fullword ascii
      $s18 = "System.Web.UI.Design.UpdateProgressDesigner, System.Web.Extensions.Design, Version=3.5.0.0, Culture=neutral, PublicKeyToken=31bf" ascii
      $s19 = "System.Configuration.ConfigurationPermissionAttribute, System.Configuration, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b0" ascii
      $s20 = "System.Web.UI.Design.TimerDesigner, System.Web.Extensions.Design, Version=3.5.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      1 of ($x*) and all of them
}

rule _root_BytMe_new_datasets_mw7_0016 {
   meta:
      description = "mw7 - file 0016"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "a0c440dae0d35490a6d13b1af1c1cc41b50895d4980e5b57a7875beee2f3185c"
   strings:
      $s1 = "Config.dll" fullword ascii
      $s2 = "CrashReport.dll" fullword ascii
      $s3 = "c:\\InitializeLog.txt" fullword wide
      $s4 = "StartupManager.dll" fullword ascii
      $s5 = "TracksEraser.dll" fullword ascii
      $s6 = "LockDll.dll" fullword ascii
      $s7 = "BootTime.dll" fullword ascii
      $s8 = "Languages.dll" fullword ascii
      $s9 = "AppMetrics.dll" fullword ascii
      $s10 = "CheckUpdate.exe" fullword wide
      $s11 = "Integrator.exe" fullword wide
      $s12 = "Initialize.exe" fullword wide
      $s13 = "%sautoupdate.exe" fullword wide
      $s14 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.MFC\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii
      $s15 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii
      $s16 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii
      $s17 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.MFC\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicK" ascii
      $s18 = "%APPDATA%\\GlarySoft\\Glary Utilities 5" fullword wide
      $s19 = "%APPDATA%\\GlarySoft\\Glary Utilities 3" fullword wide
      $s20 = "I:\\WorkFolder\\5.0\\exe\\vc\\Initialize\\sourcecode\\Release_ProTrial\\Initialize_Pro.pdb" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw7_0044 {
   meta:
      description = "mw7 - file 0044"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "a2631a6f49caae08effe78c681d64c3e43c51028f6bcac844a4d9e69c19c6c86"
   strings:
      $s1 = "BBB111111111111111111" ascii /* reversed goodware string '111111111111111111BBB' */
      $s2 = "    //" fullword ascii /* reversed goodware string '//    ' */
      $s3 = "    name=\"Microsoft.Windows.conf.exe\"" fullword ascii
      $s4 = "huT6c0- J" fullword ascii
      $s5 = "BBBBBB111111111111111" ascii
      $s6 = "petite" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "gateway" fullword ascii /* Goodware String - occured 10 times */
      $s8 = "Accepted" fullword wide /* Goodware String - occured 49 times */
      $s9 = "RegServer" fullword ascii /* Goodware String - occured 58 times */
      $s10 = "Shell_TrayWnd" fullword ascii /* Goodware String - occured 67 times */
      $s11 = "Account" fullword wide /* Goodware String - occured 107 times */
      $s12 = "TYPELIB" fullword wide /* Goodware String - occured 2639 times */
      $s13 = "Microsoft Base Cryptographic Provider v1.0" fullword ascii /* Goodware String - occured 148 times */
      $s14 = "1.3.6.1.5.5.7.3.2" fullword ascii /* Goodware String - occured 177 times */
      $s15 = "History" fullword wide /* Goodware String - occured 194 times */
      $s16 = "SeShutdownPrivilege" fullword ascii /* Goodware String - occured 216 times */
      $s17 = "Background" fullword ascii /* Goodware String - occured 229 times */
      $s18 = "HKEY_PERFORMANCE_DATA" fullword ascii /* Goodware String - occured 335 times */
      $s19 = "HKEY_DYN_DATA" fullword ascii /* Goodware String - occured 350 times */
      $s20 = "HKEY_CURRENT_CONFIG" fullword ascii /* Goodware String - occured 358 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw7_0034 {
   meta:
      description = "mw7 - file 0034"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "a1ce504a59def968cafa95637ef4418ae2ad7c397eb85440947490bc08bc5b2d"
   strings:
      $x1 = "                       /dl:MyLogger,C:\\My.dll*ForwardingLogger,C:\\Logger.dll" fullword ascii
      $x2 = "PA<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorAr" ascii
      $x3 = "hahahaha.jpg-GETPICTURE_javascript.com" fullword ascii
      $x4 = "                       /logger:XMLLogger,C:\\Loggers\\MyLogger.dll;OutputAsHTML" fullword ascii
      $s5 = "link.mx40.javascript-getpicture.com" fullword ascii
      $s6 = "cmd /c reg ADD HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v WinIcons /t REG_SZ /d " fullword ascii
      $s7 = "javascript_getpic-FUNNYPIC.JPG-eof.mx40link.com" fullword ascii
      $s8 = "javascript_GETPICTURE-myPicture.jpg-eof.com" fullword ascii
      $s9 = "e:\\winwork\\antispyware2\\trunk\\tools\\tracer\\driver\\src\\anscfg\\objfre_wxp_x86\\i386\\anscfg.pdb" fullword ascii
      $s10 = "mx50-java_getfile-mail-log.txt_eof.com" fullword ascii
      $s11 = "C:\\WINDOWS\\Temp\\12345.exe" fullword ascii
      $s12 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s13 = "Explorer.exe sychost.exe" fullword ascii
      $s14 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii
      $s15 = "2 - http://img.sunhome.ru/UsersGallery/wallpapers/94/23172203.jpg :D" fullword ascii
      $s16 = "                             /p:Configuration=Debug;TargetFrameworkVersion=v3.5" fullword ascii
      $s17 = "Assembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=" ascii
      $s18 = "link.mx40-runjava.getpic-Picture1.jpg-eof.com" fullword ascii
      $s19 = "=d:\\sp1.public.x86fre\\internal\\strongnamekeys\\fake\\windows.snk" fullword ascii
      $s20 = "hot-summerparty.jpg-link_getpic.com" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw7_0005 {
   meta:
      description = "mw7 - file 0005"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "a03c4de4ad831f31730dee4b13db19818d19174614009e28edefb19cdb9e4278"
   strings:
      $s1 = "eVdHdFdsdidcd" fullword ascii /* base64 encoded string 'yWGtWlv'\' */
      $s2 = "                <requestedExecutionLevel " fullword ascii
      $s3 = "        processorArchitecture=\"x86\"" fullword ascii
      $s4 = "^]]]7]7]7^7]7]5]]]" fullword ascii /* hex encoded string 'wwu' */
      $s5 = "]]]7^7]7^5]]]" fullword ascii /* hex encoded string 'wu' */
      $s6 = "crbkbab" fullword ascii
      $s7 = "kyjpjij" fullword ascii
      $s8 = "\\]][mQmJm~m.m$m" fullword ascii
      $s9 = "\\]]_mGm}mtmdmbm" fullword ascii
      $s10 = "    </description>" fullword ascii
      $s11 = "\\mJRhj{][]`zIS" fullword ascii
      $s12 = "\\a\\pbSpkI_K R<y" fullword ascii
      $s13 = "\\]]Am~mqmnmam" fullword ascii
      $s14 = "    <description>" fullword ascii
      $s15 = "iEhxhwhnh" fullword ascii
      $s16 = "S`ERcnBE|" fullword ascii
      $s17 = "o]nYnUnQnMnInEnAn}nynqnmninenan" fullword ascii
      $s18 = "mylwl0l#l" fullword ascii
      $s19 = "cXbWbRbHbCbxbobjbab" fullword ascii
      $s20 = "lToOo`o" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw7_0013 {
   meta:
      description = "mw7 - file 0013"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "a080fef24548f76e6f0daead032aa50c1ae5b866ea7878c175f32826553f7362"
   strings:
      $s1 = "The VMMRC.rc module version does not match VBoxVMM.dll/so/dylib. Re-install if you are a user. Developers should make sure the b" ascii
      $s2 = "_RTEnvGetExecEnvP" fullword ascii
      $s3 = "_RTThreadGetExecutionTimeMilli" fullword ascii
      $s4 = "_RTProcGetExecutablePath" fullword ascii
      $s5 = "The VMMR0.r0 module version does not match VBoxVMM.dll/so/dylib. If you just upgraded VirtualBox, please terminate all VMs and m" ascii
      $s6 = "Reason for leaving RC: Guest trap which couldn't be handled in RC. The trap is generally forwarded to the REM and executed there" ascii
      $s7 = "_RTLogDumpPrintfV" fullword ascii
      $s8 = "WinGetMsg -> hwnd=%p msg=%#x mp1=%p mp2=%p time=%#x ptl=%d,%d rsrv=%#x" fullword ascii
      $s9 = "E:/tinderbox/add-4.3/src/VBox/Runtime/common/log/log.cpp" fullword ascii
      $s10 = "dlimport.pdb" fullword ascii
      $s11 = "http://go.microsoft.com/fwlink?LinkId=83" fullword wide
      $s12 = "VbglR3ClipboardGetHostMsg failed, rc=%Rrc" fullword ascii
      $s13 = "the host kernel for memory during VM init. Let us know if you run into this and we'll adjust the code so it tries harder to avoi" ascii
      $s14 = "No available ports on the hub. This error is returned when a device is attempted created and/or attached to a hub which is out o" ascii
      $s15 = "_RTDirCreateTempSecure)" fullword ascii
      $s16 = "_RTMemExecFree3" fullword ascii
      $s17 = "An attempt on deattaching a driver without anyone actually being attached, or performing any other operation on an attached driv" ascii
      $s18 = "_RTDirCreateTemp*" fullword ascii
      $s19 = "_RTPathExecDir2" fullword ascii
      $s20 = "_RTSemFastMutexCreate" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw7_0040 {
   meta:
      description = "mw7 - file 0040"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "a2182469c33a7cd37497f778ea5027ba31ec6c3f17e2dd55a3a5326c9369c107"
   strings:
      $s1 = "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV" fullword ascii /* base64 encoded string 'UUUUUUUUUUUUUUUUUUUUUUUU' */
      $s2 = "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV" fullword ascii /* base64 encoded string 'UUUUUUUUUUUUUUUUUUUUUUUUUUUUUU' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '