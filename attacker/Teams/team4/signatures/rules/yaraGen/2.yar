/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2024-04-17
   Identifier: mw2
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule _root_BytMe_new_datasets_mw2_0026 {
   meta:
      description = "mw2 - file 0026"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "eb14af82d15b86f13e6ec395006269ad3d8d278689c91da3bf9df95e122da994"
   strings:
      $s1 = "  <description>FrameForge 3D Studio 2</description> " fullword ascii
      $s2 = "        <requestedExecutionLevel " fullword ascii
      $s3 = "* @Q,:" fullword ascii
      $s4 = "eaiouyhjrbpfcgvmndqklwxzts" fullword ascii
      $s5 = "  <assemblyIdentity version=\"1.0.0.0\"" fullword ascii
      $s6 = "}rZIcomz" fullword ascii
      $s7 = "\\s[\\.Phx" fullword ascii
      $s8 = "# =V'2m" fullword ascii
      $s9 = "G4FA -" fullword ascii
      $s10 = "eAYoVp9" fullword ascii
      $s11 = "o+ rfV[" fullword ascii
      $s12 = "ptKAb!" fullword ascii
      $s13 = "fNmh(\"" fullword ascii
      $s14 = "sCRs3Rt" fullword ascii
      $s15 = "aGHQK{$_" fullword ascii
      $s16 = "tOssA\"}" fullword ascii
      $s17 = ",;DZDJ60j" fullword ascii
      $s18 = "AJVk?n" fullword ascii
      $s19 = "JUuAK79k" fullword ascii
      $s20 = "     processorArchitecture=\"X86\"" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0009 {
   meta:
      description = "mw2 - file 0009"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "0f982b0dc7055db642ebf7bbdaf23d14285c99119ca271381680282f13695307"
   strings:
      $s1 = "FTMpd3 " fullword ascii
      $s2 = "TVEGARIZANDO" fullword wide
      $s3 = "Ueye}d" fullword ascii
      $s4 = "6.2.1.4" fullword wide
      $s5 = "6.2.1.17" fullword wide
      $s6 = "%Sb%-:T" fullword ascii
      $s7 = "R+ r&!" fullword ascii
      $s8 = "j4mu+ " fullword ascii
      $s9 = "vmLaYI2" fullword ascii
      $s10 = "[^p+ i" fullword ascii
      $s11 = "wntipy" fullword ascii
      $s12 = "cnrxov" fullword ascii
      $s13 = "- kMcc" fullword ascii
      $s14 = "LOADER ERROR" fullword ascii /* Goodware String - occured 5 times */
      $s15 = "        processorArchitecture=\"*\"/>" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "YMwph.CW" fullword ascii
      $s17 = "EqdB&#X" fullword ascii
      $s18 = "kNXZJ7:uM" fullword ascii
      $s19 = "HSdq#VLq" fullword ascii
      $s20 = "atTv0{*" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0037 {
   meta:
      description = "mw2 - file 0037"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "0e94798f078d038cd595d183322f53e9f7d37f55078c58910d7cbfb28024cde0"
   strings:
      $s1 = "  <description>FrameForge 3D Studio 2</description> " fullword ascii
      $s2 = "        <requestedExecutionLevel " fullword ascii
      $s3 = "  <assemblyIdentity version=\"1.0.0.0\"" fullword ascii
      $s4 = "TNAVEGADOR" fullword wide
      $s5 = "E* s*\\" fullword ascii
      $s6 = "+ PrJ%" fullword ascii
      $s7 = "vZNRMx0" fullword ascii
      $s8 = "+ g}vN" fullword ascii
      $s9 = "q /cg1c" fullword ascii
      $s10 = "9+Nbk /I" fullword ascii
      $s11 = "|YL -|" fullword ascii
      $s12 = "+r+ kTu." fullword ascii
      $s13 = "     processorArchitecture=\"X86\"" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "     type=\"win32\"/> " fullword ascii /* Goodware String - occured 1 times */
      $s15 = "          level=\"requireAdministrator\"" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "TFORM3" fullword wide /* Goodware String - occured 1 times */
      $s17 = "tSXbGx2(`n\"" fullword ascii
      $s18 = "jEfTSqG" fullword ascii
      $s19 = "X),hXfW?" fullword ascii
      $s20 = "ClDmp]{" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0024 {
   meta:
      description = "mw2 - file 0024"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "a96c642b0e19c116f4382cf7f923187167f0f64486325e8cc8f9405c5c69edcb"
   strings:
      $s1 = "  <description>FrameForge 3D Studio 2</description> " fullword ascii
      $s2 = "        <requestedExecutionLevel " fullword ascii
      $s3 = "qZiX*D:\\N" fullword ascii
      $s4 = "* pIox" fullword ascii
      $s5 = "* 2H4\"" fullword ascii
      $s6 = "  <assemblyIdentity version=\"1.0.0.0\"" fullword ascii
      $s7 = "edgfa`%cbmlonih%kjutwvqp%sr}|" fullword ascii
      $s8 = "e%dgfa`cbm%lonihkju%twvqpsr}%|" fullword ascii
      $s9 = ")v:\"~}" fullword ascii
      $s10 = "E:\\>`;" fullword ascii
      $s11 = "EXEFILE" fullword wide
      $s12 = "PERMISSAO" fullword wide
      $s13 = "B -M~5u" fullword ascii
      $s14 = "lkvqdi" fullword ascii
      $s15 = "XTNfVU8" fullword ascii
      $s16 = "L~~01 /s" fullword ascii
      $s17 = "(w=di,- " fullword ascii
      $s18 = "+ M1_y:]`" fullword ascii
      $s19 = "!8p5- 1a=" fullword ascii
      $s20 = "giTYYOR7" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0015 {
   meta:
      description = "mw2 - file 0015"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "841092ccfe4b8bb70e9730337b2183b9eef75fda78e9aa751a08ac6b49e9ba9a"
   strings:
      $s1 = "rPTX\\`r" fullword ascii /* reversed goodware string 'r`\\XTPr' */
      $s2 = "* (()@-" fullword ascii
      $s3 = "HEADER(#" fullword ascii
      $s4 = "TASKDIALOG_BUT" fullword ascii
      $s5 = "rdhlptr" fullword ascii
      $s6 = "rpqrstr" fullword ascii
      $s7 = "yRoot!" fullword ascii
      $s8 = "rREADWR" fullword ascii
      $s9 = "VZR;g:\"" fullword ascii
      $s10 = "TCUSTOMIZEFRM" fullword wide
      $s11 = "Exjnded" fullword ascii
      $s12 = "ptionr" fullword ascii
      $s13 = "\\klmn\\." fullword ascii
      $s14 = "\\HIJK\\." fullword ascii
      $s15 = "C- *E|h" fullword ascii
      $s16 = "%Z%A_a" fullword ascii
      $s17 = "oE (c) 2004 -" fullword ascii
      $s18 = "\\qrst\\." fullword ascii
      $s19 = "kW,%a%k" fullword ascii
      $s20 = "\\dhlp\\." fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0030 {
   meta:
      description = "mw2 - file 0030"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "20277950c8fc3612b7f46a7c44d99150b3cb1b53f4f949a789cb873ebba14ffa"
   strings:
      $s1 = "GetLongPath(" fullword ascii
      $s2 = "* (()wv" fullword ascii
      $s3 = "arefghijkl" fullword ascii
      $s4 = "tHashAr" fullword ascii
      $s5 = "SUPPORT_(_.SCK_LIN!" fullword ascii
      $s6 = "KeywZ27l;" fullword ascii
      $s7 = "%cX&q:\\" fullword ascii
      $s8 = "EPOCTNOV" fullword ascii
      $s9 = "ASTROPE" fullword ascii
      $s10 = "6Bp0CZN0" fullword ascii
      $s11 = "Mageljt" fullword ascii
      $s12 = "Aprywun" fullword ascii
      $s13 = "v&%nF%6" fullword ascii
      $s14 = "EXPIRE74" fullword ascii
      $s15 = "KDS%\" -" fullword ascii
      $s16 = "\\Delphi\\RTL" fullword ascii
      $s17 = "+_u%g* " fullword ascii
      $s18 = "        processorArchitecture=\"*\"/>" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "TBjicA" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "JAFEB/MAR" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0008 {
   meta:
      description = "mw2 - file 0008"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "6ccb58c0ce4e1880c9e38d76a1bacfff14cedfeb77888fd5dfd88c4eb353596f"
   strings:
      $s1 = "^32.dll" fullword ascii
      $s2 = ".DLL;wmIsH" fullword ascii
      $s3 = "ture.Data" fullword ascii
      $s4 = "<a.com/p" fullword ascii
      $s5 = "Logond" fullword ascii
      $s6 = "TDOCHOSTUI4" fullword ascii
      $s7 = "* (()@-3$-" fullword ascii
      $s8 = "-23(46,21" fullword ascii /* hex encoded string '#F!' */
      $s9 = ":4f\"~{+~=" fullword ascii /* hex encoded string 'O' */
      $s10 = "ALOG_FTONj" fullword ascii
      $s11 = "7\\0,:/+:72" fullword ascii /* hex encoded string 'pr' */
      $s12 = "<u* -aK" fullword ascii
      $s13 = "* 2seu tt," fullword ascii
      $s14 = "21 40$39(" fullword ascii /* hex encoded string '!@9' */
      $s15 = "* B_&D" fullword ascii
      $s16 = "%FcYxi%j" fullword ascii
      $s17 = "tte.Datz" fullword ascii
      $s18 = "orrigir" fullword ascii
      $s19 = "lblchaveemp" fullword ascii
      $s20 = "  level=\"asInvoker\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0040 {
   meta:
      description = "mw2 - file 0040"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "aca7e7293ef4e14ec245e983ccb1ed6b03a45da29dd50a80c0f0af5cd070ff89"
   strings:
      $s1 = "32.dll-" fullword ascii
      $s2 = "VNTLMSS" fullword ascii
      $s3 = "* (()@-3$-g" fullword ascii
      $s4 = "Ihiml* `" fullword ascii
      $s5 = "LHASH.O5e" fullword ascii
      $s6 = "9Root!" fullword ascii
      $s7 = "yyOhheyyyyyyhhyyyyeeyhhheeyyyhyy" fullword ascii
      $s8 = "JDDDDDDDDDDDDDDDDDDDDDDDDDDDO" fullword ascii
      $s9 = "BZUUUZUUUUUUUUUUUUUUUUUUUUUUUUUZB" fullword ascii
      $s10 = "GESTUREXU" fullword ascii
      $s11 = "IJKLMNO" fullword ascii
      $s12 = "M(PSmTP8" fullword ascii
      $s13 = "Acmmwuu" fullword ascii
      $s14 = "ptionr" fullword ascii
      $s15 = "(%R%U%X%[%^%_%`%a%b%d%f%h%i%j%kU" fullword ascii
      $s16 = "0 -$',b" fullword ascii
      $s17 = "%BH%.i" fullword ascii
      $s18 = "?#!V!W!\"!&!r%!%#%'%)%c%e%" fullword ascii
      $s19 = "8%:2%>%@%B%E%G%I%" fullword ascii
      $s20 = "g%C%<2%$%&%(%*%+%-%/%1%3%5%7%" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0039 {
   meta:
      description = "mw2 - file 0039"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "32760071669037866c8e9e9883fddeead91a49b7c5316bc02a5a416623989438"
   strings:
      $s1 = "Alt+ Clipboard does not support Icons/Menu '%s' is already being used by another formDocked control must have a name%Error remo" wide
      $s2 = "OnDownloadCompletep" fullword ascii
      $s3 = "<!<(<.<6<A<" fullword ascii /* hex encoded string 'j' */
      $s4 = "{r}}wtzzsuuwpvnslxjnlxhllxcgiyaeiybdfzfffzigeyeccybbdxbbfx`bhxchnvhmsuptytv}" fullword ascii
      $s5 = ": :.:X:\\:`:d:h:l:p:t:x:|:" fullword ascii
      $s6 = "EFilerError0JA" fullword ascii
      $s7 = ":4:<:@:D:H:L:P:T:X:\\:" fullword ascii
      $s8 = "OnKeyDown$" fullword ascii
      $s9 = ": :$:4:<:@:D:H:L:P:T:X:\\:`:d:h:l:p:t:x:|:" fullword ascii
      $s10 = "IHelpSysteml" fullword ascii
      $s11 = "TPictureAdapter`:E" fullword ascii
      $s12 = "TThreadList|NA" fullword ascii
      $s13 = "OnDragDrop`" fullword ascii
      $s14 = "OnDockDropT" fullword ascii
      $s15 = "\\\\a|ggkyuszu" fullword ascii
      $s16 = "HorzScrollBar0" fullword ascii
      $s17 = "OnStatusBar4" fullword ascii
      $s18 = "TPicture4" fullword ascii
      $s19 = "Metafile is not valid!Cannot change the size of an icon Invalid operation on TOleGraphic" fullword wide
      $s20 = "RemoteMachineName" fullword ascii /* Goodware String - occured 7 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0029 {
   meta:
      description = "mw2 - file 0029"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "82d26413b29b568df08bf5df6db4e8447b351ec517edab8351a347c722df29b6"
   strings:
      $s1 = "http://hotelmontenegro.mk/wp-includes/images/wbint.exe" fullword ascii
      $s2 = "C:\\winner.exe" fullword ascii
      $s3 = "http://hotelmontenegro.mk/wp-includes/images/smtip.exe" fullword ascii
      $s4 = "C:\\calc.exe" fullword ascii
      $s5 = "OnExecuteD" fullword ascii
      $s6 = "PasswordChar|" fullword ascii
      $s7 = "Separator\"Unable to find a Table of Contents" fullword wide
      $s8 = "EComponentErrorX" fullword ascii
      $s9 = "6!676?6C6\\6" fullword ascii /* hex encoded string 'fvlf' */
      $s10 = "OnGetSiteInfoD" fullword ascii
      $s11 = "5 5$585]5" fullword ascii /* hex encoded string 'UXU' */
      $s12 = "LargeChangeT" fullword ascii
      $s13 = "EWriteError4" fullword ascii
      $s14 = "IHelpSystem," fullword ascii
      $s15 = ": :4:G:K:\\:h:l:x:|:" fullword ascii
      $s16 = "ERangeErrorPp#" fullword ascii
      $s17 = "CommonAVID" fullword ascii
      $s18 = "    version=\"1.0.0.0\" " fullword ascii
      $s19 = "EFOpenError," fullword ascii
      $s20 = "OnCloseD" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0014 {
   meta:
      description = "mw2 - file 0014"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "5ab6cfc47da27138ca0fa1e399e5ae3b1f860f3cdbd6e78cf47bc3e9946d8143"
   strings:
      $x1 = "The credentials supplied were not complete, and could not be verified. Additional information can be returned from the context.4" wide
      $s2 = "The logon attempt failed;The credentials supplied to the package were not recognized4No credentials are available in the securit" wide
      $s3 = "Thread Error: %s (%d)-Cannot terminate an externally created thread,Cannot wait for an externally created thread2Cannot call Sta" wide
      $s4 = "Successfull API call7Not enough memory is available to complete this requestThe handle specified is invalid'The function reques" wide
      $s5 = "Unsupported operation./Could not encode header data using charset \"%s\"jThis \"Portable Network Graphics\" image is not valid b" wide
      $s6 = "C:\\Builds\\TP\\indysockets\\lib\\protocols\\IdHeaderCoderIndy.pas" fullword wide
      $s7 = "C:\\Builds\\TP\\indysockets\\lib\\protocols\\IdSSLOpenSSLHeaders.pas" fullword wide
      $s8 = "C:\\Builds\\TP\\rtl\\common\\TypInfo.pas" fullword wide
      $s9 = "C:\\Builds\\TP\\rtl\\common\\SyncObjs.pas" fullword wide
      $s10 = "C:\\Builds\\TP\\indysockets\\lib\\system\\IdStreamVCL.pas" fullword wide
      $s11 = "C:\\Builds\\TP\\indysockets\\lib\\system\\IdGlobal.pas" fullword wide
      $s12 = "C:\\Builds\\TP\\indysockets\\lib\\system\\IdStack.pas" fullword wide
      $s13 = "C:\\Builds\\TP\\indysockets\\lib\\core\\IdThread.pas" fullword wide
      $s14 = "C:\\Builds\\TP\\indysockets\\lib\\protocols\\IdZLibCompressorBase.pas" fullword wide
      $s15 = "C:\\Builds\\TP\\indysockets\\lib\\protocols\\IdCookie.pas" fullword wide
      $s16 = "C:\\Builds\\TP\\indysockets\\lib\\protocols\\IdHTTP.pas" fullword wide
      $s17 = "-The chunks must be compatible to be assigned.jThis \"Portable Network Graphics\" image is invalid because the decoder found an " wide
      $s18 = "ExecuteMacroLines" fullword ascii
      $s19 = "ExecuteMacro" fullword ascii
      $s20 = "OnExecuteMacro" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw2_0022 {
   meta:
      description = "mw2 - file 0022"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "1ac8d72ecc4f21bec7f353bc0ee6e8f3407c988c09c18d102511eee7a368469f"
   strings:
      $s1 = "AEY.ucx" fullword ascii
      $s2 = "T:\"#;zY" fullword ascii
      $s3 = "TDUNHILL" fullword wide
      $s4 = "M /Q,*'" fullword ascii
      $s5 = "A8 /Y@" fullword ascii
      $s6 = "g`+ f^p" fullword ascii
      $s7 = "Ezv%Nt%" fullword ascii
      $s8 = "%_%/%q]" fullword ascii
      $s9 = "i -JO~" fullword ascii
      $s10 = "ubmltx" fullword ascii
      $s11 = "LOADER ERROR" fullword ascii /* Goodware String - occured 5 times */
      $s12 = "PpMe}As$j_" fullword ascii
      $s13 = "OKlsZ#]m" fullword ascii
      $s14 = "rQAVJbhN" fullword ascii
      $s15 = "NCnN1{+n" fullword ascii
      $s16 = "XxAL!s" fullword ascii
      $s17 = "BSle2[|sE" fullword ascii
      $s18 = "sebbP >" fullword ascii
      $s19 = "RHofkiE:" fullword ascii
      $s20 = "4wSWiQ+gs" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0047 {
   meta:
      description = "mw2 - file 0047"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "9f517ead2d84de2d66326e35f2022df1d041258b3ffb2a69c5b39bc895b69aa4"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s2 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s3 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s4 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s5 = "GBPlugin.exe" fullword ascii
      $s6 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s7 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s8 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s9 = "//ns.adobe.com/xap/1.0/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/Resour" ascii
      $s10 = "//ns.adobe.com/xap/1.0/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/Resour" ascii
      $s11 = "\"http://ns.adobe.com/xap/1.0/rights/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stRef=\"http://ns.adobe.com/xap/1." ascii
      $s12 = "//ns.adobe.com/xap/1.0/\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" x" ascii
      $s13 = "ent#\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmp:CreatorTool=\"Ad" ascii
      $s14 = ")http://ns.adobe.com/xap/1.0/" fullword ascii
      $s15 = "rhttp://ns.adobe.com/xap/1.0/" fullword ascii
      $s16 = "https://www.santandernet.com.br/default.asp?txtAgencia=" fullword ascii
      $s17 = "xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmp:CreatorTool=\"Ado" ascii
      $s18 = "[http://ns.adobe.com/xap/1.0/" fullword ascii
      $s19 = "pe/ResourceRef#\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmpRights:Marked=\"False\" xmpMM:DocumentID=\"xmp.did:133BEAAB12A41" ascii
      $s20 = "https://www.santandernetibe.com.br/default.asp?txtAgencia=" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0028 {
   meta:
      description = "mw2 - file 0028"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "c99b74a890425df90f96a049942fa5efbf88b7103155342412d83e14c7acbce8"
   strings:
      $s1 = "download.exe" fullword wide
      $s2 = "d:\\Sources\\Personal\\download\\Release\\download.pdb" fullword ascii
      $s3 = "  download <url> <path[\\file.ext]> [<login>] [<password>]" fullword ascii
      $s4 = "File Downloader - %s" fullword ascii
      $s5 = "FileDownloader/1.0" fullword ascii
      $s6 = "File Downloader" fullword wide
      $s7 = "Downloads a file from a HTTP or a FTP server." fullword ascii
      $s8 = "Copyright (c) 2004, Noel Danjou <webmaster@noeld.com>." fullword ascii
      $s9 = "Download failure" fullword ascii
      $s10 = "Unable to get the HTTP status code" fullword ascii
      $s11 = "Passive FTP semantics enabled" fullword ascii
      $s12 = "FTP initialization failed" fullword ascii
      $s13 = "  /delete             Deletes the local file if a download fails" fullword ascii
      $s14 = "  login and password  [optional] authentication on the server" fullword ascii
      $s15 = "  /passive            Uses passive FTP semantics" fullword ascii
      $s16 = "  /post               Uses POST (instead of GET) as the HTTP verb" fullword ascii
      $s17 = "Version %d.%02d (build %d.%d)" fullword ascii
      $s18 = "            [/passive][/post][/proxy][/newest][/delete]" fullword ascii
      $s19 = "  /newest             Only downloads the newest file matching the wildcard (FTP)" fullword ascii
      $s20 = "Protocol: FTP" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0023 {
   meta:
      description = "mw2 - file 0023"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "24030137d3bf55a81b687bc3df719a8c5708e35fb1232eec94ae5b9ae59b2370"
   strings:
      $s1 = "aws.com/" fullword ascii
      $s2 = "~~~~zzzzvvvvssssqqqqoooommmmkkkkiiiiggggeeeebbbb^^^^[[[[WWWWTTTTPPPPLLLLCCCC????::::777733330000))))''''%%%%!!!!" fullword ascii
      $s3 = "+m}%c:\\" fullword ascii
      $s4 = ".=4-333]/" fullword ascii /* hex encoded string 'C3' */
      $s5 = "zwwztqqtroor" fullword ascii
      $s6 = "ommomkkmkiik" fullword ascii
      $s7 = "heghzwyz" fullword ascii
      $s8 = "omkokigkgecg" fullword ascii
      $s9 = "; -a^L" fullword ascii
      $s10 = "ptionr" fullword ascii
      $s11 = "%M%]t3" fullword ascii
      $s12 = "(c) 2004 -" fullword ascii
      $s13 = "2 -AyUO" fullword ascii
      $s14 = "p* ,+0" fullword ascii
      $s15 = "Virtu?" fullword ascii
      $s16 = ".KtL&x" fullword ascii
      $s17 = "omboBox" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "pssViol" fullword ascii
      $s19 = "PsFTtv{" fullword ascii
      $s20 = "xjOjHYo" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0049 {
   meta:
      description = "mw2 - file 0049"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "65388a54cf48711223df906330f55713b40a0d648aec48c615bec3bd706e05b3"
   strings:
      $s1 = "kernel32.dllwGet" fullword ascii
      $s2 = "MTarget" fullword ascii
      $s3 = "'L3'L3'" fullword ascii /* reversed goodware string ''3L'3L'' */
      $s4 = "YTSle:\"*8" fullword ascii
      $s5 = "* (()@-3$-" fullword ascii
      $s6 = "4MSIE 6*;" fullword ascii
      $s7 = "oftware" fullword ascii
      $s8 = "?7%d%%`Q" fullword ascii
      $s9 = "    version=\"1.0.0.0\" " fullword ascii
      $s10 = "(mOG:\\" fullword ascii
      $s11 = "Keyw/l;" fullword ascii
      $s12 = "WbEX.aPubB" fullword ascii
      $s13 = "EASTROP" fullword ascii
      $s14 = "WHIFTJIS" fullword ascii
      $s15 = "ETRYIGB" fullword ascii
      $s16 = "Umivsbw" fullword ascii
      $s17 = "xmpmja " fullword ascii
      $s18 = "Iarface" fullword ascii
      $s19 = "LOCALHOS" fullword ascii
      $s20 = "g%s_%d" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0002 {
   meta:
      description = "mw2 - file 0002"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "cc619840bf98f3358c6d8630ad4537f74407a8802904abe24466256a6eb8749f"
   strings:
      $s1 = "HSX.exe" fullword wide
      $s2 = "http://schemas.microsoft.com/cdo/" fullword wide
      $s3 = "C:\\Arquivos de programas\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
      $s4 = "o en el password " fullword wide
      $s5 = "<<- J.A.B.O.T.I.C.A.B.A ->><<-- E.M.P.R.E.S.A -->>" fullword wide
      $s6 = "m.silva@uol.com.br" fullword wide
      $s7 = "<<- J.A.B.O.T.I.C.A.B.A ->><<--  T.O.K.E.N  -- 1 -->>" fullword wide
      $s8 = "<<- J.A.B.O.T.I.C.A.B.A ->><<--  T.O.K.E.N  -- 2 -->>" fullword wide
      $s9 = "z*\\AG:\\TRB-30-01-12\\LEO-VIADINHO\\HSBC_CARD_JUJU\\KKSALSK8W8QU9S3223.vbp" fullword wide
      $s10 = "DDD333" ascii /* reversed goodware string '333DDD' */
      $s11 = "Meu HSBC - HSBC Bank Brasil S.A." fullword ascii
      $s12 = "iii333" fullword ascii /* reversed goodware string '333iii' */
      $s13 = "333vvv" fullword ascii /* reversed goodware string 'vvv333' */
      $s14 = "DDDfff" ascii /* reversed goodware string 'fffDDD' */
      $s15 = "SE4hTHhTH" fullword ascii /* base64 encoded string 'HN!LxS' */
      $s16 = "gravaimportante" fullword ascii
      $s17 = "[[[333" fullword ascii /* reversed goodware string '333[[[' */
      $s18 = "configuration/smtpauthenticate" fullword wide
      $s19 = "xway\\SimpLite-MSN 2.5\\Plugins;C:\\WINDOWS\\sy" fullword wide
      $s20 = "{3'\"3'\"" fullword ascii /* hex encoded string '3' */
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0005 {
   meta:
      description = "mw2 - file 0005"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "ab1bcce559649d9cacedcf97268285c85bacb1cbc8942cc8e59455847acc6f05"
   strings:
      $s1 = "A*\\AG:\\TRB-30-01-12\\LEO-VIADINHO\\INFECT-18-12-11\\HASJGDSAD82D.vbp" fullword wide
      $s2 = "MKAKJSLAA82878278983083.exe" fullword wide
      $s3 = "http://schemas.microsoft.com/cdo/" fullword wide
      $s4 = "7E7E7D7C6C6269636574796E70464447545F44725F5E45435B5E60564269625442475953544268615B52445055705352554342" wide /* hex encoded string '~~}|lbicetynpFDGT_Dr_^EC[^`VBibTBGYSTBha[RDPUpSRUCB' */
      $s5 = "7E7E7D7C6C6269636574796E70464447545F44725F5E45435B5E605642696254424759535442684546524346544346" wide /* hex encoded string '~~}|lbicetynpFDGT_Dr_^EC[^`VBibTBGYSTBhEFRCFTCF' */
      $s6 = "7E7E7D7C6C6269636574796E70464447545F44725F5E45435B5E60564269625442475953544268454050454352" wide /* hex encoded string '~~}|lbicetynpFDGT_Dr_^EC[^`VBibTBGYSTBhE@PECR' */
      $s7 = "736D74702E676D61696C2E636F6D" wide /* hex encoded string 'smtp.gmail.com' */
      $s8 = "636F6E646F6D696E696F736F6C6C617240676D61696C2E636F6D" wide /* hex encoded string 'condominiosollar@gmail.com' */
      $s9 = "706F7032383631736562" wide /* hex encoded string 'pop2861seb' */
      $s10 = "656469666963696F736F6C6C617240676D61696C2E636F6D" wide /* hex encoded string 'edificiosollar@gmail.com' */
      $s11 = "C:\\Arquivos de programas\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
      $s12 = "o en el password " fullword wide
      $s13 = "configuration/smtpauthenticate" fullword wide
      $s14 = "$$$ XXX - G.O.L.D. - XXX $$$" fullword wide
      $s15 = "servidor" fullword wide
      $s16 = "EnvioCompleto" fullword ascii
      $s17 = "Posible error : nombre del Servidor " fullword wide
      $s18 = "Posible error : error en la el nombre de usuario, " fullword wide
      $s19 = "UIEHRIWEUHRIWEURH" fullword ascii
      $s20 = "Descripcion" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0036 {
   meta:
      description = "mw2 - file 0036"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "680f18f5ee3dec9b02608507d746ad3ecb17bab18f43f544582d79c6828a1666"
   strings:
      $s1 = "HSX.exe" fullword wide
      $s2 = "http://schemas.microsoft.com/cdo/" fullword wide
      $s3 = "C:\\Arquivos de programas\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
      $s4 = "o en el password " fullword wide
      $s5 = "<<- J.A.B.O.T.I.C.A.B.A ->><<-- E.M.P.R.E.S.A -->>" fullword wide
      $s6 = "m.silva@uol.com.br" fullword wide
      $s7 = "<<- J.A.B.O.T.I.C.A.B.A ->><<--  T.O.K.E.N  -- 1 -->>" fullword wide
      $s8 = "<<- J.A.B.O.T.I.C.A.B.A ->><<--  T.O.K.E.N  -- 2 -->>" fullword wide
      $s9 = "z*\\AG:\\JABULANI-NOVA\\HSBC_CARD_JUJU\\KKSALSK8W8QU9S3223.vbp" fullword wide
      $s10 = "DDD333" ascii /* reversed goodware string '333DDD' */
      $s11 = "Meu HSBC - HSBC Bank Brasil S.A." fullword ascii
      $s12 = "iii333" fullword ascii /* reversed goodware string '333iii' */
      $s13 = "333vvv" fullword ascii /* reversed goodware string 'vvv333' */
      $s14 = "DDDfff" ascii /* reversed goodware string 'fffDDD' */
      $s15 = "SE4hTHhTH" fullword ascii /* base64 encoded string 'HN!LxS' */
      $s16 = "gravaimportante" fullword ascii
      $s17 = "[[[333" fullword ascii /* reversed goodware string '333[[[' */
      $s18 = "configuration/smtpauthenticate" fullword wide
      $s19 = "xway\\SimpLite-MSN 2.5\\Plugins;C:\\WINDOWS\\sy" fullword wide
      $s20 = "{3'\"3'\"" fullword ascii /* hex encoded string '3' */
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0001 {
   meta:
      description = "mw2 - file 0001"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "845dd985872b15fa3705df8ae1897eea1315f322a648085671a0959a9573d3cb"
   strings:
      $s1 = "nationalswrw.exe" fullword wide
      $s2 = "C:\\WINDOWS\\system32\\ieframe.oca" fullword ascii
      $s3 = "http://schemas.microsoft.com/cdo/" fullword wide
      $s4 = "7E7E7D7C6C6269636574796E70464447545F44725F5E45435B5E60564269625442475953544268615B52445055705352554342" wide /* hex encoded string '~~}|lbicetynpFDGT_Dr_^EC[^`VBibTBGYSTBha[RDPUpSRUCB' */
      $s5 = "7E7E7D7C6C6269636574796E70464447545F44725F5E45435B5E605642696254424759535442684546524346544346" wide /* hex encoded string '~~}|lbicetynpFDGT_Dr_^EC[^`VBibTBGYSTBhEFRCFTCF' */
      $s6 = "7E7E7D7C6C6269636574796E70464447545F44725F5E45435B5E60564269625442475953544268454050454352" wide /* hex encoded string '~~}|lbicetynpFDGT_Dr_^EC[^`VBibTBGYSTBhE@PECR' */
      $s7 = "~*\\AG:\\TRB-30-01-12\\LEO-VIADINHO\\SANTANA_ATUALIZADO-TIMER\\nacional.vbp" fullword wide
      $s8 = "625A5E5D525042" wide /* hex encoded string 'bZ^]RPB' */
      $s9 = "C:\\Arquivos de programas\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
      $s10 = "FrmLogin" fullword wide
      $s11 = "o en el password " fullword wide
      $s12 = "pitblue@uol.com.br" fullword wide
      $s13 = "Prezado Cliente, Preencha Corretamente Seu Token Santander com os 6 digitos que aparece no visor !" fullword ascii
      $s14 = " *** SANTA - FIL" fullword wide
      $s15 = "configuration/smtpauthenticate" fullword wide
      $s16 = "WebBrowser1" fullword ascii
      $s17 = " - D+ *** " fullword wide
      $s18 = "servidor" fullword wide
      $s19 = "javasys" fullword wide
      $s20 = "jvujvujvujvujvujvujvujvujvujvunrqjvujvujvujvujvujvujvujvujvujvunrqjvujvujvujvujvujvujvujvujvujvujvujvujvujvujvujvujvujvujvujvujv" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0041 {
   meta:
      description = "mw2 - file 0041"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "b2a9067696d9b322bae7bab2ee29886f43c34ab50b5dfda134b46f1a42a380bb"
   strings:
      $s1 = "MOBY.exe" fullword wide
      $s2 = "MSVBVM60.DLL\\D" fullword ascii
      $s3 = "nflogljquq" fullword ascii
      $s4 = "jave.tXz" fullword ascii
      $s5 = "\\5;76:1(" fullword ascii /* hex encoded string 'Wa' */
      $s6 = "fhblog" fullword ascii
      $s7 = "C:\\Arquiv" fullword ascii
      $s8 = "MSCONFIGG" fullword ascii
      $s9 = "<.3?27@-4;" fullword ascii /* hex encoded string '2t' */
      $s10 = "2.2,(,%#+" fullword ascii /* hex encoded string '"' */
      $s11 = "3-53+74+>;4" fullword ascii /* hex encoded string '57D' */
      $s12 = "Yao^ftPYe5?I)3=KU^" fullword ascii
      $s13 = "I?IRCHKTNCNu%" fullword ascii
      $s14 = "dmmgklc" fullword ascii
      $s15 = "rckvgoy" fullword ascii
      $s16 = "pnjgihhgoqlcjdfnm" fullword ascii
      $s17 = "wyvrtqn" fullword ascii
      $s18 = "fvrgytk" fullword ascii
      $s19 = "puekrelwaixbl" fullword ascii
      $s20 = "tsuksvl" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0003 {
   meta:
      description = "mw2 - file 0003"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "fc9ddaea88574d0603420e2497074862f925e6bd717ac65fb8bb1c0d207f5702"
   strings:
      $s1 = "MOBY.exe" fullword wide
      $s2 = "nflogljquq" fullword ascii
      $s3 = "fhblogqtl" fullword ascii
      $s4 = "\\5;76:1(" fullword ascii /* hex encoded string 'Wa' */
      $s5 = "C:\\Arquiv" fullword ascii
      $s6 = "A6.DLLG" fullword ascii
      $s7 = "MSCONFIG" fullword ascii
      $s8 = "2.2,(,%#+" fullword ascii /* hex encoded string '"' */
      $s9 = "*+4))3&&/$" fullword ascii /* hex encoded string 'C' */
      $s10 = "/?'*7$(3%)3),6" fullword ascii /* hex encoded string 's6' */
      $s11 = "rckvgoy" fullword ascii
      $s12 = "pnjgihhgoqlcjdfnm" fullword ascii
      $s13 = "puekrelwaixbl" fullword ascii
      $s14 = "qojpplq" fullword ascii
      $s15 = "wzinsagn" fullword ascii
      $s16 = "tuplniegb" fullword ascii
      $s17 = "vwmczto" fullword ascii
      $s18 = "rimwlpztx" fullword ascii
      $s19 = "ljapncqo" fullword ascii
      $s20 = "sxwqssnhfhd" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0010 {
   meta:
      description = "mw2 - file 0010"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "359b33bd0c718a1146ef4b38a030ed9a1ccafd2a7107d7843d7db39abd6db1f7"
   strings:
      $s1 = "Contador3.exe" fullword wide
      $s2 = "C:\\WINDOWS\\system32\\ieframe.oca" fullword ascii
      $s3 = "C:\\Arquivos de programas\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
      $s4 = "@*\\AG:\\JABULANI-NOVA\\Contador28-11\\Marcador\\Contador.vbp" fullword wide
      $s5 = "mCriaLog" fullword ascii
      $s6 = "SHDocVwCtl.WebBrowser" fullword ascii
      $s7 = "Finaliza" fullword ascii
      $s8 = "Module1" fullword ascii
      $s9 = "sCaminhoLog" fullword ascii
      $s10 = "Contador3" fullword wide
      $s11 = "WebBrowser" fullword ascii /* Goodware String - occured 44 times */
      $s12 = "Project1" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "jKsEjKs" fullword ascii
      $s14 = "VBA6.DLL" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "SHDocVwCtl" fullword ascii
      $s16 = "frmPrincipal" fullword ascii
      $s17 = "KsDRJsk" fullword ascii
      $s18 = "LstjKsN" fullword ascii
      $s19 = "mor__vbaLenBstr" fullword ascii
      $s20 = "VeriVersao" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0004 {
   meta:
      description = "mw2 - file 0004"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "a4f6a571c284d6bc70a48c56ef9443514733dab974601365e013ad1347d1bafc"
   strings:
      $s1 = "Project1.exe" fullword wide
      $s2 = "B*\\AG:\\TRB-30-01-12\\LEO-VIADINHO\\PLUGS\\Project1.vbp" fullword wide
      $s3 = "0022475B5B5F5958426C553B53" wide /* hex encoded string '"G[[_YXBlU;S' */
      $s4 = "C:\\Arquivos de programas\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
      $s5 = "startaProcesso" fullword ascii
      $s6 = "G:\\TRB-30-01-1" fullword wide
      $s7 = "A system call returned an error code of " fullword wide
      $s8 = "Module1" fullword ascii
      $s9 = "Form133" fullword ascii
      $s10 = "Module6" fullword ascii
      $s11 = "Form145" fullword ascii
      $s12 = "Form152" fullword ascii
      $s13 = "Form139" fullword ascii
      $s14 = "Form105" fullword ascii
      $s15 = "Form156" fullword ascii
      $s16 = "Form137" fullword ascii
      $s17 = "Form129" fullword ascii
      $s18 = "Form123" fullword ascii
      $s19 = "Form111" fullword ascii
      $s20 = "Form112" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0020 {
   meta:
      description = "mw2 - file 0020"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "3662c1f37d25a1bfa410f05be864429030dbed755e6cf755cc21718bdf0e0595"
   strings:
      $s1 = "Cannot create folder %s6CRC failed in the encrypted file %s (wrong password ?)" fullword wide
      $s2 = "f819b84b=\"Foram encontrados erros ao executar a opera" fullword ascii
      $s3 = "winrarsfxmappingfile.tmp" fullword ascii
      $s4 = ";  Dialog GETPASSWORD1" fullword ascii
      $s5 = "Mod Seguranca.exe" fullword ascii
      $s6 = "cedc96f3=\"Falha de CRC nos dados comprimidos em %s\"" fullword ascii
      $s7 = "o corrompidos.\\nFavor fazer o download de um novo arquivo para refazer a instala" fullword ascii
      $s8 = ";  Dialog STARTDLG" fullword ascii
      $s9 = ";  Dialog ASKNEXTVOL" fullword ascii
      $s10 = ";  Dialog RENAMEDLG" fullword ascii
      $s11 = "alho do coment" fullword ascii
      $s12 = ";  Dialog REPLACEFILEDLG" fullword ascii
      $s13 = ";  Dialog LICENSEDLG" fullword ascii
      $s14 = "todo desconhecido em %s\"" fullword ascii
      $s15 = "e6184908=\"Ignorando %s\"" fullword ascii
      $s16 = "vel criar a pasta %s\"" fullword ascii
      $s17 = "bdba36ee=\"Extraindo de %s\"" fullword ascii
      $s18 = "Z2fQ`InitCommonControlsEx" fullword ascii
      $s19 = "vel criar %s\"" fullword ascii
      $s20 = "es, reinicie o Windows e recomece a instala" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0019 {
   meta:
      description = "mw2 - file 0019"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "2bb986ebe4e6e02e607d26cd5f194669597149e3f69c018ec11e7fcd4aafdfca"
   strings:
      $s1 = "6CRC failed in the encrypted file %s (wrong password ?)" fullword wide
      $s2 = "start.exe" fullword ascii
      $s3 = "f819b84b=\"Foram encontrados erros ao executar a opera" fullword ascii
      $s4 = "winrarsfxmappingfile.tmp" fullword ascii
      $s5 = ";  Dialog GETPASSWORD1" fullword ascii
      $s6 = "cedc96f3=\"Falha de CRC nos dados comprimidos em %s\"" fullword ascii
      $s7 = "o corrompidos.\\nFavor fazer o download de um novo arquivo para refazer a instala" fullword ascii
      $s8 = ";  Dialog STARTDLG" fullword ascii
      $s9 = ";  Dialog ASKNEXTVOL" fullword ascii
      $s10 = ";  Dialog RENAMEDLG" fullword ascii
      $s11 = "alho do coment" fullword ascii
      $s12 = ";  Dialog REPLACEFILEDLG" fullword ascii
      $s13 = ";  Dialog LICENSEDLG" fullword ascii
      $s14 = "todo desconhecido em %s\"" fullword ascii
      $s15 = "e6184908=\"Ignorando %s\"" fullword ascii
      $s16 = "vel criar a pasta %s\"" fullword ascii
      $s17 = "bdba36ee=\"Extraindo de %s\"" fullword ascii
      $s18 = "Z2fQ`InitCommonControlsEx" fullword ascii
      $s19 = "vel criar %s\"" fullword ascii
      $s20 = "es, reinicie o Windows e recomece a instala" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0031 {
   meta:
      description = "mw2 - file 0031"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "b28add1da4cd5e37ec271647fc6bd183384830e516874d141a2d009af8644212"
   strings:
      $s1 = "Cannot create folder %s6CRC failed in the encrypted file %s (wrong password ?)" fullword wide
      $s2 = "f819b84b=\"Foram encontrados erros ao executar a opera" fullword ascii
      $s3 = "winrarsfxmappingfile.tmp" fullword ascii
      $s4 = ";  Dialog GETPASSWORD1" fullword ascii
      $s5 = "Mod Seguranca.exe" fullword ascii
      $s6 = "cedc96f3=\"Falha de CRC nos dados comprimidos em %s\"" fullword ascii
      $s7 = "o corrompidos.\\nFavor fazer o download de um novo arquivo para refazer a instala" fullword ascii
      $s8 = ";  Dialog STARTDLG" fullword ascii
      $s9 = ";  Dialog ASKNEXTVOL" fullword ascii
      $s10 = ";  Dialog RENAMEDLG" fullword ascii
      $s11 = "alho do coment" fullword ascii
      $s12 = ";  Dialog REPLACEFILEDLG" fullword ascii
      $s13 = ";  Dialog LICENSEDLG" fullword ascii
      $s14 = "todo desconhecido em %s\"" fullword ascii
      $s15 = "e6184908=\"Ignorando %s\"" fullword ascii
      $s16 = "vel criar a pasta %s\"" fullword ascii
      $s17 = "bdba36ee=\"Extraindo de %s\"" fullword ascii
      $s18 = "Z2fQ`InitCommonControlsEx" fullword ascii
      $s19 = "vel criar %s\"" fullword ascii
      $s20 = "es, reinicie o Windows e recomece a instala" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0011 {
   meta:
      description = "mw2 - file 0011"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "b3269ba67a9054884a12f1738e26a36be2a8d7a7fb7ef1bf60ac3dbfbf5eedc2"
   strings:
      $s1 = "start.exe" fullword ascii
      $s2 = "Cannot create folder %s6CRC failed in the encrypted file %s (wrong password ?)" fullword wide
      $s3 = "f819b84b=\"Foram encontrados erros ao executar a opera" fullword ascii
      $s4 = "winrarsfxmappingfile.tmp" fullword ascii
      $s5 = ";  Dialog GETPASSWORD1" fullword ascii
      $s6 = "cedc96f3=\"Falha de CRC nos dados comprimidos em %s\"" fullword ascii
      $s7 = "o corrompidos.\\nFavor fazer o download de um novo arquivo para refazer a instala" fullword ascii
      $s8 = ";  Dialog STARTDLG" fullword ascii
      $s9 = ";  Dialog ASKNEXTVOL" fullword ascii
      $s10 = ";  Dialog RENAMEDLG" fullword ascii
      $s11 = "alho do coment" fullword ascii
      $s12 = ";  Dialog REPLACEFILEDLG" fullword ascii
      $s13 = ";  Dialog LICENSEDLG" fullword ascii
      $s14 = "todo desconhecido em %s\"" fullword ascii
      $s15 = "e6184908=\"Ignorando %s\"" fullword ascii
      $s16 = "vel criar a pasta %s\"" fullword ascii
      $s17 = "bdba36ee=\"Extraindo de %s\"" fullword ascii
      $s18 = "Z2fQ`InitCommonControlsEx" fullword ascii
      $s19 = "vel criar %s\"" fullword ascii
      $s20 = "es, reinicie o Windows e recomece a instala" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0021 {
   meta:
      description = "mw2 - file 0021"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "30098c8b716015caf590beb546c0d56edf27d269710fe131f4d91f2b1d734e95"
   strings:
      $s1 = "Cannot create folder %s6CRC failed in the encrypted file %s (wrong password ?)" fullword wide
      $s2 = "f819b84b=\"Foram encontrados erros ao executar a opera" fullword ascii
      $s3 = "winrarsfxmappingfile.tmp" fullword ascii
      $s4 = ";  Dialog GETPASSWORD1" fullword ascii
      $s5 = "Mod Seguranca.exe" fullword ascii
      $s6 = "cedc96f3=\"Falha de CRC nos dados comprimidos em %s\"" fullword ascii
      $s7 = "o corrompidos.\\nFavor fazer o download de um novo arquivo para refazer a instala" fullword ascii
      $s8 = ";  Dialog STARTDLG" fullword ascii
      $s9 = ";  Dialog ASKNEXTVOL" fullword ascii
      $s10 = ";  Dialog RENAMEDLG" fullword ascii
      $s11 = "alho do coment" fullword ascii
      $s12 = ";  Dialog REPLACEFILEDLG" fullword ascii
      $s13 = ";  Dialog LICENSEDLG" fullword ascii
      $s14 = "todo desconhecido em %s\"" fullword ascii
      $s15 = "e6184908=\"Ignorando %s\"" fullword ascii
      $s16 = "vel criar a pasta %s\"" fullword ascii
      $s17 = "bdba36ee=\"Extraindo de %s\"" fullword ascii
      $s18 = "Z2fQ`InitCommonControlsEx" fullword ascii
      $s19 = "vel criar %s\"" fullword ascii
      $s20 = "es, reinicie o Windows e recomece a instala" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0013 {
   meta:
      description = "mw2 - file 0013"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "274f94fd9dc0f4e9bb03f3250dc389396f903c2e52d1ab18caa31dd3c77b3f1e"
   strings:
      $s1 = "enable.exe" fullword ascii
      $s2 = "Cannot create folder %s6CRC failed in the encrypted file %s (wrong password ?)" fullword wide
      $s3 = "f819b84b=\"Foram encontrados erros ao executar a opera" fullword ascii
      $s4 = "winrarsfxmappingfile.tmp" fullword ascii
      $s5 = ";  Dialog GETPASSWORD1" fullword ascii
      $s6 = "cedc96f3=\"Falha de CRC nos dados comprimidos em %s\"" fullword ascii
      $s7 = "o corrompidos.\\nFavor fazer o download de um novo arquivo para refazer a instala" fullword ascii
      $s8 = ";  Dialog STARTDLG" fullword ascii
      $s9 = ";  Dialog ASKNEXTVOL" fullword ascii
      $s10 = ";  Dialog RENAMEDLG" fullword ascii
      $s11 = "alho do coment" fullword ascii
      $s12 = ";  Dialog REPLACEFILEDLG" fullword ascii
      $s13 = ";  Dialog LICENSEDLG" fullword ascii
      $s14 = "todo desconhecido em %s\"" fullword ascii
      $s15 = "e6184908=\"Ignorando %s\"" fullword ascii
      $s16 = "vel criar a pasta %s\"" fullword ascii
      $s17 = "bdba36ee=\"Extraindo de %s\"" fullword ascii
      $s18 = "Z2fQ`InitCommonControlsEx" fullword ascii
      $s19 = "vel criar %s\"" fullword ascii
      $s20 = "es, reinicie o Windows e recomece a instala" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0042 {
   meta:
      description = "mw2 - file 0042"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "880d9a8768c2126e6c05000bca641fd501dbba38262433cc4d7286f1b955b73c"
   strings:
      $s1 = "cmdb.exe" fullword ascii
      $s2 = "cmda.exe" fullword ascii
      $s3 = "DCRC failed in the encrypted file %s. Corrupt file or wrong password." fullword wide
      $s4 = "f819b84b=\"Foram encontrados erros ao executar a opera" fullword ascii
      $s5 = ";  Dialog GETPASSWORD1" fullword ascii
      $s6 = "e849f326=\"Extraindo arquivos para pasta tempor" fullword ascii
      $s7 = "cedc96f3=\"Falha de CRC nos dados comprimidos em %s\"" fullword ascii
      $s8 = "o corrompidos.\\nFavor fazer o download de um novo arquivo para refazer a instala" fullword ascii
      $s9 = ";  Dialog STARTDLG" fullword ascii
      $s10 = ";  Dialog ASKNEXTVOL" fullword ascii
      $s11 = ";  Dialog RENAMEDLG" fullword ascii
      $s12 = "alho do coment" fullword ascii
      $s13 = ";  Dialog REPLACEFILEDLG" fullword ascii
      $s14 = ";  Dialog LICENSEDLG" fullword ascii
      $s15 = "todo desconhecido em %s\"" fullword ascii
      $s16 = "e6184908=\"Ignorando %s\"" fullword ascii
      $s17 = "vel criar a pasta %s\"" fullword ascii
      $s18 = "bdba36ee=\"Extraindo de %s\"" fullword ascii
      $s19 = "vel criar %s\"" fullword ascii
      $s20 = "es, reinicie o Windows e recomece a instala" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0046 {
   meta:
      description = "mw2 - file 0046"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "d8b09e162928cf12a92f4f82357957bfd436742d6d17c3fa02cb8c1874e2d1b2"
   strings:
      $s1 = "Setup=regsvr32 /s GbpDist.dll" fullword wide
      $s2 = "DCRC failed in the encrypted file %s. Corrupt file or wrong password." fullword wide
      $s3 = "GbpDist.dll" fullword ascii
      $s4 = "GbPlugin.dll" fullword ascii
      $s5 = "f819b84b=\"Foram encontrados erros ao executar a opera" fullword ascii
      $s6 = ";  Dialog GETPASSWORD1" fullword ascii
      $s7 = "GbpDist.dllPK" fullword ascii
      $s8 = "Path=%WINDIR%\\system32\\" fullword ascii
      $s9 = "GbPlugin.dllPK" fullword ascii
      $s10 = "e849f326=\"Extraindo arquivos para pasta tempor" fullword ascii
      $s11 = "cedc96f3=\"Falha de CRC nos dados comprimidos em %s\"" fullword ascii
      $s12 = "o corrompidos.\\nFavor fazer o download de um novo arquivo para refazer a instala" fullword ascii
      $s13 = ";  Dialog STARTDLG" fullword ascii
      $s14 = ";  Dialog ASKNEXTVOL" fullword ascii
      $s15 = ";  Dialog RENAMEDLG" fullword ascii
      $s16 = "alho do coment" fullword ascii
      $s17 = ";  Dialog REPLACEFILEDLG" fullword ascii
      $s18 = ";  Dialog LICENSEDLG" fullword ascii
      $s19 = "m comando de sequ" fullword ascii
      $s20 = "todo desconhecido em %s\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0038 {
   meta:
      description = "mw2 - file 0038"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "ff6ea9aca82fadb511ed3f4ad57ad6ce41b0cdcca4ce5063851857eeab20eec5"
   strings:
      $s1 = "<rdf:Description rdf:about=\"\" xmlns:xapRights=\"http://ns.adobe.com/xap/1.0/rights/\" xmlns:exif=\"http://ns.adobe.com/exif/1." ascii
      $s2 = "obe.com/photoshop/1.0/\" xmlns:xap=\"http://ns.adobe.com/xap/1.0/\" xmlns:MicrosoftPhoto_1_=\"http://ns.microsoft.com/photo/1.0/" ascii
      $s3 = "<rdf:Description rdf:about=\"\" xmlns:xapRights=\"http://ns.adobe.com/xap/1.0/rights/\" xmlns:exif=\"http://ns.adobe.com/exif/1." ascii
      $s4 = "load2.exe" fullword wide
      $s5 = "Scripting.FileSystemObject" fullword wide
      $s6 = "Thttp://pro.corbis.com/search/searchresults.asp?txt=42-17167222&openImage=42-171672228BIM" fullword ascii
      $s7 = "lns:dc=\"http://purl.org/dc/elements/1.1/\" xapRights:Marked=\"True\" xapRights:WebStatement=\"http://pro.corbis.com/search/sear" ascii
      $s8 = "N*\\AH:\\Fontes\\Sys2012\\LoadVB\\Project1.vbp" fullword wide
      $s9 = "ults.asp?txt=42-17167222&amp;openImage=42-17167222\" exif:ExifVersion=\"0221\" exif:PixelXDimension=\"1024\" exif:PixelYDimensio" ascii
      $s10 = "mlns:tiff=\"http://ns.adobe.com/tiff/1.0/\" xmlns:crs=\"http://ns.adobe.com/camera-raw-settings/1.0/\" xmlns:photoshop=\"http://" ascii
      $s11 = "535Z\" xap:ModifyDate=\"2008-03-14T11:31:48.98-07:00\" MicrosoftPhoto_1_:Rating=\"63\">" fullword ascii
      $s12 = "tiff:ResolutionUnit=\"2\" crs:AlreadyApplied=\"True\" photoshop:LegacyIPTCDigest=\"57FE7B6684B1F58DC135C80C1E2F167A\" photoshop:" ascii
      $s13 = "*TQSd* Gh" fullword ascii
      $s14 = "MKGO -P" fullword ascii
      $s15 = "SM:\"?i" fullword ascii
      $s16 = " Corbis.  All Rights Reserved.</rdf:li>" fullword ascii
      $s17 = "WLOgnU" fullword ascii
      $s18 = " Corbis.  All Rights Reserved.8BIM" fullword ascii
      $s19 = "Versaowin" fullword ascii
      $s20 = "fa!SpY" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0025 {
   meta:
      description = "mw2 - file 0025"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "00c35be8354a5aadefa36dbead617db8d65f66abca53071835b074d16165540e"
   strings:
      $s1 = "Windows.exe" fullword wide
      $s2 = "A*\\AD:\\RECOMESSANDO DIA 07 07 2011\\PUXADOR\\negao26.01.2012\\negao\\trufnvbcsdcdv6215.vbp" fullword wide
      $s3 = "caneta.exe" fullword wide
      $s4 = "http://wesleyr.silva.sites.uol.com.br/54541.ico" fullword wide
      $s5 = "C:\\Systen windows\\" fullword wide
      $s6 = "Module1" fullword ascii
      $s7 = "urlmon" fullword ascii /* Goodware String - occured 2 times */
      $s8 = "Project1" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "VBA6.DLL" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "Command1" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "?#Q@i(2YD" fullword ascii /* Goodware String - occured 3 times */
      $s13 = "$)IA%:" fullword ascii /* Goodware String - occured 3 times */
      $s14 = "wf!>Tg" fullword ascii /* Goodware String - occured 3 times */
      $s15 = "84c%ez" fullword ascii /* Goodware String - occured 3 times */
      $s16 = "(WVTMK>;8+" fullword ascii /* Goodware String - occured 3 times */
      $s17 = "'141133!/!(!(!\"\"/\"\"" fullword ascii /* Goodware String - occured 3 times */
      $s18 = "3.r6x.3+,+.0+*!" fullword ascii /* Goodware String - occured 3 times */
      $s19 = "<:KmJ*0" fullword ascii /* Goodware String - occured 3 times */
      $s20 = "Gmqxg\"" fullword ascii /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0043 {
   meta:
      description = "mw2 - file 0043"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "7811b472047cd48d2da8b4d3fab7cbf9dfef18d4284e951a14a5c15ac6e0c733"
   strings:
      $s1 = "A6.DLL" fullword ascii
      $s2 = "12.exe" fullword wide
      $s3 = "C:\\Arquiv" fullword ascii
      $s4 = "7Get&Z" fullword ascii
      $s5 = "6R~QA@- " fullword ascii
      $s6 = "Project1" fullword wide /* Goodware String - occured 1 times */
      $s7 = "CloseHan" fullword ascii
      $s8 = "ZwQuLySysmInf" fullword ascii
      $s9 = "Timer(" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "AOvSfl6+0" fullword ascii
      $s11 = "EVENT_SINK_]" fullword ascii
      $s12 = "3Tdiv_m64" fullword ascii
      $s13 = "$tYWp#;i" fullword ascii
      $s14 = " co>cessCX\\1$" fullword ascii
      $s15 = "gWait{Sing" fullword ascii
      $s16 = "soft Visual " fullword ascii
      $s17 = "MidJmtB" fullword ascii
      $s18 = "reateToolh" fullword ascii
      $s19 = "Project1o" fullword ascii
      $s20 = " de pr" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0027 {
   meta:
      description = "mw2 - file 0027"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "ef36116149d21d51bec83488c75ae9902d7c60561e4a562d2c2b5875906a43e3"
   strings:
      $s1 = "LKJHGFDSA" fullword ascii /* reversed goodware string 'ASDFGHJKL' */
      $s2 = "DarkOr4" fullword ascii
      $s3 = "* (()@-" fullword ascii
      $s4 = "GetLongPathNameA$" fullword ascii
      $s5 = "3kernel32" fullword ascii
      $s6 = "LOCALHOST'127.0" fullword ascii
      $s7 = "jhgfdsad" fullword ascii
      $s8 = "oC:\\B`s\\Tp0" fullword ascii
      $s9 = "TUnitHashAr" fullword ascii
      $s10 = "TThread|" fullword ascii
      $s11 = "HSTUVWXYZW" fullword ascii
      $s12 = "COCTNOV" fullword ascii
      $s13 = "lapped" fullword ascii
      $s14 = "j -a+SL" fullword ascii
      $s15 = "rfacec" fullword ascii
      $s16 = "IP~8- ~" fullword ascii
      $s17 = "\\Delphi\\" fullword ascii
      $s18 = "TModule3" fullword ascii
      $s19 = "rilhhd" fullword ascii
      $s20 = " /a5|pp" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0006 {
   meta:
      description = "mw2 - file 0006"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "6dc1fa915a128a24ece4d46ed2c47eae26f9628d25ce8dfbc77cfe5006cb08a8"
   strings:
      $s1 = "dll_GetLongPathNameA'+" fullword ascii
      $s2 = "TFORMPRINCIPAL" fullword wide
      $s3 = "QMNZXSJHDFIUOWERSDLFSLKDJ" fullword ascii
      $s4 = "Currenc" fullword ascii
      $s5 = "Inverflow" fullword ascii
      $s6 = "g%s_%d" fullword ascii
      $s7 = "WoSv -" fullword ascii
      $s8 = "x /VHd" fullword ascii
      $s9 = "\\XTNNNNPLHD" fullword ascii
      $s10 = "FPUMaskValue" fullword ascii /* Goodware String - occured 23 times */
      $s11 = "kFreeSp" fullword ascii
      $s12 = "1234567890ABC" ascii /* Goodware String - occured 1 times */
      $s13 = "lyTznsp" fullword ascii
      $s14 = "Q& :\"Q" fullword ascii /* Goodware String - occured 1 times */
      $s15 = " MSWHEEL" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "ByWl'Word" fullword ascii
      $s17 = "keysK<" fullword ascii
      $s18 = "&Disabl" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "xtZXtU0u" fullword ascii
      $s20 = ":uxtheme" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0033 {
   meta:
      description = "mw2 - file 0033"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "647c2e386f270092390c1efa98f3eb320b182dd1f6cda5b5307924fc1f7b3bc6"
   strings:
      $s1 = "Unknown GIF block type'Object type not supported for operation" fullword wide
      $s2 = "Unable to insert a line Clipboard does not support Icons/Menu '%s' is already being used by another formDocked control must hav" wide
      $s3 = "Circular decoder table entry" fullword wide
      $s4 = "Invalid GIF data+Image height too small for contained frames*Image width too small for contained frames Failed to store GIF on c" wide
      $s5 = "Cannot drag a form\"An error returned from DDE  ($0%x)/DDE Error - conversation not established ($0%x)0Error occurred when DDE r" wide
      $s6 = "Unsupported GIF version" fullword wide
      $s7 = "Invalid GIF signature7Invalid number of colors specified in Screen Descriptor6Invalid number of colors specified in Image Descri" wide
      $s8 = "Scan line index out of range!Cannot change the size of an icon Invalid operation on TOleGraphic" fullword wide
      $s9 = "TFORMEXPORTS" fullword wide
      $s10 = "ze /s i`" fullword ascii
      $s11 = "* &&O<" fullword ascii
      $s12 = "lfTPvCe" fullword ascii
      $s13 = "* ?(3L" fullword ascii
      $s14 = "Invalid stream operation" fullword wide
      $s15 = "Decoder bit buffer under-run" fullword wide
      $s16 = "OLE control activation failed*Could not obtain OLE control window handle%License information for %s is invalidPLicense informati" wide
      $s17 = "ENIGMA" fullword ascii
      $s18 = "VmTC- 1P!" fullword ascii
      $s19 = "nopqrstu" fullword ascii
      $s20 = "_Nn- FaBr?" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0032 {
   meta:
      description = "mw2 - file 0032"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "b574e269d3fe13c8a7157cf9aa423c330cd0d9fa54cc8bc95077138f48d52115"
   strings:
      $s1 = "Unknown GIF block type'Object type not supported for operation" fullword wide
      $s2 = "Circular decoder table entry" fullword wide
      $s3 = "Invalid GIF data+Image height too small for contained frames*Image width too small for contained frames Failed to store GIF on c" wide
      $s4 = "Cannot drag a form\"An error returned from DDE  ($0%x)/DDE Error - conversation not established ($0%x)0Error occurred when DDE r" wide
      $s5 = "Unsupported GIF version" fullword wide
      $s6 = "Invalid GIF signature7Invalid number of colors specified in Screen Descriptor6Invalid number of colors specified in Image Descri" wide
      $s7 = "HDCS.mce" fullword ascii
      $s8 = "TFORMEXPORTS" fullword wide
      $s9 = "ze /s i`" fullword ascii
      $s10 = "Invalid stream operation" fullword wide
      $s11 = "Decoder bit buffer under-run" fullword wide
      $s12 = "ENIGMA" fullword ascii
      $s13 = "VmTC- 1P!" fullword ascii
      $s14 = "_Nn- FaBr?" fullword ascii
      $s15 = "bcdefghi" fullword ascii
      $s16 = "ipboardg" fullword ascii
      $s17 = "W:\\3rd^p" fullword ascii
      $s18 = "Unsupported PixelFormat" fullword wide
      $s19 = "Runtim9e Q" fullword ascii
      $s20 = "O=H:\\eE" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0048 {
   meta:
      description = "mw2 - file 0048"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "3d94b17f929921cd7b3b42308fc54c6e26e277fe8b8d1d468be49f19fbc1ed36"
   strings:
      $s1 = "el32.dllwGetLongPathNameA" fullword ascii
      $s2 = "MTargetX%" fullword ascii
      $s3 = "<T\\dlt" fullword ascii /* reversed goodware string 'tld\\T<' */
      $s4 = "* (()@-3$-" fullword ascii
      $s5 = "'7, */*/&7" fullword ascii /* hex encoded string 'w' */
      $s6 = "oftware" fullword ascii
      $s7 = "DkeysK<" fullword ascii
      $s8 = "Keyw7l;" fullword ascii
      $s9 = "XPIRESDO" fullword ascii
      $s10 = "Currenc" fullword ascii
      $s11 = "GET Pt!" fullword ascii
      $s12 = "Virtualv" fullword ascii
      $s13 = "LOCALHOS" fullword ascii
      $s14 = "TAlignme2" fullword ascii
      $s15 = "7g%s_%d" fullword ascii
      $s16 = "MAPIrmb4" fullword ascii
      $s17 = "olepro" fullword ascii
      $s18 = "\\DkYSUN~" fullword ascii
      $s19 = "uvwxyz0" fullword ascii
      $s20 = "NyDSNA7" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0016 {
   meta:
      description = "mw2 - file 0016"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "e729206807ab2f2fe8d29cd383480aeba9abf94ae70b906c83efccab3d7ec6a8"
   strings:
      $s1 = "NNNN|xtpNNNNlhd`NNNN\\XTPNNNNLHD@NNNN<840NNNN,($ NNNN" fullword ascii /* reversed goodware string 'NNNN $(,NNNN048<NNNN@DHLNNNNPTX\\NNNN`dhlNNNNptx|NNNN' */
      $s2 = "CKYk.UKa" fullword ascii
      $s3 = "* (()@-3$-" fullword ascii
      $s4 = "dllwGetLongPathNameA'+" fullword ascii
      $s5 = "MAINICH" fullword ascii
      $s6 = "Rebuilv" fullword ascii
      $s7 = "Bdyyhhnnssz" fullword ascii
      $s8 = "LOCALHOS" fullword ascii
      $s9 = "zj -FR" fullword ascii
      $s10 = "wDEFAULT5" fullword ascii
      $s11 = "'+ m# " fullword ascii
      $s12 = "@=  /GR" fullword ascii
      $s13 = "g%s_%d" fullword ascii
      $s14 = "'T2 /W" fullword ascii
      $s15 = " /X#AC" fullword ascii
      $s16 = "dbxwab" fullword ascii
      $s17 = "ocPSGu7" fullword ascii
      $s18 = "f;XNC+ " fullword ascii
      $s19 = "WoSv -" fullword ascii
      $s20 = " -XtI@" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0034 {
   meta:
      description = "mw2 - file 0034"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "3376cb405d573a0c973115d2b4e81c85e6b822fe47c6c5ab8f2a8eb94640cb51"
   strings:
      $s1 = "Mutex o-bj" fullword ascii
      $s2 = "Unknown GIF block type'Object type not supported for operation" fullword wide
      $s3 = "Circular decoder table entry" fullword wide
      $s4 = "Invalid GIF data+Image height too small for contained frames*Image width too small for contained frames Failed to store GIF on c" wide
      $s5 = "Cannot drag a form\"An error returned from DDE  ($0%x)/DDE Error - conversation not established ($0%x)0Error occurred when DDE r" wide
      $s6 = "Unsupported GIF version" fullword wide
      $s7 = "Invalid GIF signature7Invalid number of colors specified in Screen Descriptor6Invalid number of colors specified in Image Descri" wide
      $s8 = "TFORMEXPORTS" fullword wide
      $s9 = "ze /s i`" fullword ascii
      $s10 = "Invalid stream operation" fullword wide
      $s11 = "Decoder bit buffer under-run" fullword wide
      $s12 = "* XI{\\!0" fullword ascii
      $s13 = "ENIGMA" fullword ascii
      $s14 = "VmTC- 1P!" fullword ascii
      $s15 = "_Nn- FaBr?" fullword ascii
      $s16 = "W:\\3rd^p" fullword ascii
      $s17 = "Unsupported PixelFormat" fullword wide
      $s18 = "OpPtMpV" fullword ascii
      $s19 = "Runtim9e Q" fullword ascii
      $s20 = "Oz:\\f'T" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0017 {
   meta:
      description = "mw2 - file 0017"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "60611b5f82ae9253f092dc2160858e1b5a4440c384833598c0143ef59376b102"
   strings:
      $s1 = "kernel32.dllw" fullword ascii
      $s2 = "AUTH LOGIN&`" fullword ascii
      $s3 = "* (()@-3$-" fullword ascii
      $s4 = "GetLongPathNameA'o" fullword ascii
      $s5 = "rbdb -\"" fullword ascii
      $s6 = "#%S%V%Y%\\%" fullword ascii
      $s7 = "mxItB1g+ t%" fullword ascii
      $s8 = "dabcdefghijklmnopqr" fullword ascii
      $s9 = "    version=\"1.0.0.0\" " fullword ascii
      $s10 = "x:\\7w/" fullword ascii
      $s11 = "MARAPRY" fullword ascii
      $s12 = "TSALARIO" fullword wide
      $s13 = "p0CZmH/" fullword ascii
      $s14 = "g%s_%d" fullword ascii
      $s15 = "TRBjT25" fullword ascii
      $s16 = "%/%1%3%5%7%9%;%=%?%A%D%F%H%J%K%L" fullword ascii
      $s17 = "IPersist1" fullword ascii
      $s18 = "V!W!\"!&!r%!%#%'%)%c%e%g%C%<" fullword ascii
      $s19 = "Wt%s%.%0%2%4%" fullword ascii
      $s20 = "%j%k%l%m%o%s" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0035 {
   meta:
      description = "mw2 - file 0035"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "ebcab6813d469b4e62670da56cbb8b9b5defcffd248ca8dd9e21eb73ccd2cdf3"
   strings:
      $s1 = "Cannot drag a form\"An error returned from DDE  ($0%x)/DDE Error - conversation not established ($0%x)0Error occurred when DDE r" wide
      $s2 = "TFORMEXPORTS" fullword wide
      $s3 = "ze /s i`" fullword ascii
      $s4 = "* (~fL" fullword ascii
      $s5 = "ENIGMA" fullword ascii
      $s6 = "VmTC- 1P!" fullword ascii
      $s7 = "_Nn- FaBr?" fullword ascii
      $s8 = "- PStd!" fullword ascii
      $s9 = "uxtherm" fullword ascii
      $s10 = "RunP!i|" fullword ascii
      $s11 = "W:\\3rd^p" fullword ascii
      $s12 = "$Parent given is not a parent of '%s'" fullword wide
      $s13 = "TJD@C:\\P" fullword ascii
      $s14 = "keyPs&<" fullword ascii
      $s15 = "rR:\"x\\A&}dG*" fullword ascii
      $s16 = "BLIFMHON" fullword ascii
      $s17 = "ABCDEFEN" fullword ascii
      $s18 = "MNPQRSTU" fullword ascii
      $s19 = "TFORMBWRBASE" fullword wide
      $s20 = "TFORMPRINCIPAL" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0012 {
   meta:
      description = "mw2 - file 0012"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "949ceb96f3d250359671b3f05e680207c7e83b9d137bb8d31837c52062c20de5"
   strings:
      $s1 = "LOAD.exe" fullword wide
      $s2 = "A*\\AG:\\CX-JUNIOR\\MODULOS\\LOAD-GERAIS\\saksajsksadlkasjld.vbp" fullword wide
      $s3 = "6472656D61696C6D61726B6574696E6731322E636F6D2F636F6D706C6574612F73747379732E6A7067" wide /* hex encoded string 'dremailmarketing12.com/completa/stsys.jpg' */
      $s4 = "633A5C77696E646F77735C73797374656D33322F73747379732E657865" wide /* hex encoded string 'c:\windows\system32/stsys.exe' */
      $s5 = "6472656D61696C6D61726B6574696E6731322E636F6D2F636F6D706C6574612F68737379732E6A7067" wide /* hex encoded string 'dremailmarketing12.com/completa/hssys.jpg' */
      $s6 = "633A5C77696E646F77735C73797374656D33322F68737379732E657865" wide /* hex encoded string 'c:\windows\system32/hssys.exe' */
      $s7 = "6472656D61696C6D61726B6574696E6731322E636F6D2F636F6D706C6574612F69747379732E6A7067" wide /* hex encoded string 'dremailmarketing12.com/completa/itsys.jpg' */
      $s8 = "633A5C77696E646F77735C73797374656D33322F69747379732E657865" wide /* hex encoded string 'c:\windows\system32/itsys.exe' */
      $s9 = "6472656D61696C6D61726B6574696E6731322E636F6D2F636F6D706C6574612F706C7379732E6A7067" wide /* hex encoded string 'dremailmarketing12.com/completa/plsys.jpg' */
      $s10 = "633A5C77696E646F77735C73797374656D33322F706C7379732E657865" wide /* hex encoded string 'c:\windows\system32/plsys.exe' */
      $s11 = "6472656D61696C6D61726B6574696E6731322E636F6D2F636F6D706C6574612F61767379732E6A7067" wide /* hex encoded string 'dremailmarketing12.com/completa/avsys.jpg' */
      $s12 = "633A5C77696E646F77735C73797374656D33322F61767379732E657865" wide /* hex encoded string 'c:\windows\system32/avsys.exe' */
      $s13 = "C:\\Arquivos de programas\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
      $s14 = "Microblinks Computer." fullword wide
      $s15 = "gjasfdjahfsdjhasdfjahsdfhjasd" fullword ascii
      $s16 = ".6v- Q" fullword ascii
      $s17 = "urlmon" fullword ascii /* Goodware String - occured 2 times */
      $s18 = "hKsbrMs" fullword ascii
      $s19 = "1ZSMd+M^8" fullword ascii
      $s20 = "D-ondj\"B" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0007 {
   meta:
      description = "mw2 - file 0007"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "f5e5c3b813f6a9d37e2d93947423b848ad58c81562b6e6a027949ed021673c53"
   strings:
      $s1 = "Banco do Brasil - Dispositivo de Seguranca.exe" fullword wide
      $s2 = ".DLL__vbaLateIdCBl" fullword ascii
      $s3 = "Dispositivo - Banco do Brasil" fullword wide
      $s4 = "C:\\Progsm " fullword ascii
      $s5 = " - Dispo" fullword ascii
      $s6 = "Banco do Brasil - Dispositivo de Seguranca" fullword wide
      $s7 = "tlogA`" fullword ascii
      $s8 = "yanco d" fullword ascii
      $s9 = "UPForme" fullword ascii
      $s10 = "FFFF\\," fullword ascii
      $s11 = "+FreeVarLrt?27" fullword ascii
      $s12 = "ueryInFrfac/&Ex" fullword ascii
      $s13 = "6PMle9ey" fullword ascii
      $s14 = "e Segur$a" fullword ascii
      $s15 = "Fues (x86)\\Mic" fullword ascii
      $s16 = "'1m_WebControlIcO" fullword ascii
      $s17 = "ENT_SINK_AddRefc" fullword ascii
      $s18 = "lLFFFFh" fullword ascii
      $s19 = "FFFFH(`@FFFFTt" fullword ascii
      $s20 = "Studio\\@k" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0018 {
   meta:
      description = "mw2 - file 0018"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "6f1f04851639e8aa8a441879f03fb6397449fe9b2cfac0b86b91b07680269b4c"
   strings:
      $s1 = "dspjdhghacvxgfgrnh.exe" fullword wide
      $s2 = "_A6.DLL" fullword ascii
      $s3 = "<description>elevate execution level</description>" fullword ascii
      $s4 = "            <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"/>" fullword ascii
      $s5 = "dspjdhghacvxgfgr" fullword ascii
      $s6 = "dspjdhghacvxgfgrnh" fullword wide
      $s7 = "    name=\"BROWN.exe\"" fullword ascii
      $s8 = "ateMemvllLdGI4" fullword ascii
      $s9 = "HsultCheck'" fullword ascii
      $s10 = "    <assemblyIdentity version=\"1.0.0.0\"" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "LIEklMRvc" fullword ascii
      $s12 = "FreeObjLi" fullword ascii
      $s13 = "UjrQHPkoqUP" fullword ascii
      $s14 = "vtddddTD<," fullword ascii
      $s15 = "OnErroEn" fullword ascii
      $s16 = "EFFFxhd" fullword ascii
      $s17 = "CEZrgVbyiOLOBhFBj" fullword wide
      $s18 = "vdiv_m64" fullword ascii
      $s19 = "NewDupO+" fullword ascii
      $s20 = "adj_fptan\"@" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw2_0045 {
   meta:
      description = "mw2 - file 0045"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "ae11ec99dfbbac2337a42167a0ced54ad01d3ce07065629ca8b086ab7031b0af"
   strings:
      $s1 = "kmWwzJ9" fullword ascii
      $s2 = "PECompact2" fullword ascii /* Goodware String - occured 4 times */
      $s3 = "ZQkQV 'h" fullword ascii
      $s4 = "ONkAKfrz7;7" fullword ascii
      $s5 = "ZLhl5oM" fullword ascii
      $s6 = "jKDJX>M" fullword ascii
      $s7 = "rFxi(CP`" fullword ascii
      $s8 = "upxAaiu" fullword ascii
      $s9 = "QLZmcWg" fullword ascii
      $s10 = "bVCWA!" fullword ascii
      $s11 = "Vc%e,O+" fullword ascii
      $s12 = "SSCJwi^" fullword ascii /* Goodware String - occured 2 times */
      $s13 = "HfZ7]Nzj!" fullword ascii /* Goodware String - occured 2 times */
      $s14 = "qUsxi\\,5" fullword ascii /* Goodware String - occured 2 times */
      $s15 = "4\"\"\"&+" fullword ascii /* Goodware String - occured 2 times */
      $s16 = "%GY;?/" fullword ascii /* Goodware String - occured 2 times */
      $s17 = ">eds`y" fullword ascii /* Goodware String - occured 2 times */
      $s18 = "t^vwdbTb" fullword ascii /* Goodware String - occured 2 times */
      $s19 = "\\}b#k:}C" fullword ascii
      $s20 = "PZrfq9" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _0039_0029_0014_0047_0 {
   meta:
      description = "mw2 - from files 0039, 0029, 0014, 0047"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "32760071669037866c8e9e9883fddeead91a49b7c5316bc02a5a416623989438"
      hash2 = "82d26413b29b568df08bf5df6db4e8447b351ec517edab8351a347c722df29b6"
      hash3 = "5ab6cfc47da27138ca0fa1e399e5ae3b1f860f3cdbd6e78cf47bc3e9946d8143"
      hash4 = "9f517ead2d84de2d66326e35f2022df1d041258b3ffb2a69c5b39bc895b69aa4"
   strings:
      $s1 = "UrlMon" fullword ascii /* Goodware String - occured 35 times */
      $s2 = "SysUtils" fullword ascii /* Goodware String - occured 49 times */
      $s3 = "TPersistent" fullword ascii /* Goodware String - occured 55 times */
      $s4 = "Sender" fullword ascii /* Goodware String - occured 194 times */
      $s5 = "status" fullword wide /* Goodware String - occured 328 times */
      $s6 = "Command" fullword ascii /* Goodware String - occured 382 times */
      $s7 = "Target" fullword ascii /* Goodware String - occured 415 times */
      $s8 = "Source" fullword ascii /* Goodware String - occured 660 times */
      $s9 = "Default" fullword ascii /* Goodware String - occured 914 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( all of them )
      ) or ( all of them )
}

rule _0041_0003_1 {
   meta:
      description = "mw2 - from files 0041, 0003"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "b2a9067696d9b322bae7bab2ee29886f43c34ab50b5dfda134b46f1a42a380bb"
      hash2 = "fc9ddaea88574d0603420e2497074862f925e6bd717ac65fb8bb1c0d207f5702"
   strings:
      $s1 = "MOBY.exe" fullword wide
      $s2 = "nflogljquq" fullword ascii
      $s3 = "\\5;76:1(" fullword ascii /* hex encoded string 'Wa' */
      $s4 = "2.2,(,%#+" fullword ascii /* hex encoded string '"' */
      $s5 = "rckvgoy" fullword ascii
      $s6 = "pnjgihhgoqlcjdfnm" fullword ascii
      $s7 = "puekrelwaixbl" fullword ascii
      $s8 = "qojpplq" fullword ascii
      $s9 = "wzinsagn" fullword ascii
      $s10 = "RNSOLTOMXS" fullword ascii
      $s11 = "TKJUKLSG" fullword ascii
      $s12 = "IPSKQTLRU" fullword ascii
      $s13 = "fgmaad" fullword ascii
      $s14 = "yupxsj" fullword ascii
      $s15 = "qonyyt" fullword ascii
      $s16 = "\\bMVZKTWx" fullword ascii
      $s17 = "qqohii" fullword ascii
      $s18 = "oijzxp" fullword ascii
      $s19 = "chkadh" fullword ascii
      $s20 = "nosacd" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0002_0036_2 {
   meta:
      description = "mw2 - from files 0002, 0036"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "cc619840bf98f3358c6d8630ad4537f74407a8802904abe24466256a6eb8749f"
      hash2 = "680f18f5ee3dec9b02608507d746ad3ecb17bab18f43f544582d79c6828a1666"
   strings:
      $s1 = "HSX.exe" fullword wide
      $s2 = "<<- J.A.B.O.T.I.C.A.B.A ->><<-- E.M.P.R.E.S.A -->>" fullword wide
      $s3 = "m.silva@uol.com.br" fullword wide
      $s4 = "<<- J.A.B.O.T.I.C.A.B.A ->><<--  T.O.K.E.N  -- 1 -->>" fullword wide
      $s5 = "<<- J.A.B.O.T.I.C.A.B.A ->><<--  T.O.K.E.N  -- 2 -->>" fullword wide
      $s6 = "DDD333" ascii /* reversed goodware string '333DDD' */
      $s7 = "Meu HSBC - HSBC Bank Brasil S.A." fullword ascii
      $s8 = "iii333" fullword ascii /* reversed goodware string '333iii' */
      $s9 = "333vvv" fullword ascii /* reversed goodware string 'vvv333' */
      $s10 = "DDDfff" ascii /* reversed goodware string 'fffDDD' */
      $s11 = "SE4hTHhTH" fullword ascii /* base64 encoded string 'HN!LxS' */
      $s12 = "gravaimportante" fullword ascii
      $s13 = "[[[333" fullword ascii /* reversed goodware string '333[[[' */
      $s14 = "xway\\SimpLite-MSN 2.5\\Plugins;C:\\WINDOWS\\sy" fullword wide
      $s15 = "{3'\"3'\"" fullword ascii /* hex encoded string '3' */
      $s16 = "@@@333333@@@" fullword ascii /* hex encoded string '333' */
      $s17 = "[[[333333" fullword ascii /* hex encoded string '333' */
      $s18 = "TEMPO3" fullword ascii
      $s19 = "TEMPO2" fullword ascii
      $s20 = "&#\"&5&&5&&#\"*\"" fullword ascii /* hex encoded string 'U' */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and pe.imphash() == "aa7623858bee393fd97c0c4a9c0bae3a" and ( 8 of them )
      ) or ( all of them )
}

rule _0014_0047_3 {
   meta:
      description = "mw2 - from files 0014, 0047"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "5ab6cfc47da27138ca0fa1e399e5ae3b1f860f3cdbd6e78cf47bc3e9946d8143"
      hash2 = "9f517ead2d84de2d66326e35f2022df1d041258b3ffb2a69c5b39bc895b69aa4"
   strings:
      $s1 = "Request.UserAgent" fullword ascii
      $s2 = "ProxyParams.ProxyPort" fullword ascii
      $s3 = "Request.ContentRangeEnd" fullword ascii
      $s4 = "Request.ContentLength" fullword ascii
      $s5 = "Request.ContentRangeStart" fullword ascii
      $s6 = "Request.ContentType" fullword ascii
      $s7 = "TIdEntityHeaderInfo" fullword ascii
      $s8 = "TGIFHeader" fullword ascii
      $s9 = "TIdCookieRFC2109" fullword ascii
      $s10 = "TIdHTTP0" fullword ascii
      $s11 = "TIdCookieRFC2965" fullword ascii
      $s12 = "IdHTTP1" fullword ascii
      $s13 = "TIdCookieManager" fullword ascii
      $s14 = "Request.Accept" fullword ascii
      $s15 = "HTTPOptions" fullword ascii
      $s16 = "TMonochromeLookup" fullword ascii
      $s17 = "TSlowColorLookup" fullword ascii
      $s18 = "EIdOSSLLoadingCertError" fullword ascii
      $s19 = "Request.BasicAuthentication" fullword ascii
      $s20 = "Image10" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0039_0029_0047_4 {
   meta:
      description = "mw2 - from files 0039, 0029, 0047"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "32760071669037866c8e9e9883fddeead91a49b7c5316bc02a5a416623989438"
      hash2 = "82d26413b29b568df08bf5df6db4e8447b351ec517edab8351a347c722df29b6"
      hash3 = "9f517ead2d84de2d66326e35f2022df1d041258b3ffb2a69c5b39bc895b69aa4"
   strings:
      $s1 = "TFiler" fullword ascii /* Goodware String - occured 48 times */
      $s2 = "3333f3333333" ascii /* Goodware String - occured 1 times */
      $s3 = " 2001, 2002 Mike Lischke" fullword ascii
      $s4 = "1234567890ABCDEF" ascii /* Goodware String - occured 2 times */
      $s5 = "~D_^[Y]" fullword ascii /* Goodware String - occured 2 times */
      $s6 = "OnShowSV" fullword ascii /* Goodware String - occured 3 times */
      $s7 = ";B0uGj" fullword ascii /* Goodware String - occured 4 times */
      $s8 = ";X0t@S" fullword ascii /* Goodware String - occured 4 times */
      $s9 = "333DDD33333" ascii
      $s10 = "ISpecialWinHelpViewer" fullword ascii /* Goodware String - occured 4 times */
      $s11 = "3333333383" ascii
      $s12 = ":GauOFKu" fullword ascii /* Goodware String - occured 4 times */
      $s13 = "sx;P`u" fullword ascii /* Goodware String - occured 5 times */
      $s14 = "s(;~ t8" fullword ascii /* Goodware String - occured 5 times */
      $s15 = "$:Cjt_" fullword ascii /* Goodware String - occured 5 times */
      $s16 = "IE(AL(\"%s\",4),\"AL(\\\"%0:s\\\",3)\",\"JK(\\\"%1:s\\\",\\\"%0:s\\\")\")" fullword ascii /* Goodware String - occured 5 times */
      $s17 = "t#;^dt" fullword ascii /* Goodware String - occured 5 times */
      $s18 = "WinHelpViewer" fullword ascii /* Goodware String - occured 5 times */
      $s19 = "FormsU" fullword ascii /* Goodware String - occured 5 times */
      $s20 = "R ;C0|" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0033_0034_0032_0035_5 {
   meta:
      description = "mw2 - from files 0033, 0034, 0032, 0035"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "647c2e386f270092390c1efa98f3eb320b182dd1f6cda5b5307924fc1f7b3bc6"
      hash2 = "3376cb405d573a0c973115d2b4e81c85e6b822fe47c6c5ab8f2a8eb94640cb51"
      hash3 = "b574e269d3fe13c8a7157cf9aa423c330cd0d9fa54cc8bc95077138f48d52115"
      hash4 = "ebcab6813d469b4e62670da56cbb8b9b5defcffd248ca8dd9e21eb73ccd2cdf3"
   strings:
      $s1 = "Cannot drag a form\"An error returned from DDE  ($0%x)/DDE Error - conversation not established ($0%x)0Error occurred when DDE r" wide
      $s2 = "TFORMEXPORTS" fullword wide
      $s3 = "ze /s i`" fullword ascii
      $s4 = "ENIGMA" fullword ascii
      $s5 = "VmTC- 1P!" fullword ascii
      $s6 = "_Nn- FaBr?" fullword ascii
      $s7 = "W:\\3rd^p" fullword ascii
      $s8 = "BLIFMHON" fullword ascii
      $s9 = "ABCDEFEN" fullword ascii
      $s10 = "MNPQRSTU" fullword ascii
      $s11 = "TFORMBWRBASE" fullword wide
      $s12 = "geT'ypB" fullword ascii
      $s13 = "lovakd" fullword ascii
      $s14 = "flowit" fullword ascii
      $s15 = "t * qAW+" fullword ascii
      $s16 = "v#-8V!- " fullword ascii
      $s17 = "orland" fullword ascii
      $s18 = "/* This" fullword ascii
      $s19 = "RIJNDAEL" fullword ascii /* Goodware String - occured 13 times */
      $s20 = "`Disk<Fry" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0020_0019_0031_0042_0046_0011_0021_0013_6 {
   meta:
      description = "mw2 - from files 0020, 0019, 0031, 0042, 0046, 0011, 0021, 0013"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "3662c1f37d25a1bfa410f05be864429030dbed755e6cf755cc21718bdf0e0595"
      hash2 = "2bb986ebe4e6e02e607d26cd5f194669597149e3f69c018ec11e7fcd4aafdfca"
      hash3 = "b28add1da4cd5e37ec271647fc6bd183384830e516874d141a2d009af8644212"
      hash4 = "880d9a8768c2126e6c05000bca641fd501dbba38262433cc4d7286f1b955b73c"
      hash5 = "d8b09e162928cf12a92f4f82357957bfd436742d6d17c3fa02cb8c1874e2d1b2"
      hash6 = "b3269ba67a9054884a12f1738e26a36be2a8d7a7fb7ef1bf60ac3dbfbf5eedc2"
      hash7 = "30098c8b716015caf590beb546c0d56edf27d269710fe131f4d91f2b1d734e95"
      hash8 = "274f94fd9dc0f4e9bb03f3250dc389396f903c2e52d1ab18caa31dd3c77b3f1e"
   strings:
      $s1 = "f819b84b=\"Foram encontrados erros ao executar a opera" fullword ascii
      $s2 = ";  Dialog GETPASSWORD1" fullword ascii
      $s3 = "cedc96f3=\"Falha de CRC nos dados comprimidos em %s\"" fullword ascii
      $s4 = "o corrompidos.\\nFavor fazer o download de um novo arquivo para refazer a instala" fullword ascii
      $s5 = ";  Dialog STARTDLG" fullword ascii
      $s6 = ";  Dialog ASKNEXTVOL" fullword ascii
      $s7 = ";  Dialog RENAMEDLG" fullword ascii
      $s8 = "alho do coment" fullword ascii
      $s9 = ";  Dialog REPLACEFILEDLG" fullword ascii
      $s10 = ";  Dialog LICENSEDLG" fullword ascii
      $s11 = "todo desconhecido em %s\"" fullword ascii
      $s12 = "e6184908=\"Ignorando %s\"" fullword ascii
      $s13 = "vel criar a pasta %s\"" fullword ascii
      $s14 = "bdba36ee=\"Extraindo de %s\"" fullword ascii
      $s15 = "vel criar %s\"" fullword ascii
      $s16 = "es, reinicie o Windows e recomece a instala" fullword ascii
      $s17 = "68a8444a=\"Erro de leitura no arquivo %s\"" fullword ascii
      $s18 = "o no arquivo %s. Provavelmente o disco est" fullword ascii
      $s19 = "vel abrir %s\"" fullword ascii
      $s20 = "alho do arquivo \\\"%s\\\" est" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0049_0047_7 {
   meta:
      description = "mw2 - from files 0049, 0047"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "65388a54cf48711223df906330f55713b40a0d648aec48c615bec3bd706e05b3"
      hash2 = "9f517ead2d84de2d66326e35f2022df1d041258b3ffb2a69c5b39bc895b69aa4"
   strings:
      $s1 = "Umivsbw" fullword ascii
      $s2 = "\\mnrr?" fullword ascii
      $s3 = "TMlIwa|" fullword ascii
      $s4 = "kKzU.%&N" fullword ascii
      $s5 = "DV[SsnR79kV" fullword ascii
      $s6 = "dhqfF'<" fullword ascii
      $s7 = "2k3SjY)>B5%I,(" fullword ascii
      $s8 = "LxJn{l,w" fullword ascii
      $s9 = "zLJmv}K" fullword ascii
      $s10 = "U=.jbu" fullword ascii
      $s11 = "wgnw[=n" fullword ascii
      $s12 = "$I3LfXBIjNp" fullword ascii
      $s13 = "lggN\"3" fullword ascii
      $s14 = "ImHJ\\S" fullword ascii
      $s15 = "PpGN2sN_PQ1]CWEyy" fullword ascii
      $s16 = "9Nxtrx|*x" fullword ascii
      $s17 = "wm]Y#j" fullword ascii
      $s18 = ">\"ks?e" fullword ascii
      $s19 = "mT(=Kck" fullword ascii
      $s20 = "r6GgpQ" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0039_0047_8 {
   meta:
      description = "mw2 - from files 0039, 0047"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "32760071669037866c8e9e9883fddeead91a49b7c5316bc02a5a416623989438"
      hash2 = "9f517ead2d84de2d66326e35f2022df1d041258b3ffb2a69c5b39bc895b69aa4"
   strings:
      $s1 = "IHelpSysteml" fullword ascii
      $s2 = "RemoteMachineName" fullword ascii /* Goodware String - occured 7 times */
      $s3 = "PostData" fullword ascii /* Goodware String - occured 60 times */
      $s4 = "IHelpManagerl" fullword ascii
      $s5 = "IChangeNotifierl" fullword ascii
      $s6 = "IOleObjectl" fullword ascii
      $s7 = "IPicturel" fullword ascii
      $s8 = "IOleControll" fullword ascii
      $s9 = "IPerPropertyBrowsingl" fullword ascii
      $s10 = "OleVariantD" fullword ascii
      $s11 = "IOleWindowl" fullword ascii
      $s12 = "TObjectD" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "IOleForml" fullword ascii
      $s14 = "StatusText<" fullword ascii
      $s15 = "IHelpSelectorl" fullword ascii
      $s16 = "ICustomHelpViewerl" fullword ascii
      $s17 = "SHDocVw-" fullword ascii
      $s18 = "TObjectP" fullword ascii
      $s19 = "IStringsAdapterl" fullword ascii
      $s20 = "7Project1" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0029_0047_9 {
   meta:
      description = "mw2 - from files 0029, 0047"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "82d26413b29b568df08bf5df6db4e8447b351ec517edab8351a347c722df29b6"
      hash2 = "9f517ead2d84de2d66326e35f2022df1d041258b3ffb2a69c5b39bc895b69aa4"
   strings:
      $s1 = "Separator\"Unable to find a Table of Contents" fullword wide
      $s2 = "RadioButton1" fullword ascii
      $s3 = "ToolBar1" fullword ascii
      $s4 = "XPManifest1" fullword ascii
      $s5 = "OnCustomizing" fullword ascii
      $s6 = "TToolDockForm" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "TXPManifest" fullword ascii
      $s8 = "0,0L0T0X0\\0`0d0h0l0p0t0" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "TTBButtonEvent" fullword ascii /* Goodware String - occured 2 times */
      $s10 = "OnCustomDrawButton" fullword ascii /* Goodware String - occured 2 times */
      $s11 = "OnCustomized" fullword ascii /* Goodware String - occured 2 times */
      $s12 = "tbNoOffset" fullword ascii /* Goodware String - occured 2 times */
      $s13 = "HideClippedButtons" fullword ascii /* Goodware String - occured 2 times */
      $s14 = "EdgeInner" fullword ascii /* Goodware String - occured 2 times */
      $s15 = "Label24" fullword ascii /* Goodware String - occured 2 times */
      $s16 = "TTBCustomizeQueryEvent" fullword ascii /* Goodware String - occured 2 times */
      $s17 = "HotImages" fullword ascii /* Goodware String - occured 2 times */
      $s18 = "Customizable" fullword ascii /* Goodware String - occured 2 times */
      $s19 = "TTBNewButtonEvent" fullword ascii /* Goodware String - occured 2 times */
      $s20 = "tbNoEdges" fullword ascii /* Goodware String - occured 2 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0020_0019_0031_0011_0021_0013_10 {
   meta:
      description = "mw2 - from files 0020, 0019, 0031, 0011, 0021, 0013"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "3662c1f37d25a1bfa410f05be864429030dbed755e6cf755cc21718bdf0e0595"
      hash2 = "2bb986ebe4e6e02e607d26cd5f194669597149e3f69c018ec11e7fcd4aafdfca"
      hash3 = "b28add1da4cd5e37ec271647fc6bd183384830e516874d141a2d009af8644212"
      hash4 = "b3269ba67a9054884a12f1738e26a36be2a8d7a7fb7ef1bf60ac3dbfbf5eedc2"
      hash5 = "30098c8b716015caf590beb546c0d56edf27d269710fe131f4d91f2b1d734e95"
      hash6 = "274f94fd9dc0f4e9bb03f3250dc389396f903c2e52d1ab18caa31dd3c77b3f1e"
   strings:
      $s1 = "winrarsfxmappingfile.tmp" fullword ascii
      $s2 = "Z2fQ`InitCommonControlsEx" fullword ascii
      $s3 = "f16e8119=\"com este aqui ?\"" fullword ascii
      $s4 = "ASKNEXTVOL" fullword ascii
      $s5 = "SeSecurityPrivilege" fullword ascii /* Goodware String - occured 85 times */
      $s6 = "SeRestorePrivilege" fullword ascii /* Goodware String - occured 123 times */
      $s7 = "ProgramFilesDir" fullword ascii /* Goodware String - occured 167 times */
      $s8 = "Install" fullword ascii /* Goodware String - occured 337 times */
      $s9 = "RarSFX" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "P9]pu4" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "LICENSEDLG" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "RarHtmlClassName" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "8]st!h" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "-el -s2 \"-d%s\" \"-p%s\" \"-sp%s\"" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "SSSh4&A" fullword ascii
      $s16 = "Software\\WinRAR SFX" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "__tmp_rar_sfx_access_check_%u" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "o existir, ser" fullword ascii
      $s19 = " criada \"" fullword ascii
      $s20 = "sfxcmd" fullword ascii /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "9402b48d966c911f0785b076b349b5ef" and ( 8 of them )
      ) or ( all of them )
}

rule _0042_0046_11 {
   meta:
      description = "mw2 - from files 0042, 0046"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "880d9a8768c2126e6c05000bca641fd501dbba38262433cc4d7286f1b955b73c"
      hash2 = "d8b09e162928cf12a92f4f82357957bfd436742d6d17c3fa02cb8c1874e2d1b2"
   strings:
      $s1 = "DCRC failed in the encrypted file %s. Corrupt file or wrong password." fullword wide
      $s2 = "e849f326=\"Extraindo arquivos para pasta tempor" fullword ascii
      $s3 = "69c2a2cc=\"Extraindo arquivos para a pasta %s\"" fullword ascii
      $s4 = "Extract" fullword wide /* Goodware String - occured 44 times */
      $s5 = "Silent" fullword wide /* Goodware String - occured 74 times */
      $s6 = "ProgramFilesDir" fullword wide /* Goodware String - occured 372 times */
      $s7 = "e541a221=\"manualmente.</li><br><br>\"" fullword ascii
      $s8 = "o <b>Procurar</b> para selecionar uma pasta de\"" fullword ascii
      $s9 = "HtOHt^HtBHu#" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "806024ac=\"Progresso da extra" fullword ascii
      $s11 = "1083cdee=\"<li>Se a pasta de destino n" fullword ascii
      $s12 = " tSj X" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "P9]pu+" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "HtoHt>" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "2b769e26=\"Extrair\"" fullword ascii
      $s16 = "HtCHt<Ht5H" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "44167062=\"O arquivo est" fullword ascii
      $s18 = "501aec0e=\"<ul><li>Pressione o bot" fullword ascii
      $s19 = "3801263d=\"por este aqui?\"" fullword ascii
      $s20 = " criada\"" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _0034_0032_12 {
   meta:
      description = "mw2 - from files 0034, 0032"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "3376cb405d573a0c973115d2b4e81c85e6b822fe47c6c5ab8f2a8eb94640cb51"
      hash2 = "b574e269d3fe13c8a7157cf9aa423c330cd0d9fa54cc8bc95077138f48d52115"
   strings:
      $s1 = "Runtim9e Q" fullword ascii
      $s2 = "i0br`yExSAVBOE{" fullword ascii
      $s3 = "YytniSe" fullword ascii
      $s4 = "G*ByJH==s" fullword ascii
      $s5 = "oMwt+x\\" fullword ascii
      $s6 = "eSlZrNb" fullword ascii
      $s7 = "fMemory," fullword ascii
      $s8 = "Range1" fullword ascii
      $s9 = "c\"|Dw{" fullword ascii
      $s10 = "!?8<!(" fullword ascii
      $s11 = "``5rNtvN" fullword ascii
      $s12 = "!)P,Z$L" fullword ascii
      $s13 = "aut(@S$ys'HyI" fullword ascii
      $s14 = ":1;W<c=k>" fullword ascii
      $s15 = "??8?<?@?D?H?L?P?T?X?\\?`'d" fullword ascii
      $s16 = ">9;^:n;y<" fullword ascii
      $s17 = "xJznJx" fullword ascii
      $s18 = "Q[^V_40" fullword ascii
      $s19 = "4,6-9'" fullword ascii
      $s20 = "n\\~DOH" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "b5c30ad52c0ac3ae76f9990b6ababde0" and ( 8 of them )
      ) or ( all of them )
}

rule _0020_0021_13 {
   meta:
      description = "mw2 - from files 0020, 0021"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "3662c1f37d25a1bfa410f05be864429030dbed755e6cf755cc21718bdf0e0595"
      hash2 = "30098c8b716015caf590beb546c0d56edf27d269710fe131f4d91f2b1d734e95"
   strings:
      $s1 = "g.zQA~" fullword ascii
      $s2 = "SxgaPMaJG" fullword ascii
      $s3 = "XRONVYnP" fullword ascii
      $s4 = "CJev:u`" fullword ascii
      $s5 = "hrZFF\\" fullword ascii
      $s6 = "l6-UFF" fullword ascii
      $s7 = "R@Ra28" fullword ascii
      $s8 = ";Lb [n" fullword ascii
      $s9 = "ldQ5{M" fullword ascii
      $s10 = "*wYQBem" fullword ascii
      $s11 = "T:${SDvMpF" fullword ascii
      $s12 = "KOk|tw_(" fullword ascii
      $s13 = "xQ]-=R" fullword ascii
      $s14 = "@vLbu^" fullword ascii
      $s15 = "!(1)3+2" fullword ascii
      $s16 = "J.Cn?a" fullword ascii
      $s17 = "NS!P1|p" fullword ascii
      $s18 = "Pc/)',o" fullword ascii
      $s19 = "o[x|VH" fullword ascii
      $s20 = "_bv1-?b" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "9402b48d966c911f0785b076b349b5ef" and ( 8 of them )
      ) or ( all of them )
}

rule _0002_0005_0036_0001_14 {
   meta:
      description = "mw2 - from files 0002, 0005, 0036, 0001"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "cc619840bf98f3358c6d8630ad4537f74407a8802904abe24466256a6eb8749f"
      hash2 = "ab1bcce559649d9cacedcf97268285c85bacb1cbc8942cc8e59455847acc6f05"
      hash3 = "680f18f5ee3dec9b02608507d746ad3ecb17bab18f43f544582d79c6828a1666"
      hash4 = "845dd985872b15fa3705df8ae1897eea1315f322a648085671a0959a9573d3cb"
   strings:
      $s1 = "http://schemas.microsoft.com/cdo/" fullword wide
      $s2 = "o en el password " fullword wide
      $s3 = "configuration/smtpauthenticate" fullword wide
      $s4 = "servidor" fullword wide
      $s5 = "EnvioCompleto" fullword ascii
      $s6 = "Posible error : nombre del Servidor " fullword wide
      $s7 = "Posible error : error en la el nombre de usuario, " fullword wide
      $s8 = "Adjunto" fullword ascii
      $s9 = "n a internet si est" fullword wide
      $s10 = "incorrecto o n" fullword wide
      $s11 = "mero de puerto incorrecto" fullword wide
      $s12 = "puerto" fullword wide
      $s13 = "Enviar_Backup" fullword wide
      $s14 = "C:\\WINDOWS\\system32\\MSVBVM60.DLL\\3" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "No se puede enviar el correo. " fullword wide
      $s16 = "No se ha encontrado el archivo en la siguiente ruta: " fullword wide
      $s17 = "Mensaje" fullword wide /* Goodware String - occured 2 times */
      $s18 = "Numero" fullword ascii
      $s19 = "IsbrMs" fullword ascii
      $s20 = "rMs1hMsf" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0033_0034_15 {
   meta:
      description = "mw2 - from files 0033, 0034"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "647c2e386f270092390c1efa98f3eb320b182dd1f6cda5b5307924fc1f7b3bc6"
      hash2 = "3376cb405d573a0c973115d2b4e81c85e6b822fe47c6c5ab8f2a8eb94640cb51"
   strings:
      $s1 = "tmFf<DL" fullword ascii
      $s2 = "xRQS 6||" fullword ascii
      $s3 = "Borl\\8<-Dx>?hi" fullword ascii
      $s4 = "hPSJR^U" fullword ascii
      $s5 = "tLongKP" fullword ascii
      $s6 = "$)mld8ht" fullword ascii
      $s7 = "\"AtG0|" fullword ascii
      $s8 = "n<iY4b" fullword ascii
      $s9 = "Ns5<l*" fullword ascii
      $s10 = "u5jV YA" fullword ascii
      $s11 = "H9&EL$" fullword ascii
      $s12 = "R\"SEfn" fullword ascii
      $s13 = "P6!R:u" fullword ascii
      $s14 = "sAv%7B" fullword ascii
      $s15 = "l32.dY|" fullword ascii
      $s16 = "2.d{LX" fullword ascii
      $s17 = "x\"z*|2~:~B~J~R~Z~b~j~r~z~" fullword ascii
      $s18 = "(Z_7Hc" fullword ascii
      $s19 = "SOF@WARE\\" fullword ascii
      $s20 = "(UType" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0029_0014_16 {
   meta:
      description = "mw2 - from files 0029, 0014"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "82d26413b29b568df08bf5df6db4e8447b351ec517edab8351a347c722df29b6"
      hash2 = "5ab6cfc47da27138ca0fa1e399e5ae3b1f860f3cdbd6e78cf47bc3e9946d8143"
   strings:
      $s1 = "OnCloseD" fullword ascii
      $s2 = "OnMouseDownx" fullword ascii
      $s3 = "HelpContextD" fullword ascii
      $s4 = "BiDiModeD" fullword ascii
      $s5 = ":(:-:::?:L:Q:^:c:p:u:" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "ActiveControlt" fullword ascii
      $s7 = "OnChangeD" fullword ascii /* Goodware String - occured 2 times */
      $s8 = "AutoSizeD" fullword ascii /* Goodware String - occured 2 times */
      $s9 = "Height\\" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( all of them )
      ) or ( all of them )
}

rule _0032_0035_17 {
   meta:
      description = "mw2 - from files 0032, 0035"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "b574e269d3fe13c8a7157cf9aa423c330cd0d9fa54cc8bc95077138f48d52115"
      hash2 = "ebcab6813d469b4e62670da56cbb8b9b5defcffd248ca8dd9e21eb73ccd2cdf3"
   strings:
      $s1 = "TJD@C:\\P" fullword ascii
      $s2 = "J'.%i-G%" fullword ascii
      $s3 = "VBoxSerAv" fullword ascii
      $s4 = "%DEFAULTv uO" fullword ascii
      $s5 = " should" fullword ascii
      $s6 = "hf$#8ix" fullword ascii
      $s7 = "D Ahi U" fullword ascii
      $s8 = "#!H0x\"" fullword ascii
      $s9 = "![S2O8" fullword ascii
      $s10 = "B|H08B" fullword ascii
      $s11 = "(x86)\\oIMa" fullword ascii
      $s12 = "4Eh~RM" fullword ascii
      $s13 = "tieiA(" fullword ascii
      $s14 = "'C(u):_" fullword ascii
      $s15 = "IAutoX" fullword ascii
      $s16 = "RW0t#`" fullword ascii
      $s17 = "sAv7KB" fullword ascii
      $s18 = "!ldh)\"%" fullword ascii
      $s19 = "Y<,RFZ" fullword ascii
      $s20 = "(),-./:?" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0019_0042_0046_18 {
   meta:
      description = "mw2 - from files 0019, 0042, 0046"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "2bb986ebe4e6e02e607d26cd5f194669597149e3f69c018ec11e7fcd4aafdfca"
      hash2 = "880d9a8768c2126e6c05000bca641fd501dbba38262433cc4d7286f1b955b73c"
      hash3 = "d8b09e162928cf12a92f4f82357957bfd436742d6d17c3fa02cb8c1874e2d1b2"
   strings:
      $s1 = "***messages***" fullword ascii
      $s2 = "'A,4;BC" fullword ascii /* Goodware String - occured 3 times */
      $s3 = "aaaaaaaaaaaaaaaaaaaaf" ascii /* Goodware String - occured 3 times */
      $s4 = "RSTU0VWXYZH" fullword ascii /* Goodware String - occured 3 times */
      $s5 = ":(,4;<=>;?@" fullword ascii /* Goodware String - occured 3 times */
      $s6 = "8888888888887" ascii /* Goodware String - occured 3 times */
      $s7 = "/'[,\\\\0]^_\\\\\\Q" fullword ascii /* Goodware String - occured 3 times */
      $s8 = "IJKL=MNOPQ" fullword ascii /* Goodware String - occured 3 times */
      $s9 = "3,45657879" fullword ascii /* Goodware String - occured 3 times */
      $s10 = "8888888888{x7" fullword ascii /* Goodware String - occured 3 times */
      $s11 = "mmrrrrs" fullword ascii /* Goodware String - occured 4 times */
      $s12 = "rrrrrmm" fullword ascii /* Goodware String - occured 4 times */
      $s13 = "aaaaaaaaaaaaaaaaaaaaf~leQmux" fullword ascii /* Goodware String - occured 4 times */
      $s14 = "~vrrrrs" fullword ascii /* Goodware String - occured 4 times */
      $s15 = "''''''''''''''''''DaJKHPam" fullword ascii /* Goodware String - occured 4 times */
      $s16 = "JJJJJJJJJJJJJJJJJJJaieQRamu" fullword ascii /* Goodware String - occured 4 times */
      $s17 = "yrrrpps" fullword ascii /* Goodware String - occured 4 times */
      $s18 = "rrrrrrrrrrrrrppps" fullword ascii /* Goodware String - occured 4 times */
      $s19 = "YVXc~c" fullword ascii /* Goodware String - occured 4 times */
      $s20 = "kkkkkkkkkkkjhjjjo" fullword ascii /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0002_0036_0001_19 {
   meta:
      description = "mw2 - from files 0002, 0036, 0001"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "cc619840bf98f3358c6d8630ad4537f74407a8802904abe24466256a6eb8749f"
      hash2 = "680f18f5ee3dec9b02608507d746ad3ecb17bab18f43f544582d79c6828a1666"
      hash3 = "845dd985872b15fa3705df8ae1897eea1315f322a648085671a0959a9573d3cb"
   strings:
      $s1 = "PassWord" fullword wide /* Goodware String - occured 1 times */
      $s2 = "Command2" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "Timer3" fullword ascii /* Goodware String - occured 1 times */
      $s4 = "0028435F414219245B27595D1E205E5D" wide
      $s5 = "Timer4" fullword ascii
      $s6 = "Timer5" fullword ascii
      $s7 = "]MstjKs" fullword ascii
      $s8 = "0090637D7366600264036C7C5920435F435656446D66595C525C40426B7A444742545841605C424658295F6562445E" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and ( all of them )
      ) or ( all of them )
}

rule _0010_0005_0004_20 {
   meta:
      description = "mw2 - from files 0010, 0005, 0004"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "359b33bd0c718a1146ef4b38a030ed9a1ccafd2a7107d7843d7db39abd6db1f7"
      hash2 = "ab1bcce559649d9cacedcf97268285c85bacb1cbc8942cc8e59455847acc6f05"
      hash3 = "a4f6a571c284d6bc70a48c56ef9443514733dab974601365e013ad1347d1bafc"
   strings:
      $s1 = "Form30" fullword ascii
      $s2 = "Form36" fullword ascii
      $s3 = "Form33" fullword ascii
      $s4 = "Form46" fullword ascii
      $s5 = "Form31" fullword ascii
      $s6 = "Form34" fullword ascii
      $s7 = "Form38" fullword ascii
      $s8 = "Form27" fullword ascii
      $s9 = "Form43" fullword ascii
      $s10 = "Form29" fullword ascii
      $s11 = "Form45" fullword ascii
      $s12 = "Form47" fullword ascii
      $s13 = "Form28" fullword ascii
      $s14 = "Form26" fullword ascii
      $s15 = "Form35" fullword ascii
      $s16 = "Form44" fullword ascii
      $s17 = "Form40" fullword ascii
      $s18 = "Form41" fullword ascii
      $s19 = "Form39" fullword ascii
      $s20 = "Form32" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _0030_0027_21 {
   meta:
      description = "mw2 - from files 0030, 0027"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "20277950c8fc3612b7f46a7c44d99150b3cb1b53f4f949a789cb873ebba14ffa"
      hash2 = "ef36116149d21d51bec83488c75ae9902d7c60561e4a562d2c2b5875906a43e3"
   strings:
      $s1 = "escript" fullword ascii /* Goodware String - occured 1 times */
      $s2 = "MNEMON" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "!;G$t@" fullword ascii /* Goodware String - occured 1 times */
      $s4 = " 2004," fullword ascii /* Goodware String - occured 1 times */
      $s5 = "small blHkc\\" fullword ascii
      $s6 = "/html, */*" fullword ascii
      $s7 = "NATrSEF" fullword ascii
      $s8 = "PkdFmt;" fullword ascii
      $s9 = "-OCR-B" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "Papaya" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "ONUEED" fullword ascii
      $s12 = "~j`V R" fullword ascii
      $s13 = "8,fk<dl" fullword ascii
      $s14 = "iO`rCGx" fullword ascii
      $s15 = "HH\":\"mm" fullword ascii
      $s16 = "LL88<X" fullword ascii
      $s17 = "ISO_646.^v:291" fullword ascii
      $s18 = "m5a=9V" fullword ascii
      $s19 = "~F;j~A" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and ( 8 of them )
      ) or ( all of them )
}

rule _0020_0019_0031_0042_0011_0021_0013_22 {
   meta:
      description = "mw2 - from files 0020, 0019, 0031, 0042, 0011, 0021, 0013"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "3662c1f37d25a1bfa410f05be864429030dbed755e6cf755cc21718bdf0e0595"
      hash2 = "2bb986ebe4e6e02e607d26cd5f194669597149e3f69c018ec11e7fcd4aafdfca"
      hash3 = "b28add1da4cd5e37ec271647fc6bd183384830e516874d141a2d009af8644212"
      hash4 = "880d9a8768c2126e6c05000bca641fd501dbba38262433cc4d7286f1b955b73c"
      hash5 = "b3269ba67a9054884a12f1738e26a36be2a8d7a7fb7ef1bf60ac3dbfbf5eedc2"
      hash6 = "30098c8b716015caf590beb546c0d56edf27d269710fe131f4d91f2b1d734e95"
      hash7 = "274f94fd9dc0f4e9bb03f3250dc389396f903c2e52d1ab18caa31dd3c77b3f1e"
   strings:
      $s1 = "HtEHt7" fullword ascii /* Goodware String - occured 1 times */
      $s2 = "t4SSVW" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "d:\\Projects\\WinRAR\\SFX\\build\\sfxrar32\\Release\\sfxrar.pdb" fullword ascii /* Goodware String - occured 3 times */
      $s4 = "YNANRC" fullword ascii /* Goodware String - occured 3 times */
      $s5 = "FAA;t$" fullword ascii /* Goodware String - occured 3 times */
      $s6 = "?vNj@_+" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of them )
      ) or ( all of them )
}

rule _0049_0048_23 {
   meta:
      description = "mw2 - from files 0049, 0048"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "65388a54cf48711223df906330f55713b40a0d648aec48c615bec3bd706e05b3"
      hash2 = "3d94b17f929921cd7b3b42308fc54c6e26e277fe8b8d1d468be49f19fbc1ed36"
   strings:
      $s1 = "oftware" fullword ascii
      $s2 = "TAlignme2" fullword ascii
      $s3 = "IONQidE?" fullword ascii
      $s4 = "cipher_?" fullword ascii
      $s5 = "+MEDIUMLOW" fullword ascii
      $s6 = "clMaroonG" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "6gSilver" fullword ascii
      $s8 = "SyncObj" fullword ascii /* Goodware String - occured 2 times */
      $s9 = "`}EwLX" fullword ascii
      $s10 = "c_MACW" fullword ascii
      $s11 = "{p_#lb" fullword ascii
      $s12 = "*-&*$Q" fullword ascii
      $s13 = "ALL:!ADH:RC4+RSA:+HIG" fullword ascii
      $s14 = "pe! 0V" fullword ascii
      $s15 = "TURKISH" fullword ascii /* Goodware String - occured 4 times */
      $s16 = "CNE\"BIG5" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0033_0014_0034_0032_0047_24 {
   meta:
      description = "mw2 - from files 0033, 0014, 0034, 0032, 0047"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "647c2e386f270092390c1efa98f3eb320b182dd1f6cda5b5307924fc1f7b3bc6"
      hash2 = "5ab6cfc47da27138ca0fa1e399e5ae3b1f860f3cdbd6e78cf47bc3e9946d8143"
      hash3 = "3376cb405d573a0c973115d2b4e81c85e6b822fe47c6c5ab8f2a8eb94640cb51"
      hash4 = "b574e269d3fe13c8a7157cf9aa423c330cd0d9fa54cc8bc95077138f48d52115"
      hash5 = "9f517ead2d84de2d66326e35f2022df1d041258b3ffb2a69c5b39bc895b69aa4"
   strings:
      $s1 = "Unknown GIF block type'Object type not supported for operation" fullword wide
      $s2 = "Circular decoder table entry" fullword wide
      $s3 = "Invalid stream operation" fullword wide
      $s4 = "Decoder bit buffer under-run" fullword wide
      $s5 = "Unsupported PixelFormat" fullword wide
      $s6 = "Color not in color table" fullword wide
      $s7 = "Color table is empty" fullword wide
      $s8 = "Invalid pixel coordinates" fullword wide
      $s9 = "Premature end of data" fullword wide
      $s10 = "Color table overflow" fullword wide
      $s11 = "Unknown extension type" fullword wide
      $s12 = "Invalid image dimensions" fullword wide /* Goodware String - occured 2 times */
      $s13 = "Image has no DIB" fullword wide /* Goodware String - occured 2 times */
      $s14 = "GIF Image" fullword wide /* Goodware String - occured 2 times */
      $s15 = "Invalid extension introducer%Failed to allocate memory for GIF DIB" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0033_0032_25 {
   meta:
      description = "mw2 - from files 0033, 0032"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "647c2e386f270092390c1efa98f3eb320b182dd1f6cda5b5307924fc1f7b3bc6"
      hash2 = "b574e269d3fe13c8a7157cf9aa423c330cd0d9fa54cc8bc95077138f48d52115"
   strings:
      $s1 = "9SandHbG" fullword ascii
      $s2 = "`\"hDpx" fullword ascii
      $s3 = "f@GAqc" fullword ascii
      $s4 = "+AhD2$" fullword ascii
      $s5 = "DThumb" fullword ascii
      $s6 = "p]rQxW" fullword ascii
      $s7 = "!/d2,5" fullword ascii
      $s8 = "5m:B?K" fullword ascii
      $s9 = ".M)[i9e" fullword ascii
      $s10 = "<\"=*.2" fullword ascii
      $s11 = "}45(X2" fullword ascii
      $s12 = "v7[N|R" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0023_0040_26 {
   meta:
      description = "mw2 - from files 0023, 0040"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "24030137d3bf55a81b687bc3df719a8c5708e35fb1232eec94ae5b9ae59b2370"
      hash2 = "aca7e7293ef4e14ec245e983ccb1ed6b03a45da29dd50a80c0f0af5cd070ff89"
   strings:
      $s1 = "NativeK" fullword ascii
      $s2 = "Object&" fullword ascii
      $s3 = "2$876$0$" fullword ascii
      $s4 = "r;iNlp" fullword ascii
      $s5 = "1F3J43" fullword ascii
      $s6 = "W\\Jx fX" fullword ascii
      $s7 = "]uH;@ 1" fullword ascii
      $s8 = "+leepU" fullword ascii
      $s9 = "rfaceE" fullword ascii
      $s10 = "^SFfc[D" fullword ascii
      $s11 = "W0AnAS" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0023_0015_27 {
   meta:
      description = "mw2 - from files 0023, 0015"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "24030137d3bf55a81b687bc3df719a8c5708e35fb1232eec94ae5b9ae59b2370"
      hash2 = "841092ccfe4b8bb70e9730337b2183b9eef75fda78e9aa751a08ac6b49e9ba9a"
   strings:
      $s1 = "&Unkn@&d" fullword ascii
      $s2 = "B.dsss+dH" fullword ascii
      $s3 = "GESTURE" fullword ascii /* Goodware String - occured 2 times */
      $s4 = "AAddzs" fullword ascii
      $s5 = "AssB&9" fullword ascii
      $s6 = "GBNujh" fullword ascii
      $s7 = "4!/xX$" fullword ascii
      $s8 = "%_P`Rj" fullword ascii
      $s9 = "No1Sup" fullword ascii
      $s10 = "R0R*_0" fullword ascii
      $s11 = "cs!tf-7" fullword ascii
      $s12 = "5-jX-T" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0034_0035_28 {
   meta:
      description = "mw2 - from files 0034, 0035"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "3376cb405d573a0c973115d2b4e81c85e6b822fe47c6c5ab8f2a8eb94640cb51"
      hash2 = "ebcab6813d469b4e62670da56cbb8b9b5defcffd248ca8dd9e21eb73ccd2cdf3"
   strings:
      $s1 = "$Parent given is not a parent of '%s'" fullword wide
      $s2 = "AAutho" fullword ascii
      $s3 = "9abcdefg" fullword ascii
      $s4 = "Ve:9*PD" fullword ascii
      $s5 = "AZh!2%" fullword ascii
      $s6 = "C\"KDS[" fullword ascii
      $s7 = " U5678" fullword ascii
      $s8 = "HWj!}+" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( all of them )
      ) or ( all of them )
}

rule _0023_0008_29 {
   meta:
      description = "mw2 - from files 0023, 0008"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "24030137d3bf55a81b687bc3df719a8c5708e35fb1232eec94ae5b9ae59b2370"
      hash2 = "6ccb58c0ce4e1880c9e38d76a1bacfff14cedfeb77888fd5dfd88c4eb353596f"
   strings:
      $s1 = "'L3'L3'>" fullword ascii /* Goodware String - occured 1 times */
      $s2 = "]vL'L'M'" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "0lp3DKs" fullword ascii
      $s4 = "?&;B4u" fullword ascii
      $s5 = "?afOD)" fullword ascii
      $s6 = "?'4\"\"C['B{" fullword ascii
      $s7 = "9;w|t4" fullword ascii
      $s8 = "9CQwclA" fullword ascii
      $s9 = "P:8bi(dl" fullword ascii
      $s10 = "F&rP'H" fullword ascii
      $s11 = "kL*y8Z?yvJw" fullword ascii
      $s12 = "\"Q[Q&B\"Q" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0015_0040_30 {
   meta:
      description = "mw2 - from files 0015, 0040"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "841092ccfe4b8bb70e9730337b2183b9eef75fda78e9aa751a08ac6b49e9ba9a"
      hash2 = "aca7e7293ef4e14ec245e983ccb1ed6b03a45da29dd50a80c0f0af5cd070ff89"
   strings:
      $s1 = "70Decma@4" fullword ascii
      $s2 = "    version=\"15.0.3890.34076\" " fullword ascii
      $s3 = "qYV~W~" fullword ascii
      $s4 = "Ov.flow" fullword ascii
      $s5 = "8yN\\PQ" fullword ascii
      $s6 = "0lsid[@" fullword ascii
      $s7 = ":H<J>L?$" fullword ascii
      $s8 = "ssViol" fullword ascii
      $s9 = "i8-r4h(" fullword ascii
      $s10 = "{u]wW-" fullword ascii
      $s11 = "dOpL[l" fullword ascii
      $s12 = "__CRITICA" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0029_0009_0015_0030_0049_0008_0047_0040_0017_31 {
   meta:
      description = "mw2 - from files 0029, 0009, 0015, 0030, 0049, 0008, 0047, 0040, 0017"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "82d26413b29b568df08bf5df6db4e8447b351ec517edab8351a347c722df29b6"
      hash2 = "0f982b0dc7055db642ebf7bbdaf23d14285c99119ca271381680282f13695307"
      hash3 = "841092ccfe4b8bb70e9730337b2183b9eef75fda78e9aa751a08ac6b49e9ba9a"
      hash4 = "20277950c8fc3612b7f46a7c44d99150b3cb1b53f4f949a789cb873ebba14ffa"
      hash5 = "65388a54cf48711223df906330f55713b40a0d648aec48c615bec3bd706e05b3"
      hash6 = "6ccb58c0ce4e1880c9e38d76a1bacfff14cedfeb77888fd5dfd88c4eb353596f"
      hash7 = "9f517ead2d84de2d66326e35f2022df1d041258b3ffb2a69c5b39bc895b69aa4"
      hash8 = "aca7e7293ef4e14ec245e983ccb1ed6b03a45da29dd50a80c0f0af5cd070ff89"
      hash9 = "60611b5f82ae9253f092dc2160858e1b5a4440c384833598c0143ef59376b102"
   strings:
      $s1 = "        processorArchitecture=\"*\"/>" fullword ascii /* Goodware String - occured 1 times */
      $s2 = "        name=\"Microsoft.Windows.Common-Controls\"" fullword ascii /* Goodware String - occured 3 times */
      $s3 = "        publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* Goodware String - occured 3 times */
      $s4 = "        version=\"6.0.0.0\"" fullword ascii /* Goodware String - occured 3 times */
      $s5 = "        language=\"*\"" fullword ascii /* Goodware String - occured 3 times */
      $s6 = "        type=\"win32\"" fullword ascii /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( all of them )
      ) or ( all of them )
}

rule _0033_0034_0032_0047_32 {
   meta:
      description = "mw2 - from files 0033, 0034, 0032, 0047"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "647c2e386f270092390c1efa98f3eb320b182dd1f6cda5b5307924fc1f7b3bc6"
      hash2 = "3376cb405d573a0c973115d2b4e81c85e6b822fe47c6c5ab8f2a8eb94640cb51"
      hash3 = "b574e269d3fe13c8a7157cf9aa423c330cd0d9fa54cc8bc95077138f48d52115"
      hash4 = "9f517ead2d84de2d66326e35f2022df1d041258b3ffb2a69c5b39bc895b69aa4"
   strings:
      $s1 = "Unsupported GIF version" fullword wide
      $s2 = "Image is empty" fullword wide
      $s3 = "Invalid reduction method" fullword wide
      $s4 = "Converting..." fullword wide /* Goodware String - occured 1 times */
      $s5 = "Invalid color index" fullword wide
      $s6 = "Saving..." fullword wide /* Goodware String - occured 2 times */
      $s7 = "Thread Error: %s (%d)" fullword wide /* Goodware String - occured 2 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and ( all of them )
      ) or ( all of them )
}

rule _0016_0017_33 {
   meta:
      description = "mw2 - from files 0016, 0017"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "e729206807ab2f2fe8d29cd383480aeba9abf94ae70b906c83efccab3d7ec6a8"
      hash2 = "60611b5f82ae9253f092dc2160858e1b5a4440c384833598c0143ef59376b102"
   strings:
      $s1 = "TAdxncP" fullword ascii
      $s2 = "6uxtheme" fullword ascii
      $s3 = "0r=<9w9i" fullword ascii /* Goodware String - occured 1 times */
      $s4 = "IYsAdap" fullword ascii
      $s5 = "EASTROPE" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "!CotK" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "'127.0" fullword ascii
      $s8 = "fv0idOp" fullword ascii
      $s9 = "HH\":\"NN" fullword ascii
      $s10 = ">81/:7" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( all of them )
      ) or ( all of them )
}

rule _0010_0002_0005_0004_0036_34 {
   meta:
      description = "mw2 - from files 0010, 0002, 0005, 0004, 0036"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "359b33bd0c718a1146ef4b38a030ed9a1ccafd2a7107d7843d7db39abd6db1f7"
      hash2 = "cc619840bf98f3358c6d8630ad4537f74407a8802904abe24466256a6eb8749f"
      hash3 = "ab1bcce559649d9cacedcf97268285c85bacb1cbc8942cc8e59455847acc6f05"
      hash4 = "a4f6a571c284d6bc70a48c56ef9443514733dab974601365e013ad1347d1bafc"
      hash5 = "680f18f5ee3dec9b02608507d746ad3ecb17bab18f43f544582d79c6828a1666"
   strings:
      $s1 = "Form18" fullword ascii
      $s2 = "Form23" fullword ascii
      $s3 = "Form20" fullword ascii
      $s4 = "Form16" fullword ascii
      $s5 = "Form17" fullword ascii
      $s6 = "Form22" fullword ascii
      $s7 = "Form25" fullword ascii
      $s8 = "Form21" fullword ascii
      $s9 = "Form19" fullword ascii
      $s10 = "Form15" fullword ascii
      $s11 = "Form24" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0004_0001_35 {
   meta:
      description = "mw2 - from files 0004, 0001"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "a4f6a571c284d6bc70a48c56ef9443514733dab974601365e013ad1347d1bafc"
      hash2 = "845dd985872b15fa3705df8ae1897eea1315f322a648085671a0959a9573d3cb"
   strings:
      $s1 = "Module6" fullword ascii
      $s2 = "Module5" fullword ascii
      $s3 = "Module7" fullword ascii
      $s4 = "Module4" fullword ascii
      $s5 = "Module3" fullword ascii
      $s6 = "Module2" fullword ascii
      $s7 = "IsetKs" fullword ascii
      $s8 = "Js0jKs" fullword ascii
      $s9 = "KsfzKs" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and ( all of them )
      ) or ( all of them )
}

rule _0026_0037_0024_36 {
   meta:
      description = "mw2 - from files 0026, 0037, 0024"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "eb14af82d15b86f13e6ec395006269ad3d8d278689c91da3bf9df95e122da994"
      hash2 = "0e94798f078d038cd595d183322f53e9f7d37f55078c58910d7cbfb28024cde0"
      hash3 = "a96c642b0e19c116f4382cf7f923187167f0f64486325e8cc8f9405c5c69edcb"
   strings:
      $s1 = "  <description>FrameForge 3D Studio 2</description> " fullword ascii
      $s2 = "        <requestedExecutionLevel " fullword ascii
      $s3 = "  <assemblyIdentity version=\"1.0.0.0\"" fullword ascii
      $s4 = "     processorArchitecture=\"X86\"" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "     type=\"win32\"/> " fullword ascii /* Goodware String - occured 1 times */
      $s6 = "          level=\"requireAdministrator\"" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "  <!-- Identify the application security requirements. -->" fullword ascii /* Goodware String - occured 2 times */
      $s8 = "     name=\"FrameForge 3D Studio 2\"" fullword ascii
      $s9 = "       </security>" fullword ascii /* Goodware String - occured 3 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( all of them )
      ) or ( all of them )
}

rule _0019_0011_37 {
   meta:
      description = "mw2 - from files 0019, 0011"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "2bb986ebe4e6e02e607d26cd5f194669597149e3f69c018ec11e7fcd4aafdfca"
      hash2 = "b3269ba67a9054884a12f1738e26a36be2a8d7a7fb7ef1bf60ac3dbfbf5eedc2"
   strings:
      $s1 = "start.exe" fullword ascii
      $s2 = "u&;vmcBL" fullword ascii
      $s3 = "@\"8n$U" fullword ascii
      $s4 = "=I,rX%" fullword ascii
      $s5 = "jVi-8|w" fullword ascii
      $s6 = "Jrs!Rl" fullword ascii
      $s7 = "mY):IF3*k4" fullword ascii
      $s8 = "e]W*2%" fullword ascii
      $s9 = "A-uYViY" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "9402b48d966c911f0785b076b349b5ef" and ( all of them )
      ) or ( all of them )
}

rule _0023_0015_0040_38 {
   meta:
      description = "mw2 - from files 0023, 0015, 0040"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "24030137d3bf55a81b687bc3df719a8c5708e35fb1232eec94ae5b9ae59b2370"
      hash2 = "841092ccfe4b8bb70e9730337b2183b9eef75fda78e9aa751a08ac6b49e9ba9a"
      hash3 = "aca7e7293ef4e14ec245e983ccb1ed6b03a45da29dd50a80c0f0af5cd070ff89"
   strings:
      $s1 = "CurrHcy" fullword ascii
      $s2 = "Ctl3DK" fullword ascii
      $s3 = "?87,[[" fullword ascii
      $s4 = "`f2]ML" fullword ascii
      $s5 = "$u:yAtt" fullword ascii
      $s6 = "so.859-1" fullword ascii
      $s7 = ",egerf" fullword ascii
      $s8 = "Xn\"bge" fullword ascii
      $s9 = "ShortI" fullword ascii
      $s10 = "L/G?:_G" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( all of them )
      ) or ( all of them )
}

rule _0034_0032_0035_39 {
   meta:
      description = "mw2 - from files 0034, 0032, 0035"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "3376cb405d573a0c973115d2b4e81c85e6b822fe47c6c5ab8f2a8eb94640cb51"
      hash2 = "b574e269d3fe13c8a7157cf9aa423c330cd0d9fa54cc8bc95077138f48d52115"
      hash3 = "ebcab6813d469b4e62670da56cbb8b9b5defcffd248ca8dd9e21eb73ccd2cdf3"
   strings:
      $s1 = "Cannot open clipboard/Menu '%s' is already being used by another formDocked control must have a name%Error removing control fro" wide /* Goodware String - occured 1 times */
      $s2 = "Scan line index out of range!Cannot change the size of an icon" fullword wide /* Goodware String - occured 3 times */
      $s3 = "aG-tb\"&9c" fullword ascii
      $s4 = " \"-D:G" fullword ascii
      $s5 = "'_h#%Hy" fullword ascii
      $s6 = "I!q@`c" fullword ascii
      $s7 = "7@D&?#&" fullword ascii
      $s8 = ">\\N<$FO" fullword ascii
      $s9 = "Unable to insert a line" fullword wide /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( all of them )
      ) or ( all of them )
}

rule _0049_0017_40 {
   meta:
      description = "mw2 - from files 0049, 0017"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "65388a54cf48711223df906330f55713b40a0d648aec48c615bec3bd706e05b3"
      hash2 = "60611b5f82ae9253f092dc2160858e1b5a4440c384833598c0143ef59376b102"
   strings:
      $s1 = "cPtr%.8X" fullword ascii
      $s2 = "D/BtnFU" fullword ascii
      $s3 = "x@\\\\VN" fullword ascii
      $s4 = "NovDec" fullword ascii
      $s5 = ":;P |@" fullword ascii
      $s6 = "__\"FD&" fullword ascii
      $s7 = "TDa0TimX" fullword ascii
      $s8 = "qYV~Wdv" fullword ascii
      $s9 = "t:@;>|" fullword ascii
      $s10 = "?foBh'" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( all of them )
      ) or ( all of them )
}

rule _0005_0001_41 {
   meta:
      description = "mw2 - from files 0005, 0001"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "ab1bcce559649d9cacedcf97268285c85bacb1cbc8942cc8e59455847acc6f05"
      hash2 = "845dd985872b15fa3705df8ae1897eea1315f322a648085671a0959a9573d3cb"
   strings:
      $s1 = "7E7E7D7C6C6269636574796E70464447545F44725F5E45435B5E60564269625442475953544268615B52445055705352554342" wide /* hex encoded string '~~}|lbicetynpFDGT_Dr_^EC[^`VBibTBGYSTBha[RDPUpSRUCB' */
      $s2 = "7E7E7D7C6C6269636574796E70464447545F44725F5E45435B5E605642696254424759535442684546524346544346" wide /* hex encoded string '~~}|lbicetynpFDGT_Dr_^EC[^`VBibTBGYSTBhEFRCFTCF' */
      $s3 = "7E7E7D7C6C6269636574796E70464447545F44725F5E45435B5E60564269625442475953544268454050454352" wide /* hex encoded string '~~}|lbicetynpFDGT_Dr_^EC[^`VBibTBGYSTBhE@PECR' */
      $s4 = "5558551F554955101E52145C56471646455E4011" wide
      $s5 = "5558551F554955101E52145C56471646455E4011635850435156725055504242" wide
      $s6 = "161A47116345514245111B46136173726E75677E6274111E5012034B02151E57" wide
      $s7 = "65505244425844491172515C475644" wide
      $s8 = "4450561151555410" wide
      $s9 = "5558551F554955101E52144056541654555510" wide
      $s10 = "Adjunto" fullword wide /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and ( all of them )
      ) or ( all of them )
}

rule _0033_0035_42 {
   meta:
      description = "mw2 - from files 0033, 0035"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "647c2e386f270092390c1efa98f3eb320b182dd1f6cda5b5307924fc1f7b3bc6"
      hash2 = "ebcab6813d469b4e62670da56cbb8b9b5defcffd248ca8dd9e21eb73ccd2cdf3"
   strings:
      $s1 = "RunP!i|" fullword ascii
      $s2 = "ex obj" fullword ascii
      $s3 = "F\"VDhv" fullword ascii
      $s4 = ")P,i$0" fullword ascii
      $s5 = "B5/6voE" fullword ascii
      $s6 = "3\"HD]r" fullword ascii
      $s7 = "j2R<PG,h6" fullword ascii
      $s8 = "c%DV~3ESD" fullword ascii
      $s9 = "b,3a!&t&" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and ( all of them )
      ) or ( all of them )
}

rule _0016_0006_43 {
   meta:
      description = "mw2 - from files 0016, 0006"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "e729206807ab2f2fe8d29cd383480aeba9abf94ae70b906c83efccab3d7ec6a8"
      hash2 = "6dc1fa915a128a24ece4d46ed2c47eae26f9628d25ce8dfbc77cfe5006cb08a8"
   strings:
      $s1 = "WoSv -" fullword ascii
      $s2 = "IDlgR3" fullword ascii
      $s3 = "kernel32." fullword ascii /* Goodware String - occured 3 times */
      $s4 = "6ISPLAY" fullword ascii
      $s5 = "{;w$t|Q" fullword ascii
      $s6 = "urmn/_" fullword ascii
      $s7 = "ORT_(_" fullword ascii
      $s8 = "HDF&rP6z" fullword ascii
      $s9 = "CWE'Up" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and ( all of them )
      ) or ( all of them )
}

rule _0010_0002_0005_0004_0036_0001_44 {
   meta:
      description = "mw2 - from files 0010, 0002, 0005, 0004, 0036, 0001"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "359b33bd0c718a1146ef4b38a030ed9a1ccafd2a7107d7843d7db39abd6db1f7"
      hash2 = "cc619840bf98f3358c6d8630ad4537f74407a8802904abe24466256a6eb8749f"
      hash3 = "ab1bcce559649d9cacedcf97268285c85bacb1cbc8942cc8e59455847acc6f05"
      hash4 = "a4f6a571c284d6bc70a48c56ef9443514733dab974601365e013ad1347d1bafc"
      hash5 = "680f18f5ee3dec9b02608507d746ad3ecb17bab18f43f544582d79c6828a1666"
      hash6 = "845dd985872b15fa3705df8ae1897eea1315f322a648085671a0959a9573d3cb"
   strings:
      $s1 = "KsDRJsk" fullword ascii
      $s2 = "Form14" fullword ascii
      $s3 = "Form13" fullword ascii
      $s4 = "Form11" fullword ascii
      $s5 = "Form12" fullword ascii
      $s6 = "Form10" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and ( all of them )
      ) or ( all of them )
}

rule _0014_0002_0047_0036_45 {
   meta:
      description = "mw2 - from files 0014, 0002, 0047, 0036"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "5ab6cfc47da27138ca0fa1e399e5ae3b1f860f3cdbd6e78cf47bc3e9946d8143"
      hash2 = "cc619840bf98f3358c6d8630ad4537f74407a8802904abe24466256a6eb8749f"
      hash3 = "9f517ead2d84de2d66326e35f2022df1d041258b3ffb2a69c5b39bc895b69aa4"
      hash4 = "680f18f5ee3dec9b02608507d746ad3ecb17bab18f43f544582d79c6828a1666"
   strings:
      $s1 = "Label16" fullword ascii /* Goodware String - occured 2 times */
      $s2 = "Label13" fullword ascii /* Goodware String - occured 2 times */
      $s3 = "Label12" fullword ascii /* Goodware String - occured 2 times */
      $s4 = "Label9" fullword ascii /* Goodware String - occured 3 times */
      $s5 = "Image5" fullword ascii /* Goodware String - occured 3 times */
      $s6 = "Image3" fullword ascii /* Goodware String - occured 4 times */
      $s7 = "Image2" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( all of them )
      ) or ( all of them )
}

rule _0002_0047_0036_46 {
   meta:
      description = "mw2 - from files 0002, 0047, 0036"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "cc619840bf98f3358c6d8630ad4537f74407a8802904abe24466256a6eb8749f"
      hash2 = "9f517ead2d84de2d66326e35f2022df1d041258b3ffb2a69c5b39bc895b69aa4"
      hash3 = "680f18f5ee3dec9b02608507d746ad3ecb17bab18f43f544582d79c6828a1666"
   strings:
      $s1 = "Label17" fullword ascii /* Goodware String - occured 1 times */
      $s2 = "Label20" fullword ascii /* Goodware String - occured 2 times */
      $s3 = "Label19" fullword ascii /* Goodware String - occured 2 times */
      $s4 = "Label18" fullword ascii /* Goodware String - occured 2 times */
      $s5 = "Label11" fullword ascii /* Goodware String - occured 3 times */
      $s6 = "Label10" fullword ascii /* Goodware String - occured 4 times */
      $s7 = "Label8" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( all of them )
      ) or ( all of them )
}

rule _0008_0040_47 {
   meta:
      description = "mw2 - from files 0008, 0040"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "6ccb58c0ce4e1880c9e38d76a1bacfff14cedfeb77888fd5dfd88c4eb353596f"
      hash2 = "aca7e7293ef4e14ec245e983ccb1ed6b03a45da29dd50a80c0f0af5cd070ff89"
   strings:
      $s1 = ";GASN1_OBJEV" fullword ascii
      $s2 = "GBNujh#" fullword ascii
      $s3 = "TQfUC4p" fullword ascii
      $s4 = "02Q283" fullword ascii
      $s5 = "%DB *J(" fullword ascii
      $s6 = "e+RC4:@" fullword ascii
      $s7 = "vGlyph" fullword ascii
      $s8 = "?3to4_" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( all of them )
      ) or ( all of them )
}

rule _0015_0008_48 {
   meta:
      description = "mw2 - from files 0015, 0008"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "841092ccfe4b8bb70e9730337b2183b9eef75fda78e9aa751a08ac6b49e9ba9a"
      hash2 = "6ccb58c0ce4e1880c9e38d76a1bacfff14cedfeb77888fd5dfd88c4eb353596f"
   strings:
      $s1 = "]%O6{@" fullword ascii
      $s2 = "oQ `.i" fullword ascii
      $s3 = "<mwaYk" fullword ascii
      $s4 = "D*F>UbT[" fullword ascii
      $s5 = "Xor_Cmp4" fullword ascii
      $s6 = "+ZSMDI" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( all of them )
      ) or ( all of them )
}

rule _0049_0006_49 {
   meta:
      description = "mw2 - from files 0049, 0006"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "65388a54cf48711223df906330f55713b40a0d648aec48c615bec3bd706e05b3"
      hash2 = "6dc1fa915a128a24ece4d46ed2c47eae26f9628d25ce8dfbc77cfe5006cb08a8"
   strings:
      $s1 = "C/BALT" fullword ascii
      $s2 = "^lHz;~" fullword ascii
      $s3 = ".FDiag" fullword ascii
      $s4 = "2C(\"Ds8" fullword ascii
      $s5 = "'2 tN!!" fullword ascii
      $s6 = "1PixTsP" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _0048_0017_50 {
   meta:
      description = "mw2 - from files 0048, 0017"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "3d94b17f929921cd7b3b42308fc54c6e26e277fe8b8d1d468be49f19fbc1ed36"
      hash2 = "60611b5f82ae9253f092dc2160858e1b5a4440c384833598c0143ef59376b102"
   strings:
      $s1 = "EOutOfMemjy" fullword ascii
      $s2 = "TTLExpir" fullword ascii
      $s3 = "vDGH'Ld" fullword ascii
      $s4 = "0;BR$-" fullword ascii
      $s5 = "*ql=dBNLL" fullword ascii
      $s6 = "+WH+\\#" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( all of them )
      ) or ( all of them )
}

rule _0040_0017_51 {
   meta:
      description = "mw2 - from files 0040, 0017"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "aca7e7293ef4e14ec245e983ccb1ed6b03a45da29dd50a80c0f0af5cd070ff89"
      hash2 = "60611b5f82ae9253f092dc2160858e1b5a4440c384833598c0143ef59376b102"
   strings:
      $s1 = "H*0\"DW" fullword ascii
      $s2 = "F,T;s$|" fullword ascii
      $s3 = "t&Cl6;" fullword ascii
      $s4 = "A7T]O@6" fullword ascii
      $s5 = "$ij8VdI" fullword ascii
      $s6 = "PsU?o4" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( all of them )
      ) or ( all of them )
}

rule _0016_0048_52 {
   meta:
      description = "mw2 - from files 0016, 0048"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "e729206807ab2f2fe8d29cd383480aeba9abf94ae70b906c83efccab3d7ec6a8"
      hash2 = "3d94b17f929921cd7b3b42308fc54c6e26e277fe8b8d1d468be49f19fbc1ed36"
   strings:
      $s1 = "FuchsiaAqua" fullword ascii
      $s2 = " %0.2d" fullword ascii
      $s3 = "#'VKQ=" fullword ascii
      $s4 = "C~(O`=" fullword ascii
      $s5 = "EK2S@F" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of them )
      ) or ( all of them )
}

rule _0023_0015_0008_0040_53 {
   meta:
      description = "mw2 - from files 0023, 0015, 0008, 0040"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "24030137d3bf55a81b687bc3df719a8c5708e35fb1232eec94ae5b9ae59b2370"
      hash2 = "841092ccfe4b8bb70e9730337b2183b9eef75fda78e9aa751a08ac6b49e9ba9a"
      hash3 = "6ccb58c0ce4e1880c9e38d76a1bacfff14cedfeb77888fd5dfd88c4eb353596f"
      hash4 = "aca7e7293ef4e14ec245e983ccb1ed6b03a45da29dd50a80c0f0af5cd070ff89"
   strings:
      $s1 = "ptionr" fullword ascii
      $s2 = "WMPhoto" fullword ascii
      $s3 = "FAcqui" fullword ascii
      $s4 = "ds`DE," fullword ascii
      $s5 = "TAl~nm>" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( all of them )
      ) or ( all of them )
}

rule _0017_0006_54 {
   meta:
      description = "mw2 - from files 0017, 0006"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "60611b5f82ae9253f092dc2160858e1b5a4440c384833598c0143ef59376b102"
      hash2 = "6dc1fa915a128a24ece4d46ed2c47eae26f9628d25ce8dfbc77cfe5006cb08a8"
   strings:
      $s1 = "SYMBOLc" fullword ascii
      $s2 = "LIENT?" fullword ascii
      $s3 = "Rebuil" fullword ascii
      $s4 = "TdUx(k" fullword ascii
      $s5 = "0$_PXR" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( all of them )
      ) or ( all of them )
}

