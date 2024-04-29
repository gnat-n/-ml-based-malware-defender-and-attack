/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2024-04-17
   Identifier: mw6
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule _root_BytMe_new_datasets_mw6_017 {
   meta:
      description = "mw6 - file 017"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "deceb572b4fd9c2e2c964ea1a574082a7bb6cc3952ad0c2eaeabe64f20d706fe"
   strings:
      $s1 = "C:\\vowixokixa.pdb" fullword ascii
      $s2 = "server\\runtime\\crypt\\tmp_787681175\\bin\\bimazehoye.pdb" fullword ascii
      $s3 = "ZipaxaBetelaluwa dobosasowav kuhavo bibuyahobu kilegodasula hufihu zozo vavexugadita jawobipepariti kizdDeyo jewigumolebew yuneb" wide
      $s4 = "ACodesoheturoxuk huva sisilijox zututuvi kiyutuputewi zurimazatahiNYivojukowosu monaxedevila zax waki vokidaf zayagehasiz vopiwo" wide
      $s5 = "bSituwizakitan kujusojigufobik wizoza numu covegecurexu hiti lolayosobo jukuvu xobofa xoyizewesebem$Fopexohikija cufuvemi waroge" wide
      $s6 = "nenosuvaraxuhibibaramirifo" fullword wide
      $s7 = "1.0.2.18" fullword wide
      $s8 = "1.5.28.29" fullword wide
      $s9 = "Gupahef" fullword wide
      $s10 = "Broken pipe" fullword ascii /* Goodware String - occured 749 times */
      $s11 = "Permission denied" fullword ascii /* Goodware String - occured 830 times */
      $s12 = " %s %d %f" fullword ascii
      $s13 = "SOqn,7'^" fullword ascii
      $s14 = "qpfnP_n._" fullword ascii
      $s15 = "ZjyiF\"" fullword ascii
      $s16 = "nFyU;C," fullword ascii
      $s17 = "WertualBridecd" fullword ascii
      $s18 = "FhDdo??" fullword ascii
      $s19 = "msjw6\"X" fullword ascii
      $s20 = "lJJOIwZ" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw6_011 {
   meta:
      description = "mw6 - file 011"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "4b6f69b3ade95902351f28e2862234569b3ddd1166b1e936441b530524a32c33"
   strings:
      $s1 = "tocuy.exe" fullword ascii
      $s2 = "7.0.21.21" fullword wide /* hex encoded string 'p!!' */
      $s3 = "MNusijodaduz zigahefu telapilewuseh kutu kebodutelabofog lacegeyeril wude life" fullword wide
      $s4 = "vufasapeyodekuhikep" fullword wide
      $s5 = "galimatimod" fullword wide
      $s6 = "ProductVersions" fullword wide
      $s7 = "=%i,Fp" fullword ascii
      $s8 = "Gorgeous" fullword ascii
      $s9 = "7.0.2.54" fullword wide
      $s10 = "- {qS{a" fullword ascii
      $s11 = "\\YNizCC^r" fullword ascii
      $s12 = "66%6E6|6" fullword ascii /* hex encoded string 'fnf' */
      $s13 = "0 %s %d %f" fullword ascii
      $s14 = "FBAE<}l" fullword ascii
      $s15 = "PaKs|p3ul" fullword ascii
      $s16 = "WkSd_`Y" fullword ascii
      $s17 = "JCyp[>y(" fullword ascii
      $s18 = "brWn*?R" fullword ascii
      $s19 = "]xEnb>z?u" fullword ascii
      $s20 = "PNWf/Md" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw6_001 {
   meta:
      description = "mw6 - file 001"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "dd3f4329365ca4f289bcaf6acdf96919271500ea44e5513519cc53b079df8762"
   strings:
      $s1 = "C:\\mafipuxo_fovosizecozidabo dakoc.pdb" fullword ascii
      $s2 = "tmp_2125291370\\bin\\nisifem.pdb" fullword ascii
      $s3 = "\"Lokadodezusuge vonimenodotasaz pan\"Lufobavohu zesufibeki yicihosasujeLGetumik vanozecub ceru panogozor hob dacohivozalofo bah" wide
      $s4 = "sekuheniwikahedesimemacovoc" fullword wide
      $s5 = "1.0.2.18" fullword wide
      $s6 = "1.6.28.29" fullword wide
      $s7 = "Gisicopayitivot" fullword wide
      $s8 = "Gazugasuzola" fullword wide
      $s9 = "Kukiwalujez" fullword wide
      $s10 = "Kizidetakogir" fullword wide
      $s11 = "XHfyXE0" fullword ascii
      $s12 = "]ms62G" fullword ascii
      $s13 = " %s %d %f" fullword ascii
      $s14 = "FileVerus" fullword wide
      $s15 = "ProductVersys" fullword wide
      $s16 = "ALmT?u" fullword ascii
      $s17 = "2hUQKYu&" fullword ascii
      $s18 = "WipdualBriclsk" fullword ascii
      $s19 = "xE&TQILZ\"S" fullword ascii
      $s20 = "Tjqfl-&i{" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw6_008 {
   meta:
      description = "mw6 - file 008"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "7c902b5da243bec90b83e4d68e4e8c097d1e36e9d9508c5095023f801440d977"
   strings:
      $s1 = "Bacepisaxu vadeyafeb hahekefabofo. Rijohol culisikirajo niyadeto poyurugenopa zutej. Pegazularac suwexifucunoz. Remekibeno wonuf" ascii
      $s2 = "apesodugu ruve macoje. Riwo tanezi deyosidopa kudekeyelomacuy vikutaj. Comuvaduzet fad fuxodoki. Xonapejoh girenahinuy gufenimew" ascii
      $s3 = "C:\\tojozakucakoni-mejipuxowoniwapuwed lesem45\\joja.pdb" fullword ascii
      $s4 = "n\\zofifon.pdb" fullword ascii
      $s5 = "4$4,42474=4" fullword ascii /* hex encoded string 'DBGD' */
      $s6 = "natikaloyabuyacololobu" fullword ascii
      $s7 = " pefucuserolifob cox. Fawaso giluyexad siyaboluwopuci tozikewoyan. We" fullword ascii
      $s8 = "XEYOHECURUGIYIV" fullword wide
      $s9 = "izuseveyili. Yajulasajanab negurugilo pifop paxufo. Lowazofuku pijutepamalane. Kato fegohilufanito duyovogas. Cohohitakex pumel " ascii
      $s10 = "[IrCN^?" fullword ascii
      $s11 = "yatalejakusi. Loyu pawovikokoxojun soyimaniwa nazasufumotu coxuvegopupayi. Conumufiduhodo vip. Gijubudub juroy xarefo hahidonisu" ascii
      $s12 = "1.0.2.27" fullword wide
      $s13 = "1.5.8.28" fullword wide
      $s14 = "Gujelowa" fullword wide
      $s15 = "rH+ /{G" fullword ascii
      $s16 = "%w%Bm3" fullword ascii
      $s17 = "qtB -4" fullword ascii
      $s18 = "FileVerus" fullword wide
      $s19 = "ProductVersus" fullword wide
      $s20 = "onesac mezelu. Nogijanot hotijasu fog wet. Kuhez heti. Perutonofavagi tilulugedox hudineduxokuw. Fasukerigubu figixuvexita. Box " ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw6_009 {
   meta:
      description = "mw6 - file 009"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "c252253deb8ce68d6c44f555d2ce707f7581dc7267f5d6a892a626469691ef9f"
   strings:
      $s1 = "C:\\hucizumu.pdb" fullword ascii
      $s2 = "t_server\\runtime\\crypt\\tmp_242268859\\bin\\mifal.pdb" fullword ascii
      $s3 = "ZipaxaBetelaluwa dobosasowav kuhavo bibuyahobu kilegodasula hufihu zozo vavexugadita jawobipepariti kizdDeyo jewigumolebew yuneb" wide
      $s4 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"></assemblyIdentity>" fullword ascii
      $s5 = "ACodesoheturoxuk huva sisilijox zututuvi kiyutuputewi zurimazatahiNYivojukowosu monaxedevila zax waki vokidaf zayagehasiz vopiwo" wide
      $s6 = "bSituwizakitan kujusojigufobik wizoza numu covegecurexu hiti lolayosobo jukuvu xobofa xoyizewesebem$Fopexohikija cufuvemi waroge" wide
      $s7 = "nenosuvaraxuhibibaramirifo" fullword wide
      $s8 = "1.0.2.18" fullword wide
      $s9 = "1.5.28.29" fullword wide
      $s10 = "Gupahef" fullword wide
      $s11 = "TLuNjA0" fullword ascii
      $s12 = "Broken pipe" fullword ascii /* Goodware String - occured 749 times */
      $s13 = "Permission denied" fullword ascii /* Goodware String - occured 830 times */
      $s14 = " %s %d %f" fullword ascii
      $s15 = "WertualBridecd" fullword ascii
      $s16 = "Ajjjjjj" fullword wide /* Goodware String - occured 1 times */
      $s17 = "Ajjjjj" fullword wide /* Goodware String - occured 1 times */
      $s18 = "FileVerus" fullword wide
      $s19 = "ProductVersys" fullword wide
      $s20 = "Kalo fovihot" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw6_025 {
   meta:
      description = "mw6 - file 025"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "b055016e0d82c57b58cd126f26b4b8f4dae1441f0019bdaa42452e815f128944"
   strings:
      $s1 = "Xuhuvejex kerijame wodolilukenajid lijopes. Kupir woxuzo. Loveverifahusa sivuninojajef nahasixume. Labiguhakideji. Loxugecikebe " ascii
      $s2 = "C:\\lodeb.pdb" fullword ascii
      $s3 = "rypt_server\\runtime\\crypt\\tmp_342552664\\bin\\gizubuhebe.pdb" fullword ascii
      $s4 = "Xenonohasusad wewibobohetixi vusopofigotetu. Yafibivekucov tidunoyeyizo. Xufebera waxilukupiluxad hicicociy telerop. Febumegatil" ascii
      $s5 = " vahubanuk tacunaxigetukiw. Dedobugilolanoh. Bejeboloye teyenuvis xasuk kepiseho. Notufuluboweges mukihinot fazuyobub zebel luci" ascii
      $s6 = "Biyuhukiw jusivimeduse mafowehu. Kelacoyez. Xujoko. Xicufosek bizosopecosofob zekedoja. Tokimakacefeho pipidihayahedid gupuwojuf" ascii
      $s7 = "robewumomak. Liruvijuh zikowu pipecovuya. Divohoxes cupoxofudegawoj lakokasujamawi noko. Coyunakuw cowopayefayo. Buwosoxuko kipu" ascii
      $s8 = "ecumahiyel. Zapef raru kubino sepudakev. Vucu voyimunuvega tiburamutadigu hutiwexudikay nilo. Dunomegeyexo fimu xorosu yojigezez" ascii
      $s9 = "vareyof. Lifakel zoyogure cox yafuv. Yubufolixo jogexawamanuyo kaxamiyixafub. Hamimidibet zidebosafuj. Roxinaxikakox cucehesufih" ascii
      $s10 = "akiwa. Behilogule posun tubizehutivure vuhemujole. Tupacijibiva pewoyoxigutu hedijakavin bodenu gip. Yis fofidujebunoc. Nigonu b" ascii
      $s11 = "VekanunibeNofob budemuvuvag gukicehem widoweziyenajo dusaheyepefu zalenosovax pel vopohisufibijor wesicumerosir" fullword wide
      $s12 = "XEYOHECURUGIYIV" fullword wide
      $s13 = "TGGGGGGGGGGGGGGGGGGGGT" fullword ascii
      $s14 = "BIGAXUNA" fullword wide
      $s15 = "TEKIDIFIFOKOJAVIPEVEFEXUJEK" fullword wide
      $s16 = "WIPUZOHET" fullword wide
      $s17 = "1.0.2.27" fullword wide
      $s18 = "1.5.8.28" fullword wide
      $s19 = " Kisusoniga hojetira. Fipoyicikubuci joze hezewe vebadoxuhufawud. Tiromij tiwofa. Covexahekupe. Nisarod pawabe nasaf. Fuxozimu n" ascii
      $s20 = "zatozahetogiko mehatiwebub xuv" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw6_019 {
   meta:
      description = "mw6 - file 019"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "3411ffa29608d19dc77f53571010425fc94abd5dac92d6c2abffab6eb468c0ea"
   strings:
      $x1 = "Nibofojegikiho. Furudexipahinul xisi vipajugoco. Wakuge fagivuf cevolay. Setabafugo pejepivupin nanemaxinel fozopicopixul. Gihiy" ascii
      $s2 = "suhix.exe" fullword ascii
      $s3 = "C:\\vekoyigo_mezehuhupusuxamedag_kepanorabacewa45.pdb" fullword ascii
      $s4 = "Junoxolicizi. Guzicibibador cowavokipacaz xaj dovitixuz. Pucu. Totu radopadohapid legav zizelutediko. Citafehilajobe culaxofonav" ascii
      $s5 = "bin\\suhix.pdb" fullword ascii
      $s6 = "nibahuwudateye. Wejibayatulebaf fadehemahihah nucecoj. Jubiwevu wufirovog mazu lutipezuto. Duhugetam jam gagavusak. Kulo wubul d" ascii
      $s7 = "kihusowiwes pulemaloge. Watepawipalat kef. Jasec. Wedomu gasikegedujofu cevir xopikehoguyivo viyoje. Keyiju soseladoy. Joyebedex" ascii
      $s8 = "alorozogihajum tayetafac. Bucolenudihom gekuzilafe. Pajef rumomur. Jajevof sisubihi wikilol butoli. Vizusukeyewo. Cukevewil" fullword ascii
      $s9 = "cruntime error " fullword wide
      $s10 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\scanf.c" fullword wide
      $s11 = "Df:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\dbgrpt.c" fullword wide
      $s12 = "lokoke yozelitu. Yeniwiboze voyihocuweyelez sapijivup hiti kavuna. Duxiwidabelake. Lutebogunaw jubutufidu rehudifasa. Pepavagowu" ascii
      $s13 = "lupu femayufakituku filugi. Yil. Wirej. Lekijugimifay kibevilakimes cuvez wiwiwuwuwaraf. Wofohiliye vubeho muwegidosur zujefevac" ascii
      $s14 = "_getArchiveInfo@8" fullword ascii
      $s15 = "adihigaloj mabeyeru. Sifirexosasod zocewibocuhiboz nexuzadi. Gido dutarecilolek boyumizuxekitak gesufer sexopawixi. Noxeyafeb ce" ascii
      $s16 = "Garanoxilofew hufudologucewut" fullword ascii
      $s17 = "jo zifo. Vepulemolagete. Dukopofirem dugafekupej. Lofopid zalutahozajomo lepunebadayo. Jizoyecukug vus jiyifokufola vucoc. Fucun" ascii
      $s18 = "eyeniye. Jofediniwu done. Xadopenexeyitu furowoxu fuce. Gebol. Hayete tifucibun. Zoluwakegu bibe domedixoderoyeh rewucifuveya yo" ascii
      $s19 = "iha pusesumezebulib. Danuxovupesazu win rume xolamibat logaxey. Hehitovamocecos funal welexow xihosud vumomubedejola. Pebufonigo" ascii
      $s20 = "Veyel herayeyohe4Larericoruyaw vecefo koyekunepavik woke dexipahacogoMKogayimobepado dayigowe luj tuli mazayuhex marekojuha piwa" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw6_024 {
   meta:
      description = "mw6 - file 024"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "556013314272ea728978b82086844082f94cb1335fa4f96913165b67da0811cb"
   strings:
      $s1 = "bobu.exe" fullword ascii
      $s2 = "ERRORDIALOG" fullword wide
      $s3 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\scanf.c" fullword wide
      $s4 = "Cudapi bubihavegijepuj. Waxahobaciyi tohagegifefocu huzef. Pedadukanusixo fozodogucujey safumoxagiz xisuyozitudical. Beyi cegiyo" ascii
      $s5 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\feoferr.c" fullword wide
      $s6 = "taku. Volamexu busigohekatovi xurecodonoyol. Netefo. Mamatifevizimuy. Jur dilorigeyec suyapidiziti. Vuhamizuviyodoh rirabunopowe" ascii
      $s7 = " bilejiv hec vuzazalagonu. Roxotamivuko dizuzonenotiyad vuvoleyemin takez. Beliso. Lojiruw ciwuhipacosawa zipogovek coyiney. Jet" ascii
      $s8 = "4'444\"\"\"\"\"\"4444'" fullword ascii /* hex encoded string 'DDDD' */
      $s9 = "* .!kU" fullword ascii
      $s10 = "Haliduciyoducu wiwebegoke)Belogof molulim hinikiwotanus guwawu romi1Vakumo cerapazilo yohem mucoxezunemeze newum dofu:Sir kidero" wide
      $s11 = "fncrbcc" fullword ascii
      $s12 = "qrnfghd" fullword ascii
      $s13 = "stlgrwkh" fullword ascii
      $s14 = "behnbea" fullword ascii
      $s15 = " Data: <%s> %s" fullword ascii
      $s16 = "avolupubotuki pucukeyugo wubogupudokiyuh nahesipaxuj dezilinawukaza. Suv jigaxafefoti xud jemasecuzofoho nic. Hesevaxe gupevemib" ascii
      $s17 = "loso. Bejufusinorezuc wud. Pup poti yeyumupugu dukaruxitazeda pusojiyevut. Humaputimokey. Yucuruzedir tofojat mejurohasakaw ruja" ascii
      $s18 = "@_set_error_mode" fullword wide
      $s19 = "HOOOOOOOO" fullword ascii
      $s20 = "LLLLLLLLQ" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw6_005 {
   meta:
      description = "mw6 - file 005"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "3009ff9d8a1675709ccb395bb2c45fb0046a19389e37f4e20bc672efee49f8cd"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
      $s2 = "ExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:s" ascii
      $s3 = " Install System v2.46</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><request" ascii
      $s4 = "?!=)3%;-7#?" fullword ascii /* hex encoded string '7' */
      $s5 = "s-microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/><supportedOS Id=\"{e" ascii
      $s6 = "8*.:* " fullword ascii
      $s7 = "HG; /fJ" fullword ascii
      $s8 = "p1!+ }" fullword ascii
      $s9 = "SHFOLDER" fullword ascii /* Goodware String - occured 65 times */
      $s10 = "SeShutdownPrivilege" fullword ascii /* Goodware String - occured 216 times */
      $s11 = "\"}.nbK" fullword ascii
      $s12 = "OdHtXlD|Tb" fullword ascii
      $s13 = "RIEh9Xa" fullword ascii
      $s14 = "YAxEV<+" fullword ascii
      $s15 = "fIMiB<2" fullword ascii
      $s16 = ";kRwa^<U" fullword ascii
      $s17 = "fMopX6h" fullword ascii
      $s18 = "RMZN!^" fullword ascii
      $s19 = "S&KvVJ~4g" fullword ascii
      $s20 = "OVaE-:5" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw6_026 {
   meta:
      description = "mw6 - file 026"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "81d1f40bc96923bb16a120f4b769bb6a2d87e46498fa7fe271438996402965df"
   strings:
      $x1 = "msvbvm60.dll" fullword ascii /* reversed goodware string 'lld.06mvbvsm' */
      $s2 = "dkernel.exe" fullword ascii
      $s3 = "services.com" fullword ascii
      $s4 = "Romantic-Devil.R.exe" fullword ascii
      $s5 = "IEXPLORER.exe" fullword ascii
      $s6 = "sistem.sys" fullword ascii
      $s7 = "sstray.exe" fullword ascii
      $s8 = "syslove.exe" fullword ascii
      $s9 = "uphyk22.exe" fullword ascii
      $s10 = "mspatch.exe" fullword ascii
      $s11 = "kangen.exe" fullword ascii
      $s12 = "Systray.exe" fullword ascii
      $s13 = "untukmu.exe" fullword ascii
      $s14 = "LEXPLORER.exe" fullword ascii
      $s15 = "C:\\Baca Bro !!!.txt" fullword ascii
      $s16 = "Command Bro !!!" fullword ascii
      $s17 = "yesbron.com" fullword ascii
      $s18 = "norton" fullword ascii /* reversed goodware string 'notron' */
      $s19 = "i75-d2\\dkernel.exe" fullword ascii
      $s20 = "br5271on.exe" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw6_012 {
   meta:
      description = "mw6 - file 012"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "8305757b75ba38b175fb67d94230f5acddcd89b315f71acfaa266b5128e782fb"
   strings:
      $s1 = "C:\\guvezamilupak\\hixe\\kasa67 tayatuwut77\\g.pdb" fullword ascii
      $s2 = "pifajegimu xivahasiwewusadakegetoyujurug ticidoxojopiras" fullword ascii
      $s3 = "C:\\Program Files (x86)\\Microsoft Visual Studio 10.0\\VC\\include\\streambuf" fullword ascii
      $s4 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\_mbslen.c" fullword wide
      $s5 = "Gf:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\dbgrpt.c" fullword wide
      $s6 = "C:\\Program Files (x86)\\Microsoft Visual Studio 10.0\\VC\\include\\xstring" fullword wide
      $s7 = "C:\\Program Files (x86)\\Microsoft Visual Studio 10.0\\VC\\include\\memory" fullword wide
      $s8 = "444444444&&4&&" fullword ascii /* hex encoded string 'DDDDD' */
      $s9 = "A_get_osfhandle" fullword wide
      $s10 = "gonogaxejama yidugegodoxasopegizaruniyeroeco balejayegovinuhayipafega" fullword wide
      $s11 = "jllllllll" fullword ascii
      $s12 = "%%g%gggggggg" fullword ascii
      $s13 = "risudajadayukibariminikenikixo" fullword wide
      $s14 = "rotahejinataritifututafizo" fullword wide
      $s15 = "ivsaruho" fullword wide
      $s16 = " Data: <%s> %s" fullword ascii
      $s17 = "G_set_error_mode" fullword wide
      $s18 = "LXXXXXXXL" fullword ascii
      $s19 = "kafasuvekolihapexos mecifemeluk" fullword ascii
      $s20 = "suwunasusebatosesejire wosegofumeteyovaxuhunuvene" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw6_015 {
   meta:
      description = "mw6 - file 015"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "2fdc9396fe626f9fb65b50148c13ac7f5c3942f0f7b4b1f201445b6e426be454"
   strings:
      $s1 = "C:\\fon\\kumela\\zofejuti\\sop.pdb" fullword ascii
      $s2 = "pifajegimu xivahasiwewusadakegetoyujurug ticidoxojopiras" fullword ascii
      $s3 = "KMicrosoft Visual C++ Runtime Library" fullword wide
      $s4 = "C:\\Program Files (x86)\\Microsoft Visual Studio 10.0\\VC\\include\\streambuf" fullword ascii
      $s5 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\_mbslen.c" fullword wide
      $s6 = "C:\\Program Files (x86)\\Microsoft Visual Studio 10.0\\VC\\include\\xstring" fullword wide
      $s7 = "C:\\Program Files (x86)\\Microsoft Visual Studio 10.0\\VC\\include\\memory" fullword wide
      $s8 = "Kf:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\dbgrpt.c" fullword wide
      $s9 = "444444444&&4&&" fullword ascii /* hex encoded string 'DDDDD' */
      $s10 = "A_get_osfhandle" fullword wide
      $s11 = "gonogaxejama yidugegodoxasopegizaruniyeroeco balejayegovinuhayipafega" fullword wide
      $s12 = "jllllllll" fullword ascii
      $s13 = "%%g%gggggggg" fullword ascii
      $s14 = "risudajadayukibariminikenikixo" fullword wide
      $s15 = "rotahejinataritifututafizo" fullword wide
      $s16 = "ivsaruho" fullword wide
      $s17 = " Data: <%s> %s" fullword ascii
      $s18 = "Dp>N:\"" fullword ascii
      $s19 = "t(gI:\\" fullword ascii
      $s20 = "K_set_error_mode" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw6_007 {
   meta:
      description = "mw6 - file 007"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "c8d7d8497ba4665ca94fb10510c32cc6e972fe1f3e6bc97ba8c013cb8dcea42a"
   strings:
      $x1 = "mciqtz32.dll" fullword ascii /* reversed goodware string 'lld.23ztqicm' */
      $x2 = "c:\\ade\\jenkins\\workspace\\8-2-build-windows-i586-cygwin\\jdk8u241\\331\\build\\windows-i586\\deploy\\tmp\\javacplexec\\obj\\j" ascii
      $x3 = "\"%s\" -Xbootclasspath/a:\"%s\\..\\lib\\deploy.jar\" %s -Djava.locale.providers=HOST,JRE,SPI -Djdk.disableLastUsageTracking -Dsu" wide
      $s4 = "AppVIsvSubsystems32.dll" fullword ascii
      $s5 = "F:\\Office\\Target\\x86\\ship\\postc2r\\x-none\\msosrec.pdb" fullword ascii
      $s6 = "  <assemblyIdentity version=\"8.0.241.7\" processorArchitecture=\"X86\" name=\"unpack200.exe\" type=\"win32\"></assemblyIdentity" ascii
      $s7 = "GetCurrentUserHandle: OpenProcessToken failed." fullword wide
      $s8 = "GetCurrentUserHandle: Can't open desktop shell process." fullword wide
      $s9 = "GetCurrentUserHandle: Can't get process token of desktop shell." fullword wide
      $s10 = "danim.dll" fullword ascii
      $s11 = "CmnCliM.dll" fullword ascii
      $s12 = "mso99Lwin32client.dll" fullword wide
      $s13 = "mso40uiWin32Client.dll" fullword ascii
      $s14 = "mso20win32client.dll" fullword wide
      $s15 = "mso40uiwin32client.dll" fullword wide
      $s16 = "Mso20Win32Client.dll" fullword ascii
      $s17 = "Mso30Win32Client.dll" fullword ascii
      $s18 = "mso30win32client.dll" fullword wide
      $s19 = "Mso99LWin32Client.dll" fullword ascii
      $s20 = "lmso.dll" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw6_014 {
   meta:
      description = "mw6 - file 014"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "f2945753c6cedf8e7b8e8f4e04859591c3edf18c7652a00f9765ac99694cc874"
   strings:
      $s1 = "http://tor.browser.ideaprog.download/sfile.exe" fullword ascii
      $s2 = "Opera.HTML\\shell\\open\\command" fullword ascii
      $s3 = "SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins" fullword ascii
      $s4 = "unleap.exe" fullword ascii
      $s5 = "FtpPassword" fullword ascii
      $s6 = "SMTP Password" fullword ascii
      $s7 = "aPLib v1.01  -  the smaller the better :)" fullword ascii
      $s8 = "\\Global Downloader" fullword ascii
      $s9 = "ftpshell.fsi" fullword ascii
      $s10 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.0; Windows 98)" fullword ascii
      $s11 = "Software\\Far\\SavedDialogHistory\\FTPHost" fullword ascii
      $s12 = "Software\\Far Manager\\SavedDialogHistory\\FTPHost" fullword ascii
      $s13 = "Software\\Far2\\SavedDialogHistory\\FTPHost" fullword ascii
      $s14 = "fireFTPsites.dat" fullword ascii
      $s15 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Microsoft Outlook Internet Settings" fullword ascii
      $s16 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" fullword ascii
      $s17 = "wiseftpsrvs.bin" fullword ascii
      $s18 = "account.cfg" fullword ascii
      $s19 = "NNTP Password" fullword ascii
      $s20 = "FTP++.Link\\shell\\open\\command" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw6_029 {
   meta:
      description = "mw6 - file 029"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "48d0dff7748083a16125cedb4b20997b979945242e25af29b29136a51f69233c"
   strings:
      $s1 = "rahe.exe" fullword ascii
      $s2 = "C:\\vimab-riyidogow.pdb" fullword ascii
      $s3 = "viteculaxejizapucoma tasexixuxukixadipeyejerax yerobaxepunehuwinuxevafur guminesiguwax" fullword ascii
      $s4 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\scanf.c" fullword wide
      $s5 = "3,3!4,464" fullword ascii /* hex encoded string '3Dd' */
      $s6 = "jigegarovilafezi" fullword wide
      $s7 = "birixicojibiyemocizetiguvozi" fullword wide
      $s8 = "garonek" fullword wide
      $s9 = " Data: <%s> %s" fullword ascii
      $s10 = "wuwipegukilosejapiranana fatucudakulowipuw bukajimafejuruburibavuhe" fullword ascii
      $s11 = "tijisixilijehogakus hetekanonuyujahaxoz wirenesa secelobevogefoj yonucizudecozosowu" fullword ascii
      $s12 = "yuwalepalubabejuzoduxedoxebika puriy" fullword ascii
      $s13 = "bojosoboxufevitabanufu lodan" fullword ascii
      $s14 = "bokema tav toselafoyori zexomulijedemegizedogoxog" fullword ascii
      $s15 = "vscanf" fullword wide
      $s16 = "Efclose" fullword wide
      $s17 = "kocereeb jalozakulukamohamigen" fullword wide
      $s18 = "moripo hojidodigim" fullword wide
      $s19 = "lifozikiwewapat tipedupime zus" fullword wide
      $s20 = "royewozaxobefo tuyixevokev jajitinizohemeyoxuloxuwa midoxiruhedami gebujisajawoyihibadeset" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw6_010 {
   meta:
      description = "mw6 - file 010"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "49b769536224f160b6087dc866edf6445531c6136ab76b9d5079ce622b043200"
   strings:
      $x1 = "<?aHp4enFzZml2d3NnY3NwY3l4bWd3d3NnY2F4a2dxbWd3eG5lZGR3dGpiZHJocnVo4Mbi4OLg4ODgQCvsKMgoISgzKB0oZihNKFYooCmFKZcp+CnHKSgpOikfKWkpci" ascii
      $s2 = "wV7UzXzER+PFbLL4tlh3q9DRfrTqAKi7EG5OAnS+CIcxlHRU8OBWH1CUlz7edmRO3kLu52eaCCt/cmDzPRUtH2dzHN/bJtsEwjK3pM53ZxjeMbvsSpywNKGvUfBvxxM8" ascii
      $s3 = "~SHLWAPI.DLL~~msvcrt.dll~comctl32.dll~" fullword ascii
      $s4 = "Nk3bVYY005h4/coS5iHq7RbinxWja5SoduabsgDGgsTxuSDn1hGOrAMzML3LQjSkeVe5VxQ5gP0C0VQruiWVEFheKQwCG3QNtxdvHnwSesgCnh3gNKXj0Rm908rDXYKf" ascii
      $s5 = "yznDXF7/4trG/4arwmwqAGa0EC4Wfc2aYX5r7F3BqE43wgDC2gAw3ftAwzeSJEWlOgybG79cIZvPwnd8haqSlsuWw30k9ooMwc3jv+Re56BI5IkNUbkB249bC7JSpr4C" ascii
      $s6 = "Uw+EK1vP/MzuaA7UYicJskaFUMbJfDkc/eYePEh+1SI2NLDXnv4k3PEB1TAFaIl/qTD+/GhjUY6S7DBUAoDE340l/zlHWKwoyFgG7Zd1KMgTaQfjIoO3nXHgN4lCl4/C" ascii
      $s7 = "mailto:hdietrich@gmail.com" fullword ascii
      $s8 = "SopCast.exe" fullword wide
      $s9 = "Copyright (C) 2004 - 2013, SopCast.com.  All rights reserved." fullword wide
      $s10 = "www.sopcast.com" fullword wide
      $s11 = "+UhTOf5eJtWjhs9o/zx17Rokvnj7T8KWJnZdxj870VN6YOP/31Wqaif+p+NaG7w/306QdIc3fUP0CE1bUK7mhNZjr8WpYJ+4KmDaTfjmxVdZ11EktwDkR4pnmZg+kcPG" ascii
      $s12 = "TKiLyvhOEyEk2Lc8q0rhM2svGIDrT0pptB9niHlewhSh+Guw0dnUCqN92i/5AyD0ByzZ1RGglYp6Md0nXdMUqfIY4IDihK8llEBoAIoAfRWxm+E0DCGluRo+z2JcZ3DY" ascii
      $s13 = "9prXRjS9IObOzQbsQEpH4cNksPyE1NPjGNIDPaCvfUpMUa5Arg9fb0/EN5ZjmeNUBlk52xOo1YKEHg4TP/4+AWaMhxqLq7vkdRlgnTgQVcgi88yxi0pCbqogJD7nEyoi" ascii
      $s14 = "G76uDRl/3Bakg/wIXwkEsrLFH073V+8CSlsur3QKbRQwHnB6Xt5iku7Yj0PESm5ny1CJv/spYZETYDYBVc4Iga80/OJtNCq80d++SqSeo0PZ0A/PWiWbSH1ImmzM05jg" ascii
      $s15 = "L0qG3hkmlBGa5DjNjmdzlRfC++03et3jIiUVpdA0Kd0CJHRRnMhcVfTPSMGpu7kDyByEwHdRkE3g0jIKlSRaC6arOCvRhCUKebacjZi5wGxxGRaa1NWoDc5wgOLb+9Xu" ascii
      $s16 = "jeqkYvGXHw6DPwdUSLlvZN8i8loGo8htkGssKNwp/KSA/oIPprQYeScMIHnM/pvsrZn5BYL2mKUYa254mTKI8X7FE61+swVxUSeJsKql5hY7BSEjeeCgB1TX0pj/TFgB" ascii
      $s17 = "5lzSachP+qU9DsDEvqEvDARPeYe7jDwBtZK6xdtCN3tcnSsb5vD5vki5nUWWOD/JMezHDtVifUjBikAeC5WzCEKixTECT/rKo9Rc8f0DJnvNYmHyP9LszXn2jCT6vQVU" ascii
      $s18 = "2AUz4bYMA8UzqOkp0AcX7lvVQGjSxwURENbRDUnUc9hyVwhIGZ4Y/jo3PI3xQJSrDwrK0+OF6LB55dr1cJXnazHt+lSkd/yREW7eU+2ovJM7gJ/OQ3NPPNJgET8pROmF" ascii
      $s19 = "FccQE7g45tbLChFlf22juotS0ws86FxYYT9iNMrsqJi+e0PYQkkm7w8Or0MR4w98htdk7oU19qiuPvnpm8mEJppC4CzDXf9Ftpf0RcLJZHskkhHbr4jcPaBJM0U8gLEF" ascii
      $s20 = "4cdg6xHmLcPTjh6A34gDNrud0XDqPrZUI7qgy+BKygmo+BHUQf3ojmGEtWLnb9/P6v/Q3nCEXaYFQ7HFbW4jPThaXgrGLVh80topQXUIZt6mibkVbEZ5fT69aoyJaBoD" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw6_006 {
   meta:
      description = "mw6 - file 006"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "2fb3d54a36d316831e170d9827dd8b7086875d24b92b1dda5b140151e75386f0"
   strings:
      $x1 = "kbdbr.dll" fullword ascii /* reversed goodware string 'lld.rbdbk' */
      $s2 = "        <requestedExecutionLevel level = 'asInvoker' uiAccess = 'false' />" fullword ascii
      $s3 = "$Symantec Componen" fullword wide
      $s4 = "  <trustInfo xmlns = \"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s5 = "!This -7Afram cannot be run in DOS mode." fullword ascii
      $s6 = "<assembly xmlns = 'urn:schemas-microsoft-com:asm.v1' manifestVersion = '1.0'>" fullword ascii
      $s7 = "Mercery" fullword wide
      $s8 = "Scoleciform" fullword wide
      $s9 = "Unfigurable" fullword wide
      $s10 = "Turnhalle" fullword wide
      $s11 = "hhhcgdjeaGGS`bGGSGDGEWACv" fullword ascii
      $s12 = "e:::eeeeeeeee;" fullword ascii
      $s13 = "<Vjph4!H" fullword ascii
      $s14 = "UUUUUUJ|JJbVU" fullword ascii
      $s15 = "V?:k[k6>=:=MMMMMMMMM" fullword ascii
      $s16 = "120614235959" ascii /* Goodware String - occured 1 times */
      $s17 = "j@jOWVj'j" fullword ascii
      $s18 = "<QWjph4!H" fullword ascii
      $s19 = "dKWWWg?Y" fullword ascii
      $s20 = "140715235959" ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw6_023 {
   meta:
      description = "mw6 - file 023"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "4b4e21801fe620c2b4942c0e69c5812077691a2693d92510c3e5a6e8b09b934f"
   strings:
      $s1 = " getUTCDayWWW" fullword ascii
      $s2 = "[.* csQ" fullword ascii
      $s3 = "PECompact2" fullword ascii /* Goodware String - occured 4 times */
      $s4 = "rZTmL< " fullword ascii
      $s5 = "3KLHR!" fullword ascii
      $s6 = "irtualFe" fullword ascii
      $s7 = "EFScwaD" fullword ascii
      $s8 = "{uzhleKQ" fullword ascii
      $s9 = "xTaGsdtSb" fullword ascii
      $s10 = "udDl\"," fullword ascii
      $s11 = "zsXirE>" fullword ascii
      $s12 = "UMTJm?" fullword ascii
      $s13 = "PrintFile" fullword ascii
      $s14 = "KAHl^V-" fullword ascii
      $s15 = "~OOiai|aq" fullword ascii
      $s16 = "kernl32.d" fullword ascii
      $s17 = "PcIr=uI" fullword ascii
      $s18 = "oYtl,\\" fullword ascii
      $s19 = "MJRC\\S" fullword ascii
      $s20 = "rGkZ8V=" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw6_020 {
   meta:
      description = "mw6 - file 020"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "6d743b99b24677afa60aa1f1763f038d492605a5fcca34ab450480a67bd8e3cf"
   strings:
      $s1 = "4444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444" ascii /* hex encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' */
      $s2 = "733333333333333333333330" ascii /* hex encoded string 's33333333330' */
      $s3 = "abbbbbbbababbabebababbbbbbbbbbbbbbbbbabaaababbabbbbbbaabbabbaabbabbdbabbbaaabbabbabababbb" ascii
      $s4 = "effffffffff" ascii
      $s5 = "eeebeccbefbefefeffbbbeffeecbfbeeeebefebebefbceefeceefefffffbfebeebeeebebfeebfecbbbeeecffc" ascii
      $s6 = "EFFEFEEFFFEFEEEE" ascii
      $s7 = "EFEFFFFFFFF" ascii
      $s8 = "EEEEEEFEEEEF" ascii
      $s9 = "<A-4qljm[n8#v" fullword ascii
      $s10 = "44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444" ascii /* Goodware String - occured 1 times */
      $s11 = "\"IQUM0-P" fullword ascii
      $s12 = "HJtH7I=" fullword ascii
      $s13 = "Bqrk:(G" fullword ascii
      $s14 = "cYCZTUK#" fullword ascii
      $s15 = "Dosya Klas" fullword wide
      $s16 = "\\OFe\"\\T" fullword ascii
      $s17 = "@1IKK5" fullword ascii
      $s18 = "/:ASFTRr" fullword ascii
      $s19 = "/uhPnY" fullword ascii
      $s20 = "#RKW\"h" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw6_016 {
   meta:
      description = "mw6 - file 016"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "dcca56dad3f0113326e3c2c025fb8c9c60721c81b5af8b7821969c7673307de9"
   strings:
      $x1 = "zRUgg13GqSqFsCQj5LQ.xGB9tY3B1AP9DTn1t12+QjOiqU3qUjBXs4c9ReS+IljNPK3r2k0PGOIrckK`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii
      $s2 = "zRUgg13GqSqFsCQj5LQ.xGB9tY3B1AP9DTn1t12+QjOiqU3qUjBXs4c9ReS+IljNPK3r2k0PGOIrckK`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii
      $s3 = "3639797246" ascii /* hex encoded string '69yrF' */
      $s4 = "Pi.exe" fullword wide
      $s5 = "S0VZMys8R3" fullword ascii /* base64 encoded string 'KEY3+<G' */
      $s6 = "AAC payload type" fullword ascii
      $s7 = "ture=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii
      $s8 = "PMP Host Context" fullword ascii
      $s9 = "Script stream" fullword ascii
      $s10 = "rwpNHi9xCBspy0yDJZC" fullword ascii
      $s11 = "IXiRCLBc2rZ7rkSw0pK" fullword ascii
      $s12 = "IljNPK3r2k0PGOIrckK`1" fullword ascii
      $s13 = "rQfvv12H5iKArMP0CU4" fullword ascii
      $s14 = "P0CWJHM9Lckn88ervK8" fullword ascii
      $s15 = "pg95CLq0nZIFLgfTpL8" fullword ascii
      $s16 = "T2LOGoOTseBjsL1nbBl" fullword ascii
      $s17 = "Ajg2CNhEjUo8eYeMQNL" fullword ascii
      $s18 = "mtJdDLL9D" fullword ascii
      $s19 = "FtpRvY4RTWg8FTtZ5ov" fullword ascii
      $s20 = "Is Compressed" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw6_004 {
   meta:
      description = "mw6 - file 004"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "e1ff405eb4bd0d3b159bc9d97006b59630425b21bf95eb48c5491d15ff35cac7"
   strings:
      $s1 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" fullword wide
      $s2 = "Stub.exe" fullword wide
      $s3 = "31313.exe" fullword ascii
      $s4 = "CloseMutex" fullword ascii
      $s5 = "MutexControl" fullword ascii
      $s6 = "aUFVZ2JiYXNZRUdPZTgzTE9wZlFhejlLM2FOUE5icVU=" fullword wide /* base64 encoded string 'iAUgbbasYEGOe83LOpfQaz9K3aNPNbqU' */
      $s7 = "Select * from Win32_ComputerSystem" fullword wide
      $s8 = "EXECUTION_STATE" fullword ascii
      $s9 = "ProcessCritical" fullword ascii
      $s10 = "k32tzjm+eH+SAvERFqInrT1ZJMK3VKP3j2BYbwo/IjFUejFyr2hfc+tc677dgoMXVgqI3OfcSNOjGPv1rWMYKWwMBKFPYQI1GgUXEV8iyHnC9djhRhqjMditcDIrxivE" wide
      $s11 = "SystemEvents_SessionEnding" fullword ascii
      $s12 = "GetAsUInt64" fullword ascii
      $s13 = "Client.Connection" fullword ascii
      $s14 = "AuthKeyLength" fullword ascii
      $s15 = "_authKey" fullword ascii
      $s16 = "iRLA1jyiDcEwhrgFtcqT7sCXzFqROrnM2qOGcNmsKQQLWSB2br7GoAjIDy+CICdMK8KedLkXS+shlQQrO02Wa7ghe/SgusOIOdhRJ2MCBbGqyM8FloENfu+WZGBbZMEZ" wide
      $s17 = "vmware" fullword wide
      $s18 = "get_AsFloat" fullword ascii
      $s19 = "get_SslClient" fullword ascii
      $s20 = "GetActiveWindowTitle" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw6_027 {
   meta:
      description = "mw6 - file 027"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "8983a49ecabbaf24302233a8b30cae3b6f13a5d7ee684b0af8a58f19e49ace72"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADZ" fullword ascii
      $s2 = "FileLoadException.exe" fullword wide
      $s3 = "50696E6E696E6748656C706572" wide /* hex encoded string 'PinningHelper' */
      $s4 = "71714E4A64" wide /* hex encoded string 'qqNJd' */
      $s5 = "get__targetGrid" fullword ascii
      $s6 = "remove_TargetGridSetting" fullword ascii
      $s7 = "_targetGrid" fullword ascii
      $s8 = "ASystem.Windows.Forms.Design.DateTimePickerDesigner, System.Design" fullword ascii
      $s9 = "set__targetGrid" fullword ascii
      $s10 = "TargetGridSettingEvent" fullword ascii
      $s11 = "TargetGridSettingEventArgs" fullword ascii
      $s12 = "add_TargetGridSetting" fullword ascii
      $s13 = "get_TargetGrid" fullword ascii
      $s14 = "set_TargetGrid" fullword ascii
      $s15 = "TargetGridSettingEventHandler" fullword ascii
      $s16 = "get_comboObs" fullword ascii
      $s17 = "get_comboTipoEnv" fullword ascii
      $s18 = "Archivos de texto|*.txt" fullword wide
      $s19 = "WindowCopy.png" fullword wide
      $s20 = "get_btnAbrir" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw6_028 {
   meta:
      description = "mw6 - file 028"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "7ca2a12054da7db5e2c5c1a6b58733f44c99aa2248944bf2ab7bbbf8b35a93cf"
   strings:
      $s1 = "ee.exe" fullword wide
      $s2 = "(Chinhu-Chakasenderwa Service Message DLL" fullword ascii
      $s3 = "Chinhu-Chakasenderwa Service Message DLL" fullword wide
      $s4 = "xwxsasn" fullword ascii
      $s5 = "Isl:\\z" fullword ascii
      $s6 = "n:\\x,3[" fullword ascii
      $s7 = " Microsoft Corporation. All Rights Reserved." fullword wide
      $s8 = " -i6@v" fullword ascii
      $s9 = "ajLCzi4" fullword ascii
      $s10 = "fRwgVF8" fullword ascii
      $s11 = "\\qUHiR_mYw" fullword ascii
      $s12 = "TripleDESCryptoServiceProvider" fullword ascii /* Goodware String - occured 36 times */
      $s13 = "MD5CryptoServiceProvider" fullword ascii /* Goodware String - occured 50 times */
      $s14 = "CipherMode" fullword ascii /* Goodware String - occured 54 times */
      $s15 = "CreateDecryptor" fullword ascii /* Goodware String - occured 77 times */
      $s16 = "Microsoft.VisualBasic" fullword ascii /* Goodware String - occured 100 times */
      $s17 = "ComputeHash" fullword ascii /* Goodware String - occured 227 times */
      $s18 = "Debugger" fullword ascii /* Goodware String - occured 245 times */
      $s19 = "System.Security.Cryptography" fullword ascii /* Goodware String - occured 306 times */
      $s20 = "MemoryStream" fullword ascii /* Goodware String - occured 422 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw6_021 {
   meta:
      description = "mw6 - file 021"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "b66d26c8c6778111c88b1eef1b6ec9958dc2de73a7057b4573d854f0e3d30af1"
   strings:
      $s1 = "%W4m* " fullword ascii
      $s2 = "(hXJUPEy#" fullword ascii
      $s3 = "rq-yzffhI/" fullword ascii
      $s4 = "!This program c-?" fullword ascii
      $s5 = "mdxjSkV" fullword ascii
      $s6 = "-6>L\"}g}" fullword ascii
      $s7 = "U^MU$c" fullword ascii
      $s8 = "x8Y.gw" fullword ascii
      $s9 = "\"hfM/5" fullword ascii
      $s10 = "0`t]lb" fullword ascii
      $s11 = "rHy<o." fullword ascii
      $s12 = "lM00]T2" fullword ascii
      $s13 = ">ls]@w" fullword ascii
      $s14 = "[xT?rP" fullword ascii
      $s15 = "@#keu?0," fullword ascii
      $s16 = "#~HgJt(}" fullword ascii
      $s17 = "[k(Q@|LL" fullword ascii
      $s18 = "\"~&Q0O" fullword ascii
      $s19 = "55\\8*~" fullword ascii
      $s20 = ";]W97p" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw6_018 {
   meta:
      description = "mw6 - file 018"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "985750482ea09493ba540c98fe42e99bc6462bd8a24561f6fd24616e08930f0e"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADi" fullword ascii
      $s2 = "53797374656d2e546872656164696e67" wide /* hex encoded string 'System.Threading' */
      $s3 = "537461747573426172546f6f6c53747269704d656e754974656d5f436c69636b" wide /* hex encoded string 'StatusBarToolStripMenuItem_Click' */
      $s4 = "7365745f436865636b4f6e436c69636b" wide /* hex encoded string 'set_CheckOnClick' */
      $s5 = "546f6f6c53747269705374617475734c6162656c" wide /* hex encoded string 'ToolStripStatusLabel' */
      $s6 = "746f6f6c53747269705374617475734c6162656c" wide /* hex encoded string 'toolStripStatusLabel' */
      $s7 = "436f6e7461696e6572436f6e74726f6c" wide /* hex encoded string 'ContainerControl' */
      $s8 = "546f6f6c53747269704974656d436c69636b65644576656e7448616e646c6572" wide /* hex encoded string 'ToolStripItemClickedEventHandler' */
      $s9 = "53797374656d2e5265736f7572636573" wide /* hex encoded string 'System.Resources' */
      $s10 = "53797374656d2e57696e646f77732e466f726d73" wide /* hex encoded string 'System.Windows.Forms' */
      $s11 = "7365745f53686f72746375744b657973" wide /* hex encoded string 'set_ShortcutKeys' */
      $s12 = "476574456e747279417373656d626c79" wide /* hex encoded string 'GetEntryAssembly' */
      $s13 = "7365745f496e697469616c4469726563746f7279" wide /* hex encoded string 'set_InitialDirectory' */
      $s14 = "2e74657874" wide /* hex encoded string '.text' */
      $s15 = "76322e302e3530373237" wide /* hex encoded string 'v2.0.50727' */
      $s16 = "23537472696e6773" wide /* hex encoded string '#Strings' */
      $s17 = "23426c6f62" wide /* hex encoded string '#Blob' */
      $s18 = "746f6f6c5374726970536570617261746f7238" wide /* hex encoded string 'toolStripSeparator8' */
      $s19 = "3c4d6f64756c653e" wide /* hex encoded string '<Module>' */
      $s20 = "6765745f42" wide /* hex encoded string 'get_B' */
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw6_002 {
   meta:
      description = "mw6 - file 002"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "8a1ceb6687babe6ab82a38ca344d1092a7fc9bd6dbaf3420a3311c50131928ef"
   strings:
      $s1 = "==NNO8/5Q//8Emig3pn5k/61REXYn5uk779zqF01LUlBUo4vGkk7N/Kn3crKLAH3m8hhsfKBQlTgAkz+e8Rc/d/M/tw35wJjedbSuWI/jSPbPo5ga75PsU9zMCc3da2v" wide
      $s2 = "MemberInfoSerializationHolder.exe" fullword wide
      $s3 = "https://apple.com" fullword wide
      $s4 = "www.airiclenz.com" fullword wide
      $s5 = "http://minie.airiclenz.com" fullword wide
      $s6 = "http://www.visualpharm.com" fullword wide
      $s7 = "Icons by www.visualpharm.com" fullword wide
      $s8 = "4D6F64756C6548616E646C65" wide /* hex encoded string 'ModuleHandle' */
      $s9 = "67327577704773" wide /* hex encoded string 'g2uwpGs' */
      $s10 = "get_ColorDialog1" fullword ascii
      $s11 = "get_Dialog_Axis" fullword ascii
      $s12 = "get_combo_Motor" fullword ascii
      $s13 = "HelloWorld.Dialog_Axis.resources" fullword ascii
      $s14 = "HelloWorld.TimelineGraph.resources" fullword ascii
      $s15 = "get_LabelVersion" fullword ascii
      $s16 = "HelloWorld.Form_Splashscreen.resources" fullword ascii
      $s17 = "HelloWorld.Form_About.resources" fullword ascii
      $s18 = "mCommandSent" fullword ascii
      $s19 = "get_combo_Type" fullword ascii
      $s20 = "HelloWorld.Resources.resources" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw6_003 {
   meta:
      description = "mw6 - file 003"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "5fa5248ba60327adaa4bb7bc36c7c4e80fb69c4368e29d8b4776f17b109f9768"
   strings:
      $s1 = "Bless00.exe" fullword wide
      $s2 = "L:\"laL" fullword ascii
      $s3 = "5uxe:\"q" fullword ascii
      $s4 = " 1996-2018 VideoLAN and VLC Author" fullword wide
      $s5 = "2033pcld0mo.resources" fullword ascii
      $s6 = "ConfuserEx v1.0.0" fullword ascii
      $s7 = "3.0.3.0" fullword wide
      $s8 = "1z8%F%" fullword ascii
      $s9 = "TdJHKG7" fullword ascii
      $s10 = "pi --iZ/" fullword ascii
      $s11 = "]_q\\F46#V+ " fullword ascii
      $s12 = "Bless00" fullword ascii
      $s13 = "c(wk> -" fullword ascii
      $s14 = "Debugger" fullword ascii /* Goodware String - occured 245 times */
      $s15 = "MemoryStream" fullword ascii /* Goodware String - occured 422 times */
      $s16 = "Encoding" fullword ascii /* Goodware String - occured 811 times */
      $s17 = "Module" fullword ascii /* Goodware String - occured 856 times */
      $s18 = ".Copyright " fullword ascii
      $s19 = "-kOQg(nA" fullword ascii
      $s20 = "&>[TEcd!" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule _root_BytMe_new_datasets_mw6_022 {
   meta:
      description = "mw6 - file 022"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "e786d07582576bc3b4c243e481182ba594d67cc052c25bb918363c73c9e4093d"
   strings:
      $x1 = "http://103.124.106.203/cof4/inst.exe,http://aretywer.xyz/Corepad092.exe,http://jg3.3uag.pw/download.exe,https://msiamericas.com/" wide
      $s2 = "a8ojAHyWHoBa8hMZ3OIGGUW1.exe" fullword wide
      $s3 = "https://iplogger.org/1ixtu7" fullword wide
      $s4 = "https://iplogger.org/1lp5k" fullword wide
      $s5 = "https://pastebin.com/raw/mH2EJxkv" fullword wide
      $s6 = "fnGetFriendlyName" fullword ascii
      $s7 = "<fnGetFriendlyName>b__a" fullword ascii
      $s8 = "fileurl" fullword ascii
      $s9 = "BundleV2" fullword ascii
      $s10 = "user-agent" fullword wide /* Goodware String - occured 10 times */
      $s11 = "referer" fullword wide /* Goodware String - occured 10 times */
      $s12 = "Payload" fullword ascii /* Goodware String - occured 30 times */
      $s13 = "Repeat" fullword ascii /* Goodware String - occured 61 times */
      $s14 = "payload" fullword ascii /* Goodware String - occured 91 times */
      $s15 = "CurrentUser" fullword ascii /* Goodware String - occured 207 times */
      $s16 = "Random" fullword ascii /* Goodware String - occured 225 times */
      $s17 = "random" fullword ascii /* Goodware String - occured 225 times */
      $s18 = "get_MachineName" fullword ascii /* Goodware String - occured 326 times */
      $s19 = "Process" fullword ascii /* Goodware String - occured 574 times */
      $s20 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and
      1 of ($x*) and 4 of them
}

rule _root_BytMe_new_datasets_mw6_013 {
   meta:
      description = "mw6 - file 013"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "cdee11382a227ef32c72808129deabd7deab5e5c41ed31108242e7f53e2c62d7"
   strings:
      $s1 = "schtasks /create /f /sc ONLOGON /RL HIGHEST /tn LimeRAT-Admin /tr \"'" fullword wide
      $s2 = "select CommandLine from Win32_Process where Name='{0}'" fullword wide
      $s3 = "NTdll.dll" fullword ascii
      $s4 = "Regasm.exe" fullword wide
      $s5 = "Registry.exe" fullword wide
      $s6 = "\\vboxhook.dll" fullword wide
      $s7 = "Win32_Processor.deviceid=\"CPU0\"" fullword wide
      $s8 = "Select * from Win32_ComputerSystem" fullword wide
      $s9 = "EXECUTION_STATE" fullword ascii
      $s10 = "vmware" fullword wide
      $s11 = "Y21kLmV4ZSAvYyBwaW5nIDAgLW4gMiAmIGRlbCA=" fullword wide /* base64 encoded string 'cmd.exe /c ping 0 -n 2 & del ' */
      $s12 = "Flood! " fullword wide
      $s13 = "ES_SYSTEM_REQUIRED" fullword ascii
      $s14 = "SystemIdleTimerReset" fullword ascii
      $s15 = "Error! " fullword wide
      $s16 = "Plugin Error! " fullword wide
      $s17 = "_USB Error! " fullword wide
      $s18 = "_PIN Error! " fullword wide
      $s19 = "microsoft corporation" fullword wide
      $s20 = "\\Contacts\\" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 80KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _029_012_019_015_024_0 {
   meta:
      description = "mw6 - from files 029, 012, 019, 015, 024"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "48d0dff7748083a16125cedb4b20997b979945242e25af29b29136a51f69233c"
      hash2 = "8305757b75ba38b175fb67d94230f5acddcd89b315f71acfaa266b5128e782fb"
      hash3 = "3411ffa29608d19dc77f53571010425fc94abd5dac92d6c2abffab6eb468c0ea"
      hash4 = "2fdc9396fe626f9fb65b50148c13ac7f5c3942f0f7b4b1f201445b6e426be454"
      hash5 = "556013314272ea728978b82086844082f94cb1335fa4f96913165b67da0811cb"
   strings:
      $s1 = " Data: <%s> %s" fullword ascii
      $s2 = "Client hook allocation failure." fullword ascii /* Goodware String - occured 14 times */
      $s3 = "Object dump complete." fullword ascii /* Goodware String - occured 14 times */
      $s4 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\malloc.h" fullword wide /* Goodware String - occured 4 times */
      $s5 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\tidtable.c" fullword ascii /* Goodware String - occured 5 times */
      $s6 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\stdenvp.c" fullword wide /* Goodware String - occured 5 times */
      $s7 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\stdargv.c" fullword ascii /* Goodware String - occured 5 times */
      $s8 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\mlock.c" fullword ascii /* Goodware String - occured 5 times */
      $s9 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\ioinit.c" fullword ascii /* Goodware String - occured 5 times */
      $s10 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\mbctype.c" fullword ascii /* Goodware String - occured 5 times */
      $s11 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\_file.c" fullword ascii /* Goodware String - occured 5 times */
      $s12 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\onexit.c" fullword ascii /* Goodware String - occured 5 times */
      $s13 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\_getbuf.c" fullword wide /* Goodware String - occured 5 times */
      $s14 = "Microsoft Visual C++ Debug Library" fullword wide /* Goodware String - occured 5 times */
      $s15 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\dbgheap.c" fullword wide /* Goodware String - occured 5 times */
      $s16 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\crt0msg.c" fullword wide /* Goodware String - occured 5 times */
      $s17 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\isctype.c" fullword wide /* Goodware String - occured 5 times */
      $s18 = "(unsigned)(c + 1) <= 256" fullword wide /* Goodware String - occured 5 times */
      $s19 = "((ptloci->lc_category[category].wlocale != NULL) && (ptloci->lc_category[category].wrefcount != NULL)) || ((ptloci->lc_category[" wide /* Goodware String - occured 5 times */
      $s20 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\dbgrptt.c" fullword wide /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _012_015_1 {
   meta:
      description = "mw6 - from files 012, 015"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "8305757b75ba38b175fb67d94230f5acddcd89b315f71acfaa266b5128e782fb"
      hash2 = "2fdc9396fe626f9fb65b50148c13ac7f5c3942f0f7b4b1f201445b6e426be454"
   strings:
      $s1 = "pifajegimu xivahasiwewusadakegetoyujurug ticidoxojopiras" fullword ascii
      $s2 = "C:\\Program Files (x86)\\Microsoft Visual Studio 10.0\\VC\\include\\streambuf" fullword ascii
      $s3 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\_mbslen.c" fullword wide
      $s4 = "C:\\Program Files (x86)\\Microsoft Visual Studio 10.0\\VC\\include\\xstring" fullword wide
      $s5 = "C:\\Program Files (x86)\\Microsoft Visual Studio 10.0\\VC\\include\\memory" fullword wide
      $s6 = "444444444&&4&&" fullword ascii /* hex encoded string 'DDDDD' */
      $s7 = "A_get_osfhandle" fullword wide
      $s8 = "gonogaxejama yidugegodoxasopegizaruniyeroeco balejayegovinuhayipafega" fullword wide
      $s9 = "jllllllll" fullword ascii
      $s10 = "%%g%gggggggg" fullword ascii
      $s11 = "risudajadayukibariminikenikixo" fullword wide
      $s12 = "rotahejinataritifututafizo" fullword wide
      $s13 = "ivsaruho" fullword wide
      $s14 = "LXXXXXXXL" fullword ascii
      $s15 = "kafasuvekolihapexos mecifemeluk" fullword ascii
      $s16 = "suwunasusebatosesejire wosegofumeteyovaxuhunuvene" fullword ascii
      $s17 = "sadenekovebirutehizeeig cehusezubaruriti bidicobopakozuzakemubuzokivebuy" fullword ascii
      $s18 = "!!!!!!!!!!!g" fullword ascii
      $s19 = "Yicucijanef" fullword wide
      $s20 = "zuxolo gesexucujoyiradejuvane fuvoxexanojoxa zadifotixapelis" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "95eaf4fd2fbe9d4cd7d4ba331c148b36" and ( 8 of them )
      ) or ( all of them )
}

rule _029_012_019_015_2 {
   meta:
      description = "mw6 - from files 029, 012, 019, 015"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "48d0dff7748083a16125cedb4b20997b979945242e25af29b29136a51f69233c"
      hash2 = "8305757b75ba38b175fb67d94230f5acddcd89b315f71acfaa266b5128e782fb"
      hash3 = "3411ffa29608d19dc77f53571010425fc94abd5dac92d6c2abffab6eb468c0ea"
      hash4 = "2fdc9396fe626f9fb65b50148c13ac7f5c3942f0f7b4b1f201445b6e426be454"
   strings:
      $s1 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\intel\\fp8.c" fullword wide /* Goodware String - occured 3 times */
      $s2 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\prebuild\\conv\\cvt.c" fullword wide /* Goodware String - occured 3 times */
      $s3 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\prebuild\\tran\\contrlfp.c" fullword wide /* Goodware String - occured 3 times */
      $s4 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\_fptostr.c" fullword wide /* Goodware String - occured 3 times */
      $s5 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\prebuild\\conv\\cfout.c" fullword wide /* Goodware String - occured 3 times */
      $s6 = "__strgtold12_l" fullword wide /* Goodware String - occured 3 times */
      $s7 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\prebuild\\include\\strgtold12.inl" fullword wide /* Goodware String - occured 3 times */
      $s8 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\prebuild\\conv\\x10fout.c" fullword wide /* Goodware String - occured 3 times */
      $s9 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\localref.c" fullword wide /* Goodware String - occured 4 times */
      $s10 = "_controlfp_s(((void *)0), 0x00010000, 0x00030000)" fullword wide /* Goodware String - occured 4 times */
      $s11 = "_setdefaultprecision" fullword wide /* Goodware String - occured 4 times */
      $s12 = "_cftoe_l" fullword wide /* Goodware String - occured 4 times */
      $s13 = "strcpy_s(p, (sizeInBytes == (size_t)-1 ? sizeInBytes : sizeInBytes - (p - buf)), \"e+000\")" fullword wide /* Goodware String - occured 4 times */
      $s14 = "sizeInBytes > (size_t)(3 + (ndec > 0 ? ndec : 0) + 5 + 1)" fullword wide /* Goodware String - occured 4 times */
      $s15 = "_cftoe2_l" fullword wide /* Goodware String - occured 4 times */
      $s16 = "sizeInBytes > (size_t)(1 + 4 + ndec + 6)" fullword wide /* Goodware String - occured 4 times */
      $s17 = "_cftoa_l" fullword wide /* Goodware String - occured 4 times */
      $s18 = "_cftof_l" fullword wide /* Goodware String - occured 4 times */
      $s19 = "_cftof2_l" fullword wide /* Goodware String - occured 4 times */
      $s20 = "_cftog_l" fullword wide /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _002_027_3 {
   meta:
      description = "mw6 - from files 002, 027"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "8a1ceb6687babe6ab82a38ca344d1092a7fc9bd6dbaf3420a3311c50131928ef"
      hash2 = "8983a49ecabbaf24302233a8b30cae3b6f13a5d7ee684b0af8a58f19e49ace72"
   strings:
      $s1 = "get_Label3" fullword ascii
      $s2 = "get_Label4" fullword ascii
      $s3 = "get_Label2" fullword ascii
      $s4 = "get_Label5" fullword ascii
      $s5 = "GetResourceString" fullword ascii /* Goodware String - occured 126 times */
      $s6 = "m_FormBeingCreated" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "m_ComputerObjectProvider" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "System.Windows.Forms.Form" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "MyForms" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "MySettings" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "My.Forms" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "m_MyFormsObjectProvider" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "My.MyProject.Forms" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "m_AppObjectProvider" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "MySettingsProperty" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "My.Settings" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "m_UserObjectProvider" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "AutoPropertyValue" fullword ascii
      $s19 = "m_MyWebServicesObjectProvider" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "get_Label1" fullword ascii /* Goodware String - occured 2 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _004_013_4 {
   meta:
      description = "mw6 - from files 004, 013"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "e1ff405eb4bd0d3b159bc9d97006b59630425b21bf95eb48c5491d15ff35cac7"
      hash2 = "cdee11382a227ef32c72808129deabd7deab5e5c41ed31108242e7f53e2c62d7"
   strings:
      $s1 = "Select * from Win32_ComputerSystem" fullword wide
      $s2 = "EXECUTION_STATE" fullword ascii
      $s3 = "vmware" fullword wide
      $s4 = "ES_SYSTEM_REQUIRED" fullword ascii
      $s5 = "microsoft corporation" fullword wide
      $s6 = "VirtualBox" fullword wide /* Goodware String - occured 5 times */
      $s7 = "GZipStream" fullword ascii /* Goodware String - occured 31 times */
      $s8 = "Manufacturer" fullword wide /* Goodware String - occured 395 times */
      $s9 = "Connect" fullword ascii /* Goodware String - occured 452 times */
      $s10 = "ES_DISPLAY_REQUIRED" fullword ascii
      $s11 = "ES_CONTINUOUS" fullword ascii
      $s12 = "\\root\\SecurityCenter2" fullword wide /* Goodware String - occured 1 times */
      $s13 = "SbieDll.dll" fullword wide /* Goodware String - occured 2 times */
      $s14 = "VIRTUAL" fullword wide /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _002_027_013_5 {
   meta:
      description = "mw6 - from files 002, 027, 013"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "8a1ceb6687babe6ab82a38ca344d1092a7fc9bd6dbaf3420a3311c50131928ef"
      hash2 = "8983a49ecabbaf24302233a8b30cae3b6f13a5d7ee684b0af8a58f19e49ace72"
      hash3 = "cdee11382a227ef32c72808129deabd7deab5e5c41ed31108242e7f53e2c62d7"
   strings:
      $s1 = "CompareString" fullword ascii /* Goodware String - occured 28 times */
      $s2 = "My.Computer" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "My.User" fullword ascii /* Goodware String - occured 1 times */
      $s4 = "Dispose__Instance__" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "MyTemplate" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "MyProject" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "My.WebServices" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "MyWebServices" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "ThreadSafeObjectProvider`1" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "My.Application" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "m_ThreadStaticValue" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "Create__Instance__" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "MyApplication" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule _017_009_6 {
   meta:
      description = "mw6 - from files 017, 009"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "deceb572b4fd9c2e2c964ea1a574082a7bb6cc3952ad0c2eaeabe64f20d706fe"
      hash2 = "c252253deb8ce68d6c44f555d2ce707f7581dc7267f5d6a892a626469691ef9f"
   strings:
      $s1 = "ZipaxaBetelaluwa dobosasowav kuhavo bibuyahobu kilegodasula hufihu zozo vavexugadita jawobipepariti kizdDeyo jewigumolebew yuneb" wide
      $s2 = "ACodesoheturoxuk huva sisilijox zututuvi kiyutuputewi zurimazatahiNYivojukowosu monaxedevila zax waki vokidaf zayagehasiz vopiwo" wide
      $s3 = "bSituwizakitan kujusojigufobik wizoza numu covegecurexu hiti lolayosobo jukuvu xobofa xoyizewesebem$Fopexohikija cufuvemi waroge" wide
      $s4 = "nenosuvaraxuhibibaramirifo" fullword wide
      $s5 = "1.5.28.29" fullword wide
      $s6 = "Gupahef" fullword wide
      $s7 = "WertualBridecd" fullword ascii
      $s8 = "Ajjjjjj" fullword wide /* Goodware String - occured 1 times */
      $s9 = "Kalo fovihot" fullword wide
      $s10 = "0Warohec tenonos fuzuxi yoxemixefi saxiyusoloseki" fullword wide
      $s11 = "Jefe behus duvo pawa" fullword wide
      $s12 = "Huro luwisifo" fullword wide
      $s13 = "l$4Y6JG" fullword ascii
      $s14 = "l$Xe[e{" fullword ascii
      $s15 = "D$L$/s" fullword ascii
      $s16 = "D$\\D,vL" fullword ascii
      $s17 = "L$$;L$(v" fullword ascii
      $s18 = "Yepemupiyaguhi+Ceyumuvahud kigopoxifuzad kod xudanocotibuniTevobovil dafayemeb vanofetew dekub segisolijupejun reteniyuyevel vuz" wide
      $s19 = "Lipewuhu lozejWNufo soyucam yaxowiwek fer weyutaf ruvahuvi xeheyurefagumuz fijobep wemegoji hucuyijuyi" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _029_019_024_7 {
   meta:
      description = "mw6 - from files 029, 019, 024"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "48d0dff7748083a16125cedb4b20997b979945242e25af29b29136a51f69233c"
      hash2 = "3411ffa29608d19dc77f53571010425fc94abd5dac92d6c2abffab6eb468c0ea"
      hash3 = "556013314272ea728978b82086844082f94cb1335fa4f96913165b67da0811cb"
   strings:
      $s1 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\scanf.c" fullword wide
      $s2 = "vscanf" fullword wide
      $s3 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\read.c" fullword wide /* Goodware String - occured 2 times */
      $s4 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\input.c" fullword wide /* Goodware String - occured 2 times */
      $s5 = "nFloatStrUsed<=(*pnFloatStrSz)" fullword wide /* Goodware String - occured 2 times */
      $s6 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\_filbuf.c" fullword wide /* Goodware String - occured 2 times */
      $s7 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\ungetc_nolock.inl" fullword wide /* Goodware String - occured 2 times */
      $s8 = "_filbuf" fullword wide /* Goodware String - occured 3 times */
      $s9 = "(cnt <= INT_MAX)" fullword wide /* Goodware String - occured 3 times */
      $s10 = "(inputbuf != NULL)" fullword wide /* Goodware String - occured 3 times */
      $s11 = "_ungetc_nolock" fullword wide /* Goodware String - occured 4 times */
      $s12 = "f:\\dd\\vctools\\crt_bld\\self_x86\\crt\\src\\strtol.c" fullword wide /* Goodware String - occured 5 times */
      $s13 = "_read_nolock" fullword wide /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _016_028_004_013_8 {
   meta:
      description = "mw6 - from files 016, 028, 004, 013"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "dcca56dad3f0113326e3c2c025fb8c9c60721c81b5af8b7821969c7673307de9"
      hash2 = "7ca2a12054da7db5e2c5c1a6b58733f44c99aa2248944bf2ab7bbbf8b35a93cf"
      hash3 = "e1ff405eb4bd0d3b159bc9d97006b59630425b21bf95eb48c5491d15ff35cac7"
      hash4 = "cdee11382a227ef32c72808129deabd7deab5e5c41ed31108242e7f53e2c62d7"
   strings:
      $s1 = "MD5CryptoServiceProvider" fullword ascii /* Goodware String - occured 50 times */
      $s2 = "CipherMode" fullword ascii /* Goodware String - occured 54 times */
      $s3 = "CreateDecryptor" fullword ascii /* Goodware String - occured 77 times */
      $s4 = "ComputeHash" fullword ascii /* Goodware String - occured 227 times */
      $s5 = "System.Security.Cryptography" fullword ascii /* Goodware String - occured 306 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

rule _008_025_9 {
   meta:
      description = "mw6 - from files 008, 025"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-04-17"
      hash1 = "7c902b5da243bec90b83e4d68e4e8c097d1e36e9d9508c5095023f801440d977"
      hash2 = "b055016e0d82c57b58cd126f26b4b8f4dae1441f0019bdaa42452e815f128944"
   strings:
      $s1 = "XEYOHECURUGIYIV" fullword wide
      $s2 = "1.0.2.27" fullword wide
      $s3 = "1.5.8.28" fullword wide
      $s4 = "l$TX[kC" fullword ascii
      $s5 = "AFX_DIALOG_LAYOUT" fullword wide /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

