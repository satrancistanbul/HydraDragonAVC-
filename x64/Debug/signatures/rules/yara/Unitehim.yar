rule chinapic_zip

{

    meta:
        description = "Find zip archives of pony panels that have china.jpg"
        author = "Brian Carter"
        last_modified = "March 31, 2017"
        
    strings:
        $txt1 = "china.jpg"
        $txt2 = "config.php"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}
rule PotentiallyCompromisedCert

{
    meta:
        description = "Search for PE files using cert issued to DEMUZA "
        author = "Brian Carter"
        last_modified = "July 21, 2017"
        sample = "7ef8f5e0ca92a0f3a5bd8cdc52236564"
        TLP = "WHITE"

    strings:
        $magic = { 50 4b 03 04 (14 | 0a) 00 }

        $txt1 = "demuza@yandex.ru" nocase
        $txt2 = "https://secure.comodo.net/CPS0C" nocase
        $txt3 = "COMODO CA Limited1"

    condition:
       $magic at 0 and all of ($txt*)
}
rule INJECTOR_PANEL_SQLITE

{
    meta:
        description = "Find sqlite dbs used with tables inject panel"
        author = "Brian Carter"
        last_modified = "August 14, 2017"

    strings:
        $magic = { 53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00 }
        $txt1 = "CREATE TABLE Settings"
        $txt2 = "CREATE TABLE Jabber"
        $txt3 = "CREATE TABLE Users"
        $txt4 = "CREATE TABLE Log"
        $txt5 = "CREATE TABLE Fakes"
        $txt6 = "CREATE TABLE ATS_links"

    condition:
        $magic at 0 and all of ($txt*)

}
rule PDF_EMBEDDED_DOCM

{
    meta:
        description = "Find pdf files that have an embedded docm with openaction"
        author = "Brian Carter"
        last_modified = "May 11, 2017"

    strings:
        $magic = { 25 50 44 46 2d }

        $txt1 = "EmbeddedFile"
        $txt2 = "docm)"
        $txt3 = "JavaScript" nocase

    condition:
        $magic at 0 and all of ($txt*)

}

rule diamondfox_zip

{

    meta:
        description = "Find zip archives of panels"
        author = "Brian Carter"
        last_modified = "March 31, 2017"
        
    strings:
        $txt1 = "gate.php"
        $txt2 = "install.php"
        $txt3 = "post.php"
        $txt4 = "plugins"
        $txt5 = "statistics.php"
        $magic = { 50 4b 03 04 }
        $not1 = "joomla" nocase
        
    condition:
        $magic at 0 and all of ($txt*) and not any of ($not*)
        
}

rule keybase_zip

{

    meta:
        description = "Find zip archives of panels"
        author = "Brian Carter"
        last_modified = "March 31, 2017"
        
    strings:
        $txt1 = "clipboard.php"
        $txt2 = "config.php"
        $txt3 = "create.php"
        $txt4 = "login.php"
        $txt5 = "screenshots.php"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}

rule zeus_zip

{

    meta:
        description = "Find zip archives of panels"
        author = "Brian Carter"
        last_modified = "April 19, 2017"
        
    strings:
        $txt1 = "cp.php"
        $txt2 = "gate.php"
        $txt3 = "botnet_bots.php"
        $txt4 = "botnet_scripts.php"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}

rule atmos_zip

{

    meta:
        description = "Find zip archives of panels"
        author = "Brian Carter"
        last_modified = "April 27, 2017"
        
    strings:
        $txt1 = "cp.php"
        $txt2 = "gate.php"
        $txt3 = "api.php"
        $txt4 = "file.php"
        $txt5 = "ts.php"
        $txt6 = "index.php"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}

rule new_pony_panel

{

    meta:
        description = "New Pony Zips"
        
    strings:
        $txt1 = "includes/design/images/"
        $txt2 = "includes/design/style.css"
        $txt3 = "admin.php"
        $txt4 = "includes/design/images/user.png"
        $txt5 = "includes/design/images/main_bg.gif"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}
rule config_php

{
    meta:
        description = "Find config.php files that have details for the db"
        author = "Brian Carter"
        last_modified = "March 31, 2017"
        
    strings:
        $txt1 = "$mysql_host ="
        $txt2 = "$mysql_user ="
        $txt3 = "mysql_pass ="
        $txt4 = "mysql_database ="
        $txt5 = "global_filter_list"
        $txt6 = "white-list"
        $php1 = "<?php"
        
    condition:
        $php1 at 0 and all of ($txt*)
        
}
rule tables_inject

{

    meta:
        description = "Find zip archives of tables inject panel"
        author = "Brian Carter"
        last_modified = "August 14, 2017"
        
    strings:
        $txt1 = "tinymce"
        $txt2 = "cunion.js"
        $txt3 = "tables.php"
        $txt4 = "sounds/1.mp3"
        $txt5 = "storage/db.sqlite"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}

rule mimikatz_sekurlsa {
    strings:
        $s1 = { 33 DB 8B C3 48 83 C4 20 5B C3 }
        $s2 = {83 64 24 30 00 44 8B 4C 24 48 48 8B 0D}
        $s3 = {83 64 24 30 00 44 8B 4D D8 48 8B 0D}
        $s4 = {84 C0 74 44 6A 08 68}
        $s5 = {8B F0 3B F3 7C 2C 6A 02 6A 10 68}
        $s6 = {8B F0 85 F6 78 2A 6A 02 6A 10 68}

    condition:
        all of them
}

rule mimikatz_decryptkeysign {
    strings:
        $s1 = { F6 C2 07 0F 85 0D 1A 02 00 }
        $s2 = { F6 C2 07 0F 85 72 EA 01 00 }
        $s3 = { 4C 8B CB 48 89 44 24 30}
        $s4 = { 4c 89 1b 48 89 43 08 49 89 5b 08 48 8d }

    condition:
        3 of them
}

rule Regin_1 {
    meta:
        info = "Regin"

    strings:
            $string_decode = {55 8b ec 5d 8b 45 08 0b c0 74 0c eb 05 fe 08 fe 08 40 80 38 00 75 f6}

    condition:
            $string_decode
}


rule Regin_Driver {
    meta:
        info = "Regin Driver Component (32-bit)"

    strings:
        // 2C8B9D2885543D7ADE3CAE98225E263B
        // This is dead space at the end of the config block that will be constant between reconfigurations
        $config_block_padding = {c739f2c8ee70ebc9cf31fac0e678d3f1f709c2f8de40dbf9ff01caf0}

    condition:
        $config_block_padding
}


rule rlpack {
    meta:
        description = "RLPack packed file"
        block = false
        quarantine = false

    strings:
        $mz = "MZ"
        $text1 = ".packed\x00"
        $text2 = ".RLPack\x00"

    condition:
        $mz at 0 and $text1 in (0..1024) and $text2 in (0..1024)
}


rule sogu {
    meta:
        block = false
        quarantine = false

    strings:
        // 08E9FC6B4687C3F7FCFB86EAC870158F @ 0x4067F6
        $mov_call_sequence = { A1 ?? ?? ?? ?? FF D0 A1 ?? ?? ?? ?? FF D0 A1 ?? ?? ?? ?? FF D0 A1 ?? ?? ?? ?? FF D0 A1 ?? ?? ?? ?? FF D0 A1 ?? ?? ?? ?? FF D0 A1 ?? ?? ?? ?? FF D0 A1 ?? ?? ?? ?? FF D0 A1 ?? ?? ?? ?? FF D0 A1 ?? ?? ?? ?? FF D0 A1 ?? ?? ?? ?? FF D0 A1 ?? ?? ?? ?? FF D0 }
    
    condition:
        $mov_call_sequence
}

/*
# 14ECD5E6FC8E501037B54CA263896A11 @ 0x80C2660
>>> data = '2D72647852323138502E2930216A76242521717E7F7C3B213D2E670559404646400F07475B0A0359495E74010308076915101708415F0B0C0A58592627627E64753E62302B2F29296400'.decode('hex')
>>> def decode(s):
    result = ''
    for i in xrange(len(s) - 5):
        result += chr(ord(s[i]) ^ (i + 5))
    return result

>>> decode(data)
'(tcp[8:4] & 0xe007ffff = 0x%xbebe) or (udp[12:4] & 0xe007ffff = 0x%xb'
>>> 

*/
// linux apt backdoor
rule turla {
    strings:
        // 14ECD5E6FC8E501037B54CA263896A11 @ 0x084680
        $xor_loop = { 8d4a05 328a ???????? 888a ???????? 42 83fa08 76eb }
        // 14ECD5E6FC8E501037B54CA263896A11 @ 0x80c2660
        $enc_string = { 2D72647852323138502E2930216A76 }

    condition:
        any of them
}


rule upx {
    meta:
        description = "UPX packed file"

        block = false
        quarantine = false

    strings:
        $mz = "MZ"
        $upx1 = {55505830000000}
        $upx2 = {55505831000000}
        $upx_sig = "UPX!"

    condition:
        $mz at 0 and $upx1 in (0..1024) and $upx2 in (0..1024) and $upx_sig in (0..1024)
}


rule vmprotect {
    meta:
        description = "VMProtect packed file"

        block = false
        quarantine = false

    strings:
        $mz = "MZ"
        $vmp0 = {2E766D7030000000}
        $vmp1 = {2E766D7031000000}

    condition:
        $mz at 0 and $vmp0 in (0x100..0x300) and $vmp1 in (0x100..0x300)
}


rule wiper {
    meta:
        description = "Wiper malware deployed in late 2014 skywiper attacks"

    strings:
        // 760C35A80D758F032D02CF4DB12D3E55 @ 0x40124A
        $decryption_main_loop = {8bcbe8????????8a143e32d088143e463bf57cec5f}
        // 760C35A80D758F032D02CF4DB12D3E55 @ 0x40118d
        $context_init_loop1 = { 8b790c8b411033f78971088bf033f789710c8b710833c64b89411075e3 }
        // 760C35A80D758F032D02CF4DB12D3E55 @ 0x4011b4
        $context_init_loop2 = { 8b510c8b41100bf28971088bf00bf289710c8b71080bc64f89411075e3 }
        $MZ = "MZ"

    condition:
        $MZ at 0 and 2 of them
}

rule wiper_payload_dropper {
    meta:
        description = "Wiper implant"
        filename = "iissvr.exe"

    strings:
        $MZ = "MZ"

        // the following 3 are used to transfer html/wav/jpg data from the resource section (these include the resource name following the http data)
        $html={485454502F312E3120323030204F4B0D0A436F6E74656E742D4C656E6774683A2025640D0A436F6E74656E742D547970653A20746578742F68746D6C0D0A4163636570742D52616E6765733A2062797465730D0A5365727665723A204D6963726F736F66742D4949532F362E300D0A0D0A000000525352435F48544D4C00}

        $wav={485454502F312E3120323030204F4B0D0A436F6E74656E742D4C656E6774683A2025640D0A436F6E74656E742D547970653A20696D6167652F6A7065670D0A4163636570742D52616E6765733A2062797465730D0A5365727665723A204D6963726F736F66742D4949532F362E300D0A0D0A0000525352435F4A504700} 

        $jpg={485454502F312E3120323030204F4B0D0A436F6E74656E742D4C656E6774683A2025640D0A436F6E74656E742D547970653A20617564696F2F7761760D0A4163636570742D52616E6765733A2062797465730D0A5365727665723A204D6963726F736F66742D4949532F362E300D0A0D0A000000525352435F57415600}

    condition:
        $MZ at 0 and ($html or $wav or $jpg)
}

/*
// Moderate confidence that this rule matches a legitimate driver component used by the wiper malware
// as opposed to it having been signed by a stolen certificate.
// It's commented out here because it could hit on legitimate software and the userland component
// will be detected by signatures anyway.
rule wiper_driver_component {
    meta:
        description = "Wiper implant"
        filename = "usbdrv3.sys"

    strings:
        $MZ = "MZ"

        // 86E212B7FC20FC406C692400294073FF @ 0x15F55
        $switch_table1 = {4C89B424C8000000488B4F088B414883F802742D83F807742883F81F742383F824741E83F82D741983F831741483F836740F83F830740ABB240000C0E9}
        // @ 0x164D8
        $switch_table2 = {488BF08B484883F903741D83F908741883F909741383F914740E83F920740983F9350F}

    condition:
        $MZ at 0 and $switch_table1 and $switch_table2
}
*/

rule wiper_payload_dropper2 {
    meta:
        description = "Wiper implant"
        filename = "ams.exe"

    strings:
        $MZ = "MZ"

        // 7E5FEE143FB44FDB0D24A1D32B2BD4BB
        $process_hacker_ascii = {5c4465766963655c4b50726f636573734861636b657232}
        $process_hacker_unicode = {5c004400650076006900630065005c004b00500072006f0063006500730073004800610063006b006500720032000000}
        $mcshield_string = {53595354454d5c43757272656e74436f6e74726f6c5365745c73657276696365735c4d63536869656c6400}

    condition:
        $MZ at 0 and ($process_hacker_ascii or $process_hacker_unicode) and $mcshield_string
}


private rule IsPeFile {
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x4550
}


private rule IsZipFile {
    condition:
        uint16(0) == 0x4B50
}


rule l_exe {
    strings:
        // 9B40C3E4B2288E29A0A15169B01F6EDE @ 0x401172
        $decrypt_helper = { 8B50FC8BD98BFA8D2C8D00000000C1E704C1EB0333FB8BDAC1EB0533DD83C0FC03FB8B5C241C8BEB33E98B4C242433D103EA8B54241433FD8B68042BEF4A8968048BCD8954241475B78B7C2420 }

    condition:
        any of them
}

rule SUSP_msg_CVE_2023_23397_Mar23 {
   meta:
      description = "MSG file with a PidLidReminderFileParameter property, potentially exploiting CVE-2023-23397"
      author = "delivr.to"
      date = "2023-03-15"
      score = 60
      reference = "https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/"
   strings:
      /* https://interoperability.blob.core.windows.net/files/MS-OXPROPS/%5bMS-OXPROPS%5d.pdf */
      /* PSETID_Appointment */
      $app = { 02 20 06 00 00 00 00 00 C0 00 00 00 00 00 00 46 }

      /* PidLidReminderFileParameter */
      $rfp = { 1F 85 00 00 }
   condition:
      uint32be(0) == 0xD0CF11E0 and
      uint32be(4) == 0xA1B11AE1 and
      $app and 
      $rfp
}rule SUSP_OneNote_Repeated_FileDataReference_Feb23 {
   meta:
      description = "Repeated references to files embedded in OneNote file. May indicate multiple copies of file hidden under image, as leveraged by Qakbot et al."
      author = "delivr.to"
      date = "2023-02-17"
      score = 60
   strings:
      /* [MS-ONESTORE] File Header */
      $one = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }

      /* FileDataStoreObject GUID */
      $fdso = { 00 e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac }

      /* FileDataReference <ifndf>{GUID} */
      /* https://interoperability.blob.core.windows.net/files/MS-ONESTORE/%5bMS-ONESTORE%5d.pdf */
      $fref = { 3C 00 69 00 66 00 6E 00 64 00 66 00 3E 00 7B 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 2D 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 2D 00 ?? 00 ?? 00 ?? 00 ?? 00 2D 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? }

   condition:
      filesize < 5MB and
      ($one at 0) and 
      $fdso and
      #fref > (#fdso * 4)
}rule SUSP_OneNote_RTLO_Character_Feb23 {
   meta:
      description = "Presence of RTLO Unicode Character in a OneNote file with embedded files"
      author = "delivr.to"
      date = "2023-02-17"
      score = 60
   strings:
      /* [MS-ONESTORE] File Header */
      $one = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }

      /* FileDataStoreObject GUID */
      $fdso = { 00 e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac }

      /* RTLO */
      $rtlo = { 00 2E 20 }

   condition:
      filesize < 5MB and
      ($one at 0) and 
      $fdso and
      $rtlo
}rule SUSP_OneNote_Win_Script_Encoding_Feb23 {
   meta:
      description = "Presence of Windows Script Encoding Header in a OneNote file with embedded files"
      author = "delivr.to"
      date = "2023-02-19"
      score = 60
   strings:
      /* [MS-ONESTORE] File Header */
      $one = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }

      /* FileDataStoreObject GUID */
      $fdso = { 00 e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac }

      /* Windows Script Encoding Header */
      $wse = { 23 40 7E 5E }

   condition:
      filesize < 5MB and
      ($one at 0) and 
      $fdso and
      $wse
}rule SUSP_PDF_MHT_ActiveMime_Sept23 {
    meta:
      description = "Presence of MHT ActiveMime within PDF for polyglot file"
      author = "delivr.to"
      date = "2023-09-04"
      score = 70
      reference = "https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html"

    strings:
        $mht0 = "mime" ascii nocase
        $mht1 = "content-location:" ascii nocase
        $mht2 = "content-type:" ascii nocase
        $act  = "edit-time-data" ascii nocase
     
    condition:
        uint32(0) == 0x46445025 and
        all of ($mht*) and
        $act
}rule SUSP_SVG_Onload_Onerror_Jul23 {
   meta:
      description = "Presence of onload or onerror attribute in SVG file"
      author = "delivr.to"
      date = "2023-07-22"
      score = 40
   strings:
      $svg = "svg" ascii wide nocase

      $onload = "onload" ascii wide nocase
      
      $onerror = "onerror" ascii wide nocase

   condition:
      ($svg) and 
      ($onload or $onerror)
}rule AlienSpy {
meta:
description = "AlienSpy"
author = "Fidelis Cybersecurity"
reference = "Fidelis Threat Advisory #1015 - Ratting on AlienSpy - Apr 08, 2015"

strings:
$sa_1 = "META-INF/MANIFEST.MF" 
$sa_2 = "Main.classPK"
$sa_3 = "plugins/Server.classPK"
$sa_4 = "IDPK"

$sb_1 = "config.iniPK"
$sb_2 = "password.iniPK"
$sb_3 = "plugins/Server.classPK"
$sb_4 = "LoadStub.classPK"
$sb_5 = "LoadStubDecrypted.classPK"
$sb_7 = "LoadPassword.classPK"
$sb_8 = "DecryptStub.classPK"
$sb_9 = "ClassLoaders.classPK"

$sc_1 = "config.xml"
$sc_2 = "options"
$sc_3 = "plugins"
$sc_4 = "util"
$sc_5 = "util/OSHelper"
$sc_6 = "Start.class"
$sc_7 = "AlienSpy"
$sc_8 = "PK"

condition:
(all of ($sa_*)) or (all of ($sb_*)) or (all of ($sc_*))

}
rule apt_win32_dll_rat_hiZorRAT
{             
               meta:
                              hash1 = "75d3d1f23628122a64a2f1b7ef33f5cf"
                              hash2 = "d9821468315ccd3b9ea03161566ef18e"
                              hash3 = "b9af5f5fd434a65d7aa1b55f5441c90a"
                              ref1 = "http://www.threatgeek.com/2016/01/introducing-hi-zor-rat.html"
                              ref2 = "https://www.fidelissecurity.com/sites/default/files/FTA_1020_Fidelis_Inocnation_FINAL.pdf"
                             
               strings:
                             
                              // Part of the encoded User-Agent = Mozilla
                              $ = { c7 [5] 40 00 62 00 c7 [5] 77 00 64 00 c7 [5] 61 00 61 00 c7 [5] 6c 00 } 
                             
                              // XOR to decode User-Agent after string stacking 0x10001630
                              $ = { 66 [7] 0d 40 83 ?? ?? 7c ?? } 
                             
                              // XOR with 0x2E - 0x10002EF6
                             
                              $ = { 80 [2] 2e 40 3b ?? 72 ?? } 
                             
                              $ = "CmdProcessExited" wide ascii
                              $ = "rootDir" wide ascii
                              $ = "DllRegisterServer" wide ascii
                              $ = "GetNativeSystemInfo" wide ascii
                              $ = "%08x%08x%08x%08x" wide ascii
                             
               condition:
                              (uint16(0) == 0x5A4D or uint32(0) == 0x4464c457f) and (all of them)
}
rule Ursnif_report_variant_memory
{
meta:
 description = "Ursnif"
 author = "Fidelis Cybersecurity"
 reference = "New Ursnif Variant Targeting Italy and U.S - June 7, 2016"

strings:
 $isfb1 = "/data.php?version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s"
 $isfb2 = "client.dll"
 $ursnif1 = "soft=1&version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&crc=%x"
 $a1 = "grabs="
 $a2 = "HIDDEN"
 $ursnif2 = "/images/"
 $randvar = "%s=%s&"
 $specialchar = "%c%02X" nocase
 $serpent_setkey = {8b 70 ec 33 70 f8 33 70 08 33 30 33 f1 81 f6 b9 79 37 9e c1 c6 0b 89 70 08 41 81 f9 84 [0-3] 72 db}
condition:
7 of them
}
import "pe"

rule BlackShades : Trojan
{
	meta:
		author="Kevin Falcoz"
		date="26/06/2013"
		description="BlackShades Server"
		
	strings:
		$signature1={62 73 73 5F 73 65 72 76 65 72}
		$signature2={43 4C 49 43 4B 5F 44 45 4C 41 59 00 53 43 4B 5F 49 44}
		$signature3={6D 6F 64 49 6E 6A 50 45}
		
	condition:
		$signature1 and $signature2 and $signature3
}

rule Bublik : Downloader
{
	meta:
		author="Kevin Falcoz"
		date="29/09/2013"
		description="Bublik Trojan Downloader"
		
	strings:
		$signature1={63 6F 6E 73 6F 6C 61 73}
		$signature2={63 6C 55 6E 00 69 6E 66 6F 2E 69 6E 69}
		
	condition:
		$signature1 and $signature2
}
/*
URL: https://github.com/0pc0deFR/YaraRules
Developpeur: 0pc0deFR (alias Kevin Falcoz)
compiler.yar contient plusieurs gles permettant d'identifier un compilateur
*/
/*
rule visual_basic_5_6 : Compiler
{
	meta:
		author="Kevin Falcoz"
		date_create="24/02/2013"
		description="Miscrosoft Visual Basic 5.0/6.0"
		
	strings:
		$str1={68 ?? ?? ?? 00 E8 ?? FF FF FF 00 00 ?? 00 00 00 30 00 00 00 ?? 00 00 00 00 00 00 00 [16] 00 00 00 00 00 00 01 00} 
	
	condition:
		$str1 at (pe.entry_point)
}
*/

rule visual_studio_net : Compiler
{
	meta:
		author="Kevin Falcoz"
		date_create="24/02/2013"
		description="Miscrosoft Visual Studio .NET/C#"
		
	strings:
		$str1={FF 25 00 20 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00} /*EntryPoint*/
	
	condition:
		$str1 at (pe.entry_point)
}
rule visual_c_plus_plus_6 : Compiler
{
	meta:
		author="Kevin Falcoz"
		date_create="25/02/2013"
		description="Miscrosoft Visual C++ 6.0"
		
	strings:
		$str1={55 8B EC 6A FF 68 [3] 00 68 [3] 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC [1] 53 56 57 89 65 E8} /*EntryPoint*/
	
	condition:
		$str1 at (pe.entry_point)
}
rule visual_c_plus_plus_6_sp : Compiler
{
	meta:
		author="Kevin Falcoz"
		date_create="25/02/2013"
		description="Miscrosoft Visual C++ 6.0 SPx"
		
	strings:
		$str1={55 8B EC 83 EC 44 56 FF 15 ?? 10 40 00 8B F0 8A 06 3C 22 75 14 8A 46 01 46 84 C0 74 04 3C 22 75 F4 80 3E} /*EntryPoint*/
	
	condition:
		$str1 at (pe.entry_point)
}
rule visual_c_plus_plus_7 : Compiler
{
	meta:
		author="Kevin Falcoz"
		date_create="25/02/2013"
		description="Miscrosoft Visual C++ 7.0"
		
	strings:
		$str1={6A 60 68 [2] 40 00 E8 [2] 00 00 BF 94 00 00 00 8B C7 E8 [4] 89 65 E8 8B F4 89 3E 56 FF 15 [2] 40 00 8B 4E 10 89 0D} /*EntryPoint*/
		$str2={6A 0C 68 [4] E8 [4] 33 C0 40 89 45 E4}
	
	condition:
		$str1 at (pe.entry_point) or $str2 at (pe.entry_point)
}
rule borland_delphi_6_7 : Compiler
{
	meta:
		author="Kevin Falcoz"
		date_create="25/02/2013"
		description="Borland Delphi 6.0 - 7.0"
		
	strings:
		$str1={55 8B EC 83 C4 F0 53 B8 [3] 00 E8 [3] FF 8B 1D [3] 00 8B 03 BA [2] 52 00 E8 [2] F6 FF B8 [2] 52 00 E8 [2] FF FF 8B 03 E8} /*EntryPoint*/
		$str2={55 8B EC B9 ?? 00 00 00 6A 00 6A 00 49 75 F9 [0-1] 53 [9-11] FF 33 C0 55 68 [3] 00 64 FF 30 64 89 20} /*EntryPoint*/
	
	condition:
		$str1 at (pe.entry_point) or $str2 at (pe.entry_point)
}

rule Grozlex : Stealer
{
	meta:
		author="Kevin Falcoz"
		date="20/08/2013"
		description="Grozlex Stealer - Possible HCStealer"
		
	strings:
		$signature={4C 00 6F 00 67 00 73 00 20 00 61 00 74 00 74 00 61 00 63 00 68 00 65 00 64 00 20 00 62 00 79 00 20 00 69 00 43 00 6F 00 7A 00 65 00 6E}
	
	condition:
		$signature
}

rule lost_door : Trojan
{
	meta:
		author="Kevin Falcoz"
		date="23/02/2013"
		description="Lost Door"
	
	strings:
		$signature1={45 44 49 54 5F 53 45 52 56 45 52} /*EDIT_SERVER*/
		
	condition:
		$signature1
}

rule upx_0_80_to_1_24 : Packer
{
	meta:
		author="Kevin Falcoz"
		date_create="25/02/2013"
		description="UPX 0.80 to 1.24"

	strings:
		$str1={6A 60 68 60 02 4B 00 E8 8B 04 00 00 83 65 FC 00 8D 45 90 50 FF 15 8C F1 48 00 C7 45 FC FE FF FF FF BF 94 00 00 00 57}
		
	condition:
		$str1 at (pe.entry_point)
}

rule upx_1_00_to_1_07 : Packer
{
	meta:
		author="Kevin Falcoz"
		date_create="19/03/2013"
		description="UPX 1.00 to 1.07"

	strings:
		$str1={60 BE 00 ?0 4? 00 8D BE 00 B0 F? FF ?7 8? [3] ?0 9? [0-9] 90 90 90 90 [0-2] 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0}
		
	condition:
		$str1 at (pe.entry_point)
}

rule upx_3 : Packer
{
	meta:
		author="Kevin Falcoz"
		date_create="25/02/2013"
		description="UPX 3.X"

	strings:
		$str1={60 BE 00 [2] 00 8D BE 00 [2] FF [1-12] EB 1? 90 90 90 90 90 [1-3] 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01}
		
	condition:
		$str1 at (pe.entry_point)
}

rule obsidium : Packer
{
	meta:
		author="Kevin Falcoz"
		date_create="21/01/2013"
		last_edit="17/03/2013"
		description="Obsidium"

	strings:
		$str1={EB 02 [2] E8 25 00 00 00 EB 04 [4] EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 [2] C3 EB 02 [2] EB 04} /*EntryPoint*/
		
	condition:
		$str1 at (pe.entry_point)
}

rule pecompact2 : Packer
{
	meta:
		author="Kevin Falcoz"
		date_create="25/02/2013"
		description="PECompact"

	strings:
		$str1={B8 [3] 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43} /*EntryPoint*/
		
	condition:
		$str1 at (pe.entry_point)
}

rule aspack : Packer
{
	meta:
		author="Kevin Falcoz"
		date_create="25/02/2013"
		description="ASPack"

	strings:
		$str1={60 E8 00 00 00 00 5D 81 ED 5D 3B 40 00 64 A1 30 00 00 00 0F B6 40 02 0A C0 74 04 33 C0 87 00 B9 ?? ?? 00 00 8D BD B7 3B 40 00 8B F7 AC} /*EntryPoint*/
		
	condition:
		$str1 at (pe.entry_point)
}

rule execryptor : Protector
{
	meta:
		author="Kevin Falcoz"
		date_create="25/02/2013"
		description="EXECryptor"

	strings:
		$str1={E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 00 00 00 31 C0 89 41 14 89 41 18 80 A1 C1 00 00 00 FE C3 31 C0 64 FF 30 64 89 20 64 8F 05 00 00 00 00} /*EntryPoint*/
		
	condition:
		$str1 at (pe.entry_point)
}

rule winrar_sfx : Packer
{
	meta:
		author="Kevin Falcoz"
		date_create="18/03/2013"
		description="Winrar SFX Archive"
	
	strings:
		$signature1={00 00 53 6F 66 74 77 61 72 65 5C 57 69 6E 52 41 52 20 53 46 58 00} 
		
	condition:
		$signature1
}

rule mpress_2_xx_x86 : Packer
{
	meta:
		author="Kevin Falcoz"
		date_create="19/03/2013"
		last_edit="24/03/2013"
		description="MPRESS v2.XX x86  - no .NET"
	
	strings:
		$signature1={60 E8 00 00 00 00 58 05 [2] 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 88 04 31 75 F6}
		
	condition:
		$signature1 at (pe.entry_point)
}

rule mpress_2_xx_x64 : Packer
{
	meta:
		author="Kevin Falcoz"
		date_create="19/03/2013"
		last_edit="24/03/2013"
		description="MPRESS v2.XX x64  - no .NET"
	
	strings:
		$signature1={57 56 53 51 52 41 50 48 8D 05 DE 0A 00 00 48 8B 30 48 03 F0 48 2B C0 48 8B FE 66 AD C1 E0 0C 48 8B C8 50 AD 2B C8 48 03 F1 8B C8 57 44 8B C1 FF C9 8A 44 39 06 88 04 31} 
		
	condition:
		$signature1 at (pe.entry_point)
}

rule mpress_2_xx_net : Packer
{
	meta:
		author="Kevin Falcoz"
		date_create="24/03/2013"
		description="MPRESS v2.XX .NET"
	
	strings:
		$signature1={21 46 00 69 00 6C 00 65 00 20 00 69 00 73 00 20 00 69 00 6E 00 76 00 61 00 6C 00 69 00 64 00 2E 00 00 0D 4D 00 50 00 52 00 45 00 53 00 53 00 00 00 00 00 2D 2D 93 6B 35 04 2E 43 85 EF}
		
	condition:
		$signature1
}

rule rpx_1_xx : Packer
{
	meta:
		author="Kevin Falcoz"
		date_create="24/03/2013"
		description="RPX v1.XX"
	
	strings:
		$signature1= "RPX 1."
		$signature2= "Copyright %C2 %A9  20"
		
	condition:
		$signature1 and $signature2
}

rule mew_11_xx : Packer
{
	meta:
		author="Kevin Falcoz"
		date_create="25/03/2013"
		description="MEW 11"
	
	strings:
		$signature1={50 72 6F 63 41 64 64 72 65 73 73 00 E9 [6-7] 00 00 00 00 00 00 00 00 00 [7] 00}
		$signature2="MEW"
		
	condition:
		$signature1 and $signature2
}

rule yoda_crypter_1_2 : Crypter
{
	meta:
		author="Kevin Falcoz"
		date_create="15/04/2013"
		description="Yoda Crypter 1.2"
	
	strings:
		$signature1={60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 AC [19] EB 01 [27] AA E2 CC}
		
	condition:
		$signature1 at (pe.entry_point)
}

rule yoda_crypter_1_3 : Crypter
{
	meta:
		author="Kevin Falcoz"
		date_create="15/04/2013"
		description="Yoda Crypter 1.3"
	
	strings:
		$signature1={55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 6C 28 40 00 B9 5D 34 40 00 81 E9 C6 28 40 00 8B D5 81 C2 C6 28 40 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC}
		
	condition:
		$signature1 at (pe.entry_point)
}

rule universal_1337_stealer_serveur : Stealer
{
	meta:
		author="Kevin Falcoz"
		date="24/02/2013"
		description="Universal 1337 Stealer Serveur"
		
	strings:
		$signature1={2A 5B 53 2D 50 2D 4C 2D 49 2D 54 5D 2A} /*[S-P-L-I-T]*/
		$signature2={2A 5B 48 2D 45 2D 52 2D 45 5D 2A} /*[H-E-R-E]*/
		$signature3={46 54 50 7E} /*FTP~*/
		$signature4={7E 31 7E 31 7E 30 7E 30} /*~1~1~0~0*/
		
	condition:
		$signature1 and $signature2 or $signature3 and $signature4
}
rule Wabot : Worm
{
	meta:
		author="Kevin Falcoz"
		date="14/08/2015"
		description="Wabot Trojan Worm"

	strings:
		$signature1={43 3A 5C 6D 61 72 69 6A 75 61 6E 61 2E 74 78 74}
		$signature2={73 49 52 43 34}

	condition:
		$signature1 and $signature2
}

rule xtreme_rat : Trojan
{
	meta:
		author="Kevin Falcoz"
		date="23/02/2013"
		description="Xtreme RAT"
	
	strings:
		$signature1={58 00 54 00 52 00 45 00 4D 00 45} /*X.T.R.E.M.E*/
		
	condition:
		$signature1
}

rule YahLover : Worm
{
	meta:
		author="Kevin Falcoz"
		date="10/06/2013"
		description="YahLover"
		
	strings:
		$signature1={42 00 49 00 54 00 52 00 4F 00 54 00 41 00 54 00 45 00 00 00 42 00 49 00 54 00 53 00 48 00 49 00 46 00 54 00 00 00 00 00 42 00 49 00 54 00 58 00 4F 00 52}
		
	condition:
		$signature1
}

rule Zegost : Trojan
{
	meta:
		author="Kevin Falcoz"
		date="10/06/2013"
		description="Zegost Trojan"
		
	strings:
		$signature1={39 2F 66 33 30 4C 69 35 75 62 4F 35 44 4E 41 44 44 78 47 38 73 37 36 32 74 71 59 3D}
		$signature2={00 BA DA 22 51 42 6F 6D 65 00}
		
	condition:
		$signature1 and $signature2
}/*

  Copyright
  =========
  Copyright (C) 2013 Trustwave Holdings, Inc.
 
  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
 
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.
 
  You should have received a copy of the GNU General Public License
  along with this program. If not, see <http://www.gnu.org/licenses/>

  ---------

  This YARA signature will attempt to detect instances of the newly discovered
  Apache iFrame injection module. Please take a minute to look at the references
  contained in the metadata section of the rule for further information.

  This signature attempts to identify the unique XTEA function used for config
  decryption. Additionally, it will attempt to identify the XTEA keys discovered
  in the samples already encountered by SpiderLabs.

*/


rule apacheInjectionXtea {
  meta:
    description = "Detection for new Apache injection module spotted in wild."
    in_the_wild = true
    reference1 = "http://blog.sucuri.net/2013/06/new-apache-module-injection.html"
    reference2 = "TBD"

  strings:
    $xteaFunction = { 8B 0F 8B 57 04 B8 F3 3A 62 CC 41 89 C0 41 89 C9 41 89 CA 41 C1 E8 0B 41 C1 E2 04 41 C1 E9 05 41 83 E0 03 45 31 D1 46 8B 04 86 41 01 C9 41 01 C0 05 47 86 C8 61 45 31 C8 44 29 C2 49 89 C0 41 83 E0 03 41 89 D1 41 89 D2 46 8B 04 86 41 C1 E9 05 41 C1 E2 04 45 31 D1 41 01 D1 41 01 C0 45 31 C8 44 29 C1 85 C0 75 A3 89 0F 89 57 04 C3 }
    $xteaKey1 = { 4A F5 5E 5E B9 8A E1 63 30 16 B6 15 23 51 66 03 }
    $xteaKey2 = { 68 2C 16 4A 30 A8 14 1F 1E AD 0D 24 E1 0E 10 01 }

  condition:
    $xteaFunction or any of ($xteaKey*)
}
rule cherryPicker
{
    meta:
        author = "Trustwave SpiderLabs"
        date = "2015-11-17"
        description = "Used to detect Cherry Picker malware.  Blog: https://www.trustwave.com/Resources/SpiderLabs-Blog/Shining-the-Spotlight-on-Cherry-Picker-PoS-Malware/?page=1&year=0&month=0"
    strings:
        $string1 = "srch1mutex" nocase
        $string2 = "SYNC32TOOLBOX" nocase
        $string3 = "kb852310.dll"
        $config1 = "[config]" nocase
        $config2 = "timeout"
        $config3 = "r_cnt"
        $config4 = "f_passive"
        $config5 = "prlog"
    condition:
        any of ($string*) or all of ($config*)

}

rule cherryInstaller
{
    strings:
        $string1 = "(inject base: %08x)"
        $string2 = "injected ok"
        $string3 = "inject failed"
        $string4 = "-i name.dll - install path dll"
        $string5 = "-s name.dll procname|PID - inject dll into processes or PID"
        $fileinfect1 = "\\ServicePackFiles\\i386\\user32.dll"
        $fileinfect2 = "\\dllcache\\user32.dll"
        $fileinfect3 = "\\user32.tmp"

    condition:
        all of ($string*) or all of ($fileinfect*)
}
rule Punkey
{
  meta:
    author = "Trustwave SpiderLabs"
    date = "2015-04-09"
    description = "Used to detect Punkey malware.  Blog: https://www.trustwave.com/Resources/SpiderLabs-Blog/New-POS-Malware-Emerges---Punkey/"
  strings:
    $pdb1 = "C:\\Documents and Settings\\Administrator\\Desktop\\Verios\\jusched\\jusched32.pdb" nocase
    $pdb2 = "C:\\Documents and Settings\\Administrator\\Desktop\\Verios\\jusched\\troi.pdb" nocase
    $pdb3 = "D:\\freelancer\\gale.kreeb\\jusched10-19\\jusched32.pdb" nocase
    $pdb4 = "D:\\freelancer\\gale.kreeb\\jusched10-19\\troi.pdb" nocase
    $pdb5 = "C:\\Users\\iptables\\Desktop\\x86\\jusched32.pdb" nocase
    $pdb6 = "C:\\Users\\iptables\\Desktop\\x86\\troi.pdb"
    $pdb7 = "C:\\Users\\iptables\\Desktop\\27 Octomber\\jusched10-27\\troi.pdb" nocase
    $pdb8 = "D:\\work\\visualstudio\\jusched\\dllx64.pdb" nocase
    $string0 = "explorer.exe" nocase
    $string1 = "jusched.exe" nocase
    $string2 = "dllx64.dll" nocase
    $string3 = "exportDataApi" nocase
    $memory1 = "troi.exe"
    $memory2 = "unkey="
    $memory3 = "key="
    $memory4 = "UPDATE"
    $memory5 = "RUN"
    $memory6 = "SCANNING"
    $memory7 = "86afc43868fea6abd40fbf6d5ed50905"
    $memory8 = "f4150d4a1ac5708c29e437749045a39a"

  condition:
    (any of ($pdb*)) or (all of ($str*)) or (all of ($mem*))
}
