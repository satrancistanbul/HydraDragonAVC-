/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

import "pe"

rule apt_c16_win_memory_pcclient 
{
  meta:
    author = "@dragonthreatlab"
    md5 = "ec532bbe9d0882d403473102e9724557"
    description = "File matching the md5 above tends to only live in memory, hence the lack of MZ header check."
    date        = "2015/01/11" 
    reference   = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
  strings:
    $str1 = "Kill You" ascii
    $str2 = "%4d-%02d-%02d %02d:%02d:%02d" ascii
    $str3 = "%4.2f  KB" ascii
    $encodefunc = {8A 08 32 CA 02 CA 88 08 40 4E 75 F4}  
  condition:
    all of them
}

rule apt_c16_win_disk_pcclient 
{
  meta:
    author = "@dragonthreatlab"
    md5 = "55f84d88d84c221437cd23cdbc541d2e"
    description = "Encoded version of pcclient found on disk"
    date        = "2015/01/11" 
    reference   = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
  strings:
    $header = {51 5C 96 06 03 06 06 06 0A 06 06 06 FF FF 06 06 BE 06 06 06 06 06 06 06 46 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 EE 06 06 06 10 1F BC 10 06 BA 0D D1 25 BE 05 52 D1 25 5A 6E 6D 73 26 76 74 6F 67 74 65 71 26 63 65 70 70 6F 7A 26 64 69 26 74 79 70 26 6D 70 26 4A 4F 53 26 71 6F 6A 69 30 11 11 0C 2A 06 06 06 06 06 06 06 73 43 96 1B 37 24 00 4E 37 24 00 4E 37 24 00 4E BA 40 F6 4E 39 24 00 4E 5E 41 FA 4E 33 24 00 4E 5E 41 FC 4E 39 24 00 4E 37 24 FF 4E 0D 24 00 4E FA 31 A3 4E 40 24 00 4E DF 41 F9 4E 36 24 00 4E F6 2A FE 4E 38 24 00 4E DF 41 FC 4E 38 24 00 4E 54 6D 63 6E 37 24 00 4E 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 56 49 06 06 52 05 09 06 5D 87 8C 5A 06 06 06 06 06 06 06 06 E6 06 10 25 0B 05 08 06 06 1C 06 06 06 1A 06 06 06 06 06 06 E5 27 06 06 06 16 06 06 06 36 06 06 06 06 06 16 06 16 06 06 06 04 06 06 0A 06 06 06 06 06 06 06 0A 06 06 06 06 06 06 06 06 76 06 06 06 0A 06 06 06 06 06 06 04 06 06 06 06 06 16 06 06 16 06 06}
  condition:
    $header at 0
}

rule apt_c16_win32_dropper 
{
  meta:
    author = "@dragonthreatlab"
    md5 = "ad17eff26994df824be36db246c8fb6a"
    description = "APT malware used to drop PcClient RAT"
    date        = "2015/01/11" 
    reference   = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
  strings:
    $mz = {4D 5A}
    $str1 = "clbcaiq.dll" ascii
    $str2 = "profapi_104" ascii
    $str3 = "/ShowWU" ascii
    $str4 = "Software\\Microsoft\\Windows\\CurrentVersion\\" ascii
    $str5 = {8A 08 2A CA 32 CA 88 08 40 4E 75 F4 5E}
  condition:
    $mz at 0 and all of ($str*)
}

rule apt_c16_win_swisyn 
{
  meta:
    author = "@dragonthreatlab"
    md5 = "a6a18c846e5179259eba9de238f67e41"
    description = "File matching the md5 above tends to only live in memory, hence the lack of MZ header check."
    date        = "2015/01/11" 
    reference   = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
  strings:
    $mz = {4D 5A}
    $str1 = "/ShowWU" ascii
    $str2 = "IsWow64Process"
    $str3 = "regsvr32 "
    $str4 = {8A 11 2A 55 FC 8B 45 08 88 10 8B 4D 08 8A 11 32 55 FC 8B 45 08 88 10}
  condition:
    $mz at 0 and all of ($str*)
}

rule apt_c16_win_wateringhole 
{
  meta:
    author = "@dragonthreatlab"
    description = "Detects code from APT wateringhole"
    date        = "2015/01/11" 
    reference   = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
  strings:
    $str1 = "function runmumaa()"
    $str2 = "Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String("
    $str3 = "function MoSaklgEs7(k)"
  condition:
    any of ($str*)
}

rule apt_c16_win64_dropper
{
    meta:
        author      = "@dragonthreatlab"
        date        = "2015/01/11" 
        description = "APT malware used to drop PcClient RAT"
        reference   = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"

    strings:
        $mz = { 4D 5A }
        $str1 = "clbcaiq.dll" ascii
        $str2 = "profapi_104" ascii
        $str3 = "\\Microsoft\\wuauclt\\wuauclt.dat" ascii
        $str4 = { 0F B6 0A 48 FF C2 80 E9 03 80 F1 03 49 FF C8 88 4A FF 75 EC }

    condition:
        $mz at 0 and all of ($str*)
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-08-08
	Identifier: Cheshire Cat
	Version: 0.1 
*/

/* Rule Set ----------------------------------------------------------------- */

rule CheshireCat_Sample2 {
	meta:
		description = "Auto-generated rule - file dc18850d065ff6a8364421a9c8f9dd5fcce6c7567f4881466cee00e5cd0c7aa8"
		author = "Florian Roth"
		reference = "https://malware-research.org/prepare-father-of-stuxnet-news-are-coming/"
		date = "2015-08-08"
		score = 70
		hash = "dc18850d065ff6a8364421a9c8f9dd5fcce6c7567f4881466cee00e5cd0c7aa8"
	strings:
		$s0 = "mpgvwr32.dll" fullword ascii
		$s1 = "Unexpected failure of wait! (%d)" fullword ascii
		$s2 = "\"%s\" /e%d /p%s" fullword ascii
		$s4 = "error in params!" fullword ascii
		$s5 = "sscanf" fullword ascii
		$s6 = "<>Param : 0x%x" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 4 of ($s*)
}

/* Generic Rules ----------------------------------------------------------- */
/* Gen1 is more exact than Gen2 - until now I had no FPs with Gen2 */

rule CheshireCat_Gen1 {
	meta:
		description = "Auto-generated rule - file ec41b029c3ff4147b6a5252cb8b659f851f4538d4af0a574f7e16bc1cd14a300"
		author = "Florian Roth"
		reference = "https://malware-research.org/prepare-father-of-stuxnet-news-are-coming/"
		date = "2015-08-08"
		super_rule = 1
		score = 90
		hash1 = "ec41b029c3ff4147b6a5252cb8b659f851f4538d4af0a574f7e16bc1cd14a300"
		hash2 = "32159d2a16397823bc882ddd3cd77ecdbabe0fde934e62f297b8ff4d7b89832a"
		hash3 = "63735d555f219765d486b3d253e39bd316bbcb1c0ec595ea45ddf6e419bef3cb"
		hash4 = "c074aeef97ce81e8c68b7376b124546cabf40e2cd3aff1719d9daa6c3f780532"
	strings:
		$x1 = "CAPESPN.DLL" fullword wide
		$x2 = "WINF.DLL" fullword wide
		$x3 = "NCFG.DLL" fullword wide
		$x4 = "msgrthlp.dll" fullword wide
		$x5 = "Local\\{c0d9770c-9841-430d-b6e3-575dac8a8ebf}" fullword ascii
		$x6 = "Local\\{1ef9f94a-5664-48a6-b6e8-c3748db459b4}" fullword ascii

		$a1 = "Interface\\%s\\info" fullword ascii
		$a2 = "Interface\\%s\\info\\%s" fullword ascii
		$a3 = "CLSID\\%s\\info\\%s" fullword ascii
		$a4 = "CLSID\\%s\\info" fullword ascii

		$b1 = "Windows Shell Icon Handler" fullword wide
		$b2 = "Microsoft Shell Icon Handler" fullword wide

		$s1 = "\\StringFileInfo\\%s\\FileVersion" fullword ascii
		$s2 = "CLSID\\%s\\AuxCLSID" fullword ascii
		$s3 = "lnkfile\\shellex\\IconHandler" fullword ascii
		$s4 = "%s: %s, %.2hu %s %hu %2.2hu:%2.2hu:%2.2hu GMT" fullword ascii
		$s5 = "%sMutex" fullword ascii
		$s6 = "\\ShellIconCache" fullword ascii
		$s7 = "+6Service Pack " fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 350KB and 7 of ($s*) and 2 of ($a*) and 1 of ($b*) and 1 of ($x*)
}

rule CheshireCat_Gen2 {
	meta:
		description = "Auto-generated rule - from files 32159d2a16397823bc882ddd3cd77ecdbabe0fde934e62f297b8ff4d7b89832a, 63735d555f219765d486b3d253e39bd316bbcb1c0ec595ea45ddf6e419bef3cb"
		author = "Florian Roth"
		reference = "https://malware-research.org/prepare-father-of-stuxnet-news-are-coming/"
		date = "2015-08-08"
		super_rule = 1
		score = 70
		hash1 = "ec41b029c3ff4147b6a5252cb8b659f851f4538d4af0a574f7e16bc1cd14a300"
		hash2 = "32159d2a16397823bc882ddd3cd77ecdbabe0fde934e62f297b8ff4d7b89832a"
		hash3 = "63735d555f219765d486b3d253e39bd316bbcb1c0ec595ea45ddf6e419bef3cb"
		hash4 = "c074aeef97ce81e8c68b7376b124546cabf40e2cd3aff1719d9daa6c3f780532"
	strings:
		$a1 = "Interface\\%s\\info" fullword ascii
		$a2 = "Interface\\%s\\info\\%s" fullword ascii
		$a3 = "CLSID\\%s\\info\\%s" fullword ascii
		$a4 = "CLSID\\%s\\info" fullword ascii

		$b1 = "Windows Shell Icon Handler" fullword wide
		$b2 = "Microsoft Shell Icon Handler" fullword wide

		$s1 = "\\StringFileInfo\\%s\\FileVersion" fullword ascii
		$s2 = "CLSID\\%s\\AuxCLSID" fullword ascii
		$s3 = "lnkfile\\shellex\\IconHandler" fullword ascii
		$s4 = "%s: %s, %.2hu %s %hu %2.2hu:%2.2hu:%2.2hu GMT" fullword ascii
		$s5 = "%sMutex" fullword ascii
		$s6 = "\\ShellIconCache" fullword ascii
		$s7 = "+6Service Pack " fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 7 of ($s*) and 2 of ($a*) and 1 of ($b*)
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

import "pe"


rule apt_hellsing_implantstrings : PE
{ 
	meta:
		Author		= "Costin Raiu, Kaspersky Lab"
		Date		= "2015-04-07"
		Description	= "detection for Hellsing implants"
		Reference	= "http://securelist.com/analysis/publications/69567/the-chronicles-of-the-hellsing-apt-the-empire-strikes-back"

	strings: 
		$mz="MZ"

		$a1="the file uploaded failed !" 
		$a2="ping 127.0.0.1"
		
		$b1="the file downloaded failed !" 
		$b2="common.asp"
		
		$c="xweber_server.exe" 
		$d="action="

		$debugpath1="d:\\Hellsing\\release\\msger\\" nocase 
		$debugpath2="d:\\hellsing\\sys\\xrat\\" nocase 
		$debugpath3="D:\\Hellsing\\release\\exe\\" nocase 
		$debugpath4="d:\\hellsing\\sys\\xkat\\" nocase 
		$debugpath5="e:\\Hellsing\\release\\clare" nocase 
		$debugpath6="e:\\Hellsing\\release\\irene\\" nocase 
		$debugpath7="d:\\hellsing\\sys\\irene\\" nocase

		$e="msger_server.dll"
		$f="ServiceMain"

	condition:
		($mz at 0) and (all of ($a*)) or (all of ($b*)) or ($c and $d) or (any of ($debugpath*)) or ($e and $f) and filesize < 500000
}

rule apt_hellsing_installer : PE
{
	meta:
		Author		= "Costin Raiu, Kaspersky Lab"
		Date		= "2015-04-07"
		Description	= "detection for Hellsing xweber/msger installers"
		Reference	= "http://securelist.com/analysis/publications/69567/the-chronicles-of-the-hellsing-apt-the-empire-strikes-back" 

	strings: 
		$mz="MZ"
		
		$cmd="cmd.exe /c ping 127.0.0.1 -n 5&cmd.exe /c del /a /f \"%s\""
		
		$a1="xweber_install_uac.exe"
		$a2="system32\\cmd.exe" wide
		$a4="S11SWFOrVwR9UlpWRVZZWAR0U1aoBHFTUl2oU1Y=" 
		$a5="S11SWFOrVwR9dnFTUgRUVlNHWVdXBFpTVgRdUlpWRVZZWARdUqhZVlpFR1kEUVNSXahTVgRaU1YEUVNSXahTVl1SWwRZValdVFFZUqgQBF1SWlZFVllYBFRTVqg=" $a6="7dqm2ODf5N/Y2N/m6+br3dnZpunl44g="
		$a7="vd/m7OXd2ai/5u7a59rr7Ki45drcqMPl5t/c5dqIZw==" 
		$a8="vd/m7OXd2ai/usPl5qjY2uXp69nZqO7l2qjf5u7a59rr7Kjf5tzr2u7n6euo4+Xm39zl2qju5dqo4+Xm39zl2t/m7ajr19vf2OPr39rj5eaZmqbs5OSI Njl2tyI" $a9="C:\\Windows\\System32\\sysprep\\sysprep.exe" wide 
		$a10="%SystemRoot%\\system32\\cmd.exe" wide 
		$a11="msger_install.dll"
		$a12={00 65 78 2E 64 6C 6C 00}

	condition:
		($mz at 0) and ($cmd and (2 of ($a*))) and filesize < 500000
}

rule apt_hellsing_proxytool : PE
{
	meta:
		Author		= "Costin Raiu, Kaspersky Lab"
		Date		= "2015-04-07"
		Description	= "detection for Hellsing proxy testing tool"
		Reference	= "http://securelist.com/analysis/publications/69567/the-chronicles-of-the-hellsing-apt-the-empire-strikes-back" 

	strings: 
		$mz="MZ"
		$a1="PROXY_INFO: automatic proxy url => %s " 
		$a2="PROXY_INFO: connection type => %d " 
		$a3="PROXY_INFO: proxy server => %s " 
		$a4="PROXY_INFO: bypass list => %s " 
		$a5="InternetQueryOption failed with GetLastError() %d" 
		$a6="D:\\Hellsing\\release\\exe\\exe\\" nocase

	condition:
		($mz at 0) and (2 of ($a*)) and filesize < 300000
}

rule apt_hellsing_xkat : PE
{
	meta:
		Author		= "Costin Raiu, Kaspersky Lab"
		Date		= "2015-04-07"
		Description	= "detection for Hellsing xKat tool"
		Reference	= "http://securelist.com/analysis/publications/69567/the-chronicles-of-the-hellsing-apt-the-empire-strikes-back"

	strings:
		$mz="MZ"
		$a1="\\Dbgv.sys"
		$a2="XKAT_BIN"
		$a3="release sys file error."
		$a4="driver_load error. "
		$a5="driver_create error."
		$a6="delete file:%s error."
		$a7="delete file:%s ok."
		$a8="kill pid:%d error."
		$a9="kill pid:%d ok."
		$a10="-pid-delete"
		$a11="kill and delete pid:%d error."
		$a12="kill and delete pid:%d ok."

	condition:
		($mz at 0) and (6 of ($a*)) and filesize < 300000
}

rule apt_hellsing_msgertype2 : PE
{
	meta:
		Author		= "Costin Raiu, Kaspersky Lab"
		Date		= "2015-04-07"
		Description	= "detection for Hellsing msger type 2 implants"
		Reference	= "http://securelist.com/analysis/publications/69567/the-chronicles-of-the-hellsing-apt-the-empire-strikes-back"

	strings:
		$mz="MZ"
		$a1="%s\\system\\%d.txt"
		$a2="_msger"
		$a3="http://%s/lib/common.asp?action=user_login&uid=%s&lan=%s&host=%s&os=%s&proxy=%s"
		$a4="http://%s/data/%s.1000001000"
		$a5="/lib/common.asp?action=user_upload&file="
		$a6="%02X-%02X-%02X-%02X-%02X-%02X"
	
	condition:
		($mz at 0) and (4 of ($a*)) and filesize < 500000
}

rule apt_hellsing_irene : PE
{
	meta:
		Author		= "Costin Raiu, Kaspersky Lab"
		Date		= "2015-04-07"
		Description	= "detection for Hellsing msger irene installer"
		Reference	= "http://securelist.com/analysis/publications/69567/the-chronicles-of-the-hellsing-apt-the-empire-strikes-back"

	strings: 
		$mz="MZ"
		$a1="\\Drivers\\usbmgr.tmp" wide
		$a2="\\Drivers\\usbmgr.sys" wide
		$a3="common_loadDriver CreateFile error! " 
		$a4="common_loadDriver StartService error && GetLastError():%d! " 
		$a5="irene" wide
		$a6="aPLib v0.43 - the smaller the better" 

	condition:
		($mz at 0) and (4 of ($a*)) and filesize < 500000
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule ZhoupinExploitCrew
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
  	$s1 = "zhoupin exploit crew" nocase
    $s2 = "zhopin exploit crew" nocase
  condition:
  	1 of them
}

rule BackDoorLogger
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "BackDoorLogger"
    $s2 = "zhuAddress"
  condition:
    all of them
}

rule Jasus
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "pcap_dump_open"
    $s2 = "Resolving IPs to poison..."
    $s3 = "WARNNING: Gateway IP can not be found"
  condition:
    all of them
}

rule LoggerModule
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "%s-%02d%02d%02d%02d%02d.r"
    $s2 = "C:\\Users\\%s\\AppData\\Cookies\\"
  condition:
    all of them
}

rule NetC
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "NetC.exe" wide
    $s2 = "Net Service"
  condition:
    all of them
}

rule ShellCreator2
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "ShellCreator2.Properties"
    $s2 = "set_IV"
  condition:
    all of them
}

rule SmartCopy2
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "SmartCopy2.Properties"
    $s2 = "ZhuFrameWork"
  condition:
    all of them
}

rule SynFlooder
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "Unable to resolve [ %s ]. ErrorCode %d"
    $s2 = "your target's IP is : %s"
    $s3 = "Raw TCP Socket Created successfully."
  condition:
    all of them
}

rule TinyZBot
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "NetScp" wide
    $s2 = "TinyZBot.Properties.Resources.resources"

    $s3 = "Aoao WaterMark"
    $s4 = "Run_a_exe"
    $s5 = "netscp.exe"

    $s6 = "get_MainModule_WebReference_DefaultWS"
    $s7 = "remove_CheckFileMD5Completed"
    $s8 = "http://tempuri.org/"

    $s9 = "Zhoupin_Cleaver"
  condition:
    ($s1 and $s2) or ($s3 and $s4 and $s5) or ($s6 and $s7 and $s8) or ($s9)
}

rule antivirusdetector
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
	strings:
		$s1 = "getShadyProcess"
		$s2 = "getSystemAntiviruses"
		$s3 = "AntiVirusDetector"
	condition:
		all of them
}

rule csext
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "COM+ System Extentions"
    $s2 = "csext.exe"
    $s3 = "COM_Extentions_bin"
  condition:
    all of them
}

rule kagent
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "kill command is in last machine, going back"
    $s2 = "message data length in B64: %d Bytes"
  condition:
    all of them
}

rule mimikatzWrapper
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "mimikatzWrapper"
    $s2 = "get_mimikatz"
  condition:
    all of them
}

rule pvz_in
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "LAST_TIME=00/00/0000:00:00PM$"
    $s2 = "if %%ERRORLEVEL%% == 1 GOTO line"
  condition:
    all of them
}

rule pvz_out
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "Network Connectivity Module" wide
    $s2 = "OSPPSVC" wide
  condition:
    all of them
}

rule wndTest
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "[Alt]" wide
    $s2 = "<< %s >>:" wide
    $s3 = "Content-Disposition: inline; comp=%s; account=%s; product=%d;"
  condition:
    all of them
}

rule zhCat
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "zhCat -l -h -tp 1234"
    $s2 = "ABC ( A Big Company )" wide
  condition:
    all of them
}

rule zhLookUp
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "zhLookUp.Properties"
  condition:
    all of them
}

rule zhmimikatz
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
    $s1 = "MimikatzRunner"
    $s2 = "zhmimikatz"
  condition:
    all of them
}

rule Zh0uSh311
{
  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"
  strings:
  	$s1 = "Zh0uSh311"
  condition:
  	all of them
}
