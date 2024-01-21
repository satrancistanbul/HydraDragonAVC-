rule GeorBotMemory
{
strings:
$a = {53 4F 46 54 57 41 52 45 5C 00 4D 69 63 72 6F 73 6F 66 74 5C 00 57 69 6E 64 6F 77 73 5C 43 75 72 72 65 6E 74 56 65 72 73 69 6F 6E 5C 00 52 75 6E 00 55 53 42 53 45 52 56}
$b = {73 79 73 74 65 6D 33 32 5C 75 73 62 73 65 72 76 2E 65 78 65}
$c = {5C 75 73 62 73 65 72 76 2E 65 78 65}
condition:
$a and ($b or $c)
}
rule Hangover_ron_babylon
{
  strings:
    $a = "Content-Disposition: form-data; name=\"uploaddir\""
    $b1 = "MBVDFRESCT"
    $b2 = "EMSCBVDFRT"
    $b3 = "EMSFRTCBVD"
    $b4= "sendFile"
    $b5 = "BUGMAAL"
    $b6 = "sMAAL"
    $b7 = "SIMPLE"
    $b8 = "SPLIME"
    $b9 = "getkey.php"
    $b10 = "MBVDFRESCT"
    $b11 = "DSMBVCTFRE"
    $b12 = "MBESCVDFRT"
    $b13 = "TCBFRVDEMS"
    $b14 = "DEMOMAKE"
    $b15 = "DEMO"
    $b16 = "UPHTTP"
    

    $c1 = "F39D45E70395ABFB8D8D2BFFC8BBD152"
    $c2 = "90B452BFFF3F395ABDC878D8BEDBD152"
    $c3 = "FFF3F395A90B452BB8BEDC878DDBD152"
    $c4 = "5A9DCB8FFF3F02B8B45BE39D152"
    $c5 = "5A902B8B45BEDCB8FFF3F39D152"
    $c6 = "78DDB5A902BB8FFF3F398B45BEDCD152"
    $c7 = "905ABEB452BFFFBDC878D83F39DBD152"
    $c8 = "D2BFFC8BBD152F3B8D89D45E70395ABF"
    $c9 = "8765F3F395A90B452BB8BEDC878"
    $c10 = "90ABDC878D8BEDBB452BFFF3F395D152"
    $c11 = "F12BDC94490B452AA8AEDC878DCBD187"
    
  condition:
    $a and (1 of ($b*) or 1 of ($c*))
    
}

rule Hangover_Fuddol {
    strings:
        $a = "\\Http downloader(fud)"
        $b = "Fileexists"
    condition:
        all of them

}

rule Hangover_UpdateEx {
    strings:
        $a1 = "UpdateEx"
        $a2 = "VBA6.DLL"
        $a3 = "MainEx"
        $a4 = "GetLogs"
        $a5 = "ProMan"
        $a6 = "RedMod"
        
    condition:
        all of them

}

rule Hangover_Tymtin_Degrab {
    strings:
        $a1 = "&dis=no&utp=op&mfol="
        $a2 = "value1=1&value2=2"
        
    condition:
        all of them

}


rule Hangover_Smackdown_Downloader {
    strings:
        $a1 = "DownloadComplete"
        $a2 = "DownloadProgress"
        $a3 = "DownloadError"
        $a4 = "UserControl"
        $a5 = "MSVBVM60.DLL"

        $b1 = "syslide"
        $b2 = "frmMina"
        $b3 = "Soundsman"
        $b4 = "New_upl"
        $b5 = "MCircle"
        $b6 = "shells_DataArrival"
        
    condition:
        3 of ($a*) and 1 of ($b*)

}


rule Hangover_Vacrhan_Downloader {
    strings:
        $a1 = "pranVacrhan"
        $a2 = "VBA6.DLL"
        $a3 = "Timer1"
        $a4 = "Timer2"
        $a5 = "IsNTAdmin"
        
    condition:
        all of them

}


rule Hangover_Smackdown_various {
    strings:
        $a1 = "pranVacrhan"
        $a2 = "NaramGaram"
        $a3 = "vampro"
        $a4 = "AngelPro"
        
        $b1 = "VBA6.DLL"
        $b2 = "advpack"
        $b3 = "IsNTAdmin"
        
        
    condition:
        1 of ($a*) and all of ($b*)

}

rule Hangover_Foler {
    strings:
        $a1 = "\\MyHood"
        $a2 = "UsbP"
        $a3 = "ID_MON"
        
    condition:
        all of them

}

rule Hangover_Appinbot {
    strings:
        $a1 = "CreateToolhelp32Snapshot"
        $a2 = "Process32First"
        $a3 = "Process32Next"
        $a4 = "FIDR/"
        $a5 = "SUBSCRIBE %d"
        $a6 = "CLOSE %d"
        
    condition:
        all of them

}

rule Hangover_Linog {
    strings:
        $a1 = "uploadedfile"
        $a2 = "Error in opening a file.."
        $a3 = "The file could not be opened"
        $a4 = "%sContent-Disposition: form-data; name=\"%s\";filename=\"%s\""

    condition:
        all of them

}


rule Hangover_Iconfall {
    strings:
        $a1 = "iconfall"
        $a2 = "78DDB5A902BB8FFF3F398B45BEDCD152"
        
    condition:
        all of them

}


rule Hangover_Deksila {
    strings:
        $a1 = "WinInetGet/0.1"
        $a2 = "dekstop2007.ico"
        $a3 = "mozila20"
        
    condition:
        all of them

}

rule Hangover_Auspo {
    strings:
        $a1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV2)"
        $a2 = "POWERS"
        $a3 = "AUSTIN"
        
    condition:
        all of them

}

rule Hangover_Slidewin {
    strings:
        $a1 = "[NumLock]"
        $a2 = "[ScrlLock]"
        $a3 = "[LtCtrl]"
        $a4 = "[RtCtrl]"
        $a5 = "[LtAlt]"
        $a6 = "[RtAlt]"
        $a7 = "[HomePage]"
        $a8 = "[MuteOn/Off]"
        $a9 = "[VolDn]"
        $a10 = "[VolUp]"
        $a11 = "[Play/Pause]"
        $a12 = "[MailBox]"
        $a14 = "[Calc]"
        $a15 = "[Unknown]"
        
    condition:
        all of them

}


rule Hangover_Gimwlog {
    strings:
        $a1 = "file closed---------------------"
        $a2 = "new file------------------"
        $a3 = "md C:\\ApplicationData\\Prefetch\\"
        
    condition:
        all of them

}


rule Hangover_Gimwup {
    strings:
        $a1 = "=======inside while==========="
        $a2 = "scan finished"
        $a3 = "logFile.txt"
        
    condition:
        all of them

}

rule Hangover2_Downloader {

  strings:

    $a = "WinInetGet/0.1" wide ascii

    $b = "Excep while up" wide ascii

    $c = "&file=" wide ascii

    $d = "&str=" wide ascii

    $e = "?cn=" wide ascii

  condition:

    all of them
}

rule Hangover2_stealer {

  strings:

    $a = "MyWebClient" wide ascii

    $b = "Location: {[0-9]+}" wide ascii

    $c = "[%s]:[C-%s]:[A-%s]:[W-%s]:[S-%d]" wide ascii

  condition:

    all of them
}

rule Hangover2_backdoor_shell {

  strings:

    $a = "Shell started at: " wide ascii

    $b = "Shell closed at: " wide ascii

    $c = "Shell is already closed!" wide ascii

    $d = "Shell is not Running!" wide ascii

  condition:

    all of them
}

rule Hangover2_Keylogger {

  strings:

    $a = "iconfall" wide ascii

    $b = "/c ipconfig /all > " wide ascii

    $c = "Global\\{CHKAJESKRB9-35NA7-94Y436G37KGT}" wide ascii

  condition:

    all of them
}


rule KINS_dropper {
	meta:
		author = "AlienVault Labs aortega@alienvault.com"
		description = "Match protocol, process injects and windows exploit present in KINS dropper"
	strings:
		// Network protocol
		$n1 = "tid=%d&ta=%s-%x" fullword
		$n2 = "fid=%d" fullword
		$n3 = "%[^.].%[^(](%[^)])" fullword
		// Injects
		$i0 = "%s [%s %d] 77 %s"
		$i01 = "Global\\%s%x"
		$i1 = "Inject::InjectProcessByName()"
		$i2 = "Inject::CopyImageToProcess()"
		$i3 = "Inject::InjectProcess()"
		$i4 = "Inject::InjectImageToProcess()"
		$i5 = "Drop::InjectStartThread()"
		// UAC bypass
		$uac1 = "ExploitMS10_092"
		$uac2 = "\\globalroot\\systemroot\\system32\\tasks\\" ascii wide
		$uac3 = "<RunLevel>HighestAvailable</RunLevel>" ascii wide
	condition:
		2 of ($n*) and 2 of ($i*) and 2 of ($uac*)
}

rule KINS_DLL_zeus {
	meta:
		author = "AlienVault Labs aortega@alienvault.com"
		description = "Match default bot in KINS leaked dropper, Zeus"
	strings:
		// Network protocol
		$n1 = "%BOTID%" fullword
		$n2 = "%opensocks%" fullword
		$n3 = "%openvnc%" fullword
		$n4 = /Global\\(s|v)_ev/ fullword
		// Crypted strings
		$s1 = "\x72\x6E\x6D\x2C\x36\x7D\x76\x77"
		$s2 = "\x18\x04\x0F\x12\x16\x0A\x1E\x08\x5B\x11\x0F\x13"
		$s3 = "\x39\x1F\x01\x07\x15\x19\x1A\x33\x19\x0D\x1F"
		$s4 = "\x62\x6F\x71\x78\x63\x61\x7F\x69\x2D\x67\x79\x65"
		$s5 = "\x6F\x69\x7F\x6B\x61\x53\x6A\x7C\x73\x6F\x71"
	condition:
		all of ($n*) and 1 of ($s*)
}

rule leverage_a
{
	meta:
		author = "earada@alienvault.com"
		version = "1.0"
		description = "OSX/Leverage.A"
		date = "2013/09"
	strings:
		$a1 = "ioreg -l | grep \"IOPlatformSerialNumber\" | awk -F"
		$a2 = "+:Users:Shared:UserEvent.app:Contents:MacOS:"
		$a3 = "rm '/Users/Shared/UserEvent.app/Contents/Resources/UserEvent.icns'"
		$script1 = "osascript -e 'tell application \"System Events\" to get the hidden of every login item'"
		$script2 = "osascript -e 'tell application \"System Events\" to get the name of every login item'"
		$script3 = "osascript -e 'tell application \"System Events\" to get the path of every login item'"
		$properties = "serverVisible \x00"
	condition:
		all of them
}

rule Careto {
	meta:
		author = "AlienVault (Alberto Ortega)"
		description = "TheMask / Careto generic malware signature"
		reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"
	strings:

		/* General */
		$name1 = "Careto" ascii wide
		$s_1 = "GetSystemReport" ascii wide
		$s_2 = "SystemReport.txt" ascii wide
		$s_3 = /URL_AUX\w*=/ ascii wide
		$s_4 = /CaretoPruebas.+release/

		/* Certificate */
		$sign_0 = "Sofia"
		$sign_1 = "TecSystem Ltd"
		$sign_2 = "<<<Obsolete>>>" wide

		/* Encryption keys */
		$rc4_1 = "!$7be&.Kaw-12[}" ascii wide
		$rc4_2 = "Caguen1aMar" ascii wide
		/* http://laboratorio.blogs.hispasec.com/2014/02/analisis-del-algoritmo-de-descifrado.html */
		$rc4_3 = {8d 85 86 8a 8f 80 88 83 8d 82 88 85 86 8f 8f 87 8d 82 83 82 8c 8e 83 8d 89 82 86 87 82 83 83 81}

		/* Decryption routine fragment */
		$dec_1 = {8b 4d 08 0f be 04 59 0f be 4c 59 01 2b c7 c1 e0 04 2b cf 0b c1 50 8d 85 f0 fe ff ff}
		$dec_2 = {8b 4d f8 8b 16 88 04 11 8b 06 41 89 4d f8 c6 04 01 00 43 3b 5d fc}

	condition:
		$name1 and (any of ($s_*)) or all of ($sign_*) or any of ($rc4_*) or all of ($dec_*)
}

rule Careto_SGH {
	meta:
		author = "AlienVault (Alberto Ortega)"
		description = "TheMask / Careto SGH component signature"
		reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"
	strings:
		$m1 = "PGPsdkDriver" ascii wide fullword
		$m2 = "jpeg1x32" ascii wide fullword
		$m3 = "SkypeIE6Plugin" ascii wide fullword
		$m4 = "CDllUninstall" ascii wide fullword
	condition:
		2 of them
}

rule Careto_OSX_SBD {
	meta:
		author = "AlienVault (Alberto Ortega)"
		description = "TheMask / Careto OSX component signature"
		reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"
	strings:
		/* XORed "/dev/null strdup() setuid(geteuid())" */
		$1 = {FF 16 64 0A 7E 1A 63 4D 21 4D 3E 1E 60 0F 7C 1A 65 0F 74 0B 3E 1C 7F 12}
	condition:
		all of them
}

rule Careto_CnC {
	meta:
		author = "AlienVault (Alberto Ortega)"
		description = "TheMask / Careto CnC communication signature"
		reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"
	strings:
		$1 = "cgi-bin/commcgi.cgi" ascii wide
		$2 = "Group" ascii wide
		$3 = "Install" ascii wide
		$4 = "Bn" ascii wide
	condition:
		all of them
}

rule Careto_CnC_domains {
	meta:
		author = "AlienVault (Alberto Ortega)"
		description = "TheMask / Careto known command and control domains"
		reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"
	strings:
		$1 = "linkconf.net" ascii wide nocase
		$2 = "redirserver.net" ascii wide nocase
		$3 = "swupdt.com" ascii wide nocase
	condition:
		any of them
}


rule sandboxdetect_misc : sandboxdetect
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
		description = "Sandbox detection tricks"

	strings:
		$sbxie1 = "sbiedll" nocase ascii wide

		// CWSandbox
		$prodid1 = "55274-640-2673064-23950" ascii wide
		$prodid2 = "76487-644-3177037-23510" ascii wide
		$prodid3 = "76487-337-8429955-22614" ascii wide

		$proc1 = "joeboxserver" ascii wide
		$proc2 = "joeboxcontrol" ascii wide
	condition:
		any of them
}


rule urausy_skype_dat {
	meta:
		author = "AlienVault Labs"
		description = "Yara rule to match against memory of processes infected by Urausy skype.dat"
	strings:
		$a = "skype.dat" ascii wide
		$b = "skype.ini" ascii wide
		$win1 = "CreateWindow"
		$win2 = "YIWEFHIWQ" ascii wide
		$desk1 = "CreateDesktop"
		$desk2 = "MyDesktop" ascii wide
	condition:
		$a and $b and (all of ($win*) or all of ($desk*))
}

