rule AnomaliLABS_Lazarus_wipe_file_routine {
    meta:
        author = "aaron shelmire"
        date = "2015 May 26"
        desc = "Yara sig to detect File Wiping routine of the Lazarus group"
        reference = "https://blog.anomali.com/evidence-of-stronger-ties-between-north-korea-and-swift-banking-attacks"
    strings:
        $rand_name_routine = { 99 B9 1A 00 00 00 F7 F9 80 C2 61 88 16 8A 46 01 46 84 C0 }
        /* imports for overwrite function */
        $imp_getTick = "GetTickCount"
        $imp_srand = "srand"
        $imp_CreateFile = "CreateFileA"
        $imp_SetFilePointer = "SetFilePointer"
        $imp_WriteFile = "WriteFile"
        $imp_FlushFileBuffers = "FlushFileBuffers"
        $imp_GetFileSizeEx = "GetFileSizeEx"
        $imp_CloseHandle = "CloseHandle"
        /* imports for rename function */
        $imp_strrchr = "strrchr"
        $imp_rand = "rand"
        $Move_File = "MoveFileA"
        $Move_FileEx = "MoveFileEx"
        $imp_RemoveDir = "RemoveDirectoryA"
        $imp_DeleteFile = "DeleteFileA"
        $imp_GetLastError = "GetLastError"
    condition:
        $rand_name_routine and (11 of ($imp_*)) and (1 of ($Move_*))
}rule Trojan_W32_Gh0stMiancha_1_0_0
{
	meta: 
		Reference = "http://www.contextis.com/documents/30/TA10009_20140127_-_CTI_Threat_Advisory_-_The_Monju_Incident1.pdf"
	strings:
		$0x = { 57 5b 5a 5a 51 57 40 34 31 67 2e 31 70 34 5c 40 40 44 3b 25 3a 19 1e 5c 7b 67 60 2e 34 31 67 2e 31 70 19 1e 55 77 77 71 64 60 2e 34 3e 3b 3e 19 1e 57 7b 7a 60 71 7a 60 39 40 6d 64 71 2e 34 60 71 6c 60 3b 7c 60 79 78 19 1e 44 66 7b 6c 6d 39 57 7b 7a 7a 71 77 60 7d 7b 7a 2e 34 5f 71 71 64 39 55 78 7d 62 71 19 1e 57 7b 7a 60 71 7a 60 39 78 71 7a 73 60 7c 2e 34 24 19 1e 19 1e }
		$1 = { 5c e7 99 bd e5 8a a0 e9 bb 91 5c }
 		$1x = { 48 f3 8d a9 f1 9e b4 fd af 85 48 }
 		$2 = "DllCanLoadNow"
 		$2x = { 50 78 78 57 75 7a 58 7b 75 70 5a 7b 63 }
 		$3x = { 5a 61 79 76 71 66 34 7b 72 34 67 61 76 7f 71 6d 67 2e 34 31 70 }
 		$4 = "JXNcc2hlbGxcb3Blblxjb21tYW5k"
		$4x = { 5e 4c 5a 77 77 26 7c 78 76 53 6c 77 76 27 56 78 76 78 6c 7e 76 26 25 60 4d 43 21 7f }
 		$5 = "SEFSRFdBUkVcREVTQ1JJUFRJT05cU3lzdGVtXENlbnRyYWxQcm9jZXNzb3JcMA=="
		$5x = { 47 51 52 47 46 52 70 56 41 7f 42 77 46 51 42 40 45 25 5e 5e 41 52 46 5e 40 24 21 77 41 27 78 6e 70 53 42 60 4c 51 5a 78 76 7a 46 6d 4d 43 6c 45 77 79 2d 7e 4e 4c 5a 6e 76 27 5e 77 59 55 29 29 }
 		$6 = "C:\\Users\\why\\"
 		$6x = { 57 2e 48 41 67 71 66 67 48 63 7c 6d 48 }
 		$7 = "g:\\ykcx\\"
 		$7x = { 73 2E 48 6D 7F 77 6C 48 }
 		$8 = "(miansha)"
 		$8x = { 3C 79 7D 75 7A 67 7C 75 3D }
 		$9 = "server(\xE5\xA3\xB3)"
 		$9x = { 7C 2E 48 26 24 25 27 3A 25 25 3A 26 21 48 67 71 66 62 71 66 3C F1 B7 A7 3D 48 46 71 78 71 75 67 71 48 67 71 66 62 71 66 3A 64 70 76 }
 		$cfgDecode = { 8a ?? ?? 80 c2 7a 80 f2 19 88 ?? ?? 41 3b ce 7c ??}
 	condition:
		any of them
}rule CrowdStrike_PutterPanda_01 : fourh_stack_strings putterpanda
	{
	meta:
		description = "PUTTER PANDA - 4H RAT"
                author = "CrowdStrike"
		date = "2014-03-30"
		version = "1.0"
		in_the_wild = true
		copyright = "CrowdStrike, Inc."
		actor = "PUTTER PANDA"
		yara_version = ">=1.6"
	
	strings:
	    $key_combined_1 = { C6 44 24 ?? 34 C6 44 24 ?? 36 C6 44 24 ?? 21 C6 44 24 ?? 79 C6 44 24 ?? 6F C6 44 24 ?? 00 }
	
	
	    // ebp
	    $keyfrag_ebp_1 = { C6 45 ?? 6C }    // ld66!yo
	    $keyfrag_ebp_2 = { C6 45 ?? 64 } 
	    $keyfrag_ebp_3 = { C6 45 ?? 34 }
	    $keyfrag_ebp_4 = { C6 45 ?? 36 }
	    $keyfrag_ebp_5 = { C6 45 ?? 21 }
	    $keyfrag_ebp_6 = { C6 45 ?? 79 }
	    $keyfrag_ebp_7 = { C6 45 ?? 6F }
	
	    // esp
	    $keyfrag_esp_1 = { c6 44 ?? 6C }    // ld66!yo
	    $keyfrag_esp_2 = { c6 44 ?? 64 }
	    $keyfrag_esp_3 = { c6 44 ?? 34 }
	    $keyfrag_esp_4 = { c6 44 ?? 36 }
	    $keyfrag_esp_5 = { c6 44 ?? 21 }
	    $keyfrag_esp_6 = { c6 44 ?? 79 }
	    $keyfrag_esp_7 = { c6 44 ?? 6F }
	
	    // reduce FPs by checking for some common strings
	    $check_zeroes = "0000000"
	    $check_param = "Invalid parameter"
	    $check_ercv = "ercv= %d"
	    $check_unk = "unknown"
	
	condition:
	    any of ($key_combined*) or 
	    (1 of ($check_*) and
	        (
	            (
	                all of ($keyfrag_ebp_*) and
	                for any i in (1..#keyfrag_ebp_5) : (
	                    for all of ($keyfrag_ebp_*): ($ in (@keyfrag_ebp_5[i]-100..@keyfrag_ebp_5[i]+100))
	                )
	            )
	            or
	            (
	                for any i in (1..#keyfrag_esp_5) : (
	                    for all of ($keyfrag_esp_*): ($ in (@keyfrag_esp_5[i]-100..@keyfrag_esp_5[i]+100))
	                )
	            )
	        )
	    )
	}
    
rule CrowdStrike_PutterPanda_02 : rc4_dropper putterpanda
	{
	meta:
		description = "PUTTER PANDA - RC4 dropper"
		date = "2014-03-30"
		version = "1.0"
		in_the_wild = true
		copyright = "CrowdStrike, Inc."
		actor = "PUTTER PANDA"
	
	strings:
	    $res_lock = "LockResource"
	    $res_size = "SizeofResource"
	    $res_load = "LoadResource"
	
	    $com = "COMSPEC"
	
	    //$stack_h = { C6 4? [1-2] 68 }    
	    //$stack_o = { C6 4? [1-2] 6F }
	    //$stack_v = { C6 4? [1-2] 76 }
	    //$stack_c = { C6 4? [1-2] 63 }
	    //$stack_x = { C6 4? [1-2] 78 }
	    //$stack_dot = { C6 4? [1-2] 2E }
	
	    $cryptaq = "CryptAcquireContextA"
	
	condition:
	    uint16(0) == 0x5A4D and
	    (all of ($res_*)) and 
	    /*(all of ($stack_*)) and*/
	    $cryptaq and $com
	}
	
rule CrowdStrike_PutterPanda_03 : threepara_para_implant putterpanda
	{
	meta:
		description = "PUTTER PANDA - 3PARA RAT"
		date = "2014-03-30"
		version = "1.0"
		in_the_wild = true
		copyright = "CrowdStrike, Inc."
		actor = "PUTTER PANDA"
	
	strings:
	    $parafmt        = "%s%dpara1=%dpara2=%dpara3=%d"
	    $class_attribe  = "CCommandAttribe"
	    $class_cd       = "CCommandCD"
	    $class_cmd      = "CCommandCMD"
	    $class_nop      = "CCommandNop"
	
	condition:
	    $parafmt or all of ($class_*)
	}
	
	rule CrowdStrike_PutterPanda_04: pngdowner putterpanda
	{
	meta:
		description = "PUTTER PANDA - PNGDOWNER"
		date = "2014-03-30"
		version = "1.0"
		in_the_wild = true
		copyright = "CrowdStrike, Inc."
		actor = "PUTTER PANDA"
	
	strings:
	    $myagent = "myAgent"
	    $readfile = "read file error:"
	    $downfile = "down file success"
	    $avail = "Avaliable data:%u bytes"
	
	condition:
	    3 of them
	}

rule CrowdStrike_PutterPanda_05 : httpclient putterpanda
	{
	meta:
		description = "PUTTER PANDA - HTTPCLIENT"
		date = "2014-03-30"
		version = "1.0"
		in_the_wild = true
		copyright = "CrowdStrike, Inc."
		actor = "PUTTER PANDA"
	
	strings:
	    $recv_wrong = "Error:recv worng"
	
	condition:
	    any of them
	}
    
rule CrowdStrike_PutterPanda_06 : xor_dropper putterpanda
	{
	meta:
		description = "PUTTER PANDA - XOR based dropper"
		date = "2014-03-30"
		version = "1.0"
		in_the_wild = true
		copyright = "CrowdStrike, Inc."
		actor = "PUTTER PANDA"
	
	strings:
	    $xorloop = { 8b d0 83 e2 0f 8a 54 14 04 30 14 01 83 c0 01 3b c6 7c ed  }
	
	condition:
	    $xorloop
	}
    
rule CrowdStrike_CSIT_14003_03 : installer 

{ 

       meta: 

             copyright = "CrowdStrike, Inc" 

             description = "Flying Kitten Installer" 

             version = "1.0" 

             actor = "FLYING KITTEN" 

             in_the_wild = true 

             reference = "http://www.crowdstrike.com/blog/cat-scratch-fever-crowdstrike-tracks-newly-reported-iranian-actor-flying-kitten/"

       strings: 

             $exename = "IntelRapidStart.exe" 

             $confname = "IntelRapidStart.exe.config" 

             $cabhdr = { 4d 53 43 46 00 00 00 00 } 

       condition: 

             all of them 

}

rule CrowdStrike_FlyingKitten : rat
{
meta: 

            copyright = "CrowdStrike, Inc" 

             description = "Flying Kitten RAT" 

             version = "1.0" 

             actor = "FLYING KITTEN" 

             in_the_wild = true 

       strings: 

             $classpath = "Stealer.Properties.Resources.resources" 

             //$pdbstr = "\Stealer\obj\x86\Release\Stealer.pdb" 

       condition: 

             all of them and 

             uint16(0) == 0x5A4D and uint32(uint32(0x3c)) == 0x4550 and 

             uint16(uint32(0x3C) + 0x16) & 0x2000 == 0 and 

             ((uint16(uint32(0x3c)+24) == 0x010b and 

            uint32(uint32(0x3c)+232) > 0) or 

             (uint16(uint32(0x3c)+24) == 0x020b and 

            uint32(uint32(0x3c)+248) > 0)) 

} 

/*

//error with rule no $i

rule CrowdStrike_P2P_Zeus
{
    meta:
        copyright = "CrowdStrike, Inc"
	author = "Crowdstrike, Inc"
        description = "P2P Zeus (Gameover)"
        version = "1.0"
        last_modified = "2013-11-21"
        actor = "Gameover Spider"
        malware_family = "P2P Zeus"
        in_the_wild = true
        
    condition:
        any of them or
        for any i in (0..filesize) :
        (
            uint32(i) ^ uint32(i+4) == 0x00002606
            and uint32(i) ^ uint32(i+8) == 0x31415154
            and uint32(i) ^ uint32(i+12) == 0x00000a06
            and uint32(i) ^ uint32(i+16) == 0x00010207
            and uint32(i) ^ uint32(i+20) == 0x7cf1aa2d
            and uint32(i) ^ uint32(i+24) == 0x4390ca7b
            and uint32(i) ^ uint32(i+28) == 0xa96afd9d
            and uint32(i) ^ uint32(i+32) == 0x0b039138
            and uint32(i) ^ uint32(i+36) == 0xb3e50578
            and uint32(i) ^ uint32(i+40) == 0x896eaf36
            and uint32(i) ^ uint32(i+44) == 0x37a3f8c9
            and uint32(i) ^ uint32(i+48) == 0xb1c31bcb
            and uint32(i) ^ uint32(i+52) == 0xcb58f22c
            and uint32(i) ^ uint32(i+56) == 0x00491be8
            and uint32(i) ^ uint32(i+60) == 0x0a2a748f
        )
}

*/

rule CrowdStrike_CVE_2014_4113 {
meta:
	copyright = "CrowdStrike, Inc"
	description = "CVE-2014-4113 Microsoft Windows x64 Local Privilege Escalation Exploit"
	version = "1.0"
	last_modified = "2014-10-14"
	in_the_wild = true
strings:
	$const1 = { fb ff ff ff }
	$const2 = { 0b 00 00 00 01 00 00 00 }
	$const3 = { 25 00 00 00 01 00 00 00 }
	$const4 = { 8b 00 00 00 01 00 00 00 }
condition:
	all of them
}rule APT20140414_1NT
{
	meta:
		author = "phbiohazard"
		reference = "https://github.com/phbiohazard/Yara"
	strings:
		$dpi1 = {47 45 54 20 2f}
		$dpi2 = {2F 74 61 73 6B 73 3F 76 65 72 73 69 6F 6E 3D}
		$dpi3 = {26 67 72 6F 75 70 3D}
		$dpi4 = {26 63 6C 69 65 6E 74 3D}
	condition:
		all of them
}import "pe"

rule APT20140414_1PE
{
meta:
    author = "phbiohazard"
    reference = "https://github.com/phbiohazard/Yara"

strings:
    $genep1 = {04 01 68 9b 1a 40 00 6a 01 6a 00 6a 00 ff 15 0c}
    $genep2 = {e9 3d 87 f8 ff bb d6 fb 04 8a 10 5c d2 70 d9 cb}
    $genep3 = {57 56 8b f0 e8 70 fd ff ff 5e e8 6e 01 00 00 5f}
    $contep1 = {e9 02 47 83 c6 02 89 f2 83 f9 00}
    $contep2 = {e5 44 75 c1 8b 36 0c 44 4d c9 31 8b 8a d7 88 d8}
    $contep3 = {9c d1 d4 52 7b c5 99 29 1c d7 46 c5 f9 8c f8 e2}
    $contep4 = {e8 ef e4 bb 00 5d c3}
condition:
    $genep1 and $contep1 and $contep2 or ($genep2 at pe.entry_point and ($contep3 in (pe.entry_point..pe.entry_point + 65))) or ($genep3 at pe.entry_point and ($contep4 in (pe.entry_point..pe.entry_point + 26)))

}rule ID2015032010000026
{
meta:
author = "mbl"
info = "IOC detection - Version 1.0"
reference = "https://github.com/phbiohazard/Yara"
	strings:
		$genep1 = {4D 5A 90 00 03 00}	
		$contep1 = {4D D0 FF EB 22 C7 85 78 FF FF FF 1C 00 00 00 EB}
		$contep2 = {2F 77 77 77 2E 74 68 61 77 74 65 2E 63 6F 6D 2F}

	condition:
		$genep1 and ($contep1 in (0x5d90..0x5d9f) and $contep2 in (0x27e70..0x27e7f))

}rule StormNtServerDLL : ntserverdll
{
meta:
	author = "plxsert"
	date = "2014-02-04"
	description = "Storm ntserver dll"
	sample_filetype = "dll"
	
strings:

	$string0 = "GET ^&&%$%$^%$#^&**(*((&*^%$##$%^&*(*&^%$%^&*.htmGET ^*%%RTG*(&^%FTGYHJIJ%^&*()*&*^&%RDFG(JKJH.aspGET *(&*^TGH*JIHG^&*(&^%*(*)OK)(*&^%$EDRGF%&^.htmlGET ^&&%$%$^%$#^&**(*((&*^%$##$%^&*(*&^%$%^&*.htmGET ^*%%RTG*(&^%FTGYHJIJ%^&*()*&*^&%RDFG(JKJH.aspGET *(&*^TGH*JIHG^&*(&^%*(*)OK)(*&^%$EDRGF%&^.html"
	$string1 = "Network China NetBot" fullword
	//$string2 = "Windows China Driver" fullword
	$string3 = "Made in China DDoS" fullword
	$string4 = "SerDLL.dll" fullword
	$string5 = "Accept-Language: zh-cn" fullword
	$string6 = "dddd  asdfddddf" fullword


condition:
	all of ($string*)
}


rule StormNtServerExe : ntserverexe
{
meta:
	author = "plxsert"
	date = "2014-01-15"
	description = "Storm ntserver payload"
	sample_filetype = "exe"
	
strings:
    $callWinExec = { 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8D 4C 24 10 51 FF 15 48 50 40 00 }
    
	$string0 = "\\ntserver.dll" fullword
	$string1 = "iexplore.exe" fullword
	//$string2 = "C:\\Program Files\\Internet Explorer\\iexplore.exe" fullword
	$string3 = "SeDebugPrivilege" fullword


condition:
	all of ($string*) and ($callWinExec in (0..0x106c))
}
rule apt_ext4_linuxlistener
{
 meta:
 description = "Detects Unique Linux Backdoor, Ext4"
 author = "Insikt Group, Recorded Future"
 TLP = "White"
 date = "2018-08-14"
 md5_x64 = "d08de00e7168a441052672219e717957"
 author = "https://go.recordedfuture.com/hubfs/reports/cta-2018-0816.pdf"
 strings:
 $s1="rm /tmp/0baaf161db39"
 $op1= {3c 61 0f}
 $op2= {3c 6e 0f}
 $op3= {3c 74 0f}
 $op4= {3c 69 0f}
 $op5= {3c 3a 0f}
 condition:
 all of them
}
rule TEMP_Periscope_July2018_Spearphish : email {
    meta:
        Author = "Insikt Group, Recorded Future"
        TLP = "White"
        Date = "2018-09-22"
        Description = "Rule to identify spearphish sent by Chinese threat actor TEMP.Periscope during July 2018 campaign"
    strings:
        $eml_1 = "From:"
        $eml_2 = "To:"
        $eml_3 = "Subject:"
        $greeting_1 = "Dear,"
        $content_1 = "Melissa Coade" nocase
        $content_2 = "Below is the Report Website and conatc"
        $content_3 = "Would yo mind giving me"
        $url_1 = "file://"
        $url_2 = "https://drive.google.com/open?"
    condition:
        all of ($eml*) and all of ($greeting*) and 2 of ($content*) and 2 of ($url*)
}rule Win32_Ransomware_BadRabbit : malicious {
    meta:
        author = "ReversingLabs"
        reference = "https://www.reversinglabs.com/newsroom/news/reversinglabs-yara-rule-detects-badrabbit-encryption-rutine-specifics.html"
        date = "oct-26-2017"
    strings:
        $encrypt_file = {
            55 8B EC 83 EC ?? 53 56 57 8B 7D ?? 8B 4F ?? 33 DB 8D 45 ?? 50 53 53 51 89 5D ?? 89 
            5D ?? 89 5D ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 55 ?? 53 53 6A ?? 53 53 
            68 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 8B F0 83 FE ?? 0F 84 ?? ?? ?? ?? 8D 45 ?? 50 8D 
            4D ?? 51 57 8B CE E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 39 5D ?? 0F 84 ?? 
            ?? ?? ?? 39 5D ?? 0F 84 ?? ?? ?? ?? 8D 55 ?? 52 56 FF 15 ?? ?? ?? ?? 8B 4F ?? 8B 45 
            ?? 83 C1 ?? 2B C1 19 5D ?? 89 45 ?? 89 5D ?? 78 ?? 7F ?? 3D ?? ?? ?? ?? 76 ?? B8 ?? 
            ?? ?? ?? EB ?? C7 45 ?? ?? ?? ?? ?? 53 50 53 6A ?? 53 8B F8 56 89 45 ?? 89 7D ?? FF 
            15 ?? ?? ?? ?? 8B D8 85 DB 74 ?? 8B 55 ?? 52 6A ?? 6A ?? 6A ?? 53 FF 15 ?? ?? ?? ?? 
            8B F8 85 FF 74 ?? 8B 4D ?? 8B 55 ?? 8D 45 ?? 50 57 6A ?? 51 6A ?? 52 FF 15 ?? ?? ?? 
            ?? 85 C0 74 ?? 8B 45 ?? 50 57 FF 15 ?? ?? ?? ?? 8B 4D ?? 51 68 ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 83 C4 ?? 57 FF 15 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? 8B 7D ?? 8B 45 ?? 3B C7 73 
            ?? 2B F8 EB ?? 33 FF 8B 55 ?? 8B 42 ?? 8D 4C 38 ?? 6A ?? 51 E8 ?? ?? ?? ?? 8B 7D ?? 
            83 C4 ?? 33 DB 56 FF 15 ?? ?? ?? ?? 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 39 5D ?? 74 ?? 39 
            5D ?? 75 ?? 8B 47 ?? 8B 35 ?? ?? ?? ?? 50 FF D6 8B 7F ?? 3B FB 74 ?? 57 FF D6 5F 5E 
            5B 8B E5 5D C3 
        }

        $main_encrypt = {
            55 8B EC 56 6A ?? 6A ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 8B 75 ?? 89 46 ?? 85 C0 0F 84 
            ?? ?? ?? ?? 53 8B 1D ?? ?? ?? ?? 57 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 8D 7E ?? 57 FF 
            D3 85 C0 75 ?? FF 15 ?? ?? ?? ?? 3D ?? ?? ?? ?? 75 ?? 6A ?? 6A ?? 6A ?? 6A ?? 57 FF 
            D3 85 C0 74 ?? 8B 07 8D 5E ?? 53 50 8B 46 ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 ?? 8B 
            C6 E8 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 56 8D 4E ?? 6A ?? 51 E8 ?? 
            ?? ?? ?? 8B 56 ?? 83 C4 ?? 52 FF 15 ?? ?? ?? ?? 8B 46 ?? 50 FF 15 ?? ?? ?? ?? 8B 0B 
            51 FF 15 ?? ?? ?? ?? 8B 17 6A ?? 52 FF 15 ?? ?? ?? ?? 8B 46 ?? 50 FF 15 ?? ?? ?? ?? 
            5F 5B B9 ?? ?? ?? ?? 8D 46 ?? 8B FF C6 00 ?? 40 49 75 ?? 56 FF 15 ?? ?? ?? ?? 33 C0 
            5E 5D C2 ?? ?? 
        }

        $encryption_loop = {
            8B 7C 24 ?? 6A ?? 6A ?? 8D 43 ?? 50 33 C0 39 43 ?? 0F 95 C0 40 50 FF 15 ?? ?? ?? ?? 
            85 C0 0F 84 ?? ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? B9 ?? 
            ?? ?? ?? 8D 44 24 ?? 66 8B 10 66 3B 11 75 ?? 66 85 D2 74 ?? 66 8B 50 ?? 66 3B 51 ?? 
            75 ?? 83 C0 ?? 83 C1 ?? 66 85 D2 75 ?? 33 C0 EB ?? 1B C0 83 D8 ?? 85 C0 0F 84 ?? ?? 
            ?? ?? B9 ?? ?? ?? ?? 8D 44 24 ?? 8D 64 24 ?? 66 8B 10 66 3B 11 75 ?? 66 85 D2 74 ?? 
            66 8B 50 ?? 66 3B 51 ?? 75 ?? 83 C0 ?? 83 C1 ?? 66 85 D2 75 ?? 33 C0 EB ?? 1B C0 83 
            D8 ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 4C 24 ?? 51 57 8D 94 24 ?? ?? ?? ?? 52 FF 15 ?? ?? 
            ?? ?? 85 C0 74 ?? 8B 44 24 ?? A8 ?? 74 ?? A9 ?? ?? ?? ?? 75 ?? 8D BC 24 ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 85 C0 75 ?? 8B 45 ?? 53 48 50 8B CF 51 E8 ?? ?? ?? ?? 83 C4 ?? EB ?? 
            8D 54 24 ?? 52 FF 15 ?? ?? ?? ?? 8D 4C 24 ?? 8D 71 ?? 90 66 8B 11 83 C1 ?? 66 85 D2 
            75 ?? 2B CE D1 F9 8D 4C 4C ?? 3B C1 74 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 ?? 8D 
            94 24 ?? ?? ?? ?? 53 52 E8 ?? ?? ?? ?? 83 C4 ?? 8B 74 24 ?? 8D 44 24 ?? 50 56 FF 15 
            ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ??  
        }

    condition:
        $encrypt_file and $main_encrypt and $encryption_loop
            
}
rule potential_CVE_2017_11882
{
    meta:
      author = "ReversingLabs"
      reference = "https://www.reversinglabs.com/newsroom/news/reversinglabs-yara-rule-detects-cobalt-strike-payload-exploiting-cve-2017-11882.html"
      
    strings:
        $docfilemagic = { D0 CF 11 E0 A1 B1 1A E1 }

        $equation1 = "Equation Native" wide ascii
        $equation2 = "Microsoft Equation 3.0" wide ascii

        $mshta = "mshta"
        $http  = "http://"
        $https = "https://"
        $cmd   = "cmd"
        $pwsh  = "powershell"
        $exe   = ".exe"

        $address = { 12 0C 43 00 }

    condition:
        $docfilemagic at 0 and any of ($mshta, $http, $https, $cmd, $pwsh, $exe) and any of ($equation1, $equation2) and $address
}
rule image_eval_hunt
{
	meta:
     author = "ReversingLabs"
     reference = "https://blog.reversinglabs.com/blog/malware-in-images"
   strings:
      $png = {89 50 4E 47}
      $jpeg = {FF D8 FF}
      $gif = "GIF"
      $eval = "eval("
   condition:
      (($png at 0) or ($jpeg at 0) or ($gif at 0)) and $eval
}
rule obfuscated_dde
{
    meta:
	reference = "https://blog.reversinglabs.com/blog/cvs-dde-exploits-and-obfuscation"
	author = "ReversingLabs"
    strings:

        $dde_command_1 = /[=+-]+[ 0-9A-Za-z_\"\&\^\-\=\/\+\(\x00]*(((c|C)[\x00]*(m|M)[\x00]*(d|D)[\x00]*\|)|((m|M)[\x00]*(s|S)[\x00]*(i|I|e|E)[\x00]*(e|E|x|X)[\x00]*(x|X|c|C)[\x00]*(e|E)[\x00]*(c|C|l|L)[\x00]*\|)|((r|R)[\x00]*(u|U|e|E)[\x00]*(n|N|g|G)[\x00]*(d|D|s|S)[\x00]*(l|L|v|V)[\x00]*(l|L|r|R)[\x00]*3[\x00]*2[0-9A-Za-z\x00]*\|)|((c|C)[\x00]*(e|E)[\x00]*(r|R)[\x00]*(t|T)[\x00]*(u|U)[\x00]*(t|T)[\x00]*(i|I)[\x00]*(l|L)[0-9A-Za-z\x00]*\|))[\x00]*\'/

    condition:
        $dde_command_1
}
rule Rana_Android_resources {
meta:
     author = "ReversingLabs"
     reference = "https://blog.reversinglabs.com/blog/rana-android-malware"
strings:
        $res1 = "res/raw/cng.cn" fullword wide ascii
        $res2 = "res/raw/att.cn" fullword wide ascii
        $res3 = "res/raw/odr.od" fullword wide ascii
condition:
        any of them /* any string in the rule */
}
rule Unpacker_Stub
{
meta:
  author = "Malware Utkonos"
  date = "2020-12-30"
  description = "First Byte in decoded unpacker stub"
  exemplar = "c1d31fa7484170247564e89c97cc325d1f317fb8c8efe50e4d126c7881adf499"
  reference = "https://blog.reversinglabs.com/blog/code-reuse-across-packers-and-dll-loaders"
strings:
$a = {E8 00 00 00 00 5B 81 EB [4] 8D 83 [4] 89 83 [4] 8D B3 [4] 89 B3 [4] 8B 46 ?? 89 83 [4] 8D B3 [4] 56 8D B3 [4] 56 6A ?? 68 [4] 8D BB [4] FF D7}
condition:
(uint16(0) == 0x5A4D and uint32 (uint32(0x3C)) == 0x00004550) and $a
}
rule Artifact_ORION_aPlib
{
	meta:
		Author = "HB"
		Date = "30 Sep 2013"
		Project = "Orion"
		Reference = "https://blogs.rsa.com/wp-content/uploads/2015/05/RSA-IR-Case-Study.pdf"
	strings:
		$a1 = "aPLib v"
		$a2 = "the smaller the better :)"
		$a3 = "Joergen Ibsen"
	condition:
		all of them

}rule Kingslayer_codekey
{
meta:
	description = "detects Win32 files signed with stolen code signing key used in Kingslayer attack"
	author = "RSA Research"
	reference = "http://firstwat.ch/kingslayer"
	date = "03 February 2017"
	hash0 = "fbb7de06dcb6118e060dd55720b51528"
	hash1 = "3974a53de0601828e272136fb1ec5106"
	hash2 = "f97a2744a4964044c60ac241f92e05d7"
	hash3 = "76ab4a360b59fe99be1ba7b9488b5188"
	hash4 = "1b57396c834d2eb364d28eb0eb28d8e4"
strings:
	$val0 = { 31 33 31 31 30 34 31 39 33 39 31 39 5A 17 0D 31 35 31 31 30 34 31 39 33 39 31 39 5A }
	$ven0 = { 41 6C 74 61 69 72 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 }
condition:
	uint16(0) == 0x5A4D and $val0 and $ven0
}
rule liudoor{
meta:
        author = "RSA FirstWatch"
        date = "2015-07-23"
        description = "Detects Liudoor daemon backdoor"
        reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
        hash0 = "78b56bc3edbee3a425c96738760ee406"
        hash1 = "5aa0510f6f1b0e48f0303b9a4bfc641e"
        hash2 = "531d30c8ee27d62e6fbe855299d0e7de"
        hash3 = "2be2ac65fd97ccc97027184f0310f2f3"
		hash4 = "6093505c7f7ec25b1934d3657649ef07"
        type = "Win32 DLL"

strings:
        $string0 = "Succ"
        $string1 = "Fail"
        $string2 = "pass"
        $string3 = "exit"
        $string4 = "svchostdllserver.dll"
        $string5 = "L$,PQR"
        $string6 = "0/0B0H0Q0W0k0"
        $string7 = "QSUVWh"
        $string8 = "Ht Hu["
condition:
        all of them
}rule PNGRat_C2_Decode
/*
.text:180002CCE 8A 43 01            mov     al, [rbx+1]
.text:180002CD1 B1 71               mov     cl, 71h
.text:180002CD3 48 8D 54 24 30      lea     rdx, [rsp+148h+Src] ; Src
.text:180002CD8 C0 E0 04            shl     al, 4 ; Shift Logical Left
.text:180002CDB 41 B8 04 00 00 00   mov     r8d, 4; Size
.text:180002CE1 02 03               add     al, [rbx]       ; Add
.text:180002CE3 2A C1               sub     al, cl; Integer Subtraction
*/
{
 meta:
  Author = "BB RSAIR"
  Date   = "15Jan2015"
  reference = "https://community.rsa.com/docs/DOC-30015"
 strings:
  $decode = {8A 43 [0-1] B1 71 48 [0-4] C0 E0 04 41 B8 04 [0-3] 02 03 2A C1 }
        
 condition:
  $decode and uint16( 0) == 0x5A4D
}

rule PngRatV2
{
 meta:
  Author = "EMH RSAIR"
  Date   = "14Dec2014"
  reference = "https://community.rsa.com/docs/DOC-30015"
 strings:
  $mz = { 4D 5A }
  $reg_pw = "abe2869f-9b47-4cd9-a358-c22904dba7f7"
  $stego_c2 = "http://social.technet.microsoft.com/Forums/" nocase
  $ip_string = "%u.%u.%u.%u"
  $microsoft = {C6 44 24 30 40 C6 44 24 31 4D C6 44 24 32 49 C6 44 24 33 43 C6 44 24 34 52 C6 44 24 35 30 C6 44 24 36 53 C6 44 24 37 30 C6 44 24 38 46 C6 44 24 39 54 C6 44 24}
  $corporation = {C6 44 24 30 43 48 8B CB C6 44 24 31 30 C6 44 24 32 52 C6 44 24 33 50 C6 44 24 34 30 C6 44 24 35 52 C6 44 24 36 41 C6 44 24 37 54 C6 44 24 38 49 C6 44 24 39 30 C6 44 24 3A 4E C6 44 24 3B 00}
        
 condition:
  all of them or ($mz and $reg_pw and $ip_string and $microsoft and $corporation)
}
rule RTF_Shellcode
{
meta:
                author = "RSA-IR – Jared Greenhill"
                date = "01/21/13"
                description = "identifies RTF's with potential shellcode"
                reference = "https://community.rsa.com/community/products/netwitness/blog/2014/02/12/triaging-malicious-microsoft-office-documents-cve-2012-0158"
                filetype = "RTF"
 
strings:
                $rtfmagic={7B 5C 72 74 66}
                $scregex=/[39 30]{2,20}/
 
condition:
                ($rtfmagic at 0) and ($scregex)
}
rule RSA_IR_Windows_COM_bypass_script
{
    meta:
        author="RSA IR"
        Date="22 Apr 2016"
        reference = "https://community.rsa.com/community/products/netwitness/blog/2016/04/26/detection-of-com-whitelist-bypassing-with-ecat"
        comment1="Detects potential scripts used by COM+ Whitelist Bypass"
        comment2="More information on bypass located at: http://subt0x10.blogspot.com/2016/04/bypass-application-whitelisting-script.html"
 
    strings:
        $s1 = "<scriptlet>" nocase
        $s2 = "<registration" nocase
        $s3 = "classid=" nocase
        $s4 = "[CDATA[" nocase
        $s5 = "</script>" nocase
        $s6 = "</registration>" nocase
        $s7 = "</scriptlet>" nocase
 
    condition:
        all of ($s*)
}
rule Trojan_Derusbi {
        meta:
                Author = "RSA_IR"
                Date     = "4Sept13"
                File     = "derusbi_variants v 1.3"
                MD5      = " c0d4c5b669cc5b51862db37e972d31ec "
                Reference = "https://www.emc.com/collateral/white-papers/h12756-wp-shell-crew.pdf"
            strings:
        $b1 = {8b 15 ?? ?? ?? ?? 8b ce d3 ea 83 c6 ?? 30 90 ?? ?? ?? ??
40 3b 05 ?? ?? ?? ?? 72 ??}
        $b2 = {F3 5D 88 2E ?? ?? 00 00 BE 07 18 2E F0 5D 88 2E F7 5D 88 2E 0C A2 88 2E 4B 5D 88 2E F3 5D 88 2E}
        $b3 = {4E E6 40 BB}
        $b4 = {B1 19 BF 44}
        
        $b5 = {6A F5 44 3D ?? ?? 00 00 27 AF D4 3D 69 F5 44 3D 6E F5 44 3D 95 0A 44 3D D2 F5 44 3D 6A F5 44 3D}
        $b6 = {F3 5D 88 2E ?? ?? 00 00 BE 07 18 2E F0 5D 88 2E}
        $b7 = {D6 D5 A4 A3 ?? ?? 00 00 9B 8F 34 A3 D5 D5 A4 A3 D2 D5 A4
A3 29 2A A4 A3}
        $b8 = {C3 76 33 9F ?? ?? 00 00 8E 2C A3 9F C0 76 33 9F C7 76 33 9F 3C 89 33 9F}
 
    condition:
        2 of ($b1, $b2, $b3, $b4) and 1 of ($b5, $b6, $b7, $b8) }rule Trojan_Derusbi_AP32_Orion
{
	meta:
		Author = "HB"
		Date = "30 Sep 2013"
		Project = "Orion"
		Info = "Compressed with aPACK"
        MagicBytes = "AP32" 
		Reference = "https://blogs.rsa.com/wp-content/uploads/2015/05/RSA-IR-Case-Study.pdf"

	strings:

		$http1 = {00000000485454502F312E312032303000000000485454502F312E3020323030}
		$http2 = {00000000434F4E4E4543542025733A256420485454502F312E300D0A0D0A0000}
		$file1 = "%s\\seclogon.nls"
		$file2 = "%s\\seclogon.nt"
		$file3 = "%swindows.exe"
		$o1	= "\\wsedrf\\qazxsw"
		$o2 = "\\shell\\open\\command"
		$b1 = {4C4F47494E494E464F3A2025640A0000}
		$b2 = {436F6465506167653A2025730A000000}
		$b3 = {5C636D642E657865}

	condition:
		all of ($http*) or all of ($file*) or all of ($o*) or all of ($b*)

}rule Trojan_HIKIT
{
	meta:
		Author = "HB"
		Date = "26 Sep 2013"
		Project = "Orion"
		MD5 = "7D4F241428A2496142DF1C4A376CEC88"
		MD5 = "A5F07E00D3EEF7A16ECFEC03E94677E3"
		Reference = "https://blogs.rsa.com/wp-content/uploads/2015/05/RSA-IR-Case-Study.pdf"

	strings:
		$b1 = {63006F006E006E006500630074002000250064002E00250064002E00250064002E002500640020002500640000000000680069006B00690074003E}
		$b2 = {68006900740078002E0073007900730000006D00610074007200690078005F00700061007300730077006F007200}
		$b3 = {700072006F0078007900000063006F006E006E006500630074000000660069006C006500000000007300680065006C006C}
		$a1 = "Open backdoor error" wide
		$a2 = "data send err..." wide

	condition:
		any of ($b*) or all of ($a*)
}rule Trojan_Lurker2_ORION
{
	meta:
		Author = "HB"
		Date = "30 Sep 2013"
		Project = "Orion"
		Filename = "ntmrsvc.dll"
		Reference = "https://blogs.rsa.com/wp-content/uploads/2015/05/RSA-IR-Case-Study.pdf"

	strings:
		$b1 = {636D642E657865004C55524B}
		$b2 = {45525F52414353004C55524B25735F534D5F2573}
		$b3 = {4C55524B4552524143535F524D5F2573}
		$a1 = "01234567890123456789eric0123456789012345678karen"

	condition:
		any of them
}rule TROJAN_Notepad {
        meta:
                Author = "RSA_IR"
                Date     = "4Jun13"
                File     = "notepad.exe v 1.1"
                MD5      = "106E63DBDA3A76BEEB53A8BBD8F98927"
                Reference = "https://www.emc.com/collateral/white-papers/h12756-wp-shell-crew.pdf"
        strings:
                $s1 = "75BAA77C842BE168B0F66C42C7885997"
                $s2 = "B523F63566F407F3834BCC54AAA32524"
        condition:
                $s1 or $s2
}