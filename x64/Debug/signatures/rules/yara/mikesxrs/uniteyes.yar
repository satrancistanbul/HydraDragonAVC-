rule Trojan_W32_Gh0stMiancha_1_0_0
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

}