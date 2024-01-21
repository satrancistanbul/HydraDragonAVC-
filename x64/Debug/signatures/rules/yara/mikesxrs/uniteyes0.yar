rule backdoor_apt_pcclient
{
meta:
    author = "@patrickrolsen"
    maltype = "APT.PCCLient"
    filetype = "DLL"
    version = "0.1"
    description = "Detects the dropper: 869fa4dfdbabfabe87d334f85ddda234 AKA dw20.dll/msacm32.drv dropped by 4a85af37de44daf5917f545c6fd03902 (RTF)"
    date = "2012-10"
strings:
    $magic = { 4d 5a } // MZ
    $string1 = "www.micro1.zyns.com"
    $string2 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)"
    $string3 = "msacm32.drv" wide
    $string4 = "C:\\Windows\\Explorer.exe" wide
    $string5 = "Elevation:Administrator!" wide
    $string6 = "C:\\Users\\cmd\\Desktop\\msacm32\\Release\\msacm32.pdb"
condition:
    $magic at 0 and 4 of ($string*)
}

rule pos_memory_scrapper
{
meta:
    author = "@patrickrolsen"
    maltype = "Point of Sale (POS) Malware Memory Scraper"
    version = "0.1"
    description = "POS Memory Scraper"
    reference = "7f9cdc380eeed16eaab3e48d59f271aa -> http://www.xylibox.com/2013/05/dump-memory-grabber-blackpos.html"
    date = "12/30/2013"
strings:
    $string1 = "kartoxa" nocase
    $string2 = "CC2 region:"
    $string3 = "CC memregion:"
    $string4 = "target pid:"
    $string5 = "scan all processes:"
    $string6 = "<pid> <PATTERN>"
condition:
    all of ($string*)
}

rule FE_PCAPs
{
meta:
    author = "@patrickrolsen"
    maltype = "N/A"
    version = "0.1"
    description = "Find FireEye PCAPs uploaded to Virus Total"
    date = "12/30/2013"
strings:
    $magic = {D4 C3 B2 A1}
    $ip1 = {0A 00 00 ?? C7 10 C7 ??} // "10.0.0.?? -> 199.16.199.??
    $ip2 = {C7 10 C7 ?? 0A 00 00 ??} // "199.16.199.?? -> 10.0.0.??"
condition:
    $magic at 0 and all of ($ip*)
}

// Point of Sale (POS) Malware

rule pos_memory_scrapper2
{
meta:
    author = "@patrickrolsen"
    maltype = "Point of Sale (POS) Malware Memory Scraper"
    version = "0.2"
    description = "POS Memory Scraper"
    reference = "7f9cdc380eeed16eaab3e48d59f271aa http://www.xylibox.com/2013/05/dump-memory-grabber-blackpos.html"
    date = "01/03/2014"
strings:
    $magic = { 4D 5A } // MZ Header
    $string1 = "kartoxa" nocase
    $string2 = "CC2 region:"
    $string3 = "CC memregion:"
    $string4 = "target pid:"
    $string5 = "scan all processes:"
    $string6 = "<pid> <PATTERN>"
    $string7 = "KAPTOXA" nocase
condition:
    ($magic at 0) and all of ($string*)
}
rule pos_malwre_dexter_stardust
{
meta:
    author = "@patrickrolsen"
    maltype = "Dexter Malware - StarDust Variant"
    version = "0.1"
    description = "Table 2 arbornetworks.com/asert/wp-content/uploads/2013/12/Dexter-and-Project-Hook-Break-the-Bank.pdf"
    reference = "16b596de4c0e4d2acdfdd6632c80c070, 2afaa709ef5260184cbda8b521b076e1, and e3dd1dc82ddcfaf410372ae7e6b2f658"
    date = "12/30/2013"
strings:
    $magic = { 4D 5A } // MZ Header
    $string1 = "ceh_3\\.\\ceh_4\\..\\ceh_6"
    $string2 = "Yatoed3fe3rex23030am39497403"
    $string3 = "Poo7lo276670173quai16568unto1828Oleo9eds96006nosysump7hove19"
    $string4 = "CommonFile.exe"
condition:
    ($magic at 0) and all of ($string*)
}
    
rule pos_malware_project_hook
{
meta:
    author = "@patrickrolsen"
    maltype = "Project Hook"
    version = "0.1"
    description = "Table 1 arbornetworks.com/asert/wp-content/uploads/2013/12/Dexter-and-Project-Hook-Break-the-Bank.pdf"
    reference = "759154d20849a25315c4970fe37eac59"
    date = "12/30/2013"
strings:
    $magic = { 4D 5A } // MZ Header
    $string1 = "CallImage.exe"
    $string2 = "BurpSwim"
    $string3 = "Work\\Project\\Load"
    $string4 = "WortHisnal"
    
condition:
    ($magic at 0) and all of ($string*)
}

rule pdb_strings_Rescator
{
meta:
    author = "@patrickrolsen"
    maltype = "N/A Threat Intel..."
    version = "0.2"
    description = "Rescator PDB strings within binaries"
    date = "01/03/2014"
strings:
    $magic = { 4D 5A } // MZ Header
    $pdb1 = "\\Projects\\Rescator" nocase
condition:
    ($magic at 0) and $pdb1
}

rule rtf_Kaba_jDoe
{
meta:
    author = "@patrickrolsen"
    maltype = "APT.Kaba"
    filetype = "RTF"
    version = "0.1"
    description = "fe439af268cd3de3a99c21ea40cf493f, d0e0e68a88dce443b24453cc951cf55f, b563af92f144dea7327c9597d9de574e, and def0c9a4c732c3a1e8910db3f9451620"
    date = "2013-12-10"
strings:
    $magic1 = { 7b 5c 72 74 30 31 } // {\rt01
    $magic2 = { 7b 5c 72 74 66 31 } // {\rtf1
    $magic3 = { 7b 5c 72 74 78 61 33 } // {\rtxa3
    $author1 = { 4A 6F 68 6E 20 44 6F 65 } // "John Doe"
    $author2 = { 61 75 74 68 6f 72 20 53 74 6f 6e 65 } // "author Stone"
    $string1 = { 44 30 [16] 43 46 [23] 31 31 45 }
condition:
    ($magic1 or $magic2 or $magic3 at 0) and all of ($author*) and $string1
} 

rule rtf_yahoo_ken
{
meta:
    author = "@patrickrolsen"
    maltype = "Yahoo Ken"
    filetype = "RTF"
    version = "0.1"
    description = "Test rule"
    date = "2013-12-14"
strings:
    $magic1 = { 7b 5c 72 74 30 31 } // {\rt01
    $magic2 = { 7b 5c 72 74 66 31 } // {\rtf1
    $magic3 = { 7b 5c 72 74 78 61 33 } // {\rtxa3
    $author1 = { 79 61 68 6f 6f 20 6b 65 63 } // "yahoo ken"
condition:
    ($magic1 or $magic2 or $magic3 at 0) and $author1
} 

rule Backdoor_APT_Mongall
{
meta:
    author = "@patrickrolsen"
    maltype = "Backdoor.APT.Mongall"
    version = "0.1"
    reference = "fd69a799e21ccb308531ce6056944842" 
    date = "01/04/2014"
strings:
    $author  = "author user"
    $title   = "title Vjkygdjdtyuj" nocase
    $comp    = "company ooo"
    $cretime = "creatim\\yr2012\\mo4\\dy19\\hr15\\min10"
    $passwd  = "password 00000000"
condition:
        all of them
}

rule tran_duy_linh
{
meta:
    author = "@patrickrolsen"
    maltype = "Misc."
    version = "0.1"
    reference = "8fa804105b1e514e1998e543cd2ca4ea, 872876cfc9c1535cd2a5977568716ae1, etc." 
    date = "2013-12-12"
strings:
    $magic = {D0 CF 11 E0} //DOCFILE0
    $string1 = "Tran Duy Linh" fullword
    $string2 = "DLC Corporation" fullword
condition:
    $magic at 0 and all of ($string*)
}

rule web_log_review
{
meta:
    author = "@patrickrolsen"
    version = "0.1"
    reference = "Key words in weblogs - Very likely FPs in here."
    date = "2013-12-14"
strings:
    $s =   "GET /.htaccess" nocase
    $s0 =  "GET /db/main.php" nocase
    $s3 =  "GET /dbadmin/main.php" nocase
    $s4 =  "GET /phpinfo.php" nocase
    $s5 =  "GET /password" nocase
    $s6 =  "GET /passwd" nocase
    $s7 =  "GET /phpmyadmin2" nocase
    $s8 =  "GET /c99shell.php" nocase
    $s9 =  "GET /c99.php" nocase
    $s10 = "GET /response.write" nocase
    $s11 = "GET /&dir" nocase
    $s12 = "backdoor.php" nocase
    $s13 = "GET /.htpasswd" nocase
    $s14 = "GET /htaccess.bak" nocase
    $s15 = "GET /htaccess.txt" nocase
    $s16 = "GET /.bash_history" nocase
    $s17 = "GET /_sqladm" nocase
    $s18 = "'$IFS/etc/privpasswd;'" nocase
    $s19 = ";cat /tmp/config/usr.ini" nocase
    $s20 = "v0pCr3w" nocase
    $s21 = "eval(base64_decode" nocase
    $s22 = "nob0dyCr3w" nocase
    $s23 = "eval(gzinflate" nocase
    $s24 = "Hacked by" fullword
    $s25 = "%5Bcmd%5D" nocase
    $s26 = "[cmd]" nocase
    $s27 = "union+select" nocase
    $s28 = "UNION%20SELECT" nocase
    $s29 = "(str_rot13" nocase

condition:
    any of ($s*)
}

rule acunetix_web_scanner
{
meta:
    author = "@patrickrolsen"
    version = "0.1"
    reference = "Acunetix Web Scanner"
    date = "2013-12-14"
strings:
    $s =   "acunetix_wvs_security_test"
    $s0 =  "testasp.vulnweb.com"
    $s1 =  "GET /www.acunetix.tst"
condition:
    any of ($s*)
}

rule php_exploit_GIF
{
meta:
    author = "@patrickrolsen"
    maltype = "GIF Exploits"
    version = "0.1"
    reference = "code.google.com/p/caffsec-malware-analysis"
    date = "2013-12-14"
strings:
    $magic = {47 49 46 38 ?? 61} // GIF8<version>a
    $string1 = "; // md5 Login" nocase
    $string2 = "; // md5 Password" nocase
    $string3 = "shell_exec"
    $string4 = "(base64_decode"
    $string5 = "<?php"
    $string6 = "(str_rot13"
    $string7 = {3c 3f 70 68 70} // <?php
condition:
    ($magic at 0) and any of ($string*)
}

rule html_exploit_GIF
{
meta:
    author = "@patrickrolsen"
    maltype = "Web Shells"
    version = "0.1"
    reference = "code.google.com/p/caffsec-malware-analysis"
    date = "2013-12-14"
strings:
    $magic = {47 49 46 38 ?? 61} // GIF8<version>a
    $string1 = {3c 68 74 6d 6c 3e} // <html>
    $string2 = {3c 48 54 4d 4c 3e} // <HTML>
condition:
    ($magic at 0) and (any of ($string*))
}

rule web_shell_crews
{
meta:
    author = "@patrickrolsen"
    maltype = "Web Shell Crews"
    version = "0.4"
    reference = "http://www.exploit-db.com/exploits/24905/"
    date = "12/29/2013"
strings:
    $mz = { 4d 5a } // MZ
    
    $string1 = "v0pCr3w"
    $string2 = "BENJOLSHELL"
    $string3 = "EgY_SpIdEr"
    $string4 = "<title>HcJ"
    $string5 = "0wn3d"
    $string6 = "OnLy FoR QbH"
    $string7 = "wSiLm"
    $string8 = "b374k r3c0d3d"
    $string9 = "x'1n73ct|d"
    $string10 = "## CREATED BY KATE ##"
    $string11 = "Ikram Ali"
    $string12 = "FeeLCoMz"
    $string13 = "s3n4t00r"
    $string14 = "FaTaLisTiCz_Fx"
    $string15 = "feelscanz.pl"
    $string16 = "##[ KONFIGURASI"
    $string17 = "Created by Kiss_Me"
    $string18 = "Casper_Cell"
    $string19 = "# [ CREWET ] #"
        $string20 = "BY MACKER"
        $string21 = "FraNGky"
        $string22 = "1dt.w0lf"
        $string23 = "Modification By iFX" nocase
condition:
    not $mz at 0 and any of ($string*)
}

rule misc_php_exploits
{
meta:
    author = "@patrickrolsen"
    version = "0.4"
    data = "12/29/2013"
    reference = "Virus Total Downloading PHP files and reviewing them..."
strings:
    $mz = { 4d 5a } // MZ
    $php = "<?php"
    $string1 = "eval(gzinflate(str_rot13(base64_decode("
    $string2 = "eval(base64_decode("
    $string3 = "eval(gzinflate(base64_decode("
    $string4 = "cmd.exe /c"
    $string5 = "eva1"
    $string6 = "urldecode(stripslashes("
    $string7 = "preg_replace(\"/.*/e\",\"\\x"
    $string8 = "<?php echo \"<script>"
    $string9 = "'o'.'w'.'s'" // 'Wi'.'nd'.'o'.'w'.'s'
    $string10 = "preg_replace(\"/.*/\".'e',chr"
    $string11 = "exp1ode"
    $string12 = "cmdexec(\"killall ping;"
    $string13 = "r57shell.php"
condition:
    not $mz at 0 and $php and any of ($string*)
}

rule zend_framework
{
meta:
    author = "@patrickrolsen"
    maltype = "Zend Framework"
    version = "0.3"
    date = "12/29/2013"
strings:
    $mz = { 4d 5a } // MZ
    $php = "<?php"
    $string = "$zend_framework" nocase
condition:
    not $mz at 0 and $php and $string
}

rule jpg_web_shell
{
meta:
    author = "@patrickrolsen"
    version = "0.1"
    data = "12/19/2013"
    reference = "http://www.securelist.com/en/blog/208214192/Malware_in_metadata"
strings:
    $magic = { ff d8 ff e? } // e0, e1, e8
    $string1 = "<script src"
    $string2 = "/.*/e"
    $string3 = "base64_decode"
condition:
    ($magic at 0) and 1 of ($string*)
}  rule StormNtServerDLL : ntserverdll
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
rule Win32_Ransomware_BadRabbit : malicious {
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