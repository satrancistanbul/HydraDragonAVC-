//will match both exe and dll components
private rule NetTravExports : NetTraveler Family {

	meta:
		description = "Export names for dll component"
		author = "Katie Kleemola"
		last_updated = "2014-05-20"
	
	strings:
		//dll component exports
		$ = "?InjectDll@@YAHPAUHWND__@@K@Z"
		$ = "?UnmapDll@@YAHXZ"
		$ = "?g_bSubclassed@@3HA"
		
	condition:
		any of them
}

private rule NetTravStrings : NetTraveler Family {


	meta:
        	description = "Identifiers for NetTraveler DLL"
		author = "Katie Kleemola"
        	last_updated = "2014-05-20"

	strings:
		//network strings
		$ = "?action=updated&hostid="
		$ = "travlerbackinfo"
		$ = "?action=getcmd&hostid="
		$ = "%s?action=gotcmd&hostid="
		$ = "%s?hostid=%s&hostname=%s&hostip=%s&filename=%s&filestart=%u&filetext="

		//debugging strings
		$ = "\x00Method1 Fail!!!!!\x00"
		$ = "\x00Method3 Fail!!!!!\x00"
		$ = "\x00method currect:\x00"
		$ = /\x00\x00[\w\-]+ is Running!\x00\x00/
		$ = "\x00OtherTwo\x00"

	condition:
		any of them

}

private rule NetpassStrings : NetPass Variant {

        meta:
                description = "Identifiers for netpass variant"
                author = "Katie Kleemola"
                last_updated = "2014-05-29"

        strings:
		$exif1 = "Device Protect ApplicatioN" wide
		$exif2 = "beep.sys" wide //embedded exe name
		$exif3 = "BEEP Driver" wide //embedded exe description
		
		$string1 = "\x00NetPass Update\x00"
		$string2 = "\x00%s:DOWNLOAD\x00"
		$string3 = "\x00%s:UPDATE\x00"
		$string4 = "\x00%s:uNINSTALL\x00"

        condition:
                all of ($exif*) or any of ($string*)

}	


rule NetTraveler : Family {
	meta:
		description = "Nettravelr"
		author = "Katie Kleemola"
		last_updated = "2014-07-08"
	
	condition:
		NetTravExports or NetTravStrings or NetpassStrings

}

rule NetPass : Variant {
	meta:
		description = "netpass variant"
		author = "Katie Kleemola"
		last_updated = "2014-07-08"
	condition:
		NetpassStrings
}
private rule NSFreeCode : NSFree Family 
{
    meta:
        description = "NSFree code features"
        author = "Seth Hardy"
        last_modified = "2014-06-24"
    
    strings:
        // push vars then look for MZ
        $ = { 53 56 57 66 81 38 4D 5A }
        // nops then look for PE\0\0
        $ = { 90 90 90 90 81 3F 50 45 00 00 }
    
    condition:
        all of them
}

private rule NSFreeStrings : NSFree Family
{
    meta:
        description = "NSFree Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-24"
        
    strings:
        $ = "\\MicNS\\" nocase
        $ = "NSFreeDll" wide ascii
        // xor 0x58 dos stub
        $ = { 0c 30 31 2b 78 28 2a 37 3f 2a 39 35 78 3b 39 36 36 37 }
        
    condition:
       any of them
}

rule NSFree : Family
{
    meta:
        description = "NSFree"
        author = "Seth Hardy"
        last_modified = "2014-06-24"
        
    condition:
        NSFreeCode or NSFreeStrings
}private rule IsOLE : OLE
{
    meta:
        description = "Identifier for OLE files"
        author = "Seth Hardy"
        last_modified = "2014-05-06"
        
    strings:
        $magic = {d0 cf 11 e0 a1 b1 1a e1}
    
    condition:
        $magic at 0
}
/*

These string lists generated on the command line by:

Author:
file ~/samples/all/* | perl -ne 'if(/Author: (.*?), Template:/) { $x = $1; $x =~ s/\"/\\\"/g; while($x =~ /\\(\d{3})/) { $n = oct($1); $nn = sprintf("%02x",$n); $x =~ s/\\$1/\\x$nn/; chomp $x; } print "        \$ = \"\\x00$x\\x00\\x1e\"\n"; };' | sort | uniq

Title:
$ file ~/samples/all/* | perl -ne 'if(/Title: (.*?), Author:/) { $x = $1; $x =~ s/\"/\\\"/g; while($x =~ /\\(\d{3})/) { $n = oct($1); $nn = sprintf("%02x",$n); $x =~ s/\\$1/\\x$nn/; chomp $x; } print "        \$ = \"\\x00$x\\x00\\x1e\"\n"; };' | sort | uniq

Last Saved By:
$ file ~/samples/all/* | perl -ne 'if(/Last Saved By: (.*?), Revision/) { $x = $1; $x =~ s/\"/\\\"/g; while($x =~ /\\(\d{3})/) { $n = oct($1); $nn = sprintf("%02x",$n); $x =~ s/\\$1/\\x$nn/; chomp $x; }   print "        \$ = \"\\x00$x\\x00\\x1e\"\n"; };' | sort | uniq

*/


rule OLEAuthor : Author OLEMetadata
{
    meta:
        description = "Identifier for known OLE document authors"
        author = "Seth Hardy"
        last_modified = "2014-05-07"
        
    strings:
        $ = "\x00111\x00\x1e"
        $ = "\x0011\x00\x1e"
        $ = "\x00123\x00\x1e"
        $ = "\x002chu\x00\x1e"
        $ = "\x007513A3DEA183474\x00\x1e"
        $ = "\x00abc\x00\x1e"
        $ = "\x00Administrator\x00\x1e"
        $ = "\x00admin\x00\x1e"
        $ = "\x00Aggarwal, Aakash\x00\x1e"
        $ = "\x00beat\x00\x1e"
        $ = "\x00Ben\x00\x1e"
        $ = "\x00bf\x00\x1e"
        $ = "\x00Booksway\x00\x1e"
        $ = "\x00Bosh\x00\x1e"
        $ = "\x00captain\x00\x1e"
        $ = "\x00CC2\x00\x1e"
        $ = "\x00cyano\x00\x1e"
        $ = "\x00Dinesh\x00\x1e"
        $ = "\x00Dolker\x00\x1e"
        $ = "\x00Drokpa\x00\x1e"
        $ = "\x00Findo\x00\x1e"
        $ = "\x00FLORINE DATESSEN\x00\x1e"
        $ = "\x00funghain\x00\x1e"
        $ = "\x00HealthDeptt-01\x00\x1e"
        $ = "\x00hy9901a\x00\x1e"
        $ = "\x00IBM User\x00\x1e"
        $ = "\x00IBM\x00\x1e"
        $ = "\x00Igny\x00\x1e"
        $ = "\x00IITK\x00\x1e"
        $ = "\x00I. K\x00\x1e"
        $ = "\x00Jamal Al-Masraf\x00\x1e"
        $ = "\x00Joyce Havinga\x00\x1e"
        $ = "\x00kalume\x00\x1e"
        $ = "\x00Karma\x00\x1e"
        $ = "\x00karmayeshi\x00\x1e"
        $ = "\x00KChase\x00\x1e"
        $ = "\x00ken\x00\x1e"
        $ = "\x00khenrab\x00\x1e"
        $ = "\x00Kunga Tashi\x00\x1e"
        $ = "\x00Lenovo User\x00\x1e"
        $ = "\x00Lenovo\x00\x1e"
        $ = "\x00lenovo\x00\x1e"
        $ = "\x00Lharisang\x00\x1e"
        $ = "\x00Luitgard Hammerer\x00\x1e"
        $ = "\x00MC SYSTEM\x00\x1e"
        $ = "\x00mpzhang\x00\x1e"
        $ = "\x00neuroking\x00\x1e"
        $ = "\x00Ngawang Gelek\x00\x1e"
        $ = "\x00niu2\x00\x1e"
        $ = "\x00Owner\x00\x1e"
        $ = "\x00pema tashi\x00\x1e"
        $ = "\x00pepe\x00\x1e"
        $ = "\x00perhat64\x00\x1e"
        $ = "\x00Remote\x00\x1e"
        $ = "\x00ResuR\x00\x1e"
        $ = "\x00roy\x00\x1e"
        $ = "\x00Samphel\x00\x1e"
        $ = "\x00sard\x00\x1e"
        $ = "\x00shirley\x00\x1e"
        $ = "\x00shungqar\x00\x1e"
        $ = "\x00Sofia Olsson\x00\x1e"
        $ = "\x00Sonam Dolkar\x00\x1e"
        $ = "\x00Son Huynh Hong\x00\x1e"
        $ = "\x00system\x00\x1e"
        $ = "\x00teguete\x00\x1e"
        $ = "\x00tensangmo\x00\x1e"
        $ = "\x00tenzin1959\x00\x1e"
        $ = "\x00Tenzin\x00\x1e"
        $ = "\x00Tran Duy Linh\x00\x1e"
        $ = "\x00Traudl\x00\x1e"
        $ = "\x00Tsedup\x00\x1e"
        $ = "\x00Tsering Tamding\x00\x1e"
        $ = "\x00unknown\x00\x1e"
        $ = "\x00USER\x00\x1e"
        $ = "\x00User\x00\x1e"
        $ = "\x00user\x00\x1e"
        $ = "\x00votoystein\x00\x1e"
        $ = "\x00walkinnet\x00\x1e"
        $ = "\x00World Uyghur Congress\x00\x1e"
        $ = "\x00www\x00\x1e"
        $ = "\x00             \x00\x1e"
        $ = "\x00        \x00\x1e"
        $ = "\x00      \x00\x1e"
        $ = "\x00  \x00\x1e"
        $ = "\x00\xf4_y\xb7\x80\x05\x9e\xbf\x00\x1e"
        $ = "\x00xp\x00\x1e"
        $ = "\x00YCanPDF\x00\x1e"
        $ = "\x00y\x00\x1e"
        $ = "\x00zsh\x00\x1e"

    condition:
        IsOLE and (any of them)
}


rule OLETitle : Title OLEMetadata
{
    meta:
        description = "Identifier for known OLE document titles"
        author = "Seth Hardy"
        last_modified = "2014-05-07"
        
    strings:
        $ = "\x0001:00\x00\x1e"
        $ = "\x00    23-Aprel  chushidin keyin saet bir yirim,Xitayning 3 neper paylaqchisi seriqbuya yezida oy arilap yurup paylaqchiliq qiliwatqanda bir oyge toplann\xcaghan bir gurup uyghur yashlarni korgen we ularning yenida pichaq we tam teshidighan eswablarni korup gum\x00\x1e"
        $ = "\x0046-120603   fice W648\x00\x1e"
        $ = "\x0054-120602   15s\xb7K\x0c]\xb7\x00\x1e"
        $ = "\x005-Iyul Urumchi Qirghinchiliqi heqide qisqiche Dokilat \x00\x1e"
        $ = "\x00April 20-21, 2013\x00\x1e"
        $ = "\x00asdfasdfasdf\x00\x1e"
        $ = "\x00Bamako, le 04 d\x00\x1e"
        $ = "\x00Best\x00\x1e"
        $ = "\x00Dear All,\x00\x1e"
        $ = "\x00Dear President and Executive Members,\x00\x1e"
        $ = "\x00Full list of self-immolations in Tibet\x00\x1e"
        $ = "\x00Help stop the destruction of my home, Lhasa, Tibet\x00\x1e"
        $ = "\x00HHDL'visit in European\x00\x1e"
        $ = "\x00II) Overview & Analysis:\x00\x1e"
        $ = "\x00Institute for Defence Studies and Analyses\x00\x1e"
        $ = "\x00IPT  APPLICATION FORM\x00\x1e"
        $ = "\x00Jharkhand supports Indian Parliamentary resolution on Tibet crisis\x00\x1e"
        $ = "\x00Lieutenant General KENOSE BARRY PHILLIPE,\x00\x1e"
        $ = "\x00OPERATIONAL MANUAL:\x00\x1e"
        $ = "\x00PART 2 - Overview and Analysis\x00\x1e"
        $ = "\x00PowerPoint Presentation\x00\x1e"
        $ = "\x00Progress Chart: 15\x00\x1e"
        $ = "\x00Progress Chart:\x00\x1e"
        $ = "\x00Progress Chart\x00\x1e"
        $ = "\x00RC\x00\x1e"
        $ = "\x00(RESENDING)\x00\x1e"
        $ = "\x00Talking Points EU-China Human Rights Dialogue June 2011\x00\x1e"
        $ = "\x00TANC Community Center\x00\x1e"
        $ = "\x00The Charg\x00\x1e"
        $ = "\x00The following schedule of plans has been finalized for the purpose of holding the Second Special General Meeting of Tibetans being organized jointly by the Tibetan Parliament-in-Exile and the Kashag headed by the Kalon Tripa in accordance with the provis\x00\x1e"
        $ = "\x00The Tibet Museum Project\x00\x1e"
        $ = "\x00Tibetan Community in Switzerland & Liechtenstein, Binzstrasse 15, CH-8045 Zurich, Switzerland \x00\x1e"
        $ = "\x00TSERING BHUTI\x00\x1e"
        $ = "\x00Tsering Bhuti\x00\x1e"
        $ = "\x00 \x00\x1e"
        $ = "\x00#\x00\x1e"
        $ = "\x00\x8d\x00\x1e"
        $ = "\x00\x8d\x9a\x06\xb7\x00\x1e"
        $ = "\x00\xc8\xf8!\xb7\x00\x1e"
        $ = "\x00Yes, I would like to raise this point: how many more young Tibetan lives are to be sacrificed in these awful self immolations before China is likely to change its Tibet policies in favour of Tibetan autonomy\x00\x1e"


    condition:
        IsOLE and (any of them)
}

rule OLELastSavedBy : LastSavedBy OLEMetadata
{
    meta:
        description = "Identifier for known OLE document Last Saved By field"
        author = "Seth Hardy"
        last_modified = "2014-05-07"
        
    strings:
        $ = "\x00111\x00\x1e"
        $ = "\x0011\x00\x1e"
        $ = "\x00123\x00\x1e"
        $ = "\x00Administrator\x00\x1e"
        $ = "\x00Admin\x00\x1e"
        $ = "\x00Alex\x00\x1e"
        $ = "\x00Audit\x00\x1e"
        $ = "\x00A\x00\x1e"
        $ = "\x00beat\x00\x1e"
        $ = "\x00Ben\x00\x1e"
        $ = "\x00bf\x00\x1e"
        $ = "\x00Booksway\x00\x1e"
        $ = "\x00Bosh\x00\x1e"
        $ = "\x00captain\x00\x1e"
        $ = "\x00CL_nelson\x00\x1e"
        $ = "\x00Core\x00\x1e"
        $ = "\x00cyano\x00\x1e"
        $ = "\x00dainzin\x00\x1e"
        $ = "\x00Dolker\x00\x1e"
        $ = "\x00Findo\x00\x1e"
        $ = "\x00FLORINE DATESSEN\x00\x1e"
        $ = "\x00funghain\x00\x1e"
        $ = "\x00HP\x00\x1e"
        $ = "\x00hy9901a\x00\x1e"
        $ = "\x00IBM User\x00\x1e"
        $ = "\x00IBM\x00\x1e"
        $ = "\x00Igny\x00\x1e"
        $ = "\x00I. K\x00\x1e"
        $ = "\x00ITCO\x00\x1e"
        $ = "\x00jds\x00\x1e"
        $ = "\x00Joyce Havinga\x00\x1e"
        $ = "\x00karmayeshi\x00\x1e"
        $ = "\x00ken\x00\x1e"
        $ = "\x00khenrab\x00\x1e"
        $ = "\x00Kunga Tashi\x00\x1e"
        $ = "\x00lebrale\x00\x1e"
        $ = "\x00Lenovo User\x00\x1e"
        $ = "\x00Lenovo\x00\x1e"
        $ = "\x00lenovo\x00\x1e"
        $ = "\x00Lharisang\x00\x1e"
        $ = "\x00Lhundup Damcho\x00\x1e"
        $ = "\x00MC SYSTEM\x00\x1e"
        $ = "\x00mm\x00\x1e"
        $ = "\x00mpzhang\x00\x1e"
        $ = "\x00neuroking\x00\x1e"
        $ = "\x00niu2\x00\x1e"
        $ = "\x00Normal.d\x00\x1e"
        $ = "\x00Normal.w\x00\x1e"
        $ = "\x00Normal\x00\x1e"
        $ = "\x00one\x00\x1e"
        $ = "\x00Owner\x00\x1e"
        $ = "\x00pema tashi\x00\x1e"
        $ = "\x00pepe\x00\x1e"
        $ = "\x00PhiDiem\x00\x1e"
        $ = "\x00ResuR\x00\x1e"
        $ = "\x00roy\x00\x1e"
        $ = "\x00Samphel\x00\x1e"
        $ = "\x00system\x00\x1e"
        $ = "\x00TCC Dhasa1\x00\x1e"
        $ = "\x00tensangmo\x00\x1e"
        $ = "\x00Tenzin\x00\x1e"
        $ = "\x00test\x00\x1e"
        $ = "\x00Tibet Ever\x00\x1e"
        $ = "\x00Tran Duy Linh\x00\x1e"
        $ = "\x00Traudl\x00\x1e"
        $ = "\x00unknown\x00\x1e"
        $ = "\x00User\x00\x1e"
        $ = "\x00user\x00\x1e"
        $ = "\x00USR\x00\x1e"
        $ = "\x00walkinnet\x00\x1e"
        $ = "\x00WIN7\x00\x1e"
        $ = "\x00www\x00\x1e"
        $ = "\x00             \x00\x1e"
        $ = "\x00        \x00\x1e"
        $ = "\x00      \x00\x1e"
        $ = "\x00  \x00\x1e"
        $ = "\x00y\x00\x1e"

    condition:
        IsOLE and (any of them)
}private rule OlyxCode : Olyx Family 
{
    meta:
        description = "Olyx code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        $six = { C7 40 04 36 36 36 36 C7 40 08 36 36 36 36 }
        $slash = { C7 40 04 5C 5C 5C 5C C7 40 08 5C 5C 5C 5C }
        
    condition:
        any of them
}

private rule OlyxStrings : Olyx Family
{
    meta:
        description = "Olyx Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        $ = "/Applications/Automator.app/Contents/MacOS/DockLight"
       
    condition:
        any of them
}

rule Olyx : Family
{
    meta:
        description = "Olyx"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    condition:
        OlyxCode or OlyxStrings
}rule XYPayload : Payload
{
    meta:
        description = "Identifier for payloads using XXXXYYYY/YYYYXXXX markers"
        author = "Seth Hardy"
        last_modified = "2014-05-05"
        
    strings:
        $start_marker = "XXXXYYYY"
        $end_marker = "YYYYXXXX"
    
    condition:
        $start_marker and $end_marker
}private rule PlugXBootLDRCode : PlugX Family 
{
    meta:
        description = "PlugX boot.ldr code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-12"
        
    strings:
        $callpop = { E8 00 00 00 00 58 }
        // Compares [eax+n] to GetProcAdd, one character at a time. This goes up to GetP:
        $GetProcAdd = { 80 38 47 75 36 80 78 01 65 75 30 80 78 02 74 75 2A 80 78 03 50 }
        // Load these function strings 4 characters at a time. These check the first two blocks:
        $L4_LoadLibraryA = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 4C 6F 61 64 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 4C 69 62 72 }
        $L4_VirtualAlloc = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 56 69 72 74 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 75 61 6C 41 }
        $L4_VirtualFree = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 56 69 72 74 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 75 61 6C 46 }
        $L4_ExitThread = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 45 78 69 74 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 54 68 72 65 }
        $L4_ntdll = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 6E 74 64 6C 66 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) C6 00 }
        $L4_RtlDecompressBuffer = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 52 74 6C 44 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 65 63 6F 6D }
        $L4_memcpy = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 6D 65 6D 63 66 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 70 79 }
        
    condition:
        ($callpop at 0) or $GetProcAdd or (all of ($L4_*))
}

private rule PlugXStrings : PlugX Family
{
    meta:
        description = "PlugX Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-12"
        
    strings:
        $BootLDR = "boot.ldr" wide ascii
        $Dwork = "d:\\work" nocase
        $Plug25 = "plug2.5"
        $Plug30 = "Plug3.0"
        $Shell6 = "Shell6"
      
    condition:
        $BootLDR or ($Dwork and ($Plug25 or $Plug30 or $Shell6))
}

rule PlugX : Family
{
    meta:
        description = "PlugX"
        author = "Seth Hardy"
        last_modified = "2014-06-12"
        
    condition:
        PlugXBootLDRCode or PlugXStrings
}private rule PubSabCode : PubSab Family 
{
    meta:
        description = "PubSab code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        $decrypt = { 6B 45 E4 37 89 CA 29 C2 89 55 E4 }
        
    condition:
        any of them
}

private rule PubSabStrings : PubSab Family
{
    meta:
        description = "PubSab Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        $ = "_deamon_init"
        $ = "com.apple.PubSabAgent"
        $ = "/tmp/screen.jpeg"
       
    condition:
        any of them
}

rule PubSab : Family
{
    meta:
        description = "PubSab"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    condition:
        PubSabCode or PubSabStrings
}private rule QuarianCode : Quarian Family 
{
    meta:
        description = "Quarian code features"
        author = "Seth Hardy"
        last_modified = "2014-07-09"
    
    strings:
        // decrypt in intelnat.sys
        $ = { C1 E? 04 8B ?? F? C1 E? 05 33 C? }
        // decrypt in mswsocket.dll
        $ = { C1 EF 05 C1 E3 04 33 FB }
        $ = { 33 D8 81 EE 47 86 C8 61 }
        // loop in msupdate.dll
        $ = { FF 45 E8 81 45 EC CC 00 00 00 E9 95 FE FF FF }
    
    condition:
        any of them
}

private rule QuarianStrings : Quarian Family
{
    meta:
        description = "Quarian Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-09"
        
    strings:
        $ = "s061779s061750"
        $ = "[OnUpLoadFile]"
        $ = "[OnDownLoadFile]"
        $ = "[FileTransfer]"
        $ = "---- Not connect the Manager, so start UnInstall ----"
        $ = "------- Enter CompressDownLoadDir ---------"
        $ = "------- Enter DownLoadDirectory ---------"
        $ = "[HandleAdditionalData]"
        $ = "[mswsocket.dll]"
        $ = "msupdate.dll........Enter ThreadCmd!"
        $ = "ok1-1"
        $ = "msupdate_tmp.dll"
        $ = "replace Rpcss.dll successfully!"
        $ = "f:\\loadhiddendriver-mdl\\objfre_win7_x86\\i386\\intelnat.pdb"
        $ = "\\drivercashe\\" wide ascii
        $ = "\\microsoft\\windwos\\" wide ascii
        $ = "\\DosDevices\\LOADHIDDENDRIVER" wide ascii
        $ = "\\Device\\LOADHIDDENDRIVER" wide ascii
        $ = "Global\\state_maping" wide ascii
        $ = "E:\\Code\\2.0\\2.0_multi-port\\2.0\\ServerInstall_New-2010-0913_sp3\\msupdataDll\\Release\\msupdate_tmp.pdb"
        $ = "Global\\unInstall_event_1554_Ower" wide ascii
        
    condition:
       any of them
}

rule Quarian : Family
{
    meta:
        description = "Quarian"
        author = "Seth Hardy"
        last_modified = "2014-07-09"
        
    condition:
        QuarianCode or QuarianStrings
}private rule RegSubDatCode : RegSubDat Family 
{
    meta:
        description = "RegSubDat code features"
        author = "Seth Hardy"
        last_modified = "2014-07-14"
    
    strings:
        // decryption loop
        $ = { 80 34 3? 99 40 (3D FB 65 00 00 | 3B C6) 7? F? }
        // push then pop values
        $ = { 68 FF FF 7F 00 5? }
        $ = { 68 FF 7F 00 00 5? }
    
    condition:
        all of them
}

private rule RegSubDatStrings : RegSubDat Family
{
    meta:
        description = "RegSubDat Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-14"
        
    strings:
        $avg1 = "Button"
        $avg2 = "Allow"
        $avg3 = "Identity Protection"
        $avg4 = "Allow for all"
        $avg5 = "AVG Firewall Asks For Confirmation"
        $mutex = "0x1A7B4C9F"
        
    condition:
       all of ($avg*) or $mutex
}

rule RegSubDat : Family
{
    meta:
        description = "RegSubDat"
        author = "Seth Hardy"
        last_modified = "2014-07-14"
        
    condition:
        RegSubDatCode or RegSubDatStrings
}
private rule RSharedStrings : Surtr Family {
	meta:
		description = "identifiers for remote and gmremote"
		author = "Katie Kleemola"
		last_updated = "07-21-2014"
	
	strings:
		$ = "nView_DiskLoydb" wide
		$ = "nView_KeyLoydb" wide
		$ = "nView_skins" wide
		$ = "UsbLoydb" wide
		$ = "%sBurn%s" wide
		$ = "soul" wide

	condition:
		any of them

}


private rule RemoteStrings : Remote Variant Surtr Family {
	meta:
		description = "indicators for remote.dll - surtr stage 2"
		author = "Katie Kleemola"
		last_updated = "07-21-2014"
	
	strings:
		$ = "\x00Remote.dll\x00"
		$ = "\x00CGm_PlugBase::"
		$ = "\x00ServiceMain\x00_K_H_K_UH\x00"
		$ = "\x00_Remote_\x00" wide
	condition:
		any of them
}

private rule GmRemoteStrings : GmRemote Variant Family Surtr {
	meta:
		description = "identifiers for gmremote: surtr stage 2"
		author = "Katie Kleemola"
		last_updated = "07-21-2014"
	
	strings:
		$ = "\x00x86_GmRemote.dll\x00"
		$ = "\x00D:\\Project\\GTProject\\Public\\List\\ListManager.cpp\x00"
		$ = "\x00GmShutPoint\x00"
		$ = "\x00GmRecvPoint\x00"
		$ = "\x00GmInitPoint\x00"
		$ = "\x00GmVerPoint\x00"
		$ = "\x00GmNumPoint\x00"
		$ = "_Gt_Remote_" wide
		$ = "%sBurn\\workdll.tmp" wide
	
	condition:
		any of them

}

/*
 * Check if File has shared identifiers among Surtr Stage 2's
 * Then look for unique identifiers to each variant
*/

rule GmRemote : Family Surtr Variant GmRemote {
	meta:
		description = "identifier for gmremote"
		author = "Katie Kleemola"
		last_updated = "07-25-2014"
	
	condition:
		RSharedStrings and GmRemoteStrings
}

rule Remote : Family Surtr Variant Remote {
	meta:
		description = "identifier for remote"
		author = "Katie Kleemola"
		last_updated = "07-25-2014"
	
	condition:
		RSharedStrings and RemoteStrings
}
private rule RookieCode : Rookie Family 
{
    meta:
        description = "Rookie code features"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        // hidden AutoConfigURL
        $ = { C6 ?? ?? ?? 41 C6 ?? ?? ?? 75 [4] C6 ?? ?? ?? 6F C6 ?? ?? ?? 43 C6 ?? ?? ?? 6F C6 ?? ?? ?? 6E C6 ?? ?? ?? 66 }
        // hidden ProxyEnable
        $ = { C6 ?? ?? ?? 50 [4] C6 ?? ?? ?? 6F C6 ?? ?? ?? 78 C6 ?? ?? ?? 79 C6 ?? ?? ?? 45 C6 ?? ?? ?? 6E C6 ?? ?? ?? 61 }
        // xor on rand value?
        $ = { 8B 1D 10 A1 40 00 [18] FF D3 8A 16 32 D0 88 16 }

    condition:
        any of them
}

private rule RookieStrings : Rookie Family
{
    meta:
        description = "Rookie Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        $ = "RookIE/1.0"
        
    condition:
       any of them
}

rule Rookie : Family
{
    meta:
        description = "Rookie"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    condition:
        RookieCode or RookieStrings
}
private rule RooterCode : Rooter Family 
{
    meta:
        description = "Rooter code features"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
    
    strings:
        // xor 0x30 decryption
        $ = { 80 B0 ?? ?? ?? ?? 30 40 3D 00 50 00 00 7C F1 }
    
    condition:
        any of them
}

private rule RooterStrings : Rooter Family
{
    meta:
        description = "Rooter Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
        
    strings:
        $group1 = "seed\x00"
        $group2 = "prot\x00"
        $group3 = "ownin\x00"
        $group4 = "feed0\x00"
        $group5 = "nown\x00"

    condition:
       3 of ($group*)
}

rule Rooter : Family
{
    meta:
        description = "Rooter"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
        
    condition:
        RooterCode or RooterStrings
}private rule SafeNetCode : SafeNet Family 
{
    meta:
        description = "SafeNet code features"
        author = "Seth Hardy"
        last_modified = "2014-07-16"
        
    strings:
        // add edi, 14h; cmp edi, 50D0F8h
        $ = { 83 C7 14 81 FF F8 D0 40 00 }
    condition:
        any of them
}

private rule SafeNetStrings : SafeNet Family
{
    meta:
        description = "Strings used by SafeNet"
        author = "Seth Hardy"
        last_modified = "2014-07-16"
        
    strings:
        $ = "6dNfg8Upn5fBzGgj8licQHblQvLnUY19z5zcNKNFdsDhUzuI8otEsBODrzFCqCKr"
        $ = "/safe/record.php"
        $ = "_Rm.bat" wide ascii
        $ = "try\x0d\x0a\x09\x09\x09\x09  del %s" wide ascii
        $ = "Ext.org" wide ascii
        
    condition:
        any of them

}

rule SafeNet : Family
{
    meta:
        description = "SafeNet family"
        
    condition:
        SafeNetCode or SafeNetStrings
        
}private rule ScarhiknCode : Scarhikn Family 
{
    meta:
        description = "Scarhikn code features"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
    
    strings:
        // decryption
        $ = { 8B 06 8A 8B ?? ?? ?? ?? 30 0C 38 03 C7 55 43 E8 ?? ?? ?? ?? 3B D8 59 72 E7 }
        $ = { 8B 02 8A 8D ?? ?? ?? ?? 30 0C 30 03 C6 8B FB 83 C9 FF 33 C0 45 F2 AE F7 D1 49 3B E9 72 E2 }
    
    condition:
        any of them
}

private rule ScarhiknStrings : Scarhikn Family
{
    meta:
        description = "Scarhikn Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        $ = "9887___skej3sd"
        $ = "haha123"
        
    condition:
       any of them
}

rule Scarhikn : Family
{
    meta:
        description = "Scarhikn"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    condition:
        ScarhiknCode or ScarhiknStrings
}private rule SurtrCode : Surtr Family {
	meta: 
		author = "Katie Kleemola"
		description = "Code features for Surtr Stage1"
		last_updated = "2014-07-16"
	
	strings:
		//decrypt config
		$ = { 8A ?? ?? 84 ?? ?? 74 ?? 3C 01 74 ?? 34 01 88 41 3B ?? 72 ?? }
		//if Burn folder name is not in strings
		$ = { C6 [3] 42 C6 [3] 75 C6 [3] 72 C6 [3] 6E C6 [3] 5C }
		//mov char in _Fire
		$ = { C6 [3] 5F C6 [3] 46 C6 [3] 69 C6 [3] 72 C6 [3] 65 C6 [3] 2E C6 [3] 64 }

	condition:
		any of them

}

private rule SurtrStrings : Surtr Family {	
	meta: 
		author = "Katie Kleemola"
		description = "Strings for Surtr"
		last_updated = "2014-07-16"

	strings:
		$ = "\x00soul\x00"
		$ = "\x00InstallDll.dll\x00"
		$ = "\x00_One.dll\x00"
		$ = "_Fra.dll"
		$ = "CrtRunTime.log"
		$ = "Prod.t"
		$ = "Proe.t"
		$ = "Burn\\"
		$ = "LiveUpdata_Mem\\"

	condition:
		any of them

}

rule Surtr : Family {
	meta:
		author = "Katie Kleemola"
		description = "Rule for Surtr Stage One"
		last_updated = "2014-07-16"

	condition:
		SurtrStrings or SurtrCode

}
private rule T5000Strings : T5000 Family
{
    meta:
        description = "T5000 Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-26"
        
    strings:
        $ = "_tmpR.vbs"
        $ = "_tmpg.vbs"
        $ = "Dtl.dat" wide ascii
        $ = "3C6FB3CA-69B1-454f-8B2F-BD157762810E"
        $ = "EED5CA6C-9958-4611-B7A7-1238F2E1B17E"
        $ = "8A8FF8AD-D1DE-4cef-B87C-82627677662E"
        $ = "43EE34A9-9063-4d2c-AACD-F5C62B849089"
        $ = "A8859547-C62D-4e8b-A82D-BE1479C684C9"
        $ = "A59CF429-D0DD-4207-88A1-04090680F714"
        $ = "utd_CE31" wide ascii
        $ = "f:\\Project\\T5000\\Src\\Target\\1 KjetDll.pdb"
        $ = "l:\\MyProject\\Vc 7.1\\T5000\\T5000Ver1.28\\Target\\4 CaptureDLL.pdb"
        $ = "f:\\Project\\T5000\\Src\\Target\\4 CaptureDLL.pdb"
        $ = "E:\\VS2010\\xPlat2\\Release\\InstRes32.pdb"
        
    condition:
       any of them
}

rule T5000 : Family
{
    meta:
        description = "T5000"
        author = "Seth Hardy"
        last_modified = "2014-06-26"
        
    condition:
        T5000Strings
}rule dubseven_file_set
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for service files loading UP007"
    
    strings:
        $file1 = "\\Microsoft\\Internet Explorer\\conhost.exe"
        $file2 = "\\Microsoft\\Internet Explorer\\dll2.xor"
        $file3 = "\\Microsoft\\Internet Explorer\\HOOK.DLL"
        $file4 = "\\Microsoft\\Internet Explorer\\main.dll"
        $file5 = "\\Microsoft\\Internet Explorer\\nvsvc.exe"
        $file6 = "\\Microsoft\\Internet Explorer\\SBieDll.dll"
        $file7 = "\\Microsoft\\Internet Explorer\\mon"
        $file8 = "\\Microsoft\\Internet Explorer\\runas.exe"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        //Just a few of these as they differ
        3 of ($file*)
}

rule dubseven_dropper_registry_checks
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for registry keys checked for by the dropper"
    
    strings:
        $reg1 = "SOFTWARE\\360Safe\\Liveup"
        $reg2 = "Software\\360safe"
        $reg3 = "SOFTWARE\\kingsoft\\Antivirus"
        $reg4 = "SOFTWARE\\Avira\\Avira Destop"
        $reg5 = "SOFTWARE\\rising\\RAV"
        $reg6 = "SOFTWARE\\JiangMin"
        $reg7 = "SOFTWARE\\Micropoint\\Anti-Attack"

    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        all of ($reg*)
}

rule dubseven_dropper_dialog_remains
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for related dialog remnants. How rude."
    
    strings:
        $dia1 = "fuckMessageBox 1.0" wide
        $dia2 = "Rundll 1.0" wide
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        any of them
}
        

rule maindll_mutex
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches on the maindll mutex"
        
    strings:
        $mutex = "h31415927tttt"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $mutex
}


rule SLServer_dialog_remains
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for related dialog remnants."
    
    strings:
        $slserver = "SLServer" wide
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $slserver
}

rule SLServer_mutex
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for the mutex."
    
    strings:
        $mutex = "M&GX^DSF&DA@F"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $mutex
}

rule SLServer_command_and_control
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for the C2 server."
    
    strings:
        $c2 = "safetyssl.security-centers.com"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $c2
}

rule SLServer_campaign_code
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for the related campaign code."
    
    strings:
        $campaign = "wthkdoc0106"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $campaign
}

rule SLServer_unknown_string
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for a unique string."
    
    strings:
        $string = "test-b7fa835a39"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $string
}



private rule VidgrabCode : Vidgrab Family 
{
    meta:
        description = "Vidgrab code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    strings:
        $divbyzero = { B8 02 00 00 00 48 48 BA 02 00 00 00 83 F2 02 F7 F0 }
        // add eax, ecx; xor byte ptr [eax], ??h; inc ecx
        $xorloop = { 03 C1 80 30 (66 | 58) 41 }
        $junk = { 8B 4? ?? 8B 4? ?? 03 45 08 52 5A }
        
    condition:
        all of them
}

private rule VidgrabStrings : Vidgrab Family
{
    meta:
        description = "Vidgrab Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    strings:
        $ = "IDI_ICON5" wide ascii
        $ = "starter.exe"
        $ = "wmifw.exe"
        $ = "Software\\rar"
        $ = "tmp092.tmp"
        $ = "temp1.exe"
        
    condition:
       3 of them
}

rule Vidgrab : Family
{
    meta:
        description = "Vidgrab"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    condition:
        VidgrabCode or VidgrabStrings
}private rule WarpCode : Warp Family 
{
    meta:
        description = "Warp code features"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
    
    strings:
        // character replacement
        $ = { 80 38 2B 75 03 C6 00 2D 80 38 2F 75 03 C6 00 5F }
    
    condition:
        any of them
}

private rule WarpStrings : Warp Family
{
    meta:
        description = "Warp Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
        
    strings:
        $ = "/2011/n325423.shtml?"
        $ = "wyle"
        $ = "\\~ISUN32.EXE"

    condition:
       any of them
}

rule Warp : Family
{
    meta:
        description = "Warp"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
        
    condition:
        WarpCode or WarpStrings
}private rule WimmieShellcode : Wimmie Family 
{
    meta:
        description = "Wimmie code features"
        author = "Seth Hardy"
        last_modified = "2014-07-17"
        
    strings:
        // decryption loop
        $ = { 49 30 24 39 83 F9 00 77 F7 8D 3D 4D 10 40 00 B9 0C 03 00 00 }
        $xordecrypt = {B9 B4 1D 00 00 [8] 49 30 24 39 83 F9 00 }
        
    condition:
        any of them
}

private rule WimmieStrings : Wimmie Family
{
    meta:
        description = "Strings used by Wimmie"
        author = "Seth Hardy"
        last_modified = "2014-07-17"
        
    strings:
        $ = "\x00ScriptMan"
        $ = "C:\\WINDOWS\\system32\\sysprep\\cryptbase.dll" wide ascii
        $ = "ProbeScriptFint" wide ascii
        $ = "ProbeScriptKids"
        
    condition:
        any of them

}

rule Wimmie : Family
{
    meta:
        description = "Wimmie family"
        author = "Seth Hardy"
        last_modified = "2014-07-17"
   
    condition:
        WimmieShellcode or WimmieStrings
        
}
private rule XtremeRATCode : XtremeRAT Family 
{
    meta:
        description = "XtremeRAT code features"
        author = "Seth Hardy"
        last_modified = "2014-07-09"
    
    strings:
        // call; fstp st
        $ = { E8 ?? ?? ?? ?? DD D8 }
        // hiding string
        $ = { C6 85 ?? ?? ?? ?? 4D C6 85 ?? ?? ?? ?? 70 C6 85 ?? ?? ?? ?? 64 C6 85 ?? ?? ?? ?? 62 C6 85 ?? ?? ?? ?? 6D }
    
    condition:
        all of them
}

private rule XtremeRATStrings : XtremeRAT Family
{
    meta:
        description = "XtremeRAT Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-09"
        
    strings:
        $ = "dqsaazere"
        $ = "-GCCLIBCYGMING-EH-TDM1-SJLJ-GTHR-MINGW32"
        
    condition:
       any of them
}

rule XtremeRAT : Family
{
    meta:
        description = "XtremeRAT"
        author = "Seth Hardy"
        last_modified = "2014-07-09"
        
    condition:
        XtremeRATCode or XtremeRATStrings
}rule YayihCode : Yayih Family 
{
    meta:
        description = "Yayih code features"
        author = "Seth Hardy"
        last_modified = "2014-07-11"
    
    strings:
        //  encryption
        $ = { 80 04 08 7A 03 C1 8B 45 FC 80 34 08 19 03 C1 41 3B 0A 7C E9 }
    
    condition:
        any of them
}

rule YayihStrings : Yayih Family
{
    meta:
        description = "Yayih Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-11"
        
    strings:
        $ = "/bbs/info.asp"
        $ = "\\msinfo.exe"
        $ = "%s\\%srcs.pdf"
        $ = "\\aumLib.ini"

    condition:
       any of them
}

rule Yayih : Family
{
    meta:
        description = "Yayih"
        author = "Seth Hardy"
        last_modified = "2014-07-11"
        
    condition:
        YayihCode or YayihStrings
}