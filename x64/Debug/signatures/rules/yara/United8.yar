private rule APT3102Code : APT3102 Family 
{
    meta:
        description = "3102 code features"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        $setupthread = { B9 02 07 00 00 BE ?? ?? ?? ?? 8B F8 6A 00 F3 A5 }
  
    condition:
        any of them
}

private rule APT3102Strings : APT3102 Family
{
    meta:
        description = "3102 Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        $ = "rundll32_exec.dll\x00Update"
        // this is in the encrypted code - shares with 9002 variant
        //$ = "POST http://%ls:%d/%x HTTP/1.1"
        
    condition:
       any of them
}

rule APT3102 : Family
{
    meta:
        description = "3102"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    condition:
        APT3102Code or APT3102Strings
}private rule APT9002Code : APT9002 Family 
{
    meta:
        description = "9002 code features"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        // start code block
        $ = { B9 7A 21 00 00 BE ?? ?? ?? ?? 8B F8 ?? ?? ?? F3 A5 }
        // decryption from other variant with multiple start threads
        $ = { 8A 14 3E 8A 1C 01 32 DA 88 1C 01 8B 54 3E 04 40 3B C2 72 EC }
  
    condition:
        any of them
}

private rule APT9002Strings : APT9002 Family
{
    meta:
        description = "9002 Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        $ = "POST http://%ls:%d/%x HTTP/1.1"
        $ = "%%TEMP%%\\%s_p.ax" wide ascii
        $ = "%TEMP%\\uid.ax" wide ascii
        $ = "%%TEMP%%\\%s.ax" wide ascii
        // also triggers on surtr $ = "mydll.dll\x00DoWork"
        $ = "sysinfo\x00sysbin01"
        $ = "\\FlashUpdate.exe"
        
    condition:
       any of them
}

rule APT9002 : Family
{
    meta:
        description = "9002"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    condition:
        APT9002Code or APT9002Strings
}private rule BangatCode : Bangat Family 
{
    meta:
        description = "Bangat code features"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
    
    strings:
        // dec [ebp + procname], push eax, push edx, call get procaddress
        $ = { FE 4D ?? 8D 4? ?? 50 5? FF }
    
    condition:
        any of them
}

private rule BangatStrings : Bangat Family
{
    meta:
        description = "Bangat Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
        
    strings:
        $lib1 = "DreatePipe"
        $lib2 = "HetSystemDirectoryA"
        $lib3 = "SeleaseMutex"
        $lib4 = "DloseWindowStation"
        $lib5 = "DontrolService"
        $file = "~hhC2F~.tmp"
        $mc = "~_MC_3~"

    condition:
       all of ($lib*) or $file or $mc
}

rule Bangat : Family
{
    meta:
        description = "Bangat"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
        
    condition:
        BangatCode or BangatStrings
}private rule BoousetCode : Boouset Family 
{
    meta:
        description = "Boouset code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        $boousetdat = { C6 ?? ?? ?? ?? 00 62 C6 ?? ?? ?? ?? 00 6F C6 ?? ?? ?? ?? 00 6F C6 ?? ?? ?? ?? 00 75 }
        
    condition:
        any of them
}

private rule BoousetStrings : Boouset Family
{
    meta:
        description = "Boouset Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        $ = "Q\x00\x00\x00\x00W\x00\x00\x00\x00E\x00\x00\x00\x00R\x00\x00\x00\x00T\x00\x00\x00\x00Y\x00\x00\x00\x00"
        $ = "A\x00\x00\x00\x00S\x00\x00\x00\x00D\x00\x00\x00\x00F\x00\x00\x00\x00G\x00\x00\x00\x00H"
        $ = "Z\x00\x00\x00\x00X\x00\x00\x00\x00C\x00\x00\x00\x00V\x00\x00\x00\x00B\x00\x00\x00\x00N\x00\x00\x00\x00"
        $ = "\\~Z8314.tmp"
        $ = "hulee midimap" wide ascii
        
    condition:
       any of them
}

rule Boouset : Family
{
    meta:
        description = "Boouset"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    condition:
        BoousetCode or BoousetStrings
}private rule ComfooCode : Comfoo Family 
{
    meta:
        description = "Comfoo code features"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    strings:
        $resource = { 6A 6C 6A 59 55 E8 01 FA FF FF }
  
    condition:
        any of them
}

private rule ComfooStrings : Comfoo Family
{
    meta:
        description = "Comfoo Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    strings:
        $ = "fefj90"
        $ = "iamwaitingforu653890"
        $ = "watchevent29021803"
        $ = "THIS324NEWGAME"
        $ = "ms0ert.temp"
        $ = "\\mstemp.temp"
        
    condition:
       any of them
}

rule Comfoo : Family
{
    meta:
        description = "Comfoo"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    condition:
        ComfooCode or ComfooStrings
}private rule CookiesStrings : Cookies Family
{
    meta:
        description = "Cookies Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    strings:
        $zip1 = "ntdll.exePK"
        $zip2 = "AcroRd32.exePK"
        $zip3 = "Setup=ntdll.exe\x0d\x0aSilent=1\x0d\x0a"
        $zip4 = "Setup=%temp%\\AcroRd32.exe\x0d\x0a"
        $exe1 = "Leave GetCommand!"
        $exe2 = "perform exe success!"
        $exe3 = "perform exe failure!"
        $exe4 = "Entry SendCommandReq!"
        $exe5 = "Reqfile not exist!"
        $exe6 = "LeaveDealUpfile!"
        $exe7 = "Entry PostData!"
        $exe8 = "Leave PostFile!"
        $exe9 = "Entry PostFile!"
        $exe10 = "\\unknow.zip" wide ascii
        $exe11 = "the url no respon!"
        
    condition:
      (2 of ($zip*)) or (2 of ($exe*))
}

rule Cookies : Family
{
    meta:
        description = "Cookies"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    condition:
        CookiesStrings
}private rule cxpidCode : cxpid Family 
{
    meta:
        description = "cxpid code features"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
    
    strings:
        $entryjunk = { 55 8B EC B9 38 04 00 00 6A 00 6A 00 49 75 F9 }
    
    condition:
        any of them
}

private rule cxpidStrings : cxpid Family
{
    meta:
        description = "cxpid Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
        
    strings:
        $ = "/cxpid/submit.php?SessionID="
        $ = "/cxgid/"
        $ = "E21BC52BEA2FEF26D005CF"
        $ = "E21BC52BEA39E435C40CD8"
        $ = "                   -,L-,O+,Q-,R-,Y-,S-"
        
    condition:
       any of them
}

rule cxpid : Family
{
    meta:
        description = "cxpid"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
        
    condition:
        cxpidCode or cxpidStrings
}private rule EnfalCode : Enfal Family 
{
    meta:
        description = "Enfal code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        // mov al, 20h; sub al, bl; add [ebx+esi], al; push esi; inc ebx; call edi; cmp ebx, eax
        $decrypt = { B0 20 2A C3 00 04 33 56 43 FF D7 3B D8 }
        
    condition:
        any of them
}

private rule EnfalStrings : Enfal Family
{
    meta:
        description = "Enfal Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        $ = "D:\\work\\\xe6\xba\x90\xe5\x93\xa5\xe5\x85\x8d\xe6\x9d\x80\\tmp\\Release\\ServiceDll.pdb"
        $ = "e:\\programs\\LuridDownLoader"
        $ = "LuridDownloader for Falcon"
        $ = "DllServiceTrojan"
        $ = "\\k\\\xe6\xa1\x8c\xe8\x9d\xa2\\"
        $ = "EtenFalcon\xef\xbc\x88\xe4\xbf\xae\xe6\x94\xb9\xef\xbc\x89"
        $ = "Madonna\x00Jesus"
        $ = "/iupw82/netstate"
        $ = "fuckNodAgain"
        $ = "iloudermao"
        $ = "Crpq2.cgi"
        $ = "Clnpp5.cgi"
        $ = "Dqpq3ll.cgi"
        $ = "dieosn83.cgi"
        $ = "Rwpq1.cgi"
        $ = "/Ccmwhite"
        $ = "/Cmwhite"
        $ = "/Crpwhite"
        $ = "/Dfwhite"
        $ = "/Query.txt"
        $ = "/Ufwhite"
        $ = "/cgl-bin/Clnpp5.cgi"
        $ = "/cgl-bin/Crpq2.cgi"
        $ = "/cgl-bin/Dwpq3ll.cgi"
        $ = "/cgl-bin/Owpq4.cgi"
        $ = "/cgl-bin/Rwpq1.cgi"
        $ = "/trandocs/mm/"
        $ = "/trandocs/netstat"
        $ = "NFal.exe"
        $ = "LINLINVMAN"
        $ = "7NFP4R9W"
        
    condition:
        any of them
}

rule Enfal : Family
{
    meta:
        description = "Enfal"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    condition:
        EnfalCode or EnfalStrings
}private rule EzcobStrings : Ezcob Family
{
    meta:
        description = "Ezcob Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
        
    strings:
        $ = "\x12F\x12F\x129\x12E\x12A\x12E\x12B\x12A\x12-\x127\x127\x128\x123\x12"
        $ = "\x121\x12D\x128\x123\x12B\x122\x12E\x128\x12-\x12B\x122\x123\x12D\x12"
        $ = "Ezcob" wide ascii
        $ = "l\x12i\x12u\x122\x120\x121\x123\x120\x124\x121\x126"
        $ = "20110113144935"
        
    condition:
       any of them
}

rule Ezcob : Family
{
    meta:
        description = "Ezcob"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
        
    condition:
        EzcobStrings
}private rule HTMLVariant : FakeM Family HTML Variant
{
	meta:
		description = "Identifier for html variant of FAKEM"
		author = "Katie Kleemola"
		last_updated = "2014-05-20"
	
	strings:
		// decryption loop
		$s1 = { 8B 55 08 B9 00 50 00 00 8D 3D ?? ?? ?? 00 8B F7 AD 33 C2 AB 83 E9 04 85 C9 75 F5 }
		//mov byte ptr [ebp - x] y, x: 0x10-0x1 y: 0-9,A-F
		$s2 = { C6 45 F? (3?|4?) }

	condition:
		$s1 and #s2 == 16

}

//todo: need rules for other variants
rule FakeM : Family
{
	meta:
		description = "FakeM"
		author = "Katie Kleemola"
		last_updated = "2014-07-03"
	
	condition:
		HTMLVariant


}

rule FAKEMhtml : Variant
{
	meta:
		description = "Rule for just the HTML Variant"
		author = "Katie Kleemola"
		last_updated = "2014-07-10"
	
	condition:
		HTMLVariant
}
private rule FavoriteCode : Favorite Family 
{
    meta:
        description = "Favorite code features"
        author = "Seth Hardy"
        last_modified = "2014-06-24"
    
    strings:
        // standard string hiding
        $ = { C6 45 ?? 3B C6 45 ?? 27 C6 45 ?? 34 C6 45 ?? 75 C6 45 ?? 6B C6 45 ?? 6C C6 45 ?? 3B C6 45 ?? 2F }
        $ = { C6 45 ?? 6F C6 45 ?? 73 C6 45 ?? 73 C6 45 ?? 76 C6 45 ?? 63 C6 45 ?? 65 C6 45 ?? 78 C6 45 ?? 65 }
    
    condition:
        any of them
}

private rule FavoriteStrings : Favorite Family
{
    meta:
        description = "Favorite Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-24"
        
    strings:
        $string1 = "!QAZ4rfv"
        $file1 = "msupdater.exe"
        $file2 = "FAVORITES.DAT"
        
    condition:
       any of ($string*) or all of ($file*)
}

rule Favorite : Family
{
    meta:
        description = "Favorite"
        author = "Seth Hardy"
        last_modified = "2014-06-24"
        
    condition:
        FavoriteCode or FavoriteStrings
}private rule IsRTF : RTF
{
    meta:
        description = "Identifier for RTF files"
        author = "Seth Hardy"
        last_modified = "2014-05-05"
        
    strings:
        $magic = /^\s*{\\rt/
    
    condition:
        $magic
}

private rule IsOLE : OLE
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

private rule IsPE : PE 
{
	meta:
		description = "Identifier for PE files"
		last_modified = "2014-07-11"

	strings:
		$magic = { 5a 4d }

	condition:
		$magic at 0 and uint32(uint32(0x3C)) == 0x00004550
}
private rule GlassesCode : Glasses Family 
{
    meta:
        description = "Glasses code features"
        author = "Seth Hardy"
        last_modified = "2014-07-22"
        
    strings:
        $ = { B8 AB AA AA AA F7 E1 D1 EA 8D 04 52 2B C8 }
        $ = { B8 56 55 55 55 F7 E9 8B 4C 24 1C 8B C2 C1 E8 1F 03 D0 49 3B CA }
        
    condition:
        any of them
}

private rule GlassesStrings : Glasses Family
{
    meta:
        description = "Strings used by Glasses"
        author = "Seth Hardy"
        last_modified = "2014-07-22"
        
    strings:
        $ = "thequickbrownfxjmpsvalzydg"
        $ = "Mozilla/4.0 (compatible; Windows NT 5.1; MSIE 7.0; Trident/4.0; %s.%s)"
        $ = "\" target=\"NewRef\"></a>"
 
    condition:
        all of them

}

rule Glasses : Family
{
    meta:
        description = "Glasses family"
        author = "Seth Hardy"
        last_modified = "2014-07-22"
   
    condition:
        GlassesCode or GlassesStrings
        
}
private rule iexpl0reCode : iexpl0ree Family 
{
    meta:
        description = "iexpl0re code features"
        author = "Seth Hardy"
        last_modified = "2014-07-21"
        
    strings:
        $ = { 47 83 FF 64 0F 8C 6D FF FF FF 33 C0 5F 5E 5B C9 C3 }
        $ = { 80 74 0D A4 44 41 3B C8 7C F6 68 04 01 00 00 }
        $ = { 8A C1 B2 07 F6 EA 30 04 31 41 3B 4D 10 7C F1 }
        $ = { 47 83 FF 64 0F 8C 79 FF FF FF 33 C0 5F 5E 5B C9 C3 }
        // 88h decrypt
        $ = { 68 88 00 00 00 68 90 06 00 00 68 ?? ?? ?? ?? 89 3? E8 }
        $ = { BB 88 00 00 00 53 68 90 06 00 00 68 ?? ?? ?? ?? 89 3? E8 }
        
    condition:
        any of them
}

private rule iexpl0reStrings : iexpl0re Family
{
    meta:
        description = "Strings used by iexpl0re"
        author = "Seth Hardy"
        last_modified = "2014-07-21"
        
    strings:
        $ = "%USERPROFILE%\\IEXPL0RE.EXE"
        $ = "\"<770j (("
        $ = "\\Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\IEXPL0RE.LNK"
        $ = "\\Documents and Settings\\%s\\Application Data\\Microsoft\\Internet Explorer\\IEXPL0RE.EXE"
        $ = "LoaderV5.dll"
        // stage 2
        $ = "POST /index%0.9d.asp HTTP/1.1"
        $ = "GET /search?n=%0.9d&"
        $ = "DUDE_AM_I_SHARP-3.14159265358979x6.626176"
        $ = "WHO_A_R_E_YOU?2.99792458x1.25663706143592"
        $ = "BASTARD_&&_BITCHES_%0.8x"
        $ = "c:\\bbb\\eee.txt"
        
    condition:
        any of them

}

rule iexpl0re : Family
{
    meta:
        description = "iexpl0re family"
        author = "Seth Hardy"
        last_modified = "2014-07-21"
   
    condition:
        iexpl0reCode or iexpl0reStrings
        
}
private rule IMulerCode : IMuler Family 
{
    meta:
        description = "IMuler code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-16"
        
    strings:
        // Load these function strings 4 characters at a time. These check the first two blocks:
        $L4_tmpSpotlight = { C7 ?? 2F 74 6D 70 C7 ?? 04 2F 53 70 6F }
        $L4_TMPAAABBB = { C7 ?? ?? ?? ?? ?? 54 4D 50 41 C7 ?? ?? ?? ?? ?? 41 41 42 42 }
        $L4_FILEAGENTVer = { C7 ?? 46 49 4C 45 C7 ?? 04 41 47 45 4E }
        $L4_TMP0M34JDF8 = { C7 ?? ?? ?? ?? ?? 54 4D 50 30 C7 ?? ?? ?? ?? ?? 4D 33 34 4A }
        $L4_tmpmdworker = { C7 ?? 2F 74 6D 70 C7 ?? 04 2F 2E 6D 64 }
        
    condition:
        any of ($L4*)
}

private rule IMulerStrings : IMuler Family
{
    meta:
        description = "IMuler Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-16"
        
    strings:
        $ = "/cgi-mac/"
        $ = "xnocz1"
        $ = "checkvir.plist"
        $ = "/Users/apple/Documents/mac back"
        $ = "iMuler2"
        $ = "/Users/imac/Desktop/macback/"
        $ = "xntaskz.gz"
        $ = "2wmsetstatus.cgi"
        $ = "launch-0rp.dat"
        $ = "2wmupload.cgi"
        $ = "xntmpz"
        $ = "2wmrecvdata.cgi"
        $ = "xnorz6"
        $ = "2wmdelfile.cgi"
        $ = "/LanchAgents/checkvir"
        $ = "0PERA:%s"
        $ = "/tmp/Spotlight"
        $ = "/tmp/launch-ICS000"
        
    condition:
        any of them
}

rule IMuler : Family
{
    meta:
        description = "IMuler"
        author = "Seth Hardy"
        last_modified = "2014-06-16"
        
    condition:
        IMulerCode or IMulerStrings
}private rule Insta11Code : Insta11 Family 
{
    meta:
        description = "Insta11 code features"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
    
    strings:
        // jmp $+5; push 423h
        $jumpandpush = { E9 00 00 00 00 68 23 04 00 00 }
    
    condition:
        any of them
}

private rule Insta11Strings : Insta11 Family
{
    meta:
        description = "Insta11 Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
        
    strings:
        $ = "XTALKER7"
        $ = "Insta11 Microsoft" wide ascii
        $ = "wudMessage"
        $ = "ECD4FC4D-521C-11D0-B792-00A0C90312E1"
        $ = "B12AE898-D056-4378-A844-6D393FE37956"
        
    condition:
       any of them
}

rule Insta11 : Family
{
    meta:
        description = "Insta11"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
        
    condition:
        Insta11Code or Insta11Strings
}import "pe"

/*
*
* This section of the rules are all specific to the new 2016
* KeyBoy sample targeting the Tibetan community. Other following
* sections capture file characteristics observed across multiple
* years of development. Don't miss the exploit doc signatures
* at the very end.
*
*/
rule new_keyboy_export
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the new 2016 sample's export"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and


        filesize < 200KB and


        //The malware family seems to share many exports
        //but this is the new kid on the block.
        pe.exports("cfsUpdate")
}


rule new_keyboy_header_codes
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the 2016 sample's header codes"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    strings:
        $s1 = "*l*" wide fullword
        $s2 = "*a*" wide fullword
        $s3 = "*s*" wide fullword
        $s4 = "*d*" wide fullword
        $s5 = "*f*" wide fullword
        $s6 = "*g*" wide fullword
        $s7 = "*h*" wide fullword

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and


        filesize < 200KB and


        all of them
}


/*
*
* This section of the rules are all broader and will hit on
* older KeyBoy samples and other samples possibly part of a
* a larger development effort.
*
*/

rule keyboy_commands
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the 2016 sample's sent and received commands"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    strings:
        $s1 = "Update" wide fullword
        $s2 = "UpdateAndRun" wide fullword
        $s3 = "Refresh" wide fullword
        $s4 = "OnLine" wide fullword
        $s5 = "Disconnect" wide fullword
        $s6 = "Pw_Error" wide fullword
        $s7 = "Pw_OK" wide fullword
        $s8 = "Sysinfo" wide fullword
        $s9 = "Download" wide fullword
        $s10 = "UploadFileOk" wide fullword
        $s11 = "RemoteRun" wide fullword
        $s12 = "FileManager" wide fullword

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and


        filesize < 200KB and


        6 of them
}

rule keyboy_errors
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the sample's shell error2 log statements"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    strings:
        //These strings are in ASCII pre-2015 and UNICODE in 2016
        $error = "Error2" ascii wide
        //2016 specific:
        $s1 = "Can't find [%s]!Check the file name and try again!" ascii wide
        $s2 = "Open [%s] error! %d" ascii wide
        $s3 = "The Size of [%s] is zero!" ascii wide
        $s4 = "CreateThread DownloadFile[%s] Error!" ascii wide
        $s5 = "UploadFile [%s] Error:Connect Server Failed!" ascii wide
        $s6 = "Receive [%s] Error(Recved[%d] != Send[%d])!" ascii wide
        $s7 = "Receive [%s] ok! Use %2.2f seconds, Average speed %2.2f k/s" ascii wide
        $s8 = "CreateThread UploadFile[%s] Error!" ascii wide
        //Pre-2016:
        $s9 = "Ready Download [%s] ok!" ascii wide
        $s10 = "Get ControlInfo from FileClient error!" ascii wide
        $s11 = "FileClient has a error!" ascii wide
        $s12 = "VirtualAlloc SendBuff Error(%d)" ascii wide
        $s13 = "ReadFile [%s] Error(%d)..." ascii wide
        $s14 = "ReadFile [%s] Data[Readed(%d) != FileSize(%d)] Error..." ascii wide
        $s15 = "CreateThread DownloadFile[%s] Error!" ascii wide
        $s16 = "RecvData MyRecv_Info Size Error!" ascii wide
        $s17 = "RecvData MyRecv_Info Tag Error!" ascii wide
        $s18 = "SendData szControlInfo_1 Error!" ascii wide
        $s19 = "SendData szControlInfo_3 Error!" ascii wide
        $s20 = "VirtualAlloc RecvBuff Error(%d)" ascii wide
        $s21 = "RecvData Error!" ascii wide
        $s22 = "WriteFile [%s} Error(%d)..." ascii wide

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and


        filesize < 200KB and


        $error and 3 of ($s*)
}


rule keyboy_systeminfo
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the system information format before sending to C2"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    strings:
        //These strings are ASCII pre-2015 and UNICODE in 2016
        $s1 = "SystemVersion:    %s" ascii wide
        $s2 = "Product  ID:      %s" ascii wide
        $s3 = "InstallPath:      %s" ascii wide
        $s4 = "InstallTime:      %d-%d-%d, %02d:%02d:%02d" ascii wide
        $s5 = "ResgisterGroup:   %s" ascii wide
        $s6 = "RegisterUser:     %s" ascii wide
        $s7 = "ComputerName:     %s" ascii wide
        $s8 = "WindowsDirectory: %s" ascii wide
        $s9 = "System Directory: %s" ascii wide
        $s10 = "Number of Processors:       %d" ascii wide
        $s11 = "CPU[%d]:  %s: %sMHz" ascii wide
        $s12 = "RAM:         %dMB Total, %dMB Free." ascii wide
        $s13 = "DisplayMode: %d x %d, %dHz, %dbit" ascii wide
        $s14 = "Uptime:      %d Days %02u:%02u:%02u" ascii wide



    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and


        filesize < 200KB and


        7 of them
}


rule keyboy_related_exports
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the new 2016 sample's export"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and


        filesize < 200KB and


        //The malware family seems to share many exports
        //but this is the new kid on the block.
        pe.exports("Embedding") or
        pe.exports("SSSS") or
        pe.exports("GetUP")
}

// Note: The use of the .Init section has been observed in nearly
// all samples with the exception of the 2013 VN dropper from the
// Rapid7 blog. The config data was stored in that sample's .data
// section.
rule keyboy_init_config_section
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the Init section where the config is stored"
        date = "2016-08-28"

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and


        //Payloads are normally smaller but the new dropper we spotted
        //is a bit larger.
        filesize < 300KB and


        //Observed virtual sizes of the .Init section vary but they've
        //always been 1024, 2048, or 4096 bytes.
        for any i in (0..pe.number_of_sections - 1):
            (
                pe.sections[i].name == ".Init" and
                pe.sections[i].virtual_size % 1024 == 0
            )
}


/*
*
* These signatures fire on the exploit documents used in this
* operation.
*
*/
rule CVE_2012_0158_KeyBoy {
  meta:
      author = "Etienne Maynier <etienne@citizenlab.ca>"
      description = "CVE-2012-0158 variant"
      file = "8307e444cad98b1b59568ad2eba5f201"


  strings:
      $a = "d0cf11e0a1b11ae1000000000000000000000000000000003e000300feff09000600000000000000000000000100000001" nocase // OLE header
      $b = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" nocase // junk data
      $c = /5(\{\\b0\}|)[ ]*2006F00(\{\\b0\}|)[ ]*6F007(\{\\b0\}|)[ ]*400200045(\{\\b0\}|)[ ]*006(\{\\b0\}|)[ ]*E007(\{\\b0\}|)[ ]*400720079/ nocase
      $d = "MSComctlLib.ListViewCtrl.2"
      $e = "ac38c874503c307405347aaaebf2ac2c31ebf6e8e3" nocase //decoding shellcode


  condition:
      all of them
}
private rule LuckyCatCode : LuckyCat Family 
{
    meta:
        description = "LuckyCat code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        $xordecrypt = { BF 0F 00 00 00 F7 F7 ?? ?? ?? ?? 32 14 39 80 F2 7B }
        $dll = { C6 ?? ?? ?? 64 C6 ?? ?? ?? 6C C6 ?? ?? ?? 6C }
        $commonletters = { B? 63 B? 61 B? 73 B? 65 }
        
    condition:
        $xordecrypt or ($dll and $commonletters)
}

private rule LuckyCatStrings : LuckyCat Family
{
    meta:
        description = "LuckyCat Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        $xorencrypted = { 77 76 75 7B 7A 79 78 7F 7E 7D 7C 73 72 71 70 }
        $tempvbs = "%s\\~temp.vbs"
        $countphp = "count.php\x00"
        $trojanname = /WMILINK=.*TrojanName=/
        $tmpfile = "d0908076343423d3456.tmp"
        $dirfile = "cmd /c dir /s /a C:\\\\ >'+tmpfolder+'\\\\C.tmp"
        $ipandmac = "objIP.DNSHostName+'_'+objIP.MACAddress.split(':').join('')+'_'+addinf+'@')"
        
    condition:
       any of them
}

rule LuckyCat : Family
{
    meta:
        description = "LuckyCat"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    condition:
        LuckyCatCode or LuckyCatStrings
}private rule LURK0Header : Family LURK0 {
	meta:
		description = "5 char code for LURK0"
		author = "Katie Kleemola"
		last_updated = "07-21-2014"
	
	strings:
		$ = { C6 [5] 4C C6 [5] 55 C6 [5] 52 C6 [5] 4B C6 [5] 30 }

	condition:
		any of them
}

private rule CCTV0Header : Family CCTV0 {
        meta:  
		description = "5 char code for LURK0"
		author = "Katie Kleemola"
		last_updated = "07-21-2014"

	strings:
		//if its just one char a time
		$ = { C6 [5] 43 C6 [5] 43 C6 [5] 54 C6 [5] 56 C6 [5] 30 }
		// bit hacky but for when samples dont just simply mov 1 char at a time
		$ = { B0 43 88 [3] 88 [3] C6 [3] 54 C6 [3] 56 [0-12] (B0 30 | C6 [3] 30) }

	condition:
		any of them
}

private rule SharedStrings : Family {
	meta:
		description = "Internal names found in LURK0/CCTV0 samples"
		author = "Katie Kleemola"
		last_updated = "07-22-2014"
	
	strings:
		// internal names
		$i1 = "Butterfly.dll"
		$i2 = /\\BT[0-9.]+\\ButterFlyDLL\\/
		$i3 = "ETClientDLL"

		// dbx
		$d1 = "\\DbxUpdateET\\" wide
		$d2 = "\\DbxUpdateBT\\" wide
		$d3 = "\\DbxUpdate\\" wide
		
		// other folders
		$mc1 = "\\Micet\\"

		// embedded file names
		$n1 = "IconCacheEt.dat" wide
		$n2 = "IconConfigEt.dat" wide

		$m1 = "\x00\x00ERXXXXXXX\x00\x00" wide
		$m2 = "\x00\x00111\x00\x00" wide
		$m3 = "\x00\x00ETUN\x00\x00" wide
		$m4 = "\x00\x00ER\x00\x00" wide

	condition:
		any of them //todo: finetune this

}

rule LURK0 : Family LURK0 {
	
	meta:
		description = "rule for lurk0"
		author = "Katie Kleemola"
		last_updated = "07-22-2014"

	condition:
		LURK0Header and SharedStrings

}

rule CCTV0 : Family CCTV0 {

	meta:
		description = "rule for cctv0"
		author = "Katie Kleemola"
		last_updated = "07-22-2014"

	condition:
		CCTV0Header and SharedStrings

}
private rule MacControlCode : MacControl Family 
{
    meta:
        description = "MacControl code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-17"
        
    strings:
        // Load these function strings 4 characters at a time. These check the first two blocks:
        $L4_Accept = { C7 ?? 41 63 63 65 C7 ?? 04 70 74 3A 20 }
        $L4_AcceptLang = { C7 ?? 41 63 63 65 C7 ?? 04 70 74 2D 4C }
        $L4_Pragma = { C7 ?? 50 72 61 67 C7 ?? 04 6D 61 3A 20 }
        $L4_Connection = { C7 ?? 43 6F 6E 6E C7 ?? 04 65 63 74 69 }
        $GEThgif = { C7 ?? 47 45 54 20 C7 ?? 04 2F 68 2E 67 }
        
    condition:
        all of ($L4*) or $GEThgif
}

private rule MacControlStrings : MacControl Family
{
    meta:
        description = "MacControl Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-17"
        
    strings:
        $ = "HTTPHeadGet"
        $ = "/Library/launched"
        $ = "My connect error with no ip!"
        $ = "Send File is Failed"
        $ = "****************************You Have got it!****************************"
        
    condition:
        any of them
}

rule MacControl : Family
{
    meta:
        description = "MacControl"
        author = "Seth Hardy"
        last_modified = "2014-06-16"
        
    condition:
        MacControlCode or MacControlStrings
}private rule MirageStrings : Mirage Family
{
    meta:
        description = "Mirage Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        $ = "Neo,welcome to the desert of real." wide ascii
        $ = "/result?hl=en&id=%s"
        
    condition:
       any of them
}

rule Mirage : Family
{
    meta:
        description = "Mirage"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    condition:
        MirageStrings
}private rule MongalCode : Mongal Family 
{
    meta:
        description = "Mongal code features"
        author = "Seth Hardy"
        last_modified = "2014-07-15"
    
    strings:
        // gettickcount value checking
        $ = { 8B C8 B8 D3 4D 62 10 F7 E1 C1 EA 06 2B D6 83 FA 05 76 EB }
        
    condition:
        any of them
}

private rule MongalStrings : Mongal Family
{
    meta:
        description = "Mongal Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-15"
        
    strings:
        $ = "NSCortr.dll"
        $ = "NSCortr1.dll"
        $ = "Sina.exe"
        
    condition:
        any of them
}

rule Mongal : Family
{
    meta:
        description = "Mongal"
        author = "Seth Hardy"
        last_modified = "2014-07-15"
        
    condition:
        MongalCode or MongalStrings
}private rule MsAttackerStage2 : MsAttacker Family
{
	meta:
		description = "Identifying strings for MsAttacker stage 2"
		last_modified = "2015-03-12"
	strings:
		$ = "MiniJS.dll"
		$ = "%s \"rundll32.exe %s RealService %s\" /f"
		$ = "reg delete HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v \"Start Pages\" /f"
		$ = "3111431114311121270018000127001808012700180"
		$ = "Global\\MSAttacker %d"
	condition:
		any of them
}
private rule MsAttackerStage1 : MsAttacker Family
{
	meta:
		description = "Identifying strings for MsAttacker stage 1"
		last_modified = "2015-03-12"

	strings:
		$ = "http://122.10.117.152/download/ms/CryptBase.32.cab"
		$ = "http://122.10.117.152/download/ms/CryptBase.64.cab"
		$ = "http://122.10.117.152/download/ms/MiniJS.dll"
		$ = "MiniJS.dll"
		$ = "%s;new Downloader('%s', '%s').Fire();"
		$ = "rundll32.exe %s RealService %s"
	condition:
		any of them
}

rule MsAttacker : MsAttacker Family {
	condition:
		MsAttackerStage1 or MsAttackerStage2
}private rule NaikonCode : Naikon Family 
{
    meta:
        description = "Naikon code features"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
    
    strings:
        // decryption
        $ = { 0F AF C1 C1 E0 1F } // imul eax, ecx; shl eah, 1fh
        $ = { 35 5A 01 00 00} // xor eax, 15ah
        $ = { 81 C2 7F 14 06 00 } // add edx, 6147fh
    
    condition:
        all of them
}

private rule NaikonStrings : Naikon Family
{
    meta:
        description = "Naikon Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        $ = "NOKIAN95/WEB"
        $ = "/tag=info&id=15"
        $ = "skg(3)=&3.2d_u1"
        $ = "\\Temp\\iExplorer.exe"
        $ = "\\Temp\\\"TSG\""
        
    condition:
       any of them
}

rule Naikon : Family
{
    meta:
        description = "Naikon"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    condition:
        NaikonCode or NaikonStrings
}private rule nAspyUpdateCode : nAspyUpdate Family 
{
    meta:
        description = "nAspyUpdate code features"
        author = "Seth Hardy"
        last_modified = "2014-07-14"
    
    strings:
        // decryption loop in dropper
        $ = { 8A 54 24 14 8A 01 32 C2 02 C2 88 01 41 4E 75 F4 }
        
    condition:
        any of them
}

private rule nAspyUpdateStrings : nAspyUpdate Family
{
    meta:
        description = "nAspyUpdate Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-14"
        
    strings:
        $ = "\\httpclient.txt"
        $ = "password <=14"
        $ = "/%ldn.txt"
        $ = "Kill You\x00"
        
    condition:
        any of them
}

rule nAspyUpdate : Family
{
    meta:
        description = "nAspyUpdate"
        author = "Seth Hardy"
        last_modified = "2014-07-14"
        
    condition:
        nAspyUpdateCode or nAspyUpdateStrings
}