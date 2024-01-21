rule hacktool_windows_hot_potato
{
    meta:
        description = "https://foxglovesecurity.com/2016/01/16/hot-potato/"
        reference = "https://github.com/foxglovesec/Potato"
        author = "@mimeframe"
    strings:
        $a1 = "Parsing initial NTLM auth..." wide ascii
        $a2 = "Got PROPFIND for /test..." wide ascii
        $a3 = "Starting NBNS spoofer..." wide ascii
        $a4 = "Exhausting UDP source ports so DNS lookups will fail..." wide ascii
        $a5 = "Usage: potato.exe -ip" wide ascii
    condition:
        any of ($a*)
}
rule hacktool_windows_mimikatz_copywrite
{
    meta:
        description = "Mimikatz credential dump tool: Author copywrite"
        reference = "https://github.com/gentilkiwi/mimikatz"
        author = "@fusionrace"
        md5_1 = "0c87c0ca04f0ab626b5137409dded15ac66c058be6df09e22a636cc2bcb021b8"
        md5_2 = "0c91f4ca25aedf306d68edaea63b84efec0385321eacf25419a3050f2394ee3b"
        md5_3 = "0fee62bae204cf89d954d2cbf82a76b771744b981aef4c651caab43436b5a143"
        md5_4 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"
        md5_5 = "09c542ff784bf98b2c4899900d4e699c5b2e2619a4c5eff68f6add14c74444ca"
        md5_6 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
    strings:
        $s1 = "Kiwi en C" fullword ascii wide
        $s2 = "Benjamin DELPY `gentilkiwi`" fullword ascii wide
        $s3 = "http://blog.gentilkiwi.com/mimikatz" fullword ascii wide
        $s4 = "Build with love for POC only" fullword ascii wide
        $s5 = "gentilkiwi (Benjamin DELPY)" fullword wide
        $s6 = "KiwiSSP" fullword wide
        $s7 = "Kiwi Security Support Provider" fullword wide
        $s8 = "kiwi flavor !" fullword wide
    condition:
        any of them
}
rule hacktool_windows_mimikatz_errors
{
    meta:
        description = "Mimikatz credential dump tool: Error messages"
        reference = "https://github.com/gentilkiwi/mimikatz"
        author = "@fusionrace"
        md5_1 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
        md5_2 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"
    strings:
        $s1 = "[ERROR] [LSA] Symbols" fullword ascii wide
        $s2 = "[ERROR] [CRYPTO] Acquire keys" fullword ascii wide
        $s3 = "[ERROR] [CRYPTO] Symbols" fullword ascii wide
        $s4 = "[ERROR] [CRYPTO] Init" fullword ascii wide
    condition:
        all of them
}
private rule cobaltstrike_template_exe
{
    meta:
        description = "Template to provide executable detection Cobalt Strike payloads"
        reference = "https://www.cobaltstrike.com"
        author = "@javutin, @joseselvi"
    strings:
        $compiler = "mingw-w64 runtime failure" nocase

        $f1 = "VirtualQuery"   fullword
        $f2 = "VirtualProtect" fullword
        $f3 = "vfprintf"       fullword
        $f4 = "Sleep"          fullword
        $f5 = "GetTickCount"   fullword

        $c1 = { // Compare case insensitive with "msvcrt", char by char
                0f b6 50 01 80 fa 53 74 05 80 fa 73 75 42 0f b6
                50 02 80 fa 56 74 05 80 fa 76 75 34 0f b6 50 03
                80 fa 43 74 05 80 fa 63 75 26 0f b6 50 04 80 fa
                52 74 05 80 fa 72 75 18 0f b6 50 05 80 fa 54 74
        }
    condition:
        uint16(0) == 0x5a4d and
        filesize < 1000KB and
        $compiler and
        all of ($f*) and
        all of ($c*)
}    