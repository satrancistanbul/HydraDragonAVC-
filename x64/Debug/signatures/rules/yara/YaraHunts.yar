rule hunt_slub_backdoor {
meta:
 author = "SBousseaden"
 date = "22-10-2020"
 reference = "https://documents.trendmicro.com/assets/white_papers/wp-operation-earth-kitsune.pdf"
 hash = "93bb93d87cedb0a99976c18a37d65f816dc904942a0fb39cc177d49372ed54e5"
 hash = "59e4510b7b15011d67eb2f80484589f7211e67756906a87ce466a7bb68f2095b"
 hash = "c7788c015244e12e4c8cc69a2b1344d589284c84102c2f1871bbb4f4c32c2936"
 hash = "6678a5964db74d477b39bd0a8c18adf02844bed8b112c7bcca6984032918bdfb"
strings:
 $s1 = "file_infos" ascii wide
 $s2 = "%ws\\%u_cmd_out.tmp" ascii wide
 $s3 = "%ws\\%u_cmd_out.zip" ascii wide
 $s4 = "[was netstat]" ascii wide
 $s5 = {63 3A 5C 77 6F 72 6B 2E 76 63 70 6B 67 5C 69 6E 73 74 61 6C 6C 65 64 5C 78 36 34 2D 77 69 6E 64 6F 77 73 2D 73 74 61 74 69 63 5C}
 $s6 = "LoadFileToMemory" ascii wide
 $s7 = "setStartupExec" ascii wide
 $s8 = "%04u-%02u-%02u %02u:%02u:%02u" ascii wide
 $s9 = "goto del_one" ascii wide
 $s10 = "goto del_two" ascii wide
condition: uint16(0) == 0x5a4d and 3 of them
}rule APT_Solarwind_Backdoor_Encoded_Strings {
meta: 
 author = "SBousseaden"
 description = "This rule is looking for some key encoded strings of the SUNBURST backdoor"
 md5 = "846E27A652A5E1BFBD0DDD38A16DC865"
 sha2 = "ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6"
 date = "14/12/2020"
 reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
strings:
 $sw = "SolarWinds"
 $priv1 = "C04NScxO9S/PSy0qzsgsCCjKLMvMSU1PBQA=" wide // SeTakeOwnershipPrivilege
 $priv2 = "C04NzigtSckvzwsoyizLzElNTwUA" wide // SeShutdownPrivilege
 $priv3 = "C04NSi0uyS9KDSjKLMvMSU1PBQA=" wide// SeRestorePrivilege
 $disc1 = "C0gsSs0rCSjKT04tLvZ0AQA=" wide // ParentProcessID
 $disc2 = "c0zJzczLLC4pSizJLwIA" wide // Administrator
 $disc3 = "c/ELdsnPTczMCy5NS8usCE5NLErO8C9KSS0CAA==" wide //DNSDomainSuffixSearchOrder
 $wmi1 = "C07NSU0uUdBScCvKz1UIz8wzNooPriwuSc11KcosSy0CAA==" wide // Select * From Win32_SystemDriver
 $wmi2 = "C07NSU0uUdBScCvKz1UIz8wzNooPKMpPTi0uBgA=" wide // Select * From Win32_Process
 $wmi3 = "C07NSU0uUdBScCvKz1UIz8wzNooPLU4tckxOzi/NKwEA" wide // Select * From Win32_UserAccount
 $wmi4 = "C07NSU0uUdBScCvKz1UIz8wzNor3Sy0pzy/KdkxJLChJLXLOz0vLTC8tSizJzM9TKM9ILUpV8AxwzUtMyklNsS0pKk0FAA==" // Select * From Win32_NetworkAdapterConfiguration where IPEnabled=true
 $key1 = "C44MDnH1jXEuLSpKzStxzs8rKcrPCU4tiSlOLSrLTE4tBgA=" wide// SYSTEM\CurrentControlSet\services
 $key2 = "Cy5JLCoBAA==" wide // start
 $pat1 = "i6420DGtjVWoNqzlAgA=" wide // [{0,5}] {1}
 $pat2 = "i6420DGtjVWoNtTRNTSrVag2quWsNgYKKVSb1MZUm9ZyAQA=" wide // [{0,5}] {1,-16} {2}	{3,5} {4}\{5}
 $pat3 = "qzaoVag2rFXwCAkJ0K82quUCAA==" wide // {0} {1} HTTP/{2}
 $pat4 = {9D 2A 9A F3 27 D6 F8 EF}
condition: uint16(0) == 0x5a4d and $sw and (2 of ($pat*) or 2 of ($priv*) or all of ($disc*) or 2 of ($wmi*) or all of ($key*))
}
rule APT_XDSSpy_XDUpload {
meta:
 author = "SBousseaden"
 date = "05/10/2020"
 reference = "https://www.welivesecurity.com/2020/10/02/xdspy-stealing-government-secrets-since-2011/"
strings:
 $s1 = "cmd.exe /u /c cd /d \"%s\" & dir /a /-c" wide
 $s2 = "commandC_dll.dll"
 $s3 = "cmd.exe /u /c del" wide
condition: uint16(0)==0x5a4d and 2 of ($s*)
}// CredAccess

rule mem_webcreds_regexp_xor {
meta:
 author = "SBousseaden"
 date = "03-08-2020"
 reference = "https://github.com/orlyjamie/mimikittenz/blob/master/Invoke-mimikittenz.ps1"
strings:
    $p1 = "&password=" xor
	$p2 = "&login_password=" xor
	$p3 = "&pass=" xor
	$p4 = "&Passwd=" xor
	$p5 = "&PersistentCookie=" xor
	$p6 = "password%5D=" xor
	$u1 = "&username=" xor
	$u2 = "&email=" xor
	$u3 = "login=" xor
	$u4 = "login_email=" xor
	$u5 = "user%5Bemail%5D=" xor
	$reg = ".{1," xor
condition: 3 of ($p*) and 3 of ($u*) and #reg>3
}

rule webcreds_regexp_b64 {
meta:
 author = "SBousseaden"
 date = "03-08-2020"
 reference = "https://github.com/orlyjamie/mimikittenz/blob/master/Invoke-mimikittenz.ps1"
strings:
    $p1 = "&password=" base64
	$p2 = "&login_password=" base64
	$p3 = "&pass=" base64
	$p4 = "&Passwd=" base64
	$p5 = "&PersistentCookie=" base64
	$p6 = "password%5D=" base64
	$u1 = "&username=" base64
	$u2 = "&email=" base64
	$u3 = "login=" base64
	$u4 = "login_email=" base64
	$u5 = "user%5Bemail%5D=" base64
	$reg = ".{1,"
condition: 3 of ($p*) and 3 of ($u*) and #reg>3
}

rule ADSync_CredDump_Wide {
meta:
 author = "SBousseaden"
 date = "04-08-2020"
 description = "AD Connect Sync Credential Extract"
 reference = "https://blog.xpnsec.com/azuread-connect-for-redteam/"
// matches on Ghostpack ADSyncQuery.exe, ADSyncGather.exe and ADSyncDecrypt.exe
strings:
 $s1 = "private_configuration_xml" wide xor
 $s2 = "LoadKeySet" xor 
 $s3 = "encrypted_configuration" wide xor
 $s4 = "GetActiveCredentialKey" xor
 $s5 = "DecryptBase64ToString" xor
 $s6 = "KeyManager" xor
 $s7 = "(LocalDB)\\.\\ADSync" wide xor
 $s8 = "mms_management_agent" wide xor
 $s9 = "keyset_id" wide xor
 $s10 = "xp_cmdshell" xor
 $s11 = "System.Data.SqlClient"
 $s12 = "Password" wide xor
 $fp1 = "mmsutils\\mmsutils.pdb"
condition: 5 of them and not $fp1
}

rule ADSync_CredDump_Xor {
meta:
 author = "SBousseaden"
 date = "03-08-2020"
 description = "Azure AdSync Service Account Password Dumping"
 reference = "https://blog.xpnsec.com/azuread-connect-for-redteam/"
strings:
 $a1 = "private_configuration_xml" xor
 $a2 = "LoadKeySet" xor
 $a3 = "encrypted_configuration" xor
 $a4 = "GetActiveCredentialKey" xor
 $a5 = "DecryptBase64ToString" xor
 $a6 = "Cryptography.KeyManager" xor
 $b1 = "mms_management_agent" xor
 $b2 = "Microsoft Azure AD Sync\\Bin\\mcrypt.dl" xor
 $b3 = "xp_cmdshell" xor
 $b4 = "Password" xor
 $b5 = "forest-login-user" xor
 $b6 = "forest-login-domain" xor
condition: 4 of ($a*) or 4 of ($b*)
}

rule ADSync_CredDump_v64 {
meta:
 author = "SBousseaden"
 date = "03-08-2020"
 description = "Azure AdSync Service Account Password Dumping"
 reference = "https://blog.xpnsec.com/azuread-connect-for-redteam/"
strings:
 $a1 = "private_configuration_xml" base64
 $a2 = "LoadKeySet" base64
 $a3 = "encrypted_configuration" base64
 $a4 = "GetActiveCredentialKey" base64
 $a5 = "DecryptBase64ToString" base64
 $a6 = "Cryptography.KeyManager" base64
 $b1 = "mms_management_agent" base64
 $b2 = "Microsoft Azure AD Sync\\Bin\\mcrypt.dl" base64
 $b3 = "xp_cmdshell" base64
 $b4 = "Password" base64
 $b5 = "forest-login-user" base64
 $b6 = "forest-login-domain" base64
condition: 4 of ($a*) or 4 of ($b*)
}
rule ADSync_CredDump_XWide {
meta:
 author = "SBousseaden"
 date = "03-08-2020"
 description = "Azure AdSync Service Account Password Dumping"
 reference = "https://blog.xpnsec.com/azuread-connect-for-redteam/"
strings:
 $a1 = "private_configuration_xml" wide xor
 $a2 = "LoadKeySet" wide xor
 $a3 = "encrypted_configuration" wide xor
 $a4 = "GetActiveCredentialKey" wide xor
 $a5 = "DecryptBase64ToString" wide xor
 $a6 = "Cryptography.KeyManager" wide xor
 $b1 = "mms_management_agent" wide xor
 $b2 = "Microsoft Azure AD Sync\\Bin\\mcrypt.dl" wide xor
 $b3 = "xp_cmdshell" wide xor
 $b4 = "Password" wide xor
 $b5 = "forest-login-user" wide xor
 $b6 = "forest-login-domain" wide xor
condition: 4 of ($a*) or 4 of ($b*)
}

rule hunt_credaccess_cloud {
meta:
 author = "SBousseaden"
 date = "20-07-2020"
 description = "hunt for the presence of more than 1 known cloud client utility related credential paths"
strings:
 $aws = "\\.aws\\credentials" xor
 $gcloud1 = "\\gcloud\\credentials.db" xor
 $gcloud2 = "\\gcloud\\legacy_credentials" xor
 $gcloud3 = "\\gcloud\\access_tokens.db" xor
 $azure1 = "\\.azure\\accessTokens.json" xor
 $azure2 = "\\.azure\\azureProfile.json" xor
 $git = "\\.config\\git\\credentials" xor // unrelated but included
 $slack1 = "\\Slack\\Cookies" xor // unrelated but included
 $slack2 = "\\Slack\\StaleCookies-8" xor // unrelated but included
condition: 4 of them
}

rule hunt_credaccess_cloud_wide_xor {
meta:
 author = "SBousseaden"
 date = "20-07-2020"
 description = "hunt for the presence of more than 1 known cloud client utility related credential paths"
strings:
 $aws = "\\.aws\\credentials" wide xor
 $gcloud1 = "\\gcloud\\credentials.db" wide xor
 $gcloud2 = "\\gcloud\\legacy_credentials" wide xor
 $gcloud3 = "\\gcloud\\access_tokens.db" wide xor
 $azure1 = "\\.azure\\accessTokens.json" wide xor
 $azure2 = "\\.azure\\azureProfile.json" wide xor
 $git = "\\.config\\git\\credentials" wide xor // unrelated but included
 $slack1 = "\\Slack\\Cookies" wide xor // unrelated but included
 $slack2 = "\\Slack\\StaleCookies-8" wide xor // unrelated but included
condition: 4 of them
}

rule hunt_credaccess_cloud_base64 {
meta:
 author = "SBousseaden"
 date = "20-07-2020"
 description = "hunt for the presence of more than 1 known cloud client utility related credential paths"
strings:
 $aws = "\\.aws\\credentials" base64
 $gcloud1 = "\\gcloud\\credentials.db" base64
 $gcloud2 = "\\gcloud\\legacy_credentials" base64
 $gcloud3 = "\\gcloud\\access_tokens.db" base64
 $azure1 = "\\.azure\\accessTokens.json" base64
 $azure2 = "\\.azure\\azureProfile.json" base64
 $git = "\\.config\\git\\credentials" base64 // unrelated but included
 $slack1 = "\\Slack\\Cookies" base64 // unrelated but included
 $slack2 = "\\Slack\\StaleCookies-8" base64 // unrelated but included
condition: 4 of them
}

rule hunt_credaccess_cloud_wide_base64 {
meta:
 author = "SBousseaden"
 date = "20-07-2020"
 description = "hunt for the presence of more than 1 known cloud client utility related credential paths"
strings:
 $aws = "\\.aws\\credentials" wide base64
 $gcloud1 = "\\gcloud\\credentials.db" wide base64
 $gcloud2 = "\\gcloud\\legacy_credentials" wide base64
 $gcloud3 = "\\gcloud\\access_tokens.db" wide base64
 $azure1 = "\\.azure\\accessTokens.json" wide base64
 $azure2 = "\\.azure\\azureProfile.json" wide base64
 $git = "\\.config\\git\\credentials" wide base64 // unrelated but included
 $slack1 = "\\Slack\\Cookies" wide base64 // unrelated but included
 $slack2 = "\\Slack\\StaleCookies-8" wide base64 // unrelated but included
condition: 4 of them
}

rule hunt_credaccess_iis {
meta:
 author = "SBousseaden"
 date = "20-07-2020"
 description = "hunt for strings related to iis credential access"
strings:
 $a1 = "aspnet_regiis.exe" nocase
 $a2 = "connectionStrings" nocase
 $a3 = "web.config" nocase
 $a4 = "-pdf" nocase
 $b1 = "appcmd.exe" nocase
 $b2 = "/text:password"
condition: (all of ($a*) or all of ($b*))
}

rule hunt_credaccess_iis_xor {
meta:
 author = "SBousseaden"
 date = "20-07-2020"
 description = "hunt for strings related to iis credential access"
strings:
 $a1 = "aspnet_regiis.exe" wide xor
 $a2 = "connectionStrings" wide xor
 $a3 = "web.config" wide xor
 $a4 = "-pdf" wide xor
 $b1 = "appcmd.exe" wide xor
 $b2 = "/text:password" wide xor
condition: (all of ($a*) or all of ($b*))
}

rule hunt_credaccess_iis_base64 {
meta:
 author = "SBousseaden"
 date = "20-07-2020"
 description = "hunt for strings related to iis credential access"
strings:
 $a1 = "aspnet_regiis.exe" base64
 $a2 = "connectionStrings" base64
 $a3 = "web.config" base64
 $a4 = "-pdf" base64
 $b1 = "appcmd.exe" base64
 $b2 = "/text:password" base64
condition: (3 of ($a*) or all of ($b*))
}

rule hunt_credaccess_iis_wide_base64 {
meta:
 author = "SBousseaden"
 date = "20-07-2020"
 description = "hunt for strings related to iis credential access"
strings:
 $a1 = "aspnet_regiis.exe" wide base64
 $a2 = "connectionStrings" wide base64
 $a3 = "web.config" wide base64
 $a4 = "-pdf" wide base64
 $b1 = "appcmd.exe" wide base64
 $b2 = "/text:password" wide base64
condition: (3 of ($a*) or all of ($b*))
}

rule hunt_TeamViewer_registry_pwddump {
meta:
 author = "SBousseaden"
 date = "23-07-2020"
 description = "cve-2019-18988 - decryption of AES 128 bits encrypted TV config pwds saved in TV registry hive"
 references = "https://community.teamviewer.com/t5/Announcements/Specification-on-CVE-2019-18988/td-p/82264"
strings:
 // hardcoded key and iv in TeamViewer_Service.exe
 $key1 = {0602000000a400005253413100040000}
 $key2 = "\\x06\\x02\\x00\\x00\\x00\\xa4\\x00\\x00\\x52\\x53\\x41\\x31\\x00\\x04\\x00\\x00"
 $iv1 = {0100010067244F436E6762F25EA8D704}
 $iv2 = "\\x01\\x00\\x01\\x00\\x67\\x24\\x4F\\x43\\x6E\\x67\\x62\\xF2\\x5E\\xA8\\xD7\\x04"
 // interesting TV regvalues are OptionsPasswordAES, ProxyPasswordAES and PermanentPassword stroed under SOFTWARE\WOW6432Node\TeamViewer or SOFTWARE\TeamViewer
 $p1 = "OptionsPasswordAES" nocase
 $p2 = "OptionsPasswordAES" nocase wide
 $p3 = "ProxyPasswordAES" nocase 
 $p4 = "ProxyPasswordAES" nocase wide
 $p5 = "PermanentPassword" nocase
 $p6 = "PermanentPassword" nocase wide
condition: any of ($key*) and any of ($iv*) and 2 of ($p*)  and filesize <700KB
}rule hunt_common_credit_card_memscrapper {
meta:
 description = "Hunting rule for possible CC data memory scrapper"
 author = "SBousseaden"
 date = "17/07/2020"
strings:
 $api1 = "NtOpenProcess"
 $api2 = "NtQueryVirtualMemory"
 $api3 = "NtReadVirtualMemory"
// https://stackoverflow.com/questions/9315647/regex-credit-card-number-tests
 $cc1 = "^3[47][0-9]{13}$" // Amex Card
 $cc2 = "^(6541|6556)[0-9]{12}$" // BCGlobal
 $cc3 = "^389[0-9]{11}$" // Carte Blanche Card
 $cc4 = "^3(?:0[0-5]|[68][0-9])[0-9]{11}$" //Diners Club Card
 $cc5 = "^65[4-9][0-9]{13}|64[4-9][0-9]{13}|6011[0-9]{12}|(622(?:12[6-9]|1[3-9][0-9]|[2-8][0-9][0-9]|9[01][0-9]|92[0-5])[0-9]{10})$" //Discover Card
 $cc6 = "^63[7-9][0-9]{13}$" // Insta Payment Card
 $cc7 = "^(?:2131|1800|35\\d{3})\\d{11}$" // JCB Card
 $cc8 = "^9[0-9]{15}$" // KoreanLocalCard
 $cc9 = "^(6304|6706|6709|6771)[0-9]{12,15}$" //Laser Card
 $cc10 = "^(5018|5020|5038|6304|6759|6761|6763)[0-9]{8,15}$" // Maestro Card
 $cc11 = "^(5[1-5][0-9]{14}|2(22[1-9][0-9]{12}|2[3-9][0-9]{13}|[3-6][0-9]{14}|7[0-1][0-9]{13}|720[0-9]{12}))$" //Mastercard
 $cc12 = "^(6334|6767)[0-9]{12}|(6334|6767)[0-9]{14}|(6334|6767)[0-9]{15}$" //Solo Card
 $cc13 = "^(4903|4905|4911|4936|6333|6759)[0-9]{12}|(4903|4905|4911|4936|6333|6759)[0-9]{14}|(4903|4905|4911|4936|6333|6759)[0-9]{15}|564182[0-9]{10}|564182[0-9]{12}|564182[0-9]{13}|633110[0-9]{10}|633110[0-9]{12}|633110[0-9]{13}$" //Switch Card
 $cc14 = "^(62[0-9]{14,17})$" //Union Pay Card
 $cc15 = "^4[0-9]{12}(?:[0-9]{3})?$" //Visa Card
 $cc16 = "^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})$" //Visa Master Card
condition: uint16(0) == 0x5a4d and 1 of ($cc*) and all of ($api*)
}rule cve_2019_1458 {
meta:
 author = "SBousseaden"
 reference = "https://github.com/unamer/CVE-2019-1458"
strings:
 $s1 = "RtlGetVersion"
 $s2 = {45 33 C9 BA 03 80 00 00 33 C9}	
 $s3 = "SploitWnd" // optional
 $s4 = "CreateWindowExW"
 $s5 = "GetKeyboardState"
 $s6 = "SetKeyboardState"
 $s7 = "SetWindowLongPtrW"
 $s9 = "SetClassLongPtrW"
 $s10 = "DestroyWindow"
 $s11 = "CreateProcess"
 $s12 = {4C 8B D1 8B 05 ?? ?? ?? 00 0F 05 C3}
 $s13 = {80 10 00 00 09 10}
 $s14 = "NtUserMessageCall"
 $s15 = "HMValidateHandle"
 $s16 = "IsMenu"
condition: uint16(0) == 0x5a4d and all of them
}
rule hunt_multi_EDR_discovery {
meta:
 description = "Hunting rule for the presence of at least 3 different known EDR driver names, more drivers can be found in the reference link"
 author = "SBousseaden"
 date = "17/07/2020"
 reference = "https://github.com/harleyQu1nn/AggressorScripts/blob/master/EDR.cna"

strings:
// base64 encoded
 $edrB1 = "cbstream.sys" base64  // Carbon Black
 $edrB2 = "carbonblackk.sys" base64  // Carbon Black
 $edrB3 = "CyOptics.sys" base64  // Cylance
 $edrB4 = "CyProtectDrv32.sys" base64   // Cylance
 $edrB5 = "CyProtectDrv64.sys" base64  // Cylance
 $edrB6 = "FeKern.sys" base64  // Fireeye
 $edrB7 = "WFP_MRT.sys" base64  // Fireeye
 $edrB8 = "edevmon.sys" base64  // ESET
 $edrB9 = "ehdrv.sys" base64  // ESET
 $edrB10 = "esensor.sys" base64  // Endgame 
 $edrB11 = "SentinelMonitor.sys" base64  // SentinelOne
 $edrB12 = "groundling32.sys" base64  // Dell SecureWorks
 $edrB13 = "groundling64.sys" base64  // Dell SecureWorks
 $edrB14 = "CRExecPrev.sys" base64  // CyberReason
 $edrB15 = "brfilter.sys" base64  // Bromium
 $edrB16 = "BrCow_x_x_x_x.sys" base64  // Bromium
 $edrB17 = "fsatp.sys" base64  // F-secure
 $edrB18 = "fsgk.sys" base64  // F-secure
 $edrB19 = "CiscoAMPCEFWDriver.sys" base64  // Cisco AMP
 $edrB20 = "CiscoAMPHeurDriver.sys" base64  // Cisco
 // base64 on wide
 $edrBW1 = "cbstream.sys" base64 wide // Carbon Black
 $edrBW2 = "carbonblackk.sys" base64 wide // Carbon Black
 $edrBW3 = "CyOptics.sys" base64 wide // Cylance
 $edrBW4 = "CyProtectDrv32.sys" base64 wide  // Cylance
 $edrBW5 = "CyProtectDrv64.sys" base64 wide // Cylance
 $edrBW6 = "FeKern.sys" base64 wide // Fireeye
 $edrBW7 = "WFP_MRT.sys" base64 wide // Fireeye
 $edrBW8 = "edevmon.sys" base64 wide // ESET
 $edrBW9 = "ehdrv.sys" base64 wide // ESET
 $edrBW10 = "esensor.sys" base64 wide // Endgame 
 $edrBW11 = "SentinelMonitor.sys" base64 wide // SentinelOne
 $edrBW12 = "groundling32.sys" base64 wide // Dell SecureWorks
 $edrBW13 = "groundling64.sys" base64 wide // Dell SecureWorks
 $edrBW14 = "CRExecPrev.sys" base64 wide // CyberReason
 $edrBW15 = "brfilter.sys" base64 wide // Bromium
 $edrBW16 = "BrCow_x_x_x_x.sys" base64 wide // Bromium
 $edrBW17 = "fsatp.sys" base64 wide // F-secure
 $edrBW18 = "fsgk.sys" base64 wide // F-secure
 $edrBW19 = "CiscoAMPCEFWDriver.sys" base64 wide // Cisco AMP
 $edrBW20 = "CiscoAMPHeurDriver.sys" base64 wide // Cisco
// XORed
 $edrX1 = "cbstream.sys" xor // Carbon Black
 $edrX2 = "carbonblackk.sys" xor // Carbon Black
 $edrX3 = "CyOptics.sys" xor // Cylance
 $edrX4 = "CyProtectDrv32.sys" xor  // Cylance
 $edrX5 = "CyProtectDrv64.sys" xor // Cylance
 $edrX6 = "FeKern.sys" xor // Fireeye
 $edrX7 = "WFP_MRT.sys" xor // Fireeye
 $edrX8 = "edevmon.sys" xor // ESET
 $edrX9 = "ehdrv.sys" xor // ESET
 $edrX10 = "esensor.sys" xor // Endgame 
 $edrX11 = "SentinelMonitor.sys" xor // SentinelOne
 $edrX12 = "groundling32.sys" xor // Dell SecureWorks
 $edrX13 = "groundling64.sys" xor // Dell SecureWorks
 $edrX14 = "CRExecPrev.sys" xor // CyberReason
 $edrX15 = "brfilter.sys" xor // Bromium
 $edrX16 = "BrCow_x_x_x_x.sys" xor // Bromium
 $edrX17 = "fsatp.sys" xor // F-secure
 $edrX18 = "fsgk.sys" xor // F-secure
 $edrX19 = "CiscoAMPCEFWDriver.sys" xor // Cisco AMP
 $edrX20 = "CiscoAMPHeurDriver.sys" xor // Cisco
// XOR on wide 
 $edrXW1 = "cbstream.sys" xor wide // Carbon Black
 $edrXW2 = "carbonblackk.sys" xor wide // Carbon Black
 $edrXW3 = "CyOptics.sys" xor wide // Cylance
 $edrXW4 = "CyProtectDrv32.sys" xor wide  // Cylance
 $edrXW5 = "CyProtectDrv64.sys" xor wide // Cylance
 $edrXW6 = "FeKern.sys" xor wide // Fireeye
 $edrXW7 = "WFP_MRT.sys" xor wide // Fireeye
 $edrXW8 = "edevmon.sys" xor wide // ESET
 $edrXW9 = "ehdrv.sys" xor wide // ESET
 $edrXW10 = "esensor.sys" xor wide // Endgame 
 $edrXW11 = "SentinelMonitor.sys" xor wide // SentinelOne
 $edrXW12 = "groundling32.sys" xor wide // Dell SecureWorks
 $edrXW13 = "groundling64.sys" xor wide // Dell SecureWorks
 $edrXW14 = "CRExecPrev.sys" xor wide // CyberReason
 $edrXW15 = "brfilter.sys" xor wide // Bromium
 $edrXW16 = "BrCow_x_x_x_x.sys" xor wide // Bromium
 $edrXW17 = "fsatp.sys" xor wide // F-secure
 $edrXW18 = "fsgk.sys" xor wide // F-secure
 $edrXW19 = "CiscoAMPCEFWDriver.sys" xor wide // Cisco AMP
 $edrXW20 = "CiscoAMPHeurDriver.sys" xor wide // Cisco
condition: 3 of them
}
import "pe"
rule hunt_lsass_ntds_ext {
meta:
 author = "SBousseaden"
 date = "09/10/2020"
 description = "hunting rule for necessary exports in a DLL that can be abused for persistence or alike by loading it into lsass via NTDS registry"
 reference = "https://blog.xpnsec.com/exploring-mimikatz-part-1/"
// FPs can be excluded accordingly
strings:
 $s1 = "%s\\debug\\%s.log" wide
 $s2 = "lsadb.pdb"
 $s3 = "CN=NTDS Settings"
condition: (pe.exports("InitializeLsaDbExtension") or pe.exports("InitializeSamDsExtension")) and not all of ($s*)
}
rule ZerloLogon_Mimikatz {
meta:
 description = "Generic Hunting rule for Mimikatz Implementation of ZeroLogon PrivEsc Exploit"
 author = "SBousseaden"
 date = "17/09/2020"
 reference1 = "https://github.com/SecuraBV/CVE-2020-1472"
 reference2 = "https://github.com/gentilkiwi/mimikatz/releases/tag/2.2.0-20200916"
strings:
 $rch1 = "NetrServerReqChallenge"
 $rch2 = "NetrServerReqChallenge" wide
 $auth1 = "NetrServerAuthenticate2"
 $auth2 = "NetrServerAuthenticate2" wide
 $pwd1 = "NetrServerPasswordSet2"
 $pwd2 = "NetrServerPasswordSet2" wide
 $rpc1 = {78 56 34 12 34 12 CD AB EF 00 01 23 45 67 CF FB}
 $rpc2 = {00 00 12 08 25 5C 11 08 25 5C 11 00 08 00 1D 00 08 00 02 5B 15 00 08 00 4C 00 F4 FF 5C 5B 11 04 F4 FF 11 08 08 5C 11 00 02 00 15 03 0C 00 4C 00 E4 FF 08 5B 11 04 F4 FF 11 00 08 00 1D 01 00 02 05 5B 15 03 04 02 4C 00 F4 FF 08 5B 11 04 0C 00 1D 00 10 00 4C 00 BE FF 5C 5B 15 00 10 00 4C 00 F0 FF 5C 5B 00}
 $rpc3 = {00 48 00 00 00 00 04 00 28 00 31 08 00 00 00 5C 3C 00 44 00 46 05 0A 01 00 00 00 00 00 00 00 00 0B 00 00 00 02 00 0B 01 08 00 08 00 0A 01 10 00 14 00 12 21 18 00 14 00 70 00 20 00 08 00 00 48 00 00 00 00 0F 00 40 00 31 08 00 00 00 5C 5E 00 60 00 46 08 0A 01 00 00 00 00 00 00 00 00 0B 00 00 00 02 00 0B 01 08 00 08 00 48 00 10 00 0D 00 0B 01 18 00 08 00 0A 01 20 00 14 00 12 21 28 00 14 00 58 01 30 00 08 00 70 00 38 00 08 00 00 48 00 00 00 00 1E 00 40 00 31 08 00 00 00 5C 8E 02 58 00 46 08 0A 01 00 00 00 00 00 00 00 00 0B 00 00 00 02 00 0B 01 08 00 08 00 48 00 10 00 0D 00 0B 01 18 00 08 00 0A 01 20 00 2A 00 12 41 28 00 2A 00 0A 01 30 00 42 00 70 00 38 00 08 00 00 48 00 00 00 00 2A 00 48 00 31 08 00 00 00 5C 56 00 40 01 46 09 0A 01 00 00 00 00 00 00 00 00 0B 00 00 00 02 00 0B 01 08 00 08 00 48 00 10 00 0D 00 0B 01 18 00 08 00 0A 01 20 00 2A 00 12 41 28 00 2A 00 12 41 30 00 5A 00 12 41 38 00 5A 00 70 00 40 00 08 00 00 00}
condition: uint16(0) == 0x5a4d and (1 of ($rch*) and 1 of ($auth*) and 1 of ($pwd*)) and 2 of ($rpc*) 
}
rule Hunt_EvtMuteHook_Memory {
meta:
 description = "memory hunt for default wevtsv EtwEventCallback hook pattern to apply to eventlog svchost memory dump"
 reference = "https://blog.dylan.codes/pwning-windows-event-logging/"
 author = "SBousseaden"
 date = "2020-09-05"
strings:
 $a = {49 BB ?? ?? ?? ?? ?? ?? ?? ?? 41 FF E3 54 24 20 4C 8B 05 61 CB 1A 00 0F 57 C0 66 0F 7F 44 24 20 E8 5B 0A 00 00 48 83 C4 38 C3}
 $b = {48 83 EC 38 4C 8B 0D 65 CB 1A 00 48 8D 54 24 20 4C 8B 05 61 CB 1A 00 0F 57 C0 66 0F 7F 44 24 20 E8 5B 0A 00 00 48 83 C4 38 C3}
condition: $a and not $b
}
rule DCSync_Mimikatz {
meta:
 description = "Hunting rule for Mimikatz Implementation of DCSync Attack"
 author = "SBousseaden"
 date = "22/09/2020"
 reference = "https://github.com/gentilkiwi/mimikatz"
strings:
 $DRS1 = "DRSGetNCChanges"
 $DRS2 = "DRSReplicaAdd"
 $DRS3 = "DRSAddEntry"
 $DRSW1 = "DRSGetNCChanges" wide
 $DRSW2 = "DRSReplicaAdd" wide
 $DRSW3 = "DRSAddEntry" wide
 $rpc1 = {35 42 51 E3 06 4B D1 11 AB 04 00 C0 4F C2 DC D2 04 00 00 00 04 5D 88 8A EB 1C C9 11 9F E8 08 00 2B 10 48 60 02}
 $rpc2 = {34 05 50 21 18 00 08 00 13 81 20 00 8A 05 70 00 28}
 $rpc3 = {0B 01 10 00 DC 05 50 21 18 00 08 00 13 21 20 00 2E 06 70 00 28}
 $rpc4 = {48 06 50 21 18 00 08 00 13 41 20 00 72 06 70 00 28}
 $rpc5 = {78 03 0B 00 10 00 7C 03 13 20 18 00 A4 03 10 01 20 00 AC 03 70 00 28}
 $rpc6 = {C0 03 50 21 18 00 08 00 13 01 20 00 74 04 70 00 28}
 $rpc7 = {8C 06 50 21 18 00 08 00 13 A1 20 00 C6 06 70 00 28}
 $def1 = "mimikatz"
 $def2 = "mimikatz" wide
condition: uint16(0) == 0x5a4d and (all of ($DRS*) or all of ($DRSW*)) and all of ($rpc*)  and not (any of ($def*))
}rule hunt_procinj_instrumentationcallback {
meta:
 date = "25-07-2020"
 author = "SBousseaden"
 description = "hunt for possible injection with Instrumentation Callback PE"
 reference = "https://movaxbx.ru/2020/07/24/weaponizing-mapping-injection-with-instrumentation-callback-for-stealthier-process-injection/"
strings:
 $mv1 = "MapViewOfFile3" xor
 $mv2 = "MapViewOfFile3" wide xor
 $mv3 = "NtMapViewOfSectionEx" xor
 $mv4 = "NtMapViewOfSectionEx" wide xor
 $mv5 = {(49 89 CA|4C 8B D1) B8 0F 01 00 00 0F 05 C3} // NtMapViewOfSectionEx
 $spi1 = "NtSetInformationProcess" xor
 $spi2 = "NtSetInformationProcess" wide xor
 $spi3 = {(49 89 CA|4C 8B D1) B8 1C 00 00 00 0F 05 C3} // NtSetInformationProcess
 $picb = {BA 28 00 00 00} // PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
 $ss1 = {41 52 50 53 55 57 56 54 41 54 41 55 41 56 41 57}  // push stuff
 $ss2 = {41 5F 41 5E 41 5D 41 5C 5C 5E 5F 5D 5B 58 41 5A}  // pop stuff
 $ss3 = {49 89 CA 0F 05 C3} // mov r10, rcx syscall ret
condition: uint16(0)==0x5a4d and $picb and 1 of ($mv*) and 1 of ($spi*) and 1 of ($ss*)
}rule hunt_skyproj_backdoor {
meta:
 author = "SBousseaden"
 date = "24-10-2020"
 reference = "https://twitter.com/SBousseaden/status/1320005809695264769"
 hash = "9F64EC0C41623E5162E51D7631B1D29934B76984E9993083BDBDABFCCBA4D300"
 hash = "F48CC6F80A0783867D2F4F0E76A6B2C29D993A2D5072AA10319B48FC398D8B7A"
 hash = "7ac73f2e5ea0ca430cf21738d3854b8a5b6a25ae4a85d140fc7e96cb87f7e2ea"
 reference = "https://unit42.paloaltonetworks.com/unit42-prince-persia-ride-lightning-infy-returns-foudre/"
strings:
 $s1 = "rundll32.exe" ascii wide
 $s2 = "data.enc" ascii wide
 $s3 = "data.bak" ascii wide
 $s4 = "did.dat" ascii wide
 $s5 = "config.xml" ascii wide 
 $s6 = "dfserv.exe" ascii wide
 $s7 = "ShellExecuteW" ascii wide
 $s8 = "Software\\temp" ascii wide
 $s9 = "getElementById" wide
 $s10 = "getElementsByTagNameNS" ascii wide
 $s11 = "TMSDOMNode5"
 $s12 = "schtasks /Create /f /XML" wide
 $s13 = "schtasks /Create /sc onstart /tr" wide
 $s14 = "/ru system /TN"  wide
 $s15 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Persisted" wide
 $s16 = "<Command>Rundll32.exe</Command>" wide
 $s17 = "<Arguments>shell32.dll,Control_RunDLL" wide
 $s18 = "\\All Users\\Start Menu\\Programs\\\\Startup\\" wide
 $s19 = "Kaspersky Lab" ascii wide
condition: uint16(0) == 0x5a4d and 5 of them
}
import "pe"
rule GOSliver {
meta:
 author = "SBousseaden"
 reference = "https://github.com/BishopFox/sliver"
strings:
 $go = "_cgo_"
condition: #go > 10 and pe.exports("RunSliver")
}
import "pe"

rule susp_msoffice_addins_wxll {
meta:
 author = "SBousseaden"
 date = "11/10/2020"
 description = "hunt for suspicious MS Office Addins with code injection capabilities"
 reference = "https://twitter.com/JohnLaTwC/status/1315287078855352326"
strings:
 $inj1 = "WriteProcessMemory"
 $inj2 = "NtWriteVirtualMemory"
 $inj3 = "RtlMoveMemory"
 $inj4 = "VirtualAllocEx"
 $inj5 = "NtAllocateVirtualMemory" 
 $inj6 = "NtUnmapViewOfSection"
 $inj7 = "VirtualProtect"
 $inj8 = "NtProtectVirtualMemory"
 $inj9 = "SetThreadContext"
 $inj10 = "NtSetContextThread"
 $inj11 = "ResumeThread"
 $inj12 = "NtResumeThread"
 $inj13 = "QueueUserAPC"
 $inj14 = "NtQueueApcThread"
 $inj15 = "NtQueueApcThreadEx"
 $inj16 = "CreateRemoteThread"
 $inj17 = "NtCreateThreadEx"
 $inj18 = "RtlCreateUserThread"
condition: uint16(0) == 0x5a4d and (pe.exports("wdAutoOpen") or pe.exports("xlAutoOpen")) and 3 of ($inj*)
}
rule hunt_susp_vhd {
meta:
 description = "Virtual hard disk file with embedded PE"
 author = "SBousseaden"
 date = "13/07/2020"
strings:
 $hvhd = {636F6E6563746978}
 $s1 = {4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00}
 $s2 = "!This program cannot be run in DOS mode." base64
 $s3 = "!This program cannot be run in DOS mode." xor
condition: $hvhd at 0 and any of ($s*) and filesize <= 10MB
}
rule Truncated_win10_x64_NativeSysCall {
meta: 
  description = "hunt of at least 3 occurences of truncated win10 x64 NativeSyscall" 
  author = "SBousseaden" 
  date = "2020-07-05" 
strings:
// mov r10,rcx
// mov eax,syscallid
// syscall
// ret
    $s1 = {(49 89 CA|4C 8B D1) B8 ?? ?? ?? ?? 0F 05 C3} 
    $s2 = {B8 ?? ?? ?? ?? (49 89 CA|4C 8B D1) 0F 05 C3}
condition: uint16(0)==0x5a4d and (#s1 >= 3 or #s2 >=3)
}
rule Infinityhook {

meta:
  author = "SBousseaden"
  date = "09/07/2020"
  reference = "https://github.com/everdox/InfinityHook"
  description = "Infinityhook is a legit research PoC to hook NT Syscalls bypassing PatchGuard"

strings:
  $EtwpDebuggerPattern = {00 2C 08 04 38 0C 00}
  $SMV = {00 00 76 66 81 3A 02 18 50 00 75 0E 48 83 EA 08 B8 33 0F 00}
  $KVASCODE = {4B 56 41 53 43 4F 44 45} // migh look for xor and base64
  $CKL = "Circular Kernel Context Logger" wide nocase
  
condition: uint16(0) == 0x5a4d and all of them

}
rule mimikatz_kiwikey {
meta:
 description = "hunt for default mimikatz kiwikey"
 author = "SBousseaden"
 date = "2020-08-08"
strings: 
 $A = {60 BA 4F CA C7 44 24 ?? DC 46 6C 7A C7 44 24 ?? 03 3C 17 81 C7 44 24 ?? 94 C0 3D F6}
 $B = {48 B8 ?? ?? ?? ?? ?? ?? ?? ?? FF D0}
condition: $A and #B>10
}
import "pe"

rule MaliciousDLLGenerator { 
meta: 
  description = "MaliciousDLLGenerator default decoder and export name" 
  author = "SBousseaden" 
  reference = "https://github.com/Mr-Un1k0d3r/MaliciousDLLGenerator" 
  date = "2020-06-07" 
strings:
  $decoder = {E8 00 00 00 00 5B 48 31 C0 48 89 C1 B1 80 48 83 C3 11 48 F7 14 CB E2 FA 48 83 C3 08 53 C3} // decoder
condition: uint16(0) == 0x5a4d and $decoder and pe.exports("Init") and pe.number_of_exports == 2
}
rule mimikatz_memssp_hookfn {
meta:
 description = "hunt for default mimikatz memssp module both ondisk and in memory artifacts"
 author = "SBousseaden"
 date = "2020-08-26"
strings: 
 $s1 = {44 30 00 38 00}
 $s2 = {48 78 00 3A 00}
 $s3 = {4C 25 00 30 00}
 $s4 = {50 38 00 78 00}
 $s5 = {54 5D 00 20 00}
 $s6 = {58 25 00 77 00}
 $s7 = {5C 5A 00 5C 00}
 $s8 = {60 25 00 77 00}
 $s9 = {64 5A 00 09 00}
 $s10 = {6C 5A 00 0A 00}
 $s11 = {68 25 00 77 00}
 $s12 = {68 25 00 77 00}
 $s13 = {6C 5A 00 0A 00}
 $B = {6D 69 6D 69 C7 84 24 8C 00 00 00 6C 73 61 2E C7 84 24 90 00 00 00 6C 6F 67} // mimilsa.log
condition: all of ($s*) or $B // you can set condition to A and not B to detect non lazy memssp users 
}
import "pe"

rule shad0w_beacon { 
meta: 
  description = "Shad0w beacon default suspicous strings" 
  author = "SBousseaden" 
  reference = "https://github.com/bats3c/shad0w" 
  date = "2020-06-04" 
strings:
  $s1 = "LdrLoadD"
  $s2 = {53 65 74 50 72 2A 65 73 73 4D} // SetPr*essM
  $s3 = "Policy" // combined with above gives SetProcessMitigationPolicy
condition: uint16(0) == 0x5a4d and all of ($s*) 
 and pe.sections[0].name == "XPU0" and pe.imports("winhttp.dll","WinHttpOpen") 
}rule shad0w_beacon_16June { 
meta: 
  description = "Shad0w beacon compressed" 
  author = "SBousseaden" 
  reference = "https://github.com/bats3c/shad0w" 
  date = "2020-06-16" 
strings:
  $s1 = {F2 AE ?? ?? ?? FF 15 ?? ?? 00 00 48 09 C0 74 09}
  $s2 = {33 2E 39 36 00 ?? ?? ?? 21 0D 24 0E 0A}
  $s3 = "VirtualProtect"
  $s4 = "GetProcAddress"
condition: uint16(0) == 0x5a4d and all of ($s*) 
}
rule shad0w_LdrLoadDll_hook { 
meta: 
  description = "Shad0w beacon LdrLoadDll hook" 
  author = "SBousseaden" 
  reference = "https://github.com/bats3c/shad0w" 
  date = "2020-06-06" 
strings:
  $s1 = "LdrLoadD"
  $s2 = "SetPr"
  $s3 = "Policy"
  $s4 = {B8 49 BB DE AD C0} // LdrLoadDll hook
condition: uint16(0) == 0x5a4d and all of ($s*)  
}
import "pe" 

rule susp_winsvc_upx {
meta:
  description = "broad hunt for any PE exporting ServiceMain API and upx packed"
  author = "SBousseaden"
  date = "2019-01-28"
strings:
  $upx1 = {55505830000000}
  $upx2 = {55505831000000}
  $upx_sig = "UPX!"
condition: uint16(0)==0x5a4d and $upx1 in (0..1024) and 
 $upx2 in (0..1024) and $upx_sig in (0..1024) and pe.exports("ServiceMain") }
rule TDL_loader_bootstrap_shellcode {
meta:
 author = "SBousseaden"
 reference = "https://github.com/hfiref0x/TDL"
strings: 
 $shc1 = {41 B8 54 64 6C 53 48 63 6B 3C 48 03 EB 44 8B 7D 50 41 8D 97 00 10 00 00 41 FF D1}
 $shc2 = {41 B8 54 64 6C 53 4C 63 73 3C 4C 03 F3 45 8B 7E 50 41 8D 97 00 10 00 00 41 FF D1 45 33 C9}
condition: uint16(0) == 0x5a4d and any of ($shc*)
}import "pe"

rule hunt_dllhijack_wow64log {
meta:
 description = "broad hunt for non MS wow64log module"
 author = "SBousseaden"
 reference = "http://waleedassar.blogspot.com/2013/01/wow64logdll.html"
 date = "2020-06-5"
condition: uint16(0)==0x5a4d and (pe.exports("Wow64LogInitialize") or 
 pe.exports("Wow64LogMessageArgList") or 
 pe.exports("Wow64LogSystemService") or 
 pe.exports("Wow64LogTerminate")) 
}