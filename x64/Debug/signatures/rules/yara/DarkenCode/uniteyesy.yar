/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule asp_file {
	meta:
		description = "Laudanum Injector Tools - file file.asp"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "ff5b1a9598735440bdbaa768b524c639e22f53c5"
	strings:
		$s1 = "' *** Written by Tim Medin <tim@counterhack.com>" fullword ascii
		$s2 = "Response.BinaryWrite(stream.Read)" fullword ascii
		$s3 = "Response.Write(Response.Status & Request.ServerVariables(\"REMOTE_ADDR\"))" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "%><a href=\"<%=Request.ServerVariables(\"URL\")%>\">web root</a><br/><%" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "set folder = fso.GetFolder(path)" fullword ascii
		$s6 = "Set file = fso.GetFile(filepath)" fullword ascii
	condition:
		uint16(0) == 0x253c and filesize < 30KB and 5 of them
}

rule php_killnc {
	meta:
		description = "Laudanum Injector Tools - file killnc.php"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "c0dee56ee68719d5ec39e773621ffe40b144fda5"
	strings:
		$s1 = "if ($_SERVER[\"REMOTE_ADDR\"] == $IP)" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "header(\"HTTP/1.0 404 Not Found\");" fullword ascii
		$s3 = "<?php echo exec('killall nc');?>" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "<title>Laudanum Kill nc</title>" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "foreach ($allowedIPs as $IP) {" fullword ascii
	condition:
		filesize < 15KB and 4 of them
}

rule asp_shell {
	meta:
		description = "Laudanum Injector Tools - file shell.asp"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "8bf1ff6f8edd45e3102be5f8a1fe030752f45613"
	strings:
		$s1 = "<form action=\"shell.asp\" method=\"POST\" name=\"shell\">" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "%ComSpec% /c dir" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "Set objCmd = wShell.Exec(cmd)" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "Server.ScriptTimeout = 180" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "cmd = Request.Form(\"cmd\")" fullword ascii /* PEStudio Blacklist: strings */
		$s6 = "' ***  http://laudanum.secureideas.net" fullword ascii
		$s7 = "Dim wshell, intReturn, strPResult" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 15KB and 4 of them
}

rule settings {
	meta:
		description = "Laudanum Injector Tools - file settings.php"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "588739b9e4ef2dbb0b4cf630b73295d8134cc801"
	strings:
		$s1 = "Port: <input name=\"port\" type=\"text\" value=\"8888\">" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "<li>Reverse Shell - " fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "<li><a href=\"<?php echo plugins_url('file.php', __FILE__);?>\">File Browser</a>" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 13KB and all of them
}

rule asp_proxy {
	meta:
		description = "Laudanum Injector Tools - file proxy.asp"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "51e97040d1737618b1775578a772fa6c5a31afd8"
	strings:
		$s1 = "'response.write \"<br/>  -value:\" & request.querystring(key)(j)" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "q = q & \"&\" & key & \"=\" & request.querystring(key)(j)" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "for each i in Split(http.getAllResponseHeaders, vbLf)" fullword ascii
		$s4 = "'urlquery = mid(urltemp, instr(urltemp, \"?\") + 1)" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "s = urlscheme & urlhost & urlport & urlpath" fullword ascii /* PEStudio Blacklist: strings */
		$s6 = "Set http = Server.CreateObject(\"Microsoft.XMLHTTP\")" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 50KB and all of them
}

rule cfm_shell {
	meta:
		description = "Laudanum Injector Tools - file shell.cfm"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "885e1783b07c73e7d47d3283be303c9719419b92"
	strings:
		$s1 = "Executable: <Input type=\"text\" name=\"cmd\" value=\"cmd.exe\"><br>" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "<cfif ( #suppliedCode# neq secretCode )>" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "<cfif IsDefined(\"form.cmd\")>" fullword ascii
	condition:
		filesize < 20KB and 2 of them
}

rule aspx_shell {
	meta:
		description = "Laudanum Injector Tools - file shell.aspx"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "076aa781a004ecb2bf545357fd36dcbafdd68b1a"
	strings:
		$s1 = "remoteIp = HttpContext.Current.Request.Headers[\"X-Forwarded-For\"].Split(new" ascii /* PEStudio Blacklist: strings */
		$s2 = "remoteIp = Request.UserHostAddress;" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "<form method=\"post\" name=\"shell\">" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "<body onload=\"document.shell.c.focus()\">" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 20KB and all of them
}

rule php_shell {
	meta:
		description = "Laudanum Injector Tools - file shell.php"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "dc5c03a21267d024ef0f5ab96a34e3f6423dfcd6"
	strings:
		$s1 = "command_hist[current_line] = document.shell.command.value;" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "if (e.keyCode == 38 && current_line < command_hist.length-1) {" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "array_unshift($_SESSION['history'], $command);" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "if (preg_match('/^[[:blank:]]*cd[[:blank:]]*$/', $command)) {" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 40KB and all of them
}

rule php_reverse_shell {
	meta:
		description = "Laudanum Injector Tools - file php-reverse-shell.php"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "3ef03bbe3649535a03315dcfc1a1208a09cea49d"
	strings:
		$s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "printit(\"Successfully opened reverse shell to $ip:$port\");" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "$input = fread($pipes[1], $chunk_size);" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 15KB and all of them
}

rule php_dns {
	meta:
		description = "Laudanum Injector Tools - file dns.php"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "01d5d16d876c55d77e094ce2b9c237de43b21a16"
	strings:
		$s1 = "$query = isset($_POST['query']) ? $_POST['query'] : '';" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "$result = dns_get_record($query, $types[$type], $authns, $addtl);" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "if ($_SERVER[\"REMOTE_ADDR\"] == $IP)" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "foreach (array_keys($types) as $t) {" fullword ascii
	condition:
		filesize < 15KB and all of them
}

rule WEB_INF_web {
	meta:
		description = "Laudanum Injector Tools - file web.xml"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "0251baed0a16c451f9d67dddce04a45dc26cb4a3"
	strings:
		$s1 = "<servlet-name>Command</servlet-name>" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "<jsp-file>/cmd.jsp</jsp-file>" fullword ascii
	condition:
		filesize < 1KB and all of them
}

rule jsp_cmd {
	meta:
		description = "Laudanum Injector Tools - file cmd.war"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "55e4c3dc00cfab7ac16e7cfb53c11b0c01c16d3d"
	strings:
		$s0 = "cmd.jsp}" fullword ascii
		$s1 = "cmd.jspPK" fullword ascii
		$s2 = "WEB-INF/web.xml" fullword ascii /* Goodware String - occured 1 times */
		$s3 = "WEB-INF/web.xmlPK" fullword ascii /* Goodware String - occured 1 times */
		$s4 = "META-INF/MANIFEST.MF" fullword ascii /* Goodware String - occured 12 times */
	condition:
		uint16(0) == 0x4b50 and filesize < 2KB and all of them
}

rule laudanum {
	meta:
		description = "Laudanum Injector Tools - file laudanum.php"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "fd498c8b195967db01f68776ff5e36a06c9dfbfe"
	strings:
		$s1 = "public function __activate()" fullword ascii
		$s2 = "register_activation_hook(__FILE__, array('WP_Laudanum', 'activate'));" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 5KB and all of them
}

rule php_file {
	meta:
		description = "Laudanum Injector Tools - file file.php"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "7421d33e8007c92c8642a36cba7351c7f95a4335"
	strings:
		$s1 = "$allowedIPs =" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "<a href=\"<?php echo $_SERVER['PHP_SELF']  ?>\">Home</a><br/>" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "$dir  = isset($_GET[\"dir\"])  ? $_GET[\"dir\"]  : \".\";" fullword ascii
		$s4 = "$curdir .= substr($curdir, -1) != \"/\" ? \"/\" : \"\";" fullword ascii
	condition:
		filesize < 10KB and all of them
}

rule warfiles_cmd {
	meta:
		description = "Laudanum Injector Tools - file cmd.jsp"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "3ae3d837e7b362de738cf7fad78eded0dccf601f"
	strings:
		$s1 = "Process p = Runtime.getRuntime().exec(request.getParameter(\"cmd\"));" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "out.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\");" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "<FORM METHOD=\"GET\" NAME=\"myform\" ACTION=\"\">" fullword ascii
		$s4 = "String disr = dis.readLine();" fullword ascii
	condition:
		filesize < 2KB and all of them
}

rule asp_dns {
	meta:
		description = "Laudanum Injector Tools - file dns.asp"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "5532154dd67800d33dace01103e9b2c4f3d01d51"
	strings:
		$s1 = "command = \"nslookup -type=\" & qtype & \" \" & query " fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "Set objCmd = objWShell.Exec(command)" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "Response.Write command & \"<br>\"" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "<form name=\"dns\" method=\"POST\">" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 21KB and all of them
}

rule php_reverse_shell_2 {
	meta:
		description = "Laudanum Injector Tools - file php-reverse-shell.php"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "025db3c3473413064f0606d93d155c7eb5049c42"
	strings:
		$s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii /* PEStudio Blacklist: strings */
		$s7 = "$shell = 'uname -a; w; id; /bin/sh -i';" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 10KB and all of them
}

rule Laudanum_Tools_Generic {
	meta:
		description = "Laudanum Injector Tools"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		super_rule = 1
		hash0 = "076aa781a004ecb2bf545357fd36dcbafdd68b1a"
		hash1 = "885e1783b07c73e7d47d3283be303c9719419b92"
		hash2 = "01d5d16d876c55d77e094ce2b9c237de43b21a16"
		hash3 = "7421d33e8007c92c8642a36cba7351c7f95a4335"
		hash4 = "f49291aef9165ee4904d2d8c3cf5a6515ca0794f"
		hash5 = "c0dee56ee68719d5ec39e773621ffe40b144fda5"
		hash6 = "f32b9c2cc3a61fa326e9caebce28ef94a7a00c9a"
		hash7 = "dc5c03a21267d024ef0f5ab96a34e3f6423dfcd6"
		hash8 = "fd498c8b195967db01f68776ff5e36a06c9dfbfe"
		hash9 = "b50ae35fcf767466f6ca25984cc008b7629676b8"
		hash10 = "5570d10244d90ef53b74e2ac287fc657e38200f0"
		hash11 = "42bcb491a11b4703c125daf1747cf2a40a1b36f3"
		hash12 = "83e4eaaa2cf6898d7f83ab80158b64b1d48096f4"
		hash13 = "dec7ea322898690a7f91db9377f035ad7072b8d7"
		hash14 = "a2272b8a4221c6cc373915f0cc555fe55d65ac4d"
		hash15 = "588739b9e4ef2dbb0b4cf630b73295d8134cc801"
		hash16 = "43320dc23fb2ed26b882512e7c0bfdc64e2c1849"
	strings:
		$s1 = "***  laudanum@secureideas.net" fullword ascii
		$s2 = "*** Laudanum Project" fullword ascii
	condition:
		filesize < 60KB and all of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule whosthere_alt {
	meta:
		description = "Auto-generated rule - file whosthere-alt.exe"
		author = "Florian Roth"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "9b4c3691872ca5adf6d312b04190c6e14dd9cbe10e94c0dd3ee874f82db897de"
	strings:
		$s0 = "WHOSTHERE-ALT v1.1 - by Hernan Ochoa (hochoa@coresecurity.com, hernan@gmail.com) - (c) 2007-2008 Core Security Technologies" fullword ascii /* PEStudio Blacklist: strings */ /* score: '49.00' */
		$s1 = "whosthere enters an infinite loop and searches for new logon sessions every 2 seconds. Only new sessions are shown if found." fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.00' */
		$s2 = "dump output to a file, -o filename" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00' */
		$s3 = "This tool lists the active LSA logon sessions with NTLM credentials." fullword ascii /* PEStudio Blacklist: strings */ /* score: '29.00' */
		$s4 = "Error: pth.dll is not in the current directory!." fullword ascii /* score: '24.00' */
		$s5 = "the output format is: username:domain:lmhash:nthash" fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.00' */
		$s6 = ".\\pth.dll" fullword ascii /* score: '16.00' */
		$s7 = "Cannot get LSASS.EXE PID!" fullword ascii /* score: '14.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 280KB and 2 of them
}

rule iam_alt_iam_alt {
	meta:
		description = "Auto-generated rule - file iam-alt.exe"
		author = "Florian Roth"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "2ea662ef58142d9e340553ce50d95c1b7a405672acdfd476403a565bdd0cfb90"
	strings:
		$s0 = "<cmd>. Create a new logon session and run a command with the specified credentials (e.g.: -r cmd.exe)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '59.00' */
		$s1 = "IAM-ALT v1.1 - by Hernan Ochoa (hochoa@coresecurity.com, hernan@gmail.com) - (c) 2007-2008 Core Security Technologies" fullword ascii /* PEStudio Blacklist: strings */ /* score: '43.00' */
		$s2 = "This tool allows you to change the NTLM credentials of the current logon session" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.00' */
		$s3 = "username:domainname:lmhash:nthash" fullword ascii /* PEStudio Blacklist: strings */ /* score: '15.00' */
		$s4 = "Error in cmdline!. Bye!." fullword ascii /* score: '12.00' */
		$s5 = "Error: Cannot open LSASS.EXE!." fullword ascii /* score: '12.00' */
		$s6 = "nthash is too long!." fullword ascii /* score: '8.00' */
		$s7 = "LSASS HANDLE: %x" fullword ascii /* score: '5.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 240KB and 2 of them
}

rule genhash_genhash {
	meta:
		description = "Auto-generated rule - file genhash.exe"
		author = "Florian Roth"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "113df11063f8634f0d2a28e0b0e3c2b1f952ef95bad217fd46abff189be5373f"
	strings:
		$s1 = "genhash.exe <password>" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00' */
		$s3 = "Password: %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.00' */
		$s4 = "%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X" fullword ascii /* score: '11.00' */
		$s5 = "This tool generates LM and NT hashes." fullword ascii /* score: '10.00' */
		$s6 = "(hashes format: LM Hash:NT hash)" fullword ascii /* score: '10.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}

rule iam_iamdll {
	meta:
		description = "Auto-generated rule - file iamdll.dll"
		author = "Florian Roth"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "892de92f71941f7b9e550de00a57767beb7abe1171562e29428b84988cee6602"
	strings:
		$s0 = "LSASRV.DLL" fullword ascii /* score: '21.00' */
		$s1 = "iamdll.dll" fullword ascii /* score: '21.00' */
		$s2 = "ChangeCreds" fullword ascii /* score: '12.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 115KB and all of them
}

rule iam_iam {
	meta:
		description = "Auto-generated rule - file iam.exe"
		author = "Florian Roth"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "8a8fcce649259f1b670bb1d996f0d06f6649baa8eed60db79b2c16ad22d14231"
	strings:
		$s1 = "<cmd>. Create a new logon session and run a command with the specified credentials (e.g.: -r cmd.exe)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '59.00' */
		$s2 = "iam.exe -h administrator:mydomain:"  ascii /* PEStudio Blacklist: strings */ /* score: '40.00' */
		$s3 = "An error was encountered when trying to change the current logon credentials!." fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.00' */
		$s4 = "optional parameter. If iam.exe crashes or doesn't work when run in your system, use this parameter." fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00' */
		$s5 = "IAM.EXE will try to locate some memory locations instead of using hard-coded values." fullword ascii /* score: '26.00' */
		$s6 = "Error in cmdline!. Bye!." fullword ascii /* score: '12.00' */
		$s7 = "Checking LSASRV.DLL...." fullword ascii /* score: '12.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule whosthere_alt_pth {
	meta:
		description = "Auto-generated rule - file pth.dll"
		author = "Florian Roth"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "fbfc8e1bc69348721f06e96ff76ae92f3551f33ed3868808efdb670430ae8bd0"
	strings:
		$s0 = "c:\\debug.txt" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00' */
		$s1 = "pth.dll" fullword ascii /* score: '20.00' */
		$s2 = "\"Primary\" string found at %.8Xh" fullword ascii /* score: '7.00' */
		$s3 = "\"Primary\" string not found!" fullword ascii /* score: '6.00' */
		$s4 = "segment 1 found at %.8Xh" fullword ascii /* score: '6.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 240KB and 4 of them
}

rule whosthere {
	meta:
		description = "Auto-generated rule - file whosthere.exe"
		author = "Florian Roth"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "d7a82204d3e511cf5af58eabdd6e9757c5dd243f9aca3999dc0e5d1603b1fa37"
	strings:
		$s1 = "by Hernan Ochoa (hochoa@coresecurity.com, hernan@gmail.com) - (c) 2007-2008 Core Security Technologies" fullword ascii /* PEStudio Blacklist: strings */ /* score: '48.00' */
		$s2 = "whosthere enters an infinite loop and searches for new logon sessions every 2 seconds. Only new sessions are shown if found." fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.00' */
		$s3 = "specify addresses to use. Format: ADDCREDENTIAL_ADDR:ENCRYPTMEMORY_ADDR:FEEDBACK_ADDR:DESKEY_ADDR:LOGONSESSIONLIST_ADDR:LOGONSES" ascii /* PEStudio Blacklist: strings */ /* score: '28.00' */
		$s4 = "Could not enable debug privileges. You must run this tool with an account with administrator privileges." fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00' */
		$s5 = "-B is now used by default. Trying to find correct addresses.." fullword ascii /* PEStudio Blacklist: strings */ /* score: '15.00' */
		$s6 = "Cannot get LSASS.EXE PID!" fullword ascii /* score: '14.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 320KB and 2 of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule APT_Malware_PutterPanda_Rel {
	meta:
		description = "Detects an APT malware related to PutterPanda"
		author = "Florian Roth"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "5367e183df155e3133d916f7080ef973f7741d34"
	strings:
		$x0 = "app.stream-media.net" fullword ascii /* score: '12.03' */
		$x1 = "File %s does'nt exist or is forbidden to acess!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '16.035' */

		$s6 = "GetProcessAddresss of pHttpQueryInfoA Failed!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '32.02' */
		$s7 = "Connect %s error!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '16.04' */
		$s9 = "Download file %s successfully!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '14.03' */
		$s10 = "index.tmp" fullword ascii /* score: '14.03' */
		$s11 = "Execute PE Successfully" fullword ascii /* PEStudio Blacklist: strings */ /* score: '13.03' */
		$s13 = "aa/22/success.xml" fullword ascii /* score: '12.005' */
		$s16 = "aa/22/index.asp" fullword ascii /* score: '11.02' */
		$s18 = "File %s a Non-Pe File" fullword ascii /* score: '8.04' */
		$s19 = "SendRequset error!" fullword ascii /* score: '8.04' */
		$s20 = "filelist[%d]=%s" fullword ascii /* score: '7.015' */
	condition:
		( uint16(0) == 0x5a4d and 1 of ($x*) ) or ( 4 of ($s*) )
}


rule APT_Malware_PutterPanda_Rel_2 {
	meta:
		description = "APT Malware related to PutterPanda Group"
		author = "Florian Roth"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "f97e01ee04970d1fc4d988a9e9f0f223ef2a6381"
	strings:
		$s0 = "http://update.konamidata.com/test/zl/sophos/td/result/rz.dat?" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.01' */
		$s1 = "http://update.konamidata.com/test/zl/sophos/td/index.dat?" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.01' */
		$s2 = "Mozilla/4.0 (Compatible; MSIE 6.0;)" fullword ascii /* PEStudio Blacklist: agent */ /* score: '20.03' */
		$s3 = "Internet connect error:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '14.035' */
		$s4 = "Proxy-Authorization:Basic" fullword ascii /* PEStudio Blacklist: strings */ /* score: '14.02' */
		$s5 = "HttpQueryInfo failed:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '13.015' */
		$s6 = "read file error:%d" fullword ascii /* score: '11.04' */
		$s7 = "downdll.dll" fullword ascii /* score: '11.025' */
		$s8 = "rz.dat" fullword ascii /* score: '10.005' */
		$s9 = "Invalid url" fullword ascii /* PEStudio Blacklist: strings */ /* score: '9.03' */
		$s10 = "Create file failed" fullword ascii /* score: '8.045' */
		$s11 = "myAgent" fullword ascii /* score: '8.025' */
		$s12 = "%s%s%d%d" fullword ascii /* score: '8.005' */
		$s13 = "down file success" fullword ascii /* score: '7.035' */
		$s15 = "error!" fullword ascii /* score: '6.04' */
		$s18 = "Avaliable data:%u bytes" fullword ascii /* score: '5.025' */
	condition:
		uint16(0) == 0x5a4d and 6 of them
}

rule APT_Malware_PutterPanda_PSAPI {
	meta:
		description = "Detects a malware related to Putter Panda"
		author = "Florian Roth"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "f93a7945a33145bb6c106a51f08d8f44eab1cdf5"
	strings:
		$s0 = "LOADER ERROR" fullword ascii /* PEStudio Blacklist: strings */ /* score: '12.03' */
		$s1 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '8.045' */
		$s2 = "psapi.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 54 times */
		$s3 = "urlmon.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 471 times */
		$s4 = "WinHttpGetProxyForUrl" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 179 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule APT_Malware_PutterPanda_WUAUCLT {
	meta:
		description = "Detects a malware related to Putter Panda"
		author = "Florian Roth"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "fd5ca5a2d444865fa8320337467313e4026b9f78"
	strings:
		$x0 = "WUAUCLT.EXE" fullword wide /* PEStudio Blacklist: strings */ /* score: '20.01' */
		$x1 = "%s\\tmp%d.exe" fullword ascii /* score: '14.01' */	
		$x2 = "Microsoft Corporation. All rights reserved." fullword wide /* score: '8.04' */

		$s1 = "Microsoft Windows Operating System" fullword wide /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 4 times */
		$s2 = "InternetQueryOptionA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 166 times */
		$s3 = "LookupPrivilegeValueA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 336 times */
		$s4 = "WNetEnumResourceA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 29 times */
		$s5 = "HttpSendRequestExA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 87 times */
		$s6 = "PSAPI.DLL" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 420 times */
		$s7 = "Microsoft(R) Windows(R) Operating System" fullword wide /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 128 times */
		$s8 = "CreatePipe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 222 times */
		$s9 = "EnumProcessModules" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 410 times */
	condition:
		all of ($x*) or 
		(1 of ($x*) and all of ($s*) )
}

rule APT_Malware_PutterPanda_Gen1 {
	meta:
		description = "Detects a malware "
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015-06-03"
		super_rule = 1
		hash0 = "bf1d385e637326a63c4d2f253dc211e6a5436b6a"
		hash1 = "76459bcbe072f9c29bb9703bc72c7cd46a692796"
		hash2 = "e105a7a3a011275002aec4b930c722e6a7ef52ad"
	strings:
		$s1 = "%s%duserid=%dthreadid=%dgroupid=%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '22.02' */
		$s2 = "ssdpsvc.dll" fullword ascii /* score: '11.00' */
		$s3 = "Fail %s " fullword ascii /* score: '10.04' */
		$s4 = "%s%dpara1=%dpara2=%dpara3=%d" fullword ascii /* score: '10.01' */
		$s5 = "LsaServiceInit" fullword ascii /* score: '7.03' */
		$s6 = "%-8d Fs %-12s Bs " fullword ascii /* score: '5.04' */
		$s7 = "Microsoft DH SChannel Cryptographic Provider" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5.00' */ /* Goodware String - occured 5 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and 5 of them
}

rule Malware_MsUpdater_String_in_EXE {
	meta:
		description = "MSUpdater String in Executable"
		author = "Florian Roth"
		score = 50
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "b1a2043b7658af4d4c9395fa77fde18ccaf549bb"
	strings:
		$x1 = "msupdate.exe" fullword wide /* PEStudio Blacklist: strings */ /* score: '20.01' */
		// $x2 = "msupdate" fullword wide /* PEStudio Blacklist: strings */ /* score: '13.01' */
		$x3 = "msupdater.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.02' */
		$x4 = "msupdater32.exe" fullword ascii
		$x5 = "msupdater32.exe" fullword wide
		$x6 = "msupdate.pif" fullword ascii

		$fp1 = "_msupdate_" wide /* False Positive */
		$fp2 = "_msupdate_" ascii /* False Positive */
		$fp3 = "/kies" wide
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and ( 1 of ($x*) ) and not ( 1 of ($fp*) ) 
}

rule APT_Malware_PutterPanda_MsUpdater_3 {
	meta:
		description = "Detects Malware related to PutterPanda - MSUpdater"
		author = "Florian Roth"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "464149ff23f9c7f4ab2f5cadb76a4f41f969bed0"
	strings:
		$s0 = "msupdater.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.02' */
		$s1 = "Explorer.exe \"" fullword ascii /* PEStudio Blacklist: strings */ /* score: '16.05' */
		$s2 = "FAVORITES.DAT" fullword ascii /* score: '11.02' */
		$s4 = "COMSPEC" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.82' */ /* Goodware String - occured 178 times */
	condition:
		uint16(0) == 0x5a4d and 3 of them
}

rule APT_Malware_PutterPanda_MsUpdater_1 {
	meta:
		description = "Detects Malware related to PutterPanda - MSUpdater"
		author = "Florian Roth"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "b55072b67543f58c096571c841a560c53d72f01a"
	strings:
		$x0 = "msupdate.exe" fullword wide /* PEStudio Blacklist: strings */ /* score: '20.01' */
		$x1 = "msupdate" fullword wide /* PEStudio Blacklist: strings */ /* score: '13.01' */

		$s1 = "Microsoft Corporation. All rights reserved." fullword wide /* score: '8.04' */
		$s2 = "Automatic Updates" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.98' */ /* Goodware String - occured 22 times */
		$s3 = "VirtualProtectEx" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.93' */ /* Goodware String - occured 68 times */
		$s4 = "Invalid parameter" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.93' */ /* Goodware String - occured 69 times */
		$s5 = "VirtualAllocEx" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.91' */ /* Goodware String - occured 95 times */
		$s6 = "WriteProcessMemory" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.87' */ /* Goodware String - occured 131 times */
	condition:
		( uint16(0) == 0x5a4d and 1 of ($x*) and 4 of ($s*) ) or
		( 1 of ($x*) and all of ($s*) )
}

rule APT_Malware_PutterPanda_MsUpdater_2 {
	meta:
		description = "Detects Malware related to PutterPanda - MSUpdater"
		author = "Florian Roth"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "365b5537e3495f8ecfabe2597399b1f1226879b1"
	strings:
		$s0 = "winsta0\\default" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.99' */ /* Goodware String - occured 6 times */
		$s1 = "EXPLORER.EXE" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.98' */ /* Goodware String - occured 22 times */
		$s2 = "WNetEnumResourceA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97' */ /* Goodware String - occured 29 times */
		$s3 = "explorer.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97' */ /* Goodware String - occured 31 times */
		$s4 = "CreateProcessAsUserA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.91' */ /* Goodware String - occured 86 times */
		$s5 = "HttpSendRequestExA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.91' */ /* Goodware String - occured 87 times */
		$s6 = "HttpEndRequestA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.91' */ /* Goodware String - occured 91 times */
		$s7 = "GetModuleBaseNameA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.88' */ /* Goodware String - occured 121 times */
		$s8 = "GetModuleFileNameExA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.86' */ /* Goodware String - occured 144 times */
		$s9 = "HttpSendRequestA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.85' */ /* Goodware String - occured 154 times */
		$s10 = "HttpOpenRequestA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.84' */ /* Goodware String - occured 159 times */
		$s11 = "InternetConnectA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.82' */ /* Goodware String - occured 183 times */
		$s12 = "Process32Next" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.80' */ /* Goodware String - occured 204 times */
		$s13 = "Process32First" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.79' */ /* Goodware String - occured 210 times */
		$s14 = "CreatePipe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.78' */ /* Goodware String - occured 222 times */
		$s15 = "EnumProcesses" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.73' */ /* Goodware String - occured 273 times */
		$s16 = "LookupPrivilegeValueA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.66' */ /* Goodware String - occured 336 times */
		$s17 = "PeekNamedPipe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.65' */ /* Goodware String - occured 347 times */
		$s18 = "EnumProcessModules" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.59' */ /* Goodware String - occured 410 times */
		$s19 = "PSAPI.DLL" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.58' */ /* Goodware String - occured 420 times */
		$s20 = "SPSSSQ" fullword ascii /* score: '4.51' */
	condition:
		uint16(0) == 0x5a4d and filesize < 220KB and all of them
}

rule APT_Malware_PutterPanda_Gen4 {
	meta:
		description = "Detects Malware related to PutterPanda"
		author = "Florian Roth"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		super_rule = 1
		hash0 = "71a8378fa8e06bcf8ee9f019c807c6bfc58dca0c"
		hash1 = "8fdd6e5ed9d69d560b6fdd5910f80e0914893552"
		hash2 = "3c4a762175326b37035a9192a981f7f4cc2aa5f0"
		hash3 = "598430b3a9b5576f03cc4aed6dc2cd8a43324e1e"
		hash4 = "6522b81b38747f4aa09c98fdaedaed4b00b21689"
	strings:
		$x1 = "rz.dat" fullword ascii /* score: '10.00' */

		$s0 = "Mozilla/4.0 (Compatible; MSIE 6.0;)" fullword ascii /* PEStudio Blacklist: agent */ /* score: '20.03' */
		$s1 = "Internet connect error:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '14.04' */
		$s2 = "Proxy-Authorization:Basic " fullword ascii /* PEStudio Blacklist: strings */ /* score: '14.02' */
		$s5 = "Invalid url" fullword ascii /* PEStudio Blacklist: strings */ /* score: '9.03' */
		$s6 = "Create file failed" fullword ascii /* score: '8.04' */
		$s7 = "myAgent" fullword ascii /* score: '8.03' */

		$z1 = "%s%s%d%d" fullword ascii /* score: '8.00' */
		$z2 = "HttpQueryInfo failed:%d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '13.02' */
		$z3 = "read file error:%d" fullword ascii /* score: '11.04' */
		$z4 = "down file success" fullword ascii /* score: '7.04' */
		$z5 = "kPStoreCreateInstance" fullword ascii /* score: '5.03' */
		$z6 = "Avaliable data:%u bytes" fullword ascii /* score: '5.03' */
		$z7 = "abe2869f-9b47-4cd9-a358-c22904dba7f7" fullword ascii /* PEStudio Blacklist: guid */ /* score: '5.00' */ /* Goodware String - occured 2 times */
	condition:
		filesize < 300KB and 
		(
			( uint16(0) == 0x5a4d and $x1 and 3 of ($s*) ) or
			( 3 of ($s*) and 4 of ($z*) )
		)
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
    Warning: Don't use this rule set without excluding the false positive hashes listed in the file falsepositive-hashes.txt from https://github.com/Neo23x0/Loki/blob/master/signatures/falsepositive-hashes.txt

*/

import "pe"
rule Regin_APT_KernelDriver_Generic_A {
	meta:
		description = "Generic rule for Regin APT kernel driver Malware - Symantec http://t.co/qu53359Cb2"
		author = "@Malwrsignatures - included in APT Scanner THOR"
		date = "23.11.14"
		hash1 = "187044596bc1328efa0ed636d8aa4a5c"
		hash2 = "06665b96e293b23acc80451abb413e50"
		hash3 = "d240f06e98c8d3e647cbf4d442d79475"
	strings:
		$m0 = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 } 
		$m1 = { 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e }
		
		$s0 = "atapi.sys" fullword wide
		$s1 = "disk.sys" fullword wide
		$s3 = "h.data" fullword ascii
		$s4 = "\\system32" fullword ascii
		$s5 = "\\SystemRoot" fullword ascii
		$s6 = "system" fullword ascii
		$s7 = "temp" fullword ascii
		$s8 = "windows" fullword ascii

		$x1 = "LRich6" fullword ascii
		$x2 = "KeServiceDescriptorTable" fullword ascii		
	condition:
		$m0 at 0 and $m1 and  	
		all of ($s*) and 1 of ($x*)
}

rule Regin_APT_KernelDriver_Generic_B {
	meta:
		description = "Generic rule for Regin APT kernel driver Malware - Symantec http://t.co/qu53359Cb2"
		author = "@Malwrsignatures - included in APT Scanner THOR"
		date = "23.11.14"
		hash1 = "ffb0b9b5b610191051a7bdf0806e1e47"
		hash2 = "bfbe8c3ee78750c3a520480700e440f8"
		hash3 = "b29ca4f22ae7b7b25f79c1d4a421139d"
		hash4 = "06665b96e293b23acc80451abb413e50"
		hash5 = "2c8b9d2885543d7ade3cae98225e263b"
		hash6 = "4b6b86c7fec1c574706cecedf44abded"
		hash7 = "187044596bc1328efa0ed636d8aa4a5c"
		hash8 = "d240f06e98c8d3e647cbf4d442d79475"
		hash9 = "6662c390b2bbbd291ec7987388fc75d7"
		hash10 = "1c024e599ac055312a4ab75b3950040a"
		hash11 = "ba7bb65634ce1e30c1e5415be3d1db1d"
		hash12 = "b505d65721bb2453d5039a389113b566"
		hash13 = "b269894f434657db2b15949641a67532"
	strings:
		$m0 = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 } 
		$s1 = { 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e }
		$s2 = "H.data" fullword ascii nocase
		$s3 = "INIT" fullword ascii
		$s4 = "ntoskrnl.exe" fullword ascii
		
		$v1 = "\\system32" fullword ascii
		$v2 = "\\SystemRoot" fullword ascii
		$v3 = "KeServiceDescriptorTable" fullword ascii	
		
		$w1 = "\\system32" fullword ascii
		$w2 = "\\SystemRoot" fullword ascii		
		$w3 = "LRich6" fullword ascii
		
		$x1 = "_snprintf" fullword ascii
		$x2 = "_except_handler3" fullword ascii
		
		$y1 = "mbstowcs" fullword ascii
		$y2 = "wcstombs" fullword ascii
		$y3 = "KeGetCurrentIrql" fullword ascii
		
		$z1 = "wcscpy" fullword ascii
		$z2 = "ZwCreateFile" fullword ascii
		$z3 = "ZwQueryInformationFile" fullword ascii
		$z4 = "wcslen" fullword ascii
		$z5 = "atoi" fullword ascii
	condition:
		$m0 at 0 and all of ($s*) and 
		( all of ($v*) or all of ($w*) or all of ($x*) or all of ($y*) or all of ($z*) ) 
		and filesize < 20KB
}

rule Regin_APT_KernelDriver_Generic_C {
	meta:
		description = "Generic rule for Regin APT kernel driver Malware - Symantec http://t.co/qu53359Cb2"
		author = "@Malwrsignatures - included in APT Scanner THOR"
		date = "23.11.14"
		hash1 = "e0895336617e0b45b312383814ec6783556d7635"
		hash2 = "732298fa025ed48179a3a2555b45be96f7079712"		
	strings:
		$m0 = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 } 
	
		$s0 = "KeGetCurrentIrql" fullword ascii
		$s1 = "5.2.3790.0 (srv03_rtm.030324-2048)" fullword wide
		$s2 = "usbclass" fullword wide
		
		$x1 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" ascii
		$x2 = "Universal Serial Bus Class Driver" fullword wide
		$x3 = "5.2.3790.0" fullword wide
		
		$y1 = "LSA Shell" fullword wide
		$y2 = "0Richw" fullword ascii		
	condition:
		$m0 at 0 and all of ($s*) and 
		( all of ($x*) or all of ($y*) ) 
		and filesize < 20KB
}

/* Update 27.11.14 */

rule Regin_sig_svcsstat {
	meta:
		description = "Detects svcstat from Regin report - file svcsstat.exe_sample"
		author = "@MalwrSignatures"
		date = "26.11.14"
		hash = "5164edc1d54f10b7cb00a266a1b52c623ab005e2"
	strings:
		$s0 = "Service Control Manager" fullword ascii
		$s1 = "_vsnwprintf" fullword ascii
		$s2 = "Root Agency" fullword ascii
		$s3 = "Root Agency0" fullword ascii
		$s4 = "StartServiceCtrlDispatcherA" fullword ascii
		$s5 = "\\\\?\\UNC" fullword wide
		$s6 = "%ls%ls" fullword wide
	condition:
		all of them and filesize < 15KB and filesize > 10KB 
}

rule Regin_Sample_1 {
	meta:
		description = "Auto-generated rule - file-3665415_sys"
		author = "@MalwrSignatures"
		date = "26.11.14"
		hash = "773d7fab06807b5b1bc2d74fa80343e83593caf2"
	strings:
		$s0 = "Getting PortName/Identifier failed - %x" fullword ascii
		$s1 = "SerialAddDevice - error creating new devobj [%#08lx]" fullword ascii
		$s2 = "External Naming Failed - Status %x" fullword ascii
		$s3 = "------- Same multiport - different interrupts" fullword ascii
		$s4 = "%x occurred prior to the wait - starting the" fullword ascii
		$s5 = "'user registry info - userPortIndex: %d" fullword ascii
		$s6 = "Could not report legacy device - %x" fullword ascii
		$s7 = "entering SerialGetPortInfo" fullword ascii
		$s8 = "'user registry info - userPort: %x" fullword ascii
		$s9 = "IoOpenDeviceRegistryKey failed - %x " fullword ascii
		$s10 = "Kernel debugger is using port at address %X" fullword ascii
		$s12 = "Release - freeing multi context" fullword ascii
		$s13 = "Serial driver will not load port" fullword ascii
		$s14 = "'user registry info - userAddressSpace: %d" fullword ascii
		$s15 = "SerialAddDevice: Enumeration request, returning NO_MORE_ENTRIES" fullword ascii
		$s20 = "'user registry info - userIndexed: %d" fullword ascii
	condition:
		all of them and filesize < 110KB and filesize > 80KB
}

rule Regin_Sample_2 {
	meta:
		description = "Auto-generated rule - file hiddenmod_hookdisk_and_kdbg_8949d000.bin"
		author = "@MalwrSignatures"
		date = "26.11.14"
		hash = "a7b285d4b896b66fce0ebfcd15db53b3a74a0400"
	strings:
		$s0 = "\\SYSTEMROOT\\system32\\lsass.exe" fullword wide
		$s1 = "atapi.sys" fullword wide
		$s2 = "disk.sys" fullword wide
		$s3 = "IoGetRelatedDeviceObject" fullword ascii
		$s4 = "HAL.dll" fullword ascii
		$s5 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services" fullword ascii
		$s6 = "PsGetCurrentProcessId" fullword ascii
		$s7 = "KeGetCurrentIrql" fullword ascii
		$s8 = "\\REGISTRY\\Machine\\System\\CurrentControlSet\\Control\\Session Manager" wide
		$s9 = "KeSetImportanceDpc" fullword ascii
		$s10 = "KeQueryPerformanceCounter" fullword ascii
		$s14 = "KeInitializeEvent" fullword ascii
		$s15 = "KeDelayExecutionThread" fullword ascii
		$s16 = "KeInitializeTimerEx" fullword ascii
		$s18 = "PsLookupProcessByProcessId" fullword ascii
		$s19 = "ExReleaseFastMutexUnsafe" fullword ascii
		$s20 = "ExAcquireFastMutexUnsafe" fullword ascii
	condition:
		all of them and filesize < 40KB and filesize > 30KB
}

rule Regin_Sample_3 {
	meta:
		description = "Detects Regin Backdoor sample fe1419e9dde6d479bd7cda27edd39fafdab2668d498931931a2769b370727129"
		author = "@Malwrsignatures"
		date = "27.11.14"
		hash = "fe1419e9dde6d479bd7cda27edd39fafdab2668d498931931a2769b370727129"		
	strings:
		$hd = { fe ba dc fe }
	
		$s0 = "Service Pack x" fullword wide
		$s1 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" fullword wide
		$s2 = "\\REGISTRY\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\HotFix" fullword wide
		$s3 = "mntoskrnl.exe" fullword wide
		$s4 = "\\REGISTRY\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Memory Management" fullword wide
		$s5 = "Memory location: 0x%p, size 0x%08x" wide fullword
		$s6 = "Service Pack" fullword wide
		$s7 = ".sys" fullword wide
		$s8 = ".dll" fullword wide		
		
		$s10 = "\\REGISTRY\\Machine\\Software\\Microsoft\\Updates" fullword wide
		$s11 = "IoGetRelatedDeviceObject" fullword ascii
		$s12 = "VMEM.sys" fullword ascii
		$s13 = "RtlGetVersion" fullword wide
		$s14 = "ntkrnlpa.exe" fullword ascii
	condition:
		( $hd at 0 ) and all of ($s*) and filesize > 160KB and filesize < 200KB
}

rule Regin_Sample_Set_1 {
	meta:
		description = "Auto-generated rule - file SHF-000052 and ndisips.sys"
		author = "@MalwrSignatures"
		date = "26.11.14"
		hash1 = "8487a961c8244004c9276979bb4b0c14392fc3b8"
		hash2 = "bcf3461d67b39a427c83f9e39b9833cfec977c61"		
	strings:
		$s0 = "HAL.dll" fullword ascii
		$s1 = "IoGetDeviceObjectPointer" fullword ascii
		$s2 = "MaximumPortsServiced" fullword wide
		$s3 = "KeGetCurrentIrql" fullword ascii
		$s4 = "ntkrnlpa.exe" fullword ascii
		$s5 = "\\REGISTRY\\Machine\\System\\CurrentControlSet\\Control\\Session Manager" wide
		$s6 = "ConnectMultiplePorts" fullword wide
		$s7 = "\\SYSTEMROOT" fullword wide
		$s8 = "IoWriteErrorLogEntry" fullword ascii
		$s9 = "KeQueryPerformanceCounter" fullword ascii
		$s10 = "KeServiceDescriptorTable" fullword ascii
		$s11 = "KeRemoveEntryDeviceQueue" fullword ascii
		$s12 = "SeSinglePrivilegeCheck" fullword ascii
		$s13 = "KeInitializeEvent" fullword ascii
		$s14 = "IoBuildDeviceIoControlRequest" fullword ascii
		$s15 = "KeRemoveDeviceQueue" fullword ascii
		$s16 = "IofCompleteRequest" fullword ascii
		$s17 = "KeInitializeSpinLock" fullword ascii
		$s18 = "MmIsNonPagedSystemAddressValid" fullword ascii
		$s19 = "IoCreateDevice" fullword ascii
		$s20 = "KefReleaseSpinLockFromDpcLevel" fullword ascii
	condition:
		all of them and filesize < 40KB and filesize > 30KB
}

rule Regin_Sample_Set_2 {
	meta:
		description = "Detects Regin Backdoor sample 4139149552b0322f2c5c993abccc0f0d1b38db4476189a9f9901ac0d57a656be and e420d0cf7a7983f78f5a15e6cb460e93c7603683ae6c41b27bf7f2fa34b2d935"
		author = "@MalwrSignatures"
		date = "27.11.14"
		hash1 = "4139149552b0322f2c5c993abccc0f0d1b38db4476189a9f9901ac0d57a656be"
		hash2 = "e420d0cf7a7983f78f5a15e6cb460e93c7603683ae6c41b27bf7f2fa34b2d935"
	strings:
		$hd = { fe ba dc fe }
	
		$s0 = "d%ls%ls" fullword wide
		$s1 = "\\\\?\\UNC" fullword wide
		$s2 = "Software\\Microsoft\\Windows\\CurrentVersion" fullword wide
		$s3 = "\\\\?\\UNC\\" fullword wide
		$s4 = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}" fullword wide
		$s5 = "System\\CurrentControlSet\\Services\\Tcpip\\Linkage" wide fullword
		$s6 = "\\\\.\\Global\\%s" fullword wide
		$s7 = "temp" fullword wide
		$s8 = "\\\\.\\%s" fullword wide
		$s9 = "Memory location: 0x%p, size 0x%08x" fullword wide		
		
		$s10 = "sscanf" fullword ascii
		$s11 = "disp.dll" fullword ascii
		$s12 = "%x:%x:%x:%x:%x:%x:%x:%x%c" fullword ascii
		$s13 = "%d.%d.%d.%d%c" fullword ascii
		$s14 = "imagehlp.dll" fullword ascii
		$s15 = "%hd %d" fullword ascii
	condition:
		( $hd at 0 ) and all of ($s*) and filesize < 450KB and filesize > 360KB
}

rule apt_regin_legspin {
	meta:
	    copyright = "Kaspersky Lab"
	    description = "Rule to detect Regin's Legspin module"
	    version = "1.0"
	    last_modified = "2015-01-22"
	    reference = "https://securelist.com/blog/research/68438/an-analysis-of-regins-hopscotch-and-legspin/"
	    md5 = "29105f46e4d33f66fee346cfd099d1cc"
	strings:
	    $mz="MZ"
	    $a1="sharepw"
	    $a2="reglist"
	    $a3="logdump"
	    $a4="Name:" wide
	    $a5="Phys Avail:"
	    $a6="cmd.exe" wide
	    $a7="ping.exe" wide
	    $a8="millisecs"
	condition:
	    ($mz at 0) and all of ($a*)
}

rule apt_regin_hopscotch {
	meta:
	    copyright = "Kaspersky Lab"
	    description = "Rule to detect Regin's Hopscotch module"
	    version = "1.0"
	    last_modified = "2015-01-22"
	    reference = "https://securelist.com/blog/research/68438/an-analysis-of-regins-hopscotch-and-legspin/"
	    md5 = "6c34031d7a5fc2b091b623981a8ae61c"
	strings:

	    $mz="MZ"

	    $a1="AuthenticateNetUseIpc"
	    $a2="Failed to authenticate to"
	    $a3="Failed to disconnect from"
	    $a4="%S\\ipc$" wide
	    $a5="Not deleting..."
	    $a6="CopyServiceToRemoteMachine"
	    $a7="DH Exchange failed"
	    $a8="ConnectToNamedPipes"
	condition:
	    ($mz at 0) and all of ($a*)
}


rule apt_regin_2011_32bit_stage1 {
meta:
copyright = "Kaspersky Lab"
 description = "Rule to detect Regin 32 bit stage 1 loaders"
 version = "1.0"
 last_modified = "2014-11-18"
strings:
$key1={331015EA261D38A7}
$key2={9145A98BA37617DE}
$key3={EF745F23AA67243D}
$mz="MZ"
condition:
($mz at 0) and any of ($key*) and filesize < 300000
}
rule apt_regin_rc5key {
meta:
copyright = "Kaspersky Lab"
 description = "Rule to detect Regin RC5 decryption keys"
 version = "1.0"
 last_modified = "2014-11-18"
strings:
$key1={73 23 1F 43 93 E1 9F 2F 99 0C 17 81 5C FF B4 01}
$key2={10 19 53 2A 11 ED A3 74 3F C3 72 3F 9D 94 3D 78}
condition:
any of ($key*)
}

rule apt_regin_vfs {
meta:
	copyright = "Kaspersky Lab"
	author = "Kaspersky Lab"
	description = "Rule to detect Regin VFSes"
	version = "1.0"
	last_modified = "2014-11-18"
strings:
	$a1={00 02 00 08 00 08 03 F6 D7 F3 52}
	$a2={00 10 F0 FF F0 FF 11 C7 7F E8 52}
	$a3={00 04 00 10 00 10 03 C2 D3 1C 93}
	$a4={00 04 00 10 C8 00 04 C8 93 06 D8}
condition:
	($a1 at 0) or ($a2 at 0) or ($a3 at 0) or ($a4 at 0)
}

rule apt_regin_dispatcher_disp_dll {

meta:
	copyright = "Kaspersky Lab"
	author = "Kaspersky Lab"
	description = "Rule to detect Regin disp.dll dispatcher"
	version = "1.0"
	last_modified = "2014-11-18"

strings:
	$mz="MZ"
	$string1="shit"
	$string2="disp.dll"
	$string3="255.255.255.255"
	$string4="StackWalk64"
	$string5="imagehlp.dll"
condition:
	($mz at 0) and (all of ($string*))
}

rule apt_regin_2013_64bit_stage1 {
meta:
copyright = "Kaspersky Lab"
 description = "Rule to detect Regin 64 bit stage 1 loaders"
 version = "1.0"
 last_modified = "2014-11-18"
 filename="wshnetc.dll"
 md5="bddf5afbea2d0eed77f2ad4e9a4f044d"
 filename="wsharp.dll"
 md5="c053a0a3f1edcbbfc9b51bc640e808ce"
strings:
$mz="MZ"
$a1="PRIVHEAD"
$a2="\\\\.\\PhysicalDrive%d"
$a3="ZwDeviceIoControlFile"
condition:
($mz at 0) and (all of ($a*)) and filesize < 100000
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-08-06
	Identifier: Threat Group 3390
*/

rule HttpBrowser_RAT_dropper_Gen1 {
	meta:
		description = "Threat Group 3390 APT Sample - HttpBrowser RAT Dropper"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 70
		hash1 = "808de72f1eae29e3c1b2c32be1b84c5064865a235866edf5e790d2a7ba709907"
		hash2 = "f6f966d605c5e79de462a65df437ddfca0ad4eb5faba94fc875aba51a4b894a7"
		hash3 = "f424965a35477d822bbadb821125995616dc980d3d4f94a68c87d0cd9b291df9"
		hash4 = "01441546fbd20487cb2525a0e34e635eff2abe5c3afc131c7182113220f02753"
		hash5 = "8cd8159f6e4689f572e2087394452e80e62297af02ca55fe221fe5d7570ad47b"
		hash6 = "10de38419c9a02b80ab7bf2f1f1f15f57dbb0fbc9df14b9171dc93879c5a0c53"
		hash7 = "c2fa67e970d00279cec341f71577953d49e10fe497dae4f298c2e9abdd3a48cc"
	strings:
		$x1 = "1001=cmd.exe" fullword ascii 
		$x2 = "1003=ShellExecuteA" fullword ascii 
		$x3 = "1002=/c del /q %s" fullword ascii
		$x4 = "1004=SetThreadPriority" fullword ascii

		/* $s1 = "pnipcn.dllUT" fullword ascii
		$s2 = "ssonsvr.exeUT" fullword ascii
		$s3 = "navlu.dllUT" fullword ascii
		$s4 = "@CONOUT$" fullword wide 
		$s5 = "VPDN_LU.exeUT" fullword ascii
		$s6 = "msi.dll.urlUT" fullword ascii
		$s7 = "setup.exeUT" fullword ascii 
		$s8 = "pnipcn.dll.urlUT" fullword ascii
		$s9 = "ldvpreg.exeUT" fullword ascii */

		$op0 = { e8 71 11 00 00 83 c4 10 ff 4d e4 8b f0 78 07 8b } /* Opcode */
		$op1 = { e8 85 34 00 00 59 59 8b 86 b4 } /* Opcode */
		$op2 = { 8b 45 0c 83 38 00 0f 84 97 } /* Opcode */
		$op3 = { 8b 45 0c 83 38 00 0f 84 98 } /* Opcode */
		$op4 = { 89 7e 0c ff 15 a0 50 40 00 59 8b d8 6a 20 59 8d } /* Opcode */
		$op5 = { 56 8d 85 cd fc ff ff 53 50 88 9d cc fc ff ff e8 } /* Opcode */
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and all of ($x*) and 1 of ($op*)
}

rule HttpBrowser_RAT_Sample1 {
	meta:
		description = "Threat Group 3390 APT Sample - HttpBrowser RAT Sample update.hancominc.com"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 80
		hash1 = "be334d1f8fa65a723af65200a166c2bbdb06690c8b30fafe772600e4662fc68b"
		hash2 = "1052ad7f4d49542e4da07fa8ea59c15c40bc09a4d726fad023daafdf05866ebb"
	strings:
		$s0 = "update.hancominc.com" fullword wide 
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and $s0
}

rule HttpBrowser_RAT_Sample2 {
	meta:
		description = "Threat Group 3390 APT Sample - HttpBrowser RAT Sample"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 80
		hash1 = "c57c5a2c322af2835ae136b75283eaaeeaa6aa911340470182a9983ae47b8992"
	strings:
		$s0 = "nKERNEL32.DLL" fullword wide
		$s1 = "WUSER32.DLL" fullword wide
		$s2 = "mscoree.dll" fullword wide
		$s3 = "VPDN_LU.exeUT" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and all of them
}

rule HttpBrowser_RAT_Gen {
	meta:
		description = "Threat Group 3390 APT Sample - HttpBrowser RAT Generic"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 90
		hash1 = "0299493ccb175d452866f5e21d023d3e92cd8d28452517d1d19c0f05f2c5ca27"
		hash2 = "065d055a90da59b4bdc88b97e537d6489602cb5dc894c5c16aff94d05c09abc7"
		hash3 = "05c7291db880f94c675eea336ecd66338bd0b1d49ad239cc17f9df08106e6684"
		hash4 = "07133f291fe022cd14346cd1f0a649aa2704ec9ccadfab809ca9c48b91a7d81b"
		hash5 = "0f8893e87ddec3d98e39a57f7cd530c28e36d596ea0a1d9d1e993dc2cae0a64d"
		hash6 = "108e6633744da6efe773eb78bd0ac804920add81c3dde4b26e953056ac1b26c5"
		hash7 = "1052ad7f4d49542e4da07fa8ea59c15c40bc09a4d726fad023daafdf05866ebb"
		hash8 = "1277ede988438d4168bb5b135135dd3b9ae7d9badcdf1421132ca4692dd18386"
		hash9 = "19be90c152f7a174835fd05a0b6f722e29c648969579ed7587ae036679e66a7b"
		hash10 = "1e7133bf5a9fe5e462321aafc2b7770b8e4183a66c7fef14364a0c3f698a29af"
		hash11 = "2264e5e8fcbdcb29027798b200939ecd8d1d3ad1ef0aef2b8ce7687103a3c113"
		hash12 = "2a1bdeb0a021fb0bdbb328bd4b65167d1f954c871fc33359cb5ea472bad6e13e"
		hash13 = "259a2e0508832d0cf3f4f5d9e9e1adde17102d2804541a9587a9a4b6f6f86669"
		hash14 = "240d9ce148091e72d8f501dbfbc7963997d5c2e881b4da59a62975ddcbb77ca2"
		hash15 = "211a1b195cf2cc70a2caf8f1aafb8426eb0e4bae955e85266490b12b5322aa16"
		hash16 = "2d25c6868c16085c77c58829d538b8f3dbec67485f79a059f24e0dce1e804438"
		hash17 = "2d932d764dd9b91166361d8c023d64a4480b5b587a6087b0ce3d2ac92ead8a7d"
		hash18 = "3556722d9aa37beadfa6ba248a66576f767e04b09b239d3fb0479fa93e0ba3fd"
		hash19 = "365e1d4180e93d7b87ba28ce4369312cbae191151ac23ff4a35f45440cb9be48"
		hash20 = "36c49f18ce3c205152eef82887eb3070e9b111d35a42b534b2fb2ee535b543c0"
		hash21 = "3eeb1fd1f0d8ab33f34183893c7346ddbbf3c19b94ba3602d377fa2e84aaad81"
		hash22 = "3fa8d13b337671323e7fe8b882763ec29b6786c528fa37da773d95a057a69d9a"
	strings:
		$s0 = "%d|%s|%04d/%02d/%02d %02d:%02d:%02d|%ld|%d" fullword wide 
		$s1 = "HttpBrowser/1.0" fullword wide
		$s2 = "set cmd : %s" ascii fullword
		$s3 = "\\config.ini" wide fullword
	condition:
		uint16(0) == 0x5a4d and filesize < 45KB and filesize > 20KB and all of them
}

rule PlugX_NvSmartMax_Gen {
	meta:
		description = "Threat Group 3390 APT Sample - PlugX NvSmartMax Generic"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 70
		hash1 = "718fc72942b9b706488575c0296017971170463f6f40fa19b08fc84b79bf0cef"
		hash2 = "1c0379481d17fc80b3330f148f1b87ff613cfd2a6601d97920a0bcd808c718d0"
		hash3 = "555952aa5bcca4fa5ad5a7269fece99b1a04816d104ecd8aefabaa1435f65fa5"
		hash4 = "71f7a9da99b5e3c9520bc2cc73e520598d469be6539b3c243fb435fe02e44338"
		hash5 = "65bbf0bd8c6e1ccdb60cf646d7084e1452cb111d97d21d6e8117b1944f3dc71e"
	strings:
		$s0 = "NvSmartMax.dll" fullword ascii
		$s1 = "NvSmartMax.dll.url" fullword ascii
		$s2 = "Nv.exe" fullword ascii
		$s4 = "CryptProtectMemory failed" fullword ascii 
		$s5 = "CryptUnprotectMemory failed" fullword ascii 
		$s7 = "r%.*s(%d)%s" fullword wide
		$s8 = " %s CRC " fullword wide

		$op0 = { c6 05 26 49 42 00 01 eb 4a 8d 85 00 f8 ff ff 50 } /* Opcode */
		$op1 = { 8d 85 c8 fe ff ff 50 8d 45 c8 50 c6 45 47 00 e8 } /* Opcode */
		$op2 = { e8 e6 65 00 00 50 68 10 43 41 00 e8 56 84 00 00 } /* Opcode */
	condition:
		uint16(0) == 0x5a4d and filesize < 800KB and all of ($s*) and 1 of ($op*)
}

rule HttpBrowser_RAT_dropper_Gen2 {
	meta:
		description = "Threat Group 3390 APT Sample - HttpBrowser RAT Dropper"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 70
		hash1 = "c57c5a2c322af2835ae136b75283eaaeeaa6aa911340470182a9983ae47b8992"
		hash2 = "dfa984174268a9f364d856fd47cfaca75804640f849624d69d81fcaca2b57166"
	strings:
		$s1 = "navlu.dll.urlUT" fullword ascii
		$s2 = "VPDN_LU.exeUT" fullword ascii
		$s3 = "pnipcn.dllUT" fullword ascii
		$s4 = "\\ssonsvr.exe" fullword ascii
		$s5 = "/c del /q %s" fullword ascii
		$s6 = "\\setup.exe" fullword ascii 
		$s7 = "msi.dllUT" fullword ascii

		$op0 = { 8b 45 0c 83 38 00 0f 84 98 } /* Opcode */
		$op1 = { e8 dd 07 00 00 ff 35 d8 fb 40 00 8b 35 7c a0 40 } /* Opcode */
		$op2 = { 83 fb 08 75 2c 8b 0d f8 af 40 00 89 4d dc 8b 0d } /* Opcode */
		$op3 = { c7 43 18 8c 69 40 00 e9 da 01 00 00 83 7d f0 00 } /* Opcode */
		$op4 = { 6a 01 e9 7c f8 ff ff bf 1a 40 00 96 1b 40 00 01 } /* Opcode */
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and 3 of ($s*) and 1 of ($op*)
}

rule ThreatGroup3390_Strings {
	meta:
		description = "Threat Group 3390 APT - Strings"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 60
	strings:
		$s1 = "\"cmd\" /c cd /d \"c:\\Windows\\Temp\\\"&copy" ascii
		$s2 = "svchost.exe a -k -r -s -m5 -v1024000 -padmin-windows2014"
		$s3 = "ren *.rar *.zip" fullword ascii
		$s4 = "c:\\temp\\ipcan.exe" fullword ascii
		$s5 = "<%eval(Request.Item(\"admin-na-google123!@#" ascii
	condition:
		1 of them and filesize < 30KB
}

rule ThreatGroup3390_C2 {
	meta:
		description = "Threat Group 3390 APT - C2 Server"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 60
	strings:
		$s1 = "api.apigmail.com"
		$s2 = "apigmail.com"
		$s3 = "backup.darkhero.org"
		$s4 = "bel.updatawindows.com"
		$s5 = "binary.update-onlines.org"
		$s6 = "blackcmd.com"
		$s7 = "castle.blackcmd.com"
		$s8 = "ctcb.blackcmd.com"
		$s9 = "darkhero.org"
		$s10 = "dav.local-test.com"
		$s11 = "test.local-test.com"
		$s12 = "dev.local-test.com"
		$s13 = "ocean.local-test.com"
		$s14 = "ga.blackcmd.com"
		$s15 = "helpdesk.blackcmd.com"
		$s16 = "helpdesk.csc-na.com"
		$s17 = "helpdesk.hotmail-onlines.com"
		$s18 = "helpdesk.lnip.org"
		$s19 = "hotmail-onlines.com"
		$s20 = "jobs.hotmail-onlines.com"
		$s21 = "justufogame.com"
		$s22 = "lnip.org"
		$s23 = "local-test.com"
		$s24 = "login.hansoftupdate.com"
		$s25 = "long.update-onlines.org"
		$s26 = "longlong.update-onlines.org"
		$s27 = "longshadow.dyndns.org"
		$s28 = "longshadow.update-onlines.org"
		$s29 = "longykcai.update-onlines.org"
		$s30 = "lostself.update-onlines.org"
		$s31 = "mac.navydocument.com"
		$s32 = "mail.csc-na.com"
		$s33 = "mantech.updatawindows.com"
		$s34 = "micr0soft.org"
		$s35 = "microsoft-outlook.org"
		$s36 = "mtc.navydocument.com"
		$s37 = "navydocument.com"
		$s38 = "mtc.update-onlines.org"
		$s39 = "news.hotmail-onlines.com"
		$s40 = "oac.3322.org"
		$s41 = "ocean.apigmail.com"
		$s42 = "pchomeserver.com"
		$s43 = "registre.organiccrap.com"
		$s44 = "security.pomsys.org"
		$s45 = "services.darkhero.org"
		$s46 = "sgl.updatawindows.com"
		$s47 = "shadow.update-onlines.org"
		$s48 = "sonoco.blackcmd.com"
		$s49 = "test.logmastre.com"
		$s50 = "up.gtalklite.com"
		$s51 = "updatawindows.com"
		$s52 = "update-onlines.org"
		$s53 = "update.deepsoftupdate.com"
		$s54 = "update.hancominc.com"
		$s55 = "update.micr0soft.org"
		$s56 = "update.pchomeserver.com"
		$s57 = "urs.blackcmd.com"
		$s58 = "wang.darkhero.org"
		$s59 = "webs.local-test.com"
		$s60 = "word.apigmail.com"
		$s61 = "wordpress.blackcmd.com"
		$s62 = "working.blackcmd.com"
		$s63 = "working.darkhero.org"
		$s64 = "working.hotmail-onlines.com"
		$s65 = "www.trendmicro-update.org"
		$s66 = "www.update-onlines.org"
		$s67 = "x.apigmail.com"
		$s68 = "ykcai.update-onlines.org"
		$s69 = "ykcailostself.dyndns-free.com"
		$s70 = "ykcainobody.dyndns.org"
		$s71 = "zj.blackcmd.com"
		$s72 = "laxness-lab.com"
		$s73 = "google-ana1ytics.com"
		$s74 = "www.google-ana1ytics.com"
		$s75 = "ftp.google-ana1ytics.com"
		$s76 = "hotmailcontact.net"
		$s77 = "208.115.242.36"
		$s78 = "208.115.242.37"
		$s79 = "208.115.242.38"
		$s80 = "66.63.178.142"
		$s81 = "72.11.148.220"
		$s82 = "72.11.141.133"
		$s83 = "74.63.195.236"
		$s84 = "74.63.195.236"
		$s85 = "74.63.195.237"
		$s86 = "74.63.195.238"
		$s87 = "103.24.0.142"
		$s88 = "103.24.1.54"
		$s89 = "106.187.45.162"
		$s90 = "192.151.236.138"
		$s91 = "192.161.61.19"
		$s92 = "192.161.61.20"
		$s93 = "192.161.61.22"
		$s94 = "103.24.1.54"
		$s95 = "67.215.232.179"
		$s96 = "96.44.177.195"
		$s97 = "49.143.192.221"
		$s98 = "67.215.232.181"
		$s99 = "67.215.232.182"
		$s100 = "96.44.182.243"
		$s101 = "96.44.182.245"
		$s102 = "96.44.182.246"
		$s103 = "49.143.205.30"
		$s104 = "working_success@163.com"
		$s105 = "ykcaihyl@163.com"
		$s106 = "working_success@163.com"
		$s107 = "yuming@yinsibaohu.aliyun.com"
	condition:
		uint16(0) == 0x5a4d and 1 of them
}
