import "pe"
import "math"

rule YAYRDR {
    meta:
        description = "Yet Another YARA Detector Rule"
        author = "techplayz32"
        date = "2025-02-23"
    strings:
        $a1 = "password" nocase
        $a2 = "credit card" nocase
        $a3 = "keylogger" nocase
        $a4 = "trojan" nocase
        $a5 = "stealer" nocase
        $a6 = "backdoor" nocase
        $a7 = "ransomware" nocase
        $a8 = "exploit" nocase
        $a9 = "shellcode" nocase
        $a10 = "inject" nocase
        $a11 = "hook" nocase
        $a12 = "dump" nocase
        $a13 = "credentials" nocase
        $a14 = "wallet" nocase
        $a15 = "private key" nocase
        $a16 = "os.system" nocase
        $a17 = "exec(b" nocase
        $a18 = "base64" nocase
        $a19 = "Bolonyokte" nocase
        $a20 = "blank.aes" nocase
        $a21 = "upx.exe" nocase
        $a22 = "api-ms-win-crt-runtime-|l1-1-.dll" nocase
        $a23 = "injection.js" nocase
        $a24 = "AES" nocase
        $a25 = "Crypto" nocase
        $a26 = "Cipher" nocase
        $a27 = "win32crypt" nocase
        $a28 = "decrypt" nocase
        $a29 = "pycryptodome" nocase
        $a30 = "WEBHOOK_URL" nocase
        $a31 = "WEBHOOK" nocase
        $a32 = "wallet" nocase
        $a33 = "extension" nocase
        $a34 = "User-Agent" nocase
        $a35 = "place your discord webhook here" nocase
        $a36 = "Pyarmor" nocase
        $a37 = "C2" nocase
        $a38 = "c2" nocase

        $b1 = "CreateRemoteThread"
        $b2 = "VirtualAllocEx"
        $b3 = "WriteProcessMemory"
        $b4 = "ReadProcessMemory"
        $b5 = "OpenProcess"
        $b6 = "QueueUserAPC"
        $b7 = "SetWindowsHookEx"
        $b8 = "InternetOpenA"
        $b9 = "HttpSendRequest"
        $b10 = "FtpPutFile"
        $b11 = "socket"
        $b12 = "connect"
        $b13 = "send"
        $b14 = "recv"
        $b15 = "CreateProcessW"
        $b16 = "regedit.exe"
        $b17 = "ShellExecuteA"
        $b18 = "nwcfg.exe"
        $b19 = "PROXYBYPASS"
        $b20 = "GetDriveTypeA"
        $b21 = "GetAsyncKeyState"
        $b22 = "schtasks.exe"
        $b23 = "ONLOGON"
        $b24 = "CPUID"
        $b25 = "blank.aes"
        $b26 = "SetUnhandledExceptionFilter"
        $b27 = "QueryPerformanceCounter"
        $b28 = "upx.exe"
        $b29 = "api-ms-win-crt-runtime-|l1-1-.dll"
        $b30 = "injection.js"
        $b31 = "GetModuleHandle"
        $b32 = "Process32First"
        $b33 = "Process32Next"
        $b34 = "AES"
        $b35 = "Crypto"
        $b36 = "Cipher"
        $b37 = "win32crypt"
        $b38 = "decrypt"
        $b39 = "RegDeleteKey"
        $b40 = "RegDeleteValue"
        $b41 = "SHGetKnownFolderPath"
        $b42 = "GetEnvironmentVariable"
        $b43 = "ShellExecute"
        $b44 = "RegCreateKeyA"
        $b45 = "RegSetValueExA"
        $b47 = "InternetConnectA"
        $b48 = "SetWindowsHookExA"
        $b49 = "NtAllocateVirtualMemory"
        $b50 = "CreateProcessA"
        $b51 = "GetProcAddress"
        $b52 = "VirtualAlloc"
        $b53 = "VirtualProtect"
        $b54 = "BlockInput" // common thingy as blocking user's input, in normal & safe apps, there ARE NO THINGS like this lol
        $b55 = "WEBHOOK_URL"
        $b56 = "WEBHOOK"
        $b57 = "SendMessageW"
        $b58 = "EnumWindows"
        $b59 = "User-Agent"
        $b60 = "place your discord webhook here"
        $b61 = "Pyarmor"
        $b62 = "C2"
        $a63 = "c2"
        // a

        // suspicious urls using direct IP addresses
        $c1 = /http:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
        // /http:\/\/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ 

        // signs of obfuscation
        $d1 = /(\\x[0-9a-fA-F]{2}){5,}/

        $e1 = /socket\.\w+\(\s*[\'"]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[\'"]\s*\)/  // e.g., socket.AF_INET("192.168.1.1")
        $e2 = /connect\(\s*[\'"]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[\'"]\s*,/      // e.g., connect("192.168.1.1", 80)
        $e3 = /httplib\.HTTPConnection\(\s*[\'"]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[\'"]\s*\)/  // e.g., httplib.HTTPConnection("192.168.1.1")
        $e4 = /urlopen\(\s*[\'"]http:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[\/]?[\'"]\s*\)/  // e.g., urlopen("http://192.168.1.1/")

        // ip addresses
        $f1 = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/ 

    condition:
        ( uint16(0) != 0x5A4D and (
            (any of ($a*) and any of ($b*)) or  // suspicious string + api call
            (any of ($a*) and $c1) or           // suspicious string + url
            (any of ($a*) and $d1) or           // suspicious string + obfuscation sign
            (any of ($b*) and $c1) or           // api call + url
            (any of ($b*) and $d1) or           // api call + obfuscation sign
            ($c1 and $d1) or                    // url + obfuscation sign
            (any of ($e*) or $f1)               // dynamic url construction or ip address
        ) ) or

        ( uint16(0) == 0x5A4D and (any of ($a*) or any of ($b*)) and (
            for any section in pe.sections: (
                (section.characteristics & 0x20000000) != 0 and  // IMAGE_SCN_MEM_EXECUTE
                (section.characteristics & 0x80000000) != 0      // IMAGE_SCN_MEM_WRITE
            ) or
            for any section in pe.sections: (
                math.entropy(section.raw_data_offset, section.raw_data_size) > 7.0 and
                section.raw_data_size > 1000
            )
        ) )
}