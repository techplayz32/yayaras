import "pe"

rule ApiCallDetector {
    meta:
        description = "Detects if any API calls were made to kernel32"
        author = "techplayz32"
        date = "2025-02-23"
    condition:
        pe.imports("kernel32.dll", "CreateProcessA") or
        pe.imports("kernel32.dll", "CreateProcessW") or
        pe.imports("kernel32.dll", "WriteFile") or
        pe.imports("kernel32.dll", "ReadFile") or
        pe.imports("advapi32.dll", "RegCreateKeyA") or
        pe.imports("advapi32.dll", "RegSetValueExA") or
        pe.imports("wininet.dll", "InternetOpenA") or
        pe.imports("wininet.dll", "InternetConnectA") or
        pe.imports("user32.dll", "SetWindowsHookExA") or
        pe.imports("ntdll.dll", "NtAllocateVirtualMemory")
}