rule LuaJit_ExecuteLuaCode {
    meta:
        description = "Detects LuaJit executable file malware wrapped in an EXE file (basically luajit executes malware code in userdata.txt)"
        author = "techplayz32"
        date = "2025-02-23"

    strings:
        $a1 = "luajit" ascii nocase
        $a2 = "userdata" ascii
        $a3 = "lua51.dll" ascii

    condition:
        3 of ($a*)
}