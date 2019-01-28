rule GroupA // 126
{
    meta:
        author = "onsoim"
        description = "malware detection"
    strings:
        $AddressOfNewExeHeader = { f8 00 }
    condition:
        $AddressOfNewExeHeader at 0x3c
}

rule GroupB // 82
{
    meta:
        author = "onsoim"
        description = "malware detection"
    strings:
        $AddressOfNewExeHeader = { 08 01 }
    condition:
        $AddressOfNewExeHeader at 0x3c
}

rule GroupC // 47 => it could be nonmalware (cerbero)
{
    meta:
        author = "onsoim"
        description = "malware detection"
    strings:
        $AddressOfNewExeHeader = { 00 01 }
    condition:
        $AddressOfNewExeHeader at 0x3c
}

rule GroupD // 6 => it could be nonmalware (visual studio)
{
    meta:
        author = "onsoim"
        description = "malware detection"
    strings:
        $AddressOfNewExeHeader = { e0 00 }
    condition:
        $AddressOfNewExeHeader at 0x3c
}

rule GroupE // 4
{
    meta:
        author = "onsoim"
        description = "malware detection"
    strings:
        $AddressOfNewExeHeader = { e8 00 }
    condition:
        $AddressOfNewExeHeader at 0x3c
}

rule GroupF // 1
{
    meta:
        author = "onsoim"
        description = "malware detection"
    strings:
        $AddressOfNewExeHeader = { 40 00 }
    condition:
        $AddressOfNewExeHeader at 0x3c
}

rule GroupG // 1
{
    meta:
        author = "onsoim"
        description = "malware detection"
    strings:
        $AddressOfNewExeHeader = { f0 00 }
    condition:
        $AddressOfNewExeHeader at 0x3c
}