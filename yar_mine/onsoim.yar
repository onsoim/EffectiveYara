/*
rule test
{
    meta:
        author = "kevoreilly"
        description = "Gandcrab Payload"
        cape_type = "Gandcrab Payload"
    strings:
        $string0 = "MZ"
        $string1 = "GDCB-DECRYPT.txt" wide
        $string2 = "GandCrabGandCrabnomoreransom.coinomoreransom.bit"
        $string3 = "action=result&e_files=%d&e_size=%I64u&e_time=%d&" wide
        $string4 = "KRAB-DECRYPT.txt" wide
    condition:
        uint16(0) == 0x5A4D and any of ($string*)
}
*/

rule e_lfanew
{
    meta:
        author = "onsoim"
        description = "malware detection"
    strings:
        $e_lfanew0 = { ( 40 | e0 | e8 | f0 | f8 ) 00 }
        $e_lfanew1 = { ( 00 | 08 ) 01 }
    condition:
        // not for all of ($e_lfanew*): ($ at 0x3c )
        for 1 of ($e_lfanew*): ($ at 0x3c )
}


