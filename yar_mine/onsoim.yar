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
        description = "e_lfanew detection"
    strings:
        $e_lfanew0 = { ( 40 | e0 | e8 | f0 | f8 ) 00 }
        $e_lfanew1 = { ( 00 | 08 ) 01 }
    condition:
        // not for all of ($e_lfanew*): ($ at 0x3c )
        for 1 of ($e_lfanew*): ( $ at 0x3c )
}

rule rich
{
    meta:
        author = "onsoim"
        description = "rich header detection"
    strings:
        $rich = { 52 69 63 68 }
        $no_stub = { 40 00 }
        $key1 = { a9 e7 d4 6d }
        $key2 = { 35 b3 8a d4 }
        $key3 = { 2a b4 da 42 }
        $key4 = { 7a 82 00 97 }
        $key5 = { 96 71 d5 94 }
        $key6 = { fb 0f ab b8 }
        $key7 = { 18 18 83 8a }
        $key8 = { bc 84 08 41 }
        $key9 = { 2a b4 5a 42 }
        $key10 = { fd 0f ab 98 }
        $key11 = { fb 0f ab d8 }
        $key12 = { ab 38 fe d1 }
        $key13 = { 5e 87 97 1f }
        $key14 = { de 86 97 1f }
        $key15 = { a4 49 7f ba }
        $key16 = { 67 26 94 d2 }
        $key17 = { bf ba d8 b5 }
        $key18 = { 9a 7a 93 cd }
        $key19 = { 25 c8 d6 a5 }
        $key20 = { f6 8d a9 a4 }
        $key21 = { 39 38 3d 81 }    
    condition:
        ( $rich and any of ($key*) ) or ( $no_stub at 0x3c )
}

rule size_range
{
    meta:
        author = "onsoim"
        description = "specific the size of malware"
    condition:
        filesize > 120831 and filesize < 574977
}

rule malware
{
    meta:
        author = "onsoim"
        description = "malware detection"
    condition:
        rich
}
