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
        //( 1 of ($e_lfanew*) ) in (0..0x40)
}

rule rich
{
    meta:
        author = "onsoim"
        description = "rich header detection"
    strings:
        $rich = { 52 69 63 68 }
        $key1 = { 18 18 83 8a }
        $key2 = { 25 c8 d6 a5 }
        $key3 = { 2a b4 ( 5a | da ) 42 }
        $key4 = { 35 b3 8a d4 }
        $key5 = { 39 38 3d 81 }
        $key6 = { ( 5e 87 | de 86 ) 97 1f }
        $key7 = { 67 26 94 d2 }
        $key8 = { 7a 82 00 97 }
        $key9 = { 96 71 d5 94 }
        $key10 = { 9a 7a 93 cd }
        $key11 = { a4 49 7f ba }
        $key12 = { a9 e7 d4 6d }
        $key13 = { ab 38 fe d1 }
        $key14 = { bc 84 08 41 }
        $key15 = { bf ba d8 b5 }
        $key16 = { f6 8d a9 a4 }
        $key17 = { fb 0f ab ( b8 | d8 ) }
        $key18 = { fd 0f ab 98 }

        $no_stub = { 40 00 }
     condition:
        ( $rich and any of ($key*) ) or ( $no_stub at 0x3c )
}

rule size_range
{
    meta:
        author = "onsoim"
        description = "specific the size of malware"
    condition:
        // filesize > 120831 and filesize < 574977
        filesize == 120832 or 
        filesize == 122368 or 
        filesize == 123904 or 
        filesize == 131307 or
        filesize == 152064 or 
        filesize == 157184 or 
        filesize == 176640 or 
        filesize == 176645 or 
        filesize == 181760 or 
        filesize == 182272 or 
        filesize == 182784 or 
        filesize == 187400 or 
        filesize == 193024 or 
        filesize == 202240 or 
        filesize == 240071 or 
        filesize == 252928 or 
        filesize == 266752 or
        filesize == 331264 or 
        filesize == 373234 or
        filesize == 440832 or 
        filesize == 461824 or 
        filesize == 543232 or 
        filesize == 571392 or 
        filesize == 574976
}

rule malware
{
    meta:
        author = "onsoim"
        description = "malware detection"
    condition:
        rich and ( e_lfanew and size_range )
}