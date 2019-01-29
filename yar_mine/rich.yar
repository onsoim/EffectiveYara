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
