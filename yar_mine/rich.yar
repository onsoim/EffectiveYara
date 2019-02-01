rule rich
{
    meta:
        author = "onsoim"
        description = "rich header detection"
    strings:
        $rich = { 52 69 63 68 }        
        $key1 = { 5e 87 97 1f }     // 276  => 74
        $key2 = { de 86 97 1f }     // 208  => 52
        $key3 = { fb 0f ab b8 }     // 176  => 44
        $key4 = { fb 0f ab d8 }     // 124  => 31
        $key5 = { fd 0f ab 98 }     // 120  => 30
        $key6 = { 18 18 83 8a }     // 60   => 15
        $key7 = { 67 26 94 d2 }     // 24   => 6
        $key8 = { a4 49 7f ba }     // 20   => 5
        $key9 = { 2a b4 da 42 }     // 8    => 2
        $key10 = { a9 e7 d4 6d }    // 4	=> 1
        $key11 = { 35 b3 8a d4 }	// 4	=> 1
        $key12 = { 7a 82 00 97 }	// 4	=> 1
        $key13 = { 96 71 d5 94 }	// 4	=> 1
        $key14 = { bc 84 08 41 }	// 4	=> 1
        $key15 = { 2a b4 5a 42 }	// 4	=> 1
        $key16 = { ab 38 fe d1 }	// 4	=> 1
        $key17 = { bf ba d8 b5 }	// 4	=> 1
        $key18 = { 9a 7a 93 cd }	// 4	=> 1
        $key19 = { 25 c8 d6 a5 }	// 4	=> 1
        $key20 = { f6 8d a9 a4 }	// 4	=> 1
        $key21 = { 39 38 3d 81 }	// 4	=> 1

        $no_stub = { 40 00 }
    condition:
        ( $rich and any of ($key*) ) or ( $no_stub at 0x3c )
}
