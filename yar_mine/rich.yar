rule rich
{
    meta:
        author = "onsoim"
        description = "rich header detection"
    strings:
        $rich = { 52 69 63 68 }
        $no_stub = { 40 00 }
    condition:
        $rich or $no_stub at 0x3c
}
