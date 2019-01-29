rule malware
{
	condition:
		filesize > 120831 and filesize < 574977
		// filesize < 1MB
}