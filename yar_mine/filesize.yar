rule size_range
{
	condition:
		//filesize > 120831 and filesize < 574977
		// filesize < 1MB
		filesize == 176640 or 
		filesize == 182784 or 
		filesize == 152064 or 
		filesize == 176645 or 
		filesize == 187400 or 
		filesize == 571392 or 
		filesize == 331264 or 
		filesize == 193024 or 
		filesize == 123904 or 
		filesize == 157184 or 
		filesize == 574976 or 
		filesize == 182272 or 
		filesize == 240071 or 
		filesize == 202240 or 
		filesize == 120832 or 
		filesize == 543232 or 
		filesize == 440832 or 
		filesize == 181760 or 
		filesize == 122368 or 
		filesize == 461824 or 
		filesize == 252928 or 
		filesize == 373234 or
		filesize == 266752 or
		filesize == 131307
}