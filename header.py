import yara
import os

folder = './sample/malware/'
#folder = './sample/nonMalware/visual_studio/'
#folder = './sample/nonMalware/cerbero/'
#folder = './sample/nonMalware/sysinternals/'

filelist = os.listdir(folder)
malware = []
for filename in filelist:
	path_filename = folder + filename
	if os.path.isfile(path_filename):
		with open(path_filename) as f:
			header = f.read(0x40)#.encode('hex')
			MZSignature = header[0x0:0x2]
			UsedBytesInTheLastPage = header[0x2:0x4]
			FileSizeInPages = header[0x4:2]
			NumberOfRelocationItems = header[0x6:0x8]
			HeaderSizeInParagraphs = header[0x8:0xa]
			MinimumExtraParagraphs = header[0xa:0xc]
			MaximumExtraParagraphs = header[0xc:0xe]
			InitialRelativeSS = header[0xe:0x10]
			InitialSP = header[0x10:0x12]
			Checksum = header[0x12:0x14]
			InitialIP = header[0x14:0x16]
			InitialRelativeCS = header[0x16:0x18]
			AddressOfRelocationTable = header[0x18:0x1a]
			OverlayNumber = header[0x1a:0x1c]
			Reserved = header[0x1c:0x24]
			OEMid = header[0x24:0x26]
			OEMinfo = header[0x26:0x28]
			Reserved2 = header[0x28:0x3c]
			AddressOfNewExeHeader = header[0x3c:0x40]

			# 7E6192BF4053D7522DEED05B2DC4E43F506511FA1B82C0CC83BFE63257B62C16 is an exception!
			"""
			if MZSignature != "MZ":
				print "MZSignature"
				print path_filename, MZSignature
			if UsedBytesInTheLastPage.encode('hex') != "9000":
				print "UsedBytesInTheLastPage"
				print path_filename, "/ 0000 =>", UsedBytesInTheLastPage.encode('hex')
#=>			if FileSizeInPages.encode('hex') != "0100":
#=>				print "FileSizeInPages"
#=>				print path_filename, FileSizeInPages.encode('hex')
			if NumberOfRelocationItems.encode('hex') != "0000":
				print "NumberOfRelocationItems"
				print path_filename, NumberOfRelocationItems.encode('hex')
			if HeaderSizeInParagraphs.encode('hex') != "0400":
				print "HeaderSizeInParagraphs"
				print path_filename, "/ 0400 =>", HeaderSizeInParagraphs.encode('hex')
			if MinimumExtraParagraphs.encode('hex') != "0000":
				print "MinimumExtraParagraphs"
				print path_filename, MinimumExtraParagraphs.encode('hex')
			if MaximumExtraParagraphs.encode('hex') != "ffff":
				print "MaximumExtraParagraphs"
				print path_filename, MaximumExtraParagraphs.encode('hex')
			if InitialRelativeSS.encode('hex') != "0000":
				print "InitialRelativeSS"
				print path_filename, InitialRelativeSS.encode('hex')
			if InitialSP.encode('hex') != "b800":
				print "InitialSP"
				print path_filename, InitialSP.encode('hex')
			if Checksum.encode('hex') != "0000":
				print "Checksum"
				print path_filename, Checksum.encode('hex')
			if InitialIP.encode('hex') != "0000":
				print "InitialIP"
				print path_filename, InitialIP.encode('hex')
			if InitialRelativeCS.encode('hex') != "0000":
				print "InitialRelativeCS"
				print path_filename, InitialRelativeCS.encode('hex')
			if AddressOfRelocationTable.encode('hex') != "4000":
				print "AddressOfRelocationTable"
				print path_filename, "/ 4000 =>", AddressOfRelocationTable.encode('hex')
			if OverlayNumber.encode('hex') != "0000":
				print "OverlayNumber"
				print path_filename, OverlayNumber.encode('hex')
			if Reserved.encode('hex') != "0000000000000000":
				print "Reserved"
				print path_filename, "/ 0000000000000000 =>", Reserved.encode('hex')
			if OEMid.encode('hex') != "0000":
				print "OEMid"
				print path_filename, "/ 0000 =>", OEMid.encode('hex')
			if OEMinfo.encode('hex') != "0000":
				print "OEMinfo"
				print path_filename, "/ 0000 =>", OEMinfo.encode('hex')
			if Reserved2.encode('hex') != "0000000000000000000000000000000000000000":
				print "Reserved2"
				print path_filename, "/ 0000000000000000000000000000000000000000 =>", Reserved2.encode('hex')
			"""
			#e_lfanew = AddressOfNewExeHeader.encode('hex')[4:8]
			if AddressOfNewExeHeader.encode('hex')[4:8] != "":
				print "AddressOfNewExeHeader"
				print path_filename, AddressOfNewExeHeader.encode('hex')#[4:8]
			