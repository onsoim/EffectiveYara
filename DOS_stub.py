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
			AddressOfNewExeHeader = header[0x3c:0x3e].encode('hex')
			stub_end = int(AddressOfNewExeHeader[2:4] + AddressOfNewExeHeader[0:2],16)
			stub = f.read(stub_end)#.encode('hex')
			print stub
			print '+' * 0x20
			