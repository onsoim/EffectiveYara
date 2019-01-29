import yara
import os
import re

folder = './sample/malware/'
#folder = './sample/nonMalware/visual_studio/'
#folder = './sample/nonMalware/cerbero/'
#folder = './sample/nonMalware/sysinternals/'

filelist = os.listdir(folder)
malware = []
xor = []
count = 0
for filename in filelist:
	path_filename = folder + filename
	if os.path.isfile(path_filename):
		with open(path_filename) as f:
			header = f.read(0x40)#.encode('hex')
			AddressOfNewExeHeader = header[0x3c:0x3e].encode('hex')
			stub_end = int(AddressOfNewExeHeader[2:4] + AddressOfNewExeHeader[0:2],16)
			stub = f.read(stub_end)#.encode('hex')
			rich = re.finditer('\x52\x69\x63\x68',stub)
			count += 1
			print count, path_filename,
			for i in rich:
				rich_index = int(i.start())# + 0x40
				print stub[i.start()+4:i.start()+8].encode('hex')
				xor.append(stub[i.start()+4:i.start()+8].encode('hex'))
			print '+' * 0x20
for key in list(set(xor)):
	print key