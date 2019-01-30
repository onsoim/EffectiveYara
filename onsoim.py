import yara
import os

folder = './sample/malware/'
#folder = './sample/nonMalware/visual_studio/'
#folder = './sample/nonMalware/cerbero/'
#folder = './sample/nonMalware/sysinternals/'

rules = yara.compile(filepath='yar_mine/onsoim.yar')
filelist = os.listdir(folder)
malware = []
for filename in filelist:
	path_filename = folder + filename
	if os.path.isfile(path_filename):
		match = rules.match(path_filename)
		print match#[0].strings
		for i in range(len(match)):
			if match[i].rule == "malware":
				malware.append(filename)
		if not match:
			print path_filename
			#print match,
			#print match[0].rule,
			#print match[0].tags,
			#print match[0].strings
			#print path_filename
			#print match, path_filename

print "[*] '%d' out of '%d'" %(len(malware), len(filelist))