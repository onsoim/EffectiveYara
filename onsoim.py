import yara
import os

def references():
	url1 = "https://yara.readthedocs.io/en/v3.4.0/writingrules.html"
	url2 = "https://malwology.com/2018/08/24/python-for-malware-analysis-getting-started/"
	url3 = "https://github.com/ctxis/CAPE/tree/master/data/yara/CAPE"

#folder = './sample/malware/'
#folder = './sample/nonMalware/visual_studio/'
#folder = './sample/nonMalware/cerbero/'
folder = './sample/nonMalware/sysinternals/'

rules = yara.compile(filepath='yar_mine/onsoim.yar')
filelist = os.listdir(folder)
malware = []
for filename in filelist:
	path_filename = folder + filename
	if os.path.isfile(path_filename):
		match = rules.match(path_filename)
		if match:
			#print match,
			#print match[0].rule,
			#print match[0].tags,
			#print match[0].strings
			#print path_filename
			malware.append(filename)
			#print match, path_filename
		else:
			print path_filename

print "[*] '%d' out of '%d'" %(len(malware), len(filelist))