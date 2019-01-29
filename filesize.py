import yara
import os

folder = './sample/malware/'
#folder = './sample/nonMalware/visual_studio/'
#folder = './sample/nonMalware/cerbero/'
#folder = './sample/nonMalware/sysinternals/'

filelist = os.listdir(folder)
filesize = []
for filename in filelist:
	path_filename = folder + filename
	if os.path.isfile(path_filename):
		with open(path_filename) as f:
			data = f.read()
			filesize.append(len(data))
print list(set(filesize))

# 120832 , 574976