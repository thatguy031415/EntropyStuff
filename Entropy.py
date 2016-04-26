import sys
import math


if len(sys.argv) != 2:
    print "Usage: file_entropy.py [path]filename"
    sys.exit()

# read the whole file into a byte array
f = open(sys.argv[1], "rb")
byteArr = map(ord, f.read())
f.close()
fileSize = len(byteArr)

'''Don't run for files over 500k; Above this size, entropy becomes less reliable as an indicator.'''
if fileSize >= 512000:
    print "Maximum filesize exceeded.  Entropy is not a reliable indicator on files above 500kb."
    sys.exit()

# calculate the frequency of each byte value in the file
freqList = []
for b in range(256):
    ctr = 0
    for byte in byteArr:
        if byte == b:
            ctr += 1
    freqList.append(float(ctr) / fileSize)
#print freqList #used only for testing and debugging of freqList

# Shannon entropy
ent = 0.0
for freq in freqList:
    if freq > 0:
        ent = ent + freq * math.log(freq, 2)
ent = -ent
print 'Shannon entropy (min bits per byte-character):'
print ent
if ent >= 6.5:
	print "File is likely packed or crypted."
else:
	print "File is likely not packed or crypted."