import sys

with open(sys.argv[1], 'rb') as f:
	data = f.read()

with open('sc.bin', 'wb') as f:
	f.write(data[data.find(b'magic1')+6:data.find(b'magic2')])
	
