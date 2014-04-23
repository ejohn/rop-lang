import struct
import sys


if len(sys.argv) != 2:
	print sys.argv[0] + " [filename]"

else:

	op_file = open(sys.argv[1], 'rb')
	content = op_file.read()


	while(content):

		chunk = struct.unpack('<I', content[:4])
		print chunk[0], 

		content = content[4:]


