from functools import reduce


def cksum(data):
	return (256 - reduce(lambda x, y: x + y, data)) % 256

def hexdump(data, length=None, sep=':'):
    if length is not None:
        lines = ""
        for seq in range(0, len(data), 16):
            line = data[seq: seq + 16]
            lines += sep.join("{:02x}".format(c) for c in line) + "\n"
    else:
        lines = sep.join("{:02x}".format(c) for c in data)
    return lines
