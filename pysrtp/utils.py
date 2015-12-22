"""
"""
import binascii
import struct
import sys


if sys.version < "3.2":
    import Crypto.Util.number
    int_to_bytes = Crypto.Util.number.long_to_bytes
    bytes_to_int = Crypto.Util.number.bytes_to_long
else:
    def int_to_bytes(i, n_bytes):
        return i.to_bytes(n_bytes, byteorder='big')

    def bytes_to_int(b):
        return int.from_bytes(b, byteorder='big')


def hexlify(s):
    n = 2
    s = binascii.hexlify(s)
    return (b' '.join([s[i:i+n] for i in range(
        0, len(s), n)])).decode('ascii')


def packet_index(roc, seq):
    return seq + (roc << 16)


def parse_rtp_header(rtp_header):
    ssrc = struct.unpack_from("!I", rtp_header, 8)[0]
    seq = struct.unpack_from("!H", rtp_header, 2)[0]

    extension_bit = 1 & (struct.unpack_from('!B', rtp_header, 0)[0] >> 4) == 1
    csrc_count = struct.unpack_from('!B', rtp_header, 0)[0] & 0x0f

    hlen = 12 + 4 * csrc_count
    if extension_bit:
        hlen += 4 + 4 * struct.unpack_from("!HH", rtp_header, hlen)[1]

    return type('RtpHeader_t', (object,), {
        'ssrc': ssrc,
        'seq': seq,
        'hlen': hlen})


def rtcp_ssrc(rtcp_header):
    return struct.unpack_from('!L', rtcp_header, 4)[0]


def parse_esrtcp_word(srtcp_header):
    packet_i = struct.unpack_from("!L", srtcp_header, 0)[0]
    encrypted = packet_i & (1 << 31) != 0
    packet_i = packet_i & ((1 << 31) - 1)
    return type('SrtcpHeader_t', (object,), {
        'encrypted': encrypted,
        'index': packet_i})
