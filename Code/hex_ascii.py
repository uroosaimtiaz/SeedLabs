import binascii
import sys

def ascii_to_hex(hex_str):
    try:
        return binascii.hexlify(hex_str.encode("utf-8")).decode("ascii")
    except (UnicodeDecodeError, binascii.Error):
        return "The message could not be converted to hexadecimal."
    
def hex_to_ascii(hex_str):
    try:
        return binascii.unhexlify(hex_str).decode("ascii")
    except (UnicodeDecodeError, binascii.Error):
        return "The bytes do not represent valid ASCII characters."