# Raw bytes sequence
data = b"\x16v\x1aA\x88\x10\xf5\x82hfk\xfax&\xc9\xa2cg\xc5i\xa1\xbf\x8e\xad\xd1\x15\x88\xb4\x1a\xb9|\x82*\xeehf\xe1@\x82#\rR\xee\xb1\xa8\x1d+\xce?\x88\xdb@\x8f{\x8cX\x83\xa8\xeb\xc0gn\x84<"

# Attempt decoding as UTF-8
try:
    print("Decoded as UTF-8:", data.decode("utf-8"))
except UnicodeDecodeError:
    print("Cannot decode as UTF-8.")

# Attempt decoding as ASCII
try:
    print("Decoded as ASCII:", data.decode("ascii"))
except UnicodeDecodeError:
    print("Cannot decode as ASCII.")

# Print as hex for inspection
print("Hex representation:", data.hex())

# Print as Base64
import base64
print("Base64 representation:", base64.b64encode(data).decode())
