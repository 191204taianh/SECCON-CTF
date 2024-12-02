from Crypto.Util.number import long_to_bytes, inverse
from Crypto.Cipher import AES
import hashlib

# Challenge parameters
n = 105270965659728963158005445847489568338624133794432049687688451306125971661031124713900002127418051522303660944175125387034394970179832138699578691141567745433869339567075081508781037210053642143165403433797282755555668756795483577896703080883972479419729546081868838801222887486792028810888791562604036658927
e = 137
c1 = 16725879353360743225730316963034204726319861040005120594887234855326369831320755783193769090051590949825166249781272646922803585636193915974651774390260491016720214140633640783231543045598365485211028668510203305809438787364463227009966174262553328694926283315238194084123468757122106412580182773221207234679
encrypted_flag = b"\xdb'\x0bL\x0f\xca\x16\xf5\x17>\xad\xfc\xe2\x10$(DVsDS~\xd3v\xe2\x86T\xb1{xL\xe53s\x90\x14\xfd\xe7\xdb\xddf\x1fx\xa3\xfc3\xcb\xb5~\x01\x9c\x91w\xa6\x03\x80&\xdb\x19xu\xedh\xe4"

# Factorize n
p = 102983541345802420358593253933338267634707798193441860014014312778355157029241
q = 102241485755046381201180762007352228706219460951420745371703646325885170329069

# Compute private key
phi_n = (p - 1) * (q - 1)
d = inverse(e, phi_n)

# Decrypt c1 to get the key
key = long_to_bytes(pow(c1, d, n))

# Compute AES key
aes_key = hashlib.sha256(key).digest()

# Decrypt the flag using AES
cipher = AES.new(aes_key, AES.MODE_ECB)
decrypted_flag = cipher.decrypt(encrypted_flag)
print("Decrypted flag (raw):", decrypted_flag)

# XOR-based decryption
def xor_decrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

# Try XOR with all single-byte keys
print("\nTrying single-byte XOR keys...")
for i in range(256):
    result = xor_decrypt(decrypted_flag, bytes([i]))
    if b"SECCON{" in result:
        print(f"Key {i}: {result}")
        break

# Multi-byte XOR patterns (e.g., repeat guessed keys)
possible_keys = [b"SECCON"]  # Add potential patterns here
for key in possible_keys:
    result = xor_decrypt(decrypted_flag, key)
    if b"SECCON{" in result:
        print(f"Key {key}: {result}")
        break
