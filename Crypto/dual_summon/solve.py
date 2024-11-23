from pwn import remote
from time import sleep

def collect_tags(conn, number, plaintext):
    """
    Collects the AES-GCM tag for a given plaintext using a specified key (1 or 2).
    """
    try:
        print(conn.recvuntil(b"[1] summon, [2] dual summon >").decode())  # Log the prompt
        conn.sendline(b"1")  # Choose summon mode
        print(conn.recvuntil(b"summon number (1 or 2) >").decode())  # Log the prompt
        conn.sendline(str(number).encode())  # Specify key number
        print(conn.recvuntil(b"name of sacrifice (hex) >").decode())  # Log the prompt
        conn.sendline(plaintext.hex().encode())  # Send the plaintext as hex
        conn.recvuntil(b"tag(hex) = ")  # Wait for the tag response
        tag = conn.recvline().strip().decode()
        print(f"Collected tag: {tag}")  # Log collected tag
        return tag
    except EOFError:
        print("Connection closed while collecting tags.")
        return None

def exploit():
    """
    Exploits the `dual_summon` functionality by finding a plaintext
    that produces matching tags for both keys, allowing flag retrieval.
    """
    # Connect to the challenge server
    conn = remote("dual-summon.seccon.games", 2222)
    print(conn.recvline().decode())  # Log initial server message

    # Step 1: Collect tags for a range of plaintext inputs
    plaintexts = [bytes([i] * 16) for i in range(256)]  # Generate test 16-byte plaintexts
    tags_key1 = {}
    tags_key2 = {}

    matching_pt = None

    for pt in plaintexts:
        print(f"Trying plaintext: {pt.hex()}")
        tag1 = collect_tags(conn, 1, pt)  # Key 1
        if tag1 is None:
            break  # Stop if connection is closed
        tag2 = collect_tags(conn, 2, pt)  # Key 2
        if tag2 is None:
            break  # Stop if connection is closed

        tags_key1[tag1] = pt
        tags_key2[tag2] = pt

        # Check for a collision
        if tag1 in tags_key2:
            matching_pt = tags_key2[tag1]
            print(f"Matching tag found with plaintext: {matching_pt.hex()}")
            break
        if tag2 in tags_key1:
            matching_pt = tags_key1[tag2]
            print(f"Matching tag found with plaintext: {matching_pt.hex()}")
            break

    if matching_pt is None:
        print("No matching tags found. Exiting...")
        return

    # Step 2: Use the matching plaintext for dual_summon
    try:
        conn.sendlineafter(b">", b"2")  # Choose dual_summon mode
        conn.sendlineafter(b">", matching_pt.hex().encode())  # Send the matching plaintext
        print("Attempting dual_summon...")
        response = conn.recvline().decode()  # Capture the server response
        print(response)  # Print response (should contain the flag)
        conn.interactive()  # Keep the connection open for interaction
    except EOFError:
        print("Connection closed while attempting dual_summon.")
        return

# Run the exploit
if __name__ == "__main__":
    exploit()
