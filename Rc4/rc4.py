import sys
import random

def rc4_encrypt(data, key):
    S = list(range(256))
    j = 0
    out = []

    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(char ^ S[(S[i] + S[j]) % 256])

    return out

def generate_random_key(length):
    return [random.randint(0, 255) for _ in range(length)]

def format_c_array(name, array, per_line=8):
    print(f"unsigned char {name}[] = {{")
    for i, byte in enumerate(array):
        if i % per_line == 0:
            print("\t", end="")
        print(f"0x{byte:02X}, ", end="")
        if (i + 1) % per_line == 0:
            print("")
    print("\n};")

def main():
    if len(sys.argv) != 2:
        print("Use: python rc4.py <binary>")
        sys.exit(1)

    input_file = sys.argv[1]

    try:
        with open(input_file, "rb") as f:
            data = list(f.read())
    except FileNotFoundError:
        print(f"File '{input_file}' not found.")
        sys.exit(1)

    key_inner = generate_random_key(16)
    key_outer = generate_random_key(16)

    encrypted_inner = rc4_encrypt(data, key_inner)
    encrypted_outer = rc4_encrypt(encrypted_inner, key_outer)

    encrypted_payload_size = len(encrypted_outer)

    print("// Double encrypted payload (RC4)")
    format_c_array("shellcode", encrypted_outer)
    print("")
    format_c_array("KeyOuter", key_outer)
    print("")
    format_c_array("decryptionkey", key_inner)

    print(f"\n// Final encrypted payload size: {encrypted_payload_size} bytes")

if __name__ == "__main__":
    main()
