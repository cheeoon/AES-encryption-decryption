import json
from base64 import b64decode, b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)


def read_string_as_bytes(filepath):
    try:
        with open(filepath, "r") as file:
            content = file.read().strip()  # Read and strip whitespace/newline
        return content.encode("utf-8")  # Convert to bytes
    except FileNotFoundError:
        print(f"Error: The file {filepath} does not exist.")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def encryptionCBC(filepath):
    data = read_string_as_bytes(filepath)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode("utf-8")
    ct = b64encode(ct_bytes).decode("utf-8")
    result = json.dumps({"iv": iv, "ciphertext": ct})
    print(result)
    return result


def decryptionCBC(encryptedResult):
    try:
        b64 = json.loads(encryptedResult)
        iv = b64decode(b64["iv"])
        ct = b64decode(b64["ciphertext"])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        print("The message was: ", pt)
        return pt
    except (ValueError, KeyError):
        print("Incorrect decryption")


def main():
    filepath = "Plaintext/1000words.txt"
    encryptedResult = encryptionCBC(filepath)
    decryptedResult = decryptionCBC(encryptedResult)
    finalOutcome = str(encryptedResult) + "\n" + str(decryptedResult)
    output_file = "finalOutcome.txt"
    try:
        with open(output_file, "w") as file:
            file.write(str(finalOutcome))  # Write the output as a string
        print(f"Result saved to '{output_file}' successfully.")
    except IOError:
        print(f"Error: Failed to write to '{output_file}'.")


if __name__ == "__main__":
    main()
