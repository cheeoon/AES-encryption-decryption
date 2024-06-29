import json
from base64 import b64decode, b64encode
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import time


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


def encryptionCBC(key, filepath):
    data = read_string_as_bytes(filepath)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode("utf-8")
    ct = b64encode(ct_bytes).decode("utf-8")
    result = json.dumps({"iv": iv, "ciphertext": ct})
    print(result)
    return result


def decryptionCBC(key, encryptedResult):
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
    output_performance_time_file = "perfomanceTimeMeasure.txt"

    if os.path.exists(output_performance_time_file):
        # Delete the file
        os.remove(output_performance_time_file)
        print(f"File '{output_performance_time_file}' deleted.")
    else:
        print(f"File '{output_performance_time_file}' does not exist.")

    bytes_sizes = [16, 24, 32]
    filepaths = [
        "Plaintext/1000words.txt",
        "Plaintext/2000words.txt",
        "Plaintext/4000words.txt",
        "Plaintext/10000words.txt",
    ]

    for filepath in filepaths:
        for bytes_size in bytes_sizes:
            key = get_random_bytes(bytes_size)
            encryption_start_time = time.time()
            encryptedResult = encryptionCBC(key, filepath)
            encryption_end_time = time.time()
            decryption_start_time = time.time()
            decryptedResult = decryptionCBC(key, encryptedResult)
            decryption_end_time = time.time()
            encryptionTimeMessage = f"Time taken for Encryption: { encryption_end_time - encryption_start_time :.6f} seconds"
            decryptionTimeMessage = f"Time taken for Decryption: { decryption_end_time - decryption_start_time :.6f} seconds"

            finalOutcome = (
                str(encryptedResult) + "\n" + str(decryptedResult) + "\n"
                f"{encryptionTimeMessage}\n"
                f"{decryptionTimeMessage}"
            )

            filename = filepath.split("/")[-1]
            filename = filename.replace(".txt", "")
            output_file = "finalOutcome" + f"{filename}" + f"{bytes_size}" + ".txt"
            finalPerformanceTimeReport = (
                f"{filename}"
                + f"{bytes_size}"
                + "\n"
                + "Time taken for Encryption:\n"
                + f"{encryption_end_time - encryption_start_time :.6f}\n"
                + "Time taken for Decryption:\n"
                + f"{decryption_end_time - decryption_start_time :.6f}\n\n"
            )
            try:
                with open(output_file, "w") as file:
                    file.write(str(finalOutcome))  # Write the output as a string
                print(f"Result saved to '{output_file}' successfully.")
            except IOError:
                print(f"Error: Failed to write to '{output_file}'.")

            try:
                with open(output_performance_time_file, "a") as file:
                    file.write(
                        str(finalPerformanceTimeReport)
                    )  # Write the output as a string
                print(f"Result saved to '{output_performance_time_file}' successfully.")
            except IOError:
                print(f"Error: Failed to write to '{output_file}'.")


if __name__ == "__main__":
    main()
