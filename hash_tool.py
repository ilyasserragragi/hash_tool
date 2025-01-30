import hashlib
from Crypto.Hash import MD2, MD4, MD5, SHA1, SHA256, SHA512, RIPEMD160 
import os
import zlib  
import bcrypt  
 
 

def encode_md2():
    source = input('Enter the value you want to encode: ').encode()
    md2_hash = MD2.new(source).hexdigest()
    print(f"MD2: {md2_hash}")

def encode_md4():
    source = input('Enter the value you want to encode: ').encode()
    md4_hash = MD4.new(source).hexdigest()
    print(f"MD4: {md4_hash}")

def encode_md5():
    source = input('Enter the value you want to encode: ').encode()
    md5 = hashlib.md5(source).hexdigest()
    print(f"MD5: {md5}")

def encode_md5_md5_hex():
    source = input('Enter the value you want to encode: ').encode()
    md5_hex = hashlib.md5(source).hexdigest()
    md5_md5_hex = hashlib.md5(md5_hex.encode()).hexdigest()
    print(f"MD5(MD5_HEX): {md5_md5_hex}")

def encode_md5_half():
    source = input('Enter the value you want to encode: ').encode()
    md5 = hashlib.md5(source).hexdigest()
    md5_half = md5[:16]  
    print(f"MD5-Half: {md5_half}")

def encode_sha1():
    source = input('Enter the value you want to encode: ').encode()
    sha1 = hashlib.sha1(source).hexdigest()
    print(f"SHA1: {sha1}")

def encode_sha224():
    source = input('Enter the value you want to encode: ').encode()
    sha224 = hashlib.sha224(source).hexdigest()
    print(f"SHA224: {sha224}")

def encode_sha256():
    source = input('Enter the value you want to encode: ').encode()
    sha256 = hashlib.sha256(source).hexdigest()
    print(f"SHA256: {sha256}")

def encode_sha384():
    source = input('Enter the value you want to encode: ').encode()
    sha384 = hashlib.sha384(source).hexdigest()
    print(f"SHA384: {sha384}")

def encode_sha512():
    source = input('Enter the value you want to encode: ').encode()
    sha512 = hashlib.sha512(source).hexdigest()
    print(f"SHA512: {sha512}")

def encode_ripemd160():
    source = input('Enter the value you want to encode: ').encode()
    ripemd160 = hashlib.new('ripemd160', source).hexdigest()
    print(f"RIPEMD160: {ripemd160}")

def encode_mysql_sha1_sha1_bin():
    source = input('Enter the value you want to encode: ').encode()
    sha1_bin = hashlib.sha1(source).digest()  
    mysql_hash = hashlib.sha1(sha1_bin).hexdigest()
    print(f"MySQL 4.1+ (SHA1(SHA1_BIN)): {mysql_hash}")

def encode_blake2s():
    source = input('Enter the value you want to encode: ').encode()
    blake2s_hash = hashlib.blake2s(source).hexdigest()
    print(f"BLAKE2s: {blake2s_hash}")

def encode_blake2b():
    source = input('Enter the value you want to encode: ').encode()
    blake2b_hash = hashlib.blake2b(source).hexdigest()
    print(f"BLAKE2b: {blake2b_hash}")

def encode_crc32():
    source = input('Enter the value you want to encode: ').encode()
    crc32_hash = f"{zlib.crc32(source):08x}"  
    print(f"CRC32: {crc32_hash}")

def encode_bcrypt():
    source = input('Enter the value you want to encode: ').encode()
    salt = bcrypt.gensalt()  
    bcrypt_hash = bcrypt.hashpw(source, salt)
    print(f"bcrypt: {bcrypt_hash.decode()}")




def decode_hash(target_hash, wordlist):
    if not os.path.exists(wordlist):
        print("Error: Wordlist file not found!")
        return None, None

    algorithms = [
        "md2", "md4", "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
        "ripemd160", "mysql_sha1_sha1_bin", "blake2s", "blake2b", "crc32"
    ]

    with open(wordlist, 'r', encoding='latin-1') as file:
        for line in file:
            word = line.strip()
            if not word:  
                continue

            
            md5_hex = hashlib.md5(word.encode()).hexdigest()
            md5_md5_hex = hashlib.md5(md5_hex.encode()).hexdigest()
            if md5_md5_hex == target_hash:
                return word, "MD5(MD5_HEX)"

            md5 = hashlib.md5(word.encode()).hexdigest()
            md5_half = md5[:16]
            if md5_half == target_hash:
                return word, "MD5-Half"

           
            sha1_bin = hashlib.sha1(word.encode()).digest()  
            mysql_hash = hashlib.sha1(sha1_bin).hexdigest()
            if mysql_hash == target_hash:
                return word, "MySQL 4.1+ (SHA1(SHA1_BIN))"

           
            for algo in algorithms:
                try:
                    if algo == "md2":
                        md2_hash = MD2.new(word.encode()).hexdigest()
                        if md2_hash == target_hash:
                            return word, "MD2"
                    elif algo == "md4":
                        md4_hash = MD4.new(word.encode()).hexdigest()
                        if md4_hash == target_hash:
                            return word, "MD4"
                    elif algo == "crc32":
                        crc32_hash = f"{zlib.crc32(word.encode()):08x}"
                        if crc32_hash == target_hash:
                            return word, "CRC32"
                    else:
                        hasher = hashlib.new(algo, word.encode())
                        hashed_word = hasher.hexdigest()
                        if hashed_word == target_hash:
                            return word, algo.upper()
                except ValueError:
                    continue
    return None, None

def decode_string():
    target_hash = input("Enter the hash value you want to decode: ").strip().lower()
    wordlist = input("Enter the path to the wordlist file (default : rockyou.txt) : ").strip()
    print("Decoding... Please wait...")
    result, hash_type = decode_hash(target_hash, wordlist)
    if result:
        print(f"\nDecoded string: {result}")
        print(f"Hash type: {hash_type}")
    else:
        print("No matching word found in the wordlist!")





def main():
    print(" Hashing and Decoding Program by iliass errajraji !")
    while True:
        print("\nSelect an option:")
        print("1: Encode")
        print("2: Decode")
        print("3: Exit")
        choice = input("Enter your choice (1, 2, or 3): ").strip()

        if choice == "1":
            print("\nSelect a hash algorithm:")
            print("1: MD2")
            print("2: MD4")
            print("3: MD5")
            print("4: MD5(MD5_HEX)")
            print("5: MD5-Half")
            print("6: SHA1")
            print("7: SHA224")
            print("8: SHA256")
            print("9: SHA384")
            print("10: SHA512")
            print("11: RIPEMD160")
            print("12: MySQL 4.1+ (SHA1(SHA1_BIN))")
            print("13: BLAKE2s")
            print("14: BLAKE2b")
            print("15: CRC32")
            print("16: bcrypt")
            algo_choice = input("Enter your choice (1-16): ").strip()

            if algo_choice == "1":
                encode_md2()
            elif algo_choice == "2":
                encode_md4()
            elif algo_choice == "3":
                encode_md5()
            elif algo_choice == "4":
                encode_md5_md5_hex()
            elif algo_choice == "5":
                encode_md5_half()
            elif algo_choice == "6":
                encode_sha1()
            elif algo_choice == "7":
                encode_sha224()
            elif algo_choice == "8":
                encode_sha256()
            elif algo_choice == "9":
                encode_sha384()
            elif algo_choice == "10":
                encode_sha512()
            elif algo_choice == "11":
                encode_ripemd160()
            elif algo_choice == "12":
                encode_mysql_sha1_sha1_bin()
            elif algo_choice == "13":
                encode_blake2s()
            elif algo_choice == "14":
                encode_blake2b()
            elif algo_choice == "15":
                encode_crc32()
            elif algo_choice == "16":
                encode_bcrypt()
            else:
                print("Invalid choice!")

        elif choice == "2":
            decode_string()

        elif choice == "3":
            print("Thank you for using the program. Goodbye!")
            input("Press Enter to exit...")  
            break

        else:
            print("Invalid choice! Please try again.")

if __name__ == "__main__":
    main()
