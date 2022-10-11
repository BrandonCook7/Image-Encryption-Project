from aes import *

def main():
    print("Hello World!")
    #aes = AES("password12345678")
    #aes = AES("A quick brown fox jumps over dog")
    #aes = AES("A quick brown fox jumps over dogs")
    aes = AES("A quick brown fox jumps over dog, testing")
    aes.encrypt_aes()
    #aes.convert_key()
    #aes.pad_hex()

if __name__ == "__main__":
    main()
