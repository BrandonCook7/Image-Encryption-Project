from aes import *

def main():
    print("Hello World!")
    #aes = AES("password12345678", "The brita is ove")
    #aes = AES("password12345678", "passwordpassword")
    aes = AES("Thats my Kung Fu", "Two One Nine Two")
    #aes =  AES("0000000000000000", "dsadsads")
    #aes = AES("pa")
    #aes = AES("A quick brown fox jumps over dog")
    #aes = AES("A quick brown fox jumps over dogs")
    #aes = AES("brandonmadethis", "A quick brown fox jumps over dog, testing")
    aes.encrypt_aes()
    #aes.convert_key()
    #aes.pad_hex()

if __name__ == "__main__":
    main()
