from aes import *
from utils import select_file_encrypted, select_file_decrypted

def main():
    print("Hello World!")
    #aes = AES("password12345678", "The brita is ove")
    #aes = AES("password12345678", "passwordpassword")
    #aes = AES("Thats my Kung Fu", "Two One Nine Two")
    #aes =  AES("0000000000000000", "dsadsads")
    #aes = AES("pa")
    #aes = AES("A quick brown fox jumps over dog")
    #aes = AES("A quick brown fox jumps over dogs")
    #aes = AES("brandonmadethis", "A quick brown fox jumps over dog, testing")
    #aes.encrypt_aes()
    #aes.decyrpt_aes()
    #aes.convert_key()
    #aes.pad_hex()
    menu()

def menu():
    print("AES Image Encryptor")
    choice = -1
    in_menu = True
    while in_menu:
        while(choice < 0 or choice > 2):
            print("Encrypt Text (1)")
            print("Decrypt Text (2)")
            print("Quit (0)")
            choice = int(input())
        if choice == 0:
            break
        elif choice == 1:
            input_filename = select_file_encrypted("Select file to encrypt")
            output_filename = select_file_decrypted("Choose location to write encrypted file")
            # message = input("Enter message to encrypt: ")
            password = input("Enter password to encrypt message: ")
            password2 = input("Enter password again: ")
            if password == password2:
                aes = AES()
                aes.encrypt_aes(input_filename, output_filename, password)
                print("Encrypted message is stored in " + output_filename)
            else:
                print("Passwords do not match")
                break
            choice = -1
        elif choice == 2:
            #input("What file do you want to decrypt? ")
            input_filename = select_file_encrypted("Select file to decrypt")
            output_filename = select_file_decrypted("Choose location to write decrypted file")
            password = input("Enter password of encrypted message: ")
            password2 = input("Enter password again: ")
            if password == password2:
                aes = AES()
                aes.decyrpt_aes(input_filename, output_filename, password)
            else:
                print("Passwords do not match")
                break
            choice = -1

    


if __name__ == "__main__":
    main()
