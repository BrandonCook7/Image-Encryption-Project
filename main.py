from aes import *
from utils import select_data_all, select_data_file, select_data_jpeg

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
    aes = AES()
    #aes.encrypt_aes("message_file", "output.txt", "brandon")
    aes.encrypt_aes("random_image.jpg", "image_e.jpg", "brandon")
    aes.decyrpt_aes("image_e.jpg", "decrypted_image.jpg", "brandon")
    #menu()

def menu():
    print("AES Image Encryptor")
    choice = -1
    in_menu = True
    while in_menu:
        while(choice < 0 or choice > 2):
            print("Encrypt File (1)")
            print("Decrypt File (2)")
            print("Quit (0)")
            choice = int(input())
        if choice == 0:
            break
        elif choice == 1:
            input_filename = select_data_all("Select file to encrypt")
            if input_filename[len(input_filename)-3:] == "jpg" or input_filename[len(input_filename)-4:] == "jpeg":
                output_filename = select_data_jpeg("Choose location to write encrypted image")
            else:
                output_filename = select_data_file("Choose location to write encrypted file")
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
            output_filename = select_data_all("Select file to decrypt")
            if output_filename[len(output_filename)-3:] == "jpg" or output_filename[len(output_filename)-4:] == "jpeg":
                output_filename = select_data_jpeg("Choose location to write decrypted image")
            else:
                output_filename = select_data_file("Choose location to write decrypted file")
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
