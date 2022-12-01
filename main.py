from aes import *
from utils import *#select_data_all, select_data_file, select_data_jpeg, select_data_ppm, select_save_location

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
    #aes.convert_base64_to_jpeg("random_image.jpg", "image_d.jpg")
    #aes.encrypt_aes("message_file", "output.txt", "brandon")
    #aes.encrypt_aes("bear_image.jpg", "image_l.jpg", "brandon")
    #aes.decyrpt_aes("image_l.jpg", "decrypted_image.jpg", "brandon")
    #aes.encrypt_aes("random_image.jpg", "image_e.jpg", "brandon")
    #aes.decyrpt_aes("image_e.jpg", "decrypted_image.jpg", "brandon")
    # aes.encrypt_aes("100_image.jpg", "image_q.ppm", "idk")
    # aes.decyrpt_aes("temp/image_q.ppm", "final_image.jpg", "idk")
    #aes.encrypt_aes("bear_image.jpg", "image_e_test.ppm", "idk")
    #aes.decyrpt_aes("temp/image_e_test.ppm", "image_fully_done.jpg", "idk")
    #aes.encrypt_aes("jake_image.jpg", "jake_encyrpted.ppm", "brandon-wazzu01")
    #aes.decyrpt_aes("jake_encyrpted.ppm", "jake_decyrpted.jpg", "brandon-wazzu01")
    menu()

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
            if input_filename == "":
                break
            elif input_filename[len(input_filename)-3:] == "jpg" or input_filename[len(input_filename)-4:] == "jpeg":
                #output_filename = select_data_ppm("Choose location to write encrypted image", input_filename[:-4] + "_encyrpt.ppm")
                output_location = select_save_location("Choose location to write encrypted image");
                file_name = utils.find_file_name(input_filename)
                output_filename = output_location + "/" + file_name[:-4] + "-encyrpted.ppm"

                fp = open(output_filename, 'x')
                fp.close()
            else:
                output_filename = select_data_file("Choose location to write encrypted file")
            # message = input("Enter message to encrypt: ")
            if output_filename == "":
                break
            password = input("Enter password to encrypt message: ")
            password2 = input("Enter password again: ")
            if password == password2:
                aes = AES()
                aes.encrypt_aes(input_filename, output_filename, password)
                print("Encrypted file is stored in " + output_filename)
            else:
                print("Passwords do not match")
                break
            choice = -1
        elif choice == 2:
            input_filename = select_data_all("Select file to decrypt")
            if input_filename == "":
                break
            elif input_filename[len(input_filename)-3:] == "ppm":
                #output_filename = select_data_jpeg("Choose location to write decrypted image")
                output_location = select_save_location("Choose location to write decrypted image");
                file_name = utils.find_file_name(input_filename)
                if file_name[-14:] == "-encyrpted.ppm":
                    output_filename = output_location + "/" + file_name[:-14] + "-decyrpted.jpg"
                else:
                    output_filename = output_location + "/" + file_name[:-4] + "-decyrpted.jpg"

                fp = open(output_filename, 'x')
                fp.close()
            else:
                output_filename = select_data_file("Choose location to write decrypted file")
            if output_filename == "":
                break
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
