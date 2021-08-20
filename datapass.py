# -*- coding: utf-8 -*-
from cryptography.fernet import Fernet
from hashlib import sha256
from time import sleep
#import pyautogui
import getpass
import pickle
import base64
import json
import os


logo = """
 __________________________________________________________________
|   ____      _     _____     _     ____      _     ____   ____    |
|  |  _ \    / \   |_   _|   / \   |  _ \    / \   / ___| / ___|   | 
|  | | | |  / _ \    | |    / _ \  | |_) |  / _ \  \___ \ \___ \   |
|  | |_| | / ___ \   | |   / ___ \ |  __/  / ___ \  ___) | ___) |  |
|  |____/ /_/   \_\  |_|  /_/   \_\|_|    /_/   \_\|____/ |____/   |
|__________________________________________________________________|

"""

bar = """===================================================================="""

sessions_directory = "data/"

class Session:
    
    def __init__(self, name, password):
        self.name = name
        self.password = password
        self.vault = 'e30='
        self.keys = []
        self.on_session = False
        self.hash_id = Fernet.generate_key()
        print("Session created!")
    
        
    class Encryption:
        def encrypt_dict_to_byte(self, dict):
            stringed_dic = str(dict)
            encoded_dic = stringed_dic.encode('utf-8')
            byted_dic = base64.b64encode(encoded_dic)
            return byted_dic
        
        def decrypt_bytes_to_dict(self, bites):
            dic_bytes = base64.b64decode(bites)
            ascii_dic = dic_bytes.decode('utf-8')
            ascii_dic = ascii_dic.replace("'", "\"") # Double quotes is standard format for json
            output_dic = json.loads(ascii_dic) # Json library convert stirng dictionary to real dictionary type.
            return output_dic
        
        def encrypt_string(self, string, hash_id):
            encoded_string = string.encode('utf-8')
            f = Fernet(hash_id)
            encrypted_message = f.encrypt(encoded_string).decode()
            return encrypted_message

        def decrypt_string(self, string, hash_id):
            encrypt = string.encode('utf-8')
            f = Fernet(hash_id)
            decrypted_message = f.decrypt(encrypt)
            return decrypted_message.decode('utf-8')
    
    def add_entry(self, site, password, hash_id):
        if self.on_session:
            encryption = self.Encryption()
            password = encryption.encrypt_string(password, hash_id)
            dictionary = encryption.decrypt_bytes_to_dict(self.vault)
            dictionary[site] = password
            self.vault = encryption.encrypt_dict_to_byte(dictionary)
            self.keys.append(site)
        print('Session is not on.')     
        
    def retrieve_entry(self, site, hash_id):
        if self.on_session:
            encryption = self.Encryption()
            dictionary = encryption.decrypt_bytes_to_dict(self.vault)
            password = dictionary[site]
            password = encryption.decrypt_string(password, hash_id)
            return password
            
    def delete_entry(self, site):
        if self.on_session:
            pass

def hash_function(string):
    h = sha256(string.encode('utf-8'))
    hashed = h.hexdigest()
    return hashed

def check_session():

    if not os.path.exists(sessions_directory):
        os.mkdir(sessions_directory)
    if os.listdir(sessions_directory) == []:
        print("\nNew session needed.")
        create_session()
    return os.listdir(sessions_directory)

def save_session(session):
    #session = bin(session)
    session_file = open(sessions_directory + session.name, "wb")
    pickle.dump(session, session_file)
    session_file.close()

def create_session():
    print("What shall your session name be?")
    session_name = input(">: ")
    print("Creating new session: " + session_name)
    while True:
        print("Please, create a master password to the session.")
        session_pass1 = getpass.getpass(prompt = ">: ")
        print("Please, confirm the master password.")
        session_pass2 = getpass.getpass(prompt = ">: ")
        if session_pass1 != session_pass2:
            print("Password doesn't match.")
            continue
        session_pass = hash_function(session_pass2)  
        new_session = Session(session_name, session_pass)
        session_file = open(sessions_directory + session_name, "wb")
        pickle.dump(new_session, session_file)
        session_file.close()
        return new_session

def load_session(session_name):
    session_file = open(sessions_directory + session_name, "rb")
    session = pickle.load(session_file)
    session_file.close()
    while not session.on_session:
        print("Would you please confirm the master password to this session?")
        password = input(">: ")
        password = hash_function(password)
        if session.password == password:
            print('Access granted')
            return session
        else:
            print('Access denied.')
                

def run():
    print("\nWelcome to...\n" + bar + logo + bar)
    print("\nYour very own password management system.")
    sleep(1)
    print("...")
    sleep(2)
    print("Who could tell?\n")
    print(bar)
    while True:
        sessions = check_session()
        print(bar)
        print("Type CREATE to create a new session or <THE NAME> one of the sessions below to open it.")
        print(", ".join(sessions))
        first_input = input(">: ")
        if first_input.upper() == "CREATE":
            create_session()
        if first_input.upper() == "EXIT":
            print("Terminating...")
            return None
        if first_input in sessions:
            session = load_session(first_input)
            session.on_session = True
            print(f"SESSION FOR {session.name} STARTED!")
            break
    while session.on_session:
        print("Type ADD to add a new entry to your vault.")
        print("Type <NAME> of your site below to retrieve a password.")
        print("Type OPEN to open your vault.")
        print("Type EXIT to close your vault.")
        second_input = input(">: ")
        if second_input.upper() == "EXIT":
            session.on_session = False
            save_session(session)
            print("Terminating...")
            break
        if second_input.upper() == 'ADD':
            print("What is the site you're saving the password from?")
            entry_site = input(">: ")
            print("Now tell me the password.")
            entry_password = input(">: ")
            session.add_entry(entry_site, entry_password, session.hash_id)
            save_session(session)
        if second_input.upper() == 'OPEN':
            print("Which site are you retrieving the password from?")

            entry_site = input(">:")
            print("Your password is:")
            print(session.retrieve_entry(entry_site, session.hash_id))
            
run()




#check and list password entries in session
#create entry
#edit entry
#delete entry
#retrieve password


#Access granted
