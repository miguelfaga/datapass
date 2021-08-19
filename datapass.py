# -*- coding: utf-8 -*-

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
        self.vault = b'e30='
        self.on_session = False
        print("Session created!")
    
    class Encryption():
        
        def decrypt_bytes_to_dict(self, bytes):
            msg_bytes = base64.b64decode(bytes)
            ascii_msg = msg_bytes.decode('ascii')
            ascii_msg = ascii_msg.replace("'", "\"") # Double quotes is standard format for json
            output_dict = json.loads(ascii_msg) # Json library convert stirng dictionary to real dictionary type.
            return output_dict
    
        def encrypt_dict_to_byte(self, dict):
            message = str(dict)
            ascii_message = message.encode('ascii')
            output_byte = base64.b64encode(ascii_message)
            return output_byte
        
        def encrypt_string(self, string):
            return string
        
        def decrypt_string(self, string):
            return string
    
    def add_entry(self, site, password):
        if self.on_session:
            encryption = self.Encryption()
            password = encryption.encrypt_string(password)
            dictionary = encryption.decrypt_bytes_to_dict(self.vault)
            print(dictionary)
            print(password)
            print(site)
            dictionary[site] = password
            self.vault = encryption.encrypt_dict_to_byte(dictionary)
        print('Session is not on.')     
        
    def retrieve_entry(self, site):
        pass
    
    def delete_entry(self, site):
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
                
def save_session(session):
    session_file = open(sessions_directory + session.name, "wb")
    pickle.dump(session, session_file)
    session_file.close()

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
        if first_input == "CREATE":
            create_session()
        if first_input == "EXIT":
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
        print("Type EXIT to close your vault.")
        second_input = input(">: ")
        if second_input == "EXIT":
            session.on_session = False
            save_session(session)
            print("Terminating...")
            break
        if second_input == 'ADD':
            print("What is the site you're saving the password from?")
            entry_site = input(">: ")
            print("Now tell me the password.")
            entry_password = input(">: ")
            session.add_entry(entry_site, entry_password)
            
#run()




#check and list password entries in session
#create entry
#edit entry
#delete entry
#retrieve password


#Access granted
