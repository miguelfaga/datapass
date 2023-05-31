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
    '''Datapass Session.
    
    Attributes:
    -----------
    name : str
           Session name.
    password : str
           Encrypted password.
        vault : binary 
            Contains a vault (dict) in binary.
        keys : list
            Sites' list.
        on_session : bool
            Session control variable.
        '''
        
        #--------------------------------------------------------------------
        #Constructors
        
    def __init__(self, name, password):
        '''
        Initiate a session.
        '''
        self.name = name
        self.password = password
        self.vault = 'e30='
        self.keys = []
        self.on_session = False
        self.hash_id = Fernet.generate_key()
        print("Session created!")
    
        
    class Encryption:
        '''
        Nested encryption class.
        '''
        
        def encrypt_dict_to_byte(self, dic):
            #Translates dictionary into bytes
            stringed_dic = str(dic)
            encoded_dic = stringed_dic.encode('utf-8')
            byted_dic = base64.b64encode(encoded_dic)
            return byted_dic
        
        def decrypt_bytes_to_dict(self, bites):
            #Translates bytes into dictionary
            dic_bytes = base64.b64decode(bites)
            ascii_dic = dic_bytes.decode('utf-8')
            ascii_dic = ascii_dic.replace("'", "\"") # Double quotes is standard format for json
            output_dic = json.loads(ascii_dic) # Json library convert string dictionary to real dictionary type.
            return output_dic
        
        def encrypt_string(self, string, hash_id):
            #Encrypts a given string
            encoded_string = string.encode('utf-8')
            f = Fernet(hash_id)
            encrypted_message = f.encrypt(encoded_string).decode()
            return encrypted_message

        def decrypt_string(self, string, hash_id):
            #Decrypts a string
            encrypt = string.encode('utf-8')
            f = Fernet(hash_id)
            decrypted_message = f.decrypt(encrypt)
            return decrypted_message.decode('utf-8')
    
    def add_entry(self, site, password, hash_id):
        '''
        Adds a new entry to the session.
        '''
        if self.on_session:
            encryption = self.Encryption()
            password = encryption.encrypt_string(password, hash_id)
            dictionary = encryption.decrypt_bytes_to_dict(self.vault)
            dictionary[site] = password
            self.vault = encryption.encrypt_dict_to_byte(dictionary)
            self.keys.append(site)
        print('Session is not on.')     
        
    def retrieve_entry(self, site, hash_id):
        '''
        Retrieves an entry in the session.
        '''
        if self.on_session:
            encryption = self.Encryption()
            dictionary = encryption.decrypt_bytes_to_dict(self.vault)
            password = dictionary[site]
            password = encryption.decrypt_string(password, hash_id)
            return password
            
    def delete_entry(self, site):
        '''
        Deletes an entry in the session.
        '''
        if self.on_session:
            pass

def hash_function(string):
    '''
    Hash function converts string to hash to confirm password input.
    '''
    h = sha256(string.encode('utf-8'))
    hashed = h.hexdigest()
    return hashed

def check_session():
    '''
    List all saved sessions in the program.
    If the list is empty, calls create_function.
    '''
    if not os.path.exists(sessions_directory):
        os.mkdir(sessions_directory)
    if os.listdir(sessions_directory) == []:
        print("\nNew session needed.")
        create_session()
    return os.listdir(sessions_directory)

def save_session(session):
    '''
    Session autosave.
    '''
    session_file = open(sessions_directory + session.name, "wb")
    pickle.dump(session, session_file)
    session_file.close()

def create_session():
    '''
    Deletes a saved session in the program.
    '''
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
    '''
    Load a saved session in the program.
    '''
    session_file = open(sessions_directory + session_name, "rb")
    session = pickle.load(session_file)
    session_file.close()
    while not session.on_session:
        print("Would you please confirm the master password to this session?")
        password = getpass.getpass(prompt = ">: ")
        password = hash_function(password)
        if session.password == password:
            sleep(1)
            print('Access granted')
            return session
        else:
            sleep(1)
            print('Access denied.')
            break
                

def run():
    '''
    Runs DATAPASS. Should this be a different file?
    '''
    print("\nWelcome to...\n" + bar + logo + bar)
    print("\nYour very own password management system.")
    sleep(1)
    print("...")
    sleep(2)
    print("Who could tell?\n")
    sleep(1)
    print(bar)
    while True:
        sessions = check_session()
        print(bar)
        print("\nType CREATE to create a new session or <THE NAME> one of the sessions below to open it.")
        print(", ".join(sessions))
        first_input = input(">: ")
        if first_input.upper() == "CREATE":
            create_session()
        if first_input.upper() == "EXIT":
            print("Terminating...")
            return None
        if first_input in sessions:
            session = load_session(first_input)
            if session == None:
                print("Let's try again, shall we?")
                sleep(1)
            else:
                session.on_session = True
                print(f"SESSION FOR {session.name} STARTED!")
                break

    while session.on_session:
        print("\nType ADD to add a new entry to your vault.")
        print("Type OPEN to open your vault.")
        print("Type EXIT to close your vault and terminate.")
        #print(session.keys)
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
            print("\nWhich site are you retrieving the password from?")
            pannel = ""
            for key in session.keys:
                button = "  [{: ^10}]  ".format(key)
                if session.keys.index(key) % 2 != 0:
                    button +="\n"
                pannel += button
            print(pannel)
            entry_site = input(">:")
            if entry_site in session.keys:
                print("\nYour password is:")
                print(session.retrieve_entry(entry_site, session.hash_id))
                sleep(2)
            else:
                print("Try again.")
            
if __name__ == "__main__":
    try:
        run()
    except:
        print("AI CARALHO") 


#tratar exceções:
#   senha errada para entrar na sessão no loop
#   

#check entries in session
#create entry
#edit entry
#delete entry