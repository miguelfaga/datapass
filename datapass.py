# -*- coding: utf-8 -*-
from time import sleep
#import pyautogui
import getpass
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

def create_session():
    print("What shall be your session name?")
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
        print("Session created.\n")
        break
        #return session_name, session_pass2
    print(bar)
    

def check_session():
    directory = "sessions/"
    if not os.path.exists(directory):
        os.mkdir(directory)
    if os.listdir(directory) == []:
        print("\nNew session detected")
        create_session()
    
def open_session():
    pass

def welcome():
    print("\nWelcome to...\n" + bar + logo + bar)
    print("\nYour very own password management system.")
    sleep(1)
    print("...")
    sleep(2)
    print("Who could tell?\n")
    print(bar)

welcome()
check_session()
open_session()

#Access granted
#Access denied