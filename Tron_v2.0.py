# Tron Virus Finder

import glob, re
def checkForSignatures():
    print ("Tron has found signs of a virus")
    programs = glob.glob("*.py")
    for p in programs:
        thisFileInfected = False
        file = open(p, "r")
        file.close()

# Line 15 will search for stings to ID a virus.

        for line in lines:
            if (re.search("#CLU#",line)):
                print("Tron is engageing a virus found in file" + p)
                thisFileInfected = True
            if (thisFileInfected == False):
                print (p + " apperars to be clean" )

    print("End of Line")

checkForSignatures()

# Module 2 Cipher.

import pyperclip

message = 'This is my  secret message.'
key = 13

mode = 'encrypt' # set to encrypt or decrypt
SYMBOLS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890 !?.`~@#$%^&*()_+-=[]{}|;:<>,/'

translated = ''

message = message.upper()

for symbol in message:
 if symbol in SYMBOLS:
         symbolIndex = SYMBOLS.find(symbol)
         if mode == 'encrypt':
             translatedIndex = symbolIndex + key
         elif mode == 'decrypt':
             translatedIndex = symbolIndex - key

         if translatedIndex >= len(SYMBOLS):
             translatedIndex = translatedIndex - len(SYMBOLS)
 elif translatedIndex < 0:
        translatedIndex = translatedIndex + len(SYMBOLS)

        translated = translated + SYMBOLS[translatedIndex]

 else:
    translated = translated + symbol

print(translated)

pyperclip.copy(translated)


# Module 3 Nmap Scanner.

import Nmap

scanner = Namp.PortScanner()
print("Welcome, this is a Grid automation tool")
print(" Security of your GRID is our concern ")

ip_addr = input("Enter the IP address you want to scan:")
print("The IP you entered is: ", ip_addr)
type(ip_addr)

resp = input("""\nPlease enter the type of scan you want to run
                1)SYN ACK Scan
                2)UDP Scan
                3)Comprehensive Scan \n""")
print("You have selected option: ", resp)

if resp == '1':
    print()"Nmap Version: ", scanner.namp_version1()
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("Ip Staus: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
elif resp == '2':
    print() "Nmap Version: ", scanner.namp_version1()
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("Ip Staus: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['udp'].keys())


# Module 4 SAST Scanner. - Needs to be finished.

import os 
import sys 
import re
from ast_walker import (FuncAnalyzer,
                        file_parser,
                        ClassAnalyzer)


MAX_LINE_LEN = 79

ERRORS_DICT  = {'Long Line': 'S002',
                'Indentation': 'S002',
                'Semicolon': 'S003',
                'Inline Comments': 'S004',
                'TODO': 'S005',
                'Blank lines': 'S006',
                'Construction space': 'S007',
               }

def_constructor_ptn = re.compile(r'^\s?def\s\w+')
