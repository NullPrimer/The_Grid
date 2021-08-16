# Tron is a Defensive program created to protect User endpoints
# Module 1 Tron Virus Finder
# Scans python files for Viruses. (Pytohn files only for now )

import glob, re
def checkForSignatures():
    print ("Tron has found signs of a virus")
    programs = glob.glob("*.py")
    for p in programs:
        thisFileInfected = False
        file = open(p, "r")
        file.close()

# Line 15 will search for stings to ID a virus. # Not yet baselined. 

        for line in lines:
            if (re.search("#CLU#", line)): # Baseline with live signatures.
                print("Tron is engageing a virus found in file" + p)
            if (thisFileInfected == True):
                print("Found the source of the virus, Engaging")
            if (thisFileInfected == False):
                print (p + " apperars to be clean " )

    print("End of Line")

checkForSignatures()

# Module 2 Cipher.

import pyperclip

message = 'This is my  secret message.'
key = 13

mode = "decrypt" # set to encrypt or decrypt
SYMBOLS = 'ABDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890 !?.`~@#$%^&*()_+-=[]{}|;:<>,/'

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
class_constructor_ptn = re.compile(r'^\s?class\s\w+')

if len(sys.argv) >= 2:
    file_or_dir = sys.argv[1]

else:
    file_or_dir = ''

is_dir = os.path.isdir(file_or_dir)
is_file = os.path.isfile(file_or_dir)

class Analyser:
    """ A python static code analyser"""
    previous_blanks = 0

    def __init__(self, file_to_analyser: str = file_or_dir):
        self.file = file_to_analyse
        self.check_all()

    def check_all(self):
        current_line = self.file_reader()
        processed_files = []
        while True:
            try:
               c_file_line = next(current_line)
                current_f_line, line_num, file_path = c_file_line
                self.check_long_line(c_file_line)
                self.check_indent_error(c_file_line)
                self.check_for_semicolon(c_file_line)
                self.check_inline_comment(c_file_line)
                self.check_to_do(c_file_line)
                self.check_blank_lines(c_file_line)
                self.check_constructor_space(c_file_line)
                if file_path not in processed_files:
                    parsed_file = file_parser(file_path)
                    ClassAnalyzer(file_path).visit_ClassDef(parsed_file)
                    FuncAnalyzer(file_path).visit_FunctionDef(parsed_file)
                    processed_files.append(file_path)
            except StopIteration:
                break 
            # Finish Mod 4 

# Module 5 System Monitor

import psutil
from datetime import datetime
import pandas as pd
import time
import os


def get_size(bytes):
    """
    Returns size of bytes in a nice format
    """
    for unit in ['', 'K', 'M', 'G', 'T', 'P']:
        if bytes < 1024:
            return f"{bytes:.2f}{unit}B"
        bytes /= 1024


def get_processes_info():
    # the list the contain all process dictionaries
    processes = []
    for process in psutil.process_iter():
        # get all process info in one shot
        with process.oneshot():
            # get the process id
            pid = process.pid
            if pid == 0:
                # System Idle Process for Windows NT, useless to see anyways
                continue
            # get the name of the file executed
            name = process.name()
            # get the time the process was spawned
            try:
                create_time = datetime.fromtimestamp(process.create_time())
            except OSError:
                # system processes, using boot time instead
                create_time = datetime.fromtimestamp(psutil.boot_time())
            try:
                # get the number of CPU cores that can execute this process
                cores = len(process.cpu_affinity())
            except psutil.AccessDenied:
                cores = 0
            # get the CPU usage percentage
            cpu_usage = process.cpu_percent()
            # get the status of the process (running, idle, etc.)
            status = process.status()
            try:
                # get the process priority (a lower value means a more prioritized process)
                nice = int(process.nice())
            except psutil.AccessDenied:
                nice = 0
            try:
                # get the memory usage in bytes
                memory_usage = process.memory_full_info().uss
            except psutil.AccessDenied:
                memory_usage = 0
            # total process read and written bytes
            io_counters = process.io_counters()
            read_bytes = io_counters.read_bytes
            write_bytes = io_counters.write_bytes
            # get the number of total threads spawned by this process
            n_threads = process.num_threads()
            # get the username of user spawned the process
            try:
                username = process.username()
            except psutil.AccessDenied:
                username = "N/A"
            
        processes.append({
            'pid': pid, 'name': name, 'create_time': create_time,
            'cores': cores, 'cpu_usage': cpu_usage, 'status': status, 'nice': nice,
            'memory_usage': memory_usage, 'read_bytes': read_bytes, 'write_bytes': write_bytes,
            'n_threads': n_threads, 'username': username,
        })

    return processes


def construct_dataframe(processes):
    # convert to pandas dataframe
    df = pd.DataFrame(processes)
    # set the process id as index of a process
    df.set_index('pid', inplace=True)
    # sort rows by the column passed as argument
    df.sort_values(sort_by, inplace=True, ascending=not descending)
    # pretty printing bytes
    df['memory_usage'] = df['memory_usage'].apply(get_size)
    df['write_bytes'] = df['write_bytes'].apply(get_size)
    df['read_bytes'] = df['read_bytes'].apply(get_size)
    # convert to proper date format
    df['create_time'] = df['create_time'].apply(datetime.strftime, args=("%Y-%m-%d %H:%M:%S",))
    # reorder and define used columns
    df = df[columns.split(",")]
    return df

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Process Viewer & Monitor")
    parser.add_argument("-c", "--columns", help="""Columns to show,
                                                available are name,create_time,cores,cpu_usage,status,nice,memory_usage,read_bytes,write_bytes,n_threads,username.
                                                Default is name,cpu_usage,memory_usage,read_bytes,write_bytes,status,create_time,nice,n_threads,cores.""",
                        default="name,cpu_usage,memory_usage,read_bytes,write_bytes,status,create_time,nice,n_threads,cores")
    parser.add_argument("-s", "--sort-by", dest="sort_by", help="Column to sort by, default is memory_usage .", default="memory_usage")
    parser.add_argument("--descending", action="store_true", help="Whether to sort in descending order.")
    parser.add_argument("-n", help="Number of processes to show, will show all if 0 is specified, default is 25 .", default=25)
    parser.add_argument("-u", "--live-update", action="store_true", help="Whether to keep the program on and updating process information each second")

    # parse arguments
    args = parser.parse_args()
    columns = args.columns
    sort_by = args.sort_by
    descending = args.descending
    n = int(args.n)
    live_update = args.live_update
    # print the processes for the first time
    processes = get_processes_info()
    df = construct_dataframe(processes)
    if n == 0:
        print(df.to_string())
    elif n > 0:
        print(df.head(n).to_string())
    while live_update:
        processes = get_processes_info()
        df = construct_dataframe(processes)
        os.system("cls") if "nt" in os.name else os.system("clear")
        if n == 0:
            print(df.to_string())
        elif n > 0:
            print(df.head(n).to_string())
        time.sleep(0.7)
        
# Module 6 MAC Changer.

    import subprocess
import optparse

parser = optparse.OptionParser()
parser.add_option("-i", "--interface", dest="interface", help="Interface to change its MAC address")
parser.add_option("-m", "--mac", dest="new_mac", help="New MAC address")

(options, arguments) = parser.parse_args()

interface = options.interface
new_mac = options.new_MAC

print("[+] Changing MAC address for" + interface + " to " + new_mac)

subprocess.call(["ifconfing", interface, "down"])
subprocess.call(["ifconfing", interface, "hw", "ether", new_mac])
subprocess.call(["ifconfing", interface, "up"])


