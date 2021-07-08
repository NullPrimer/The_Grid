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