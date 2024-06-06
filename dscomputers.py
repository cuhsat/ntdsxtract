#!/usr/bin/env python
# This file is part of ntdsxtract.
#
# ntdsxtract is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ntdsxtract is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with ntdsxtract.  If not, see <http://www.gnu.org/licenses/>.

'''
@author:        Csaba Barta
@license:       GNU General Public License 2.0 or later
@contact:       csaba.barta@gmail.com
'''
import sys
import re
from binascii import *
from ntds.version import *
from ntds.dsdatabase import *
from ntds.dsrecord import *
from ntds.dsobjects import *
from ntds.dstime import *
from ntds.lib.dump import *
import time
from ntds.lib.fs import *
from ntds.lib.hashoutput import *
from ntds.lib.csvoutput import *

def usage():
    print("DSComputers v" + str(ntds.version.version))
    print("Extracts information related to computer objects\n")
    print("usage: %s <datatable> <work directory> [option]\n" % sys.argv[0])
    print("  datatable")
    print("    The path to the file called datatable extracted by esedbexport")
    print("  work directory")
    print("    The path to the directory where ntdsxtract should store its")
    print("    cache files and output files. If the directory does not exist")
    print("    it will be created.")
    print("  options:")
    print("    --name <computer name regexp>")
    print("          List computers identified by the regular expression")
    print("    --syshive <path to system hive>")
    print("          Required for password hash, history and supplemental credentials extraction")
    print("          This option should be specified before the password hash")
    print("          and password history extraction options!")
    print("    --lmoutfile <path to the LM hash output file>")
    print("    --ntoutfile <path to the NT hash output file>")
    print("    --pwdformat <format of the hash output>")
    print("          ophc - OphCrack format")
    print("                 When this format is specified the NT output file will be used")
    print("          john - John The Ripper format")
    print("    --passwordhashes")
    print("    --passwordhistory")
    print("    --supplcreds")
    print("    --bitlocker")
    print("          Extract Bitlocker recovery information (recovery password)")
    print("    --csvoutfile <name of the CSV output file>")
    print("          The filename of the csv file to which ntdsxtract should write the")
    print("          output")
    print("    --debug")
    print("          Turn on detailed error messages and stack trace\n")

def processComputer(computer):
    global csvoutfile
    global pwdump
    global pwdformat
    global pwhdump
    global bitldump
    global suppcreddump

    print(str(computer))
    
    # The main computer record
    if csvoutfile != "":
        write_csv([computer.RecordId, computer.Name, computer.DNSHostName, str(computer.GUID),
                str(computer.SID), computer.OSName, computer.OSVersion,
                "=\"" + dsGetDSTimeStampStr(computer.WhenCreated) + "\"", "=\"" + dsGetDSTimeStampStr(computer.WhenChanged) + "\"",
                "", "", "", "", "", "", str(computer.DialInAccessPermission)
                ])
    
    if pwdump is True:
        print("Password hashes:")
        (lm, nt) = computer.getPasswordHashes()
        if nt != '':
            if pwdformat == 'john':
                print("\t" + format_john(computer.Name,computer.SID,nt,'NT'))
                ntof.writelines(format_john(computer.Name, computer.SID, nt, 'NT') + "\n")
            if lm != '':
                if pwdformat == 'john':
                    print("\t" + format_john(computer.Name,computer.SID,lm,'LM'))
                    lmof.writelines(format_john(computer.Name, computer.SID, lm, 'LM') + "\n")
                if pwdformat == 'ophc':
                    print("\t" + format_ophc(computer.Name,computer.SID, lm, nt))
                    ntof.writelines(format_ophc(computer.Name,computer.SID, lm, nt) + "\n")
    
    if pwhdump == True:
        print("Password history:")
        lmhistory = None
        nthistory = None
        (lmhistory, nthistory) = computer.getPasswordHistory()
        if nthistory != None:
            if pwdformat == 'john':
                hashid = 0
                for nthash in nthistory:
                    print("\t" + format_john(computer.Name + "_nthistory" + str(hashid),computer.SID, nthash, 'NT'))
                    ntof.writelines(format_john(computer.Name + "_nthistory" + str(hashid), nthash,computer.SID, 'NT') + "\n")
                    hashid += 1
                if lmhistory != None:
                    hashid = 0
                    for lmhash in lmhistory:
                        print("\t" + format_john(computer.Name + "_lmhistory" + str(hashid),computer.SID, lmhash, 'LM'))
                        lmof.writelines(format_john(computer.Name + "_lmhistory" + str(hashid),computer.SID, lmhash, 'LM') + "\n")
                        hashid += 1
            if pwdformat == 'ophc':
                if lmhistory != None:
                    for hashid in range(0,len(lmhistory)):
                        print("\t" + format_ophc(computer.Name + "_history" + str(hashid),computer.SID, lmhistory[hashid], nthistory[hashid]))
                        ntof.writelines(format_ophc(computer.Name + "_history" + str(hashid), computer.SID, lmhistory[hashid], nthistory[hashid]) + "\n")

    if bitldump == True:
        print("Recovery information:")
        for rinfo in computer.getRecoveryInformations(db):
            print("\t" + rinfo.Name)
            print("\tRecovery GUID: " + str(rinfo.RecoveryGUID))
            print("\tVolume GUID:   " + str(rinfo.VolumeGUID))
            print("\tWhen created: " + dsGetDSTimeStampStr(rinfo.WhenCreated))
            print("\tWhen changed: " + dsGetDSTimeStampStr(rinfo.WhenChanged))
            print("\tRecovery password: " + rinfo.RecoveryPassword)
            print("\tFVE Key package:\n" + dump(unhexlify(rinfo.FVEKeyPackage),16, 16))

            if csvoutfile != "":
                write_csv([computer.RecordId, computer.Name, computer.DNSHostName, str(computer.GUID),
                    str(computer.SID), computer.OSName, computer.OSVersion,
                    "=\"" + dsGetDSTimeStampStr(computer.WhenCreated) + "\"", "=\"" + dsGetDSTimeStampStr(computer.WhenChanged) + "\"",
                    rinfo.Name, str(rinfo.RecoveryGUID), str(rinfo.VolumeGUID), "=\"" + dsGetDSTimeStampStr(rinfo.WhenCreated) + "\"",
                    "=\"" +dsGetDSTimeStampStr(rinfo.WhenChanged) + "\"", rinfo.RecoveryPassword
                    ])

    if suppcreddump == True:
        creds = None
        creds = computer.getSupplementalCredentials()
        if creds != None:
            print("Supplemental credentials:")
            creds.Print("  ")

    print("")

if len(sys.argv) < 3:
    usage()
    sys.exit(1)

syshive = ""
ntoutfile = ""
lmoutfile = ""
csvoutfile = ""
pwdformat = ""
pwdump = False
pwhdump = False
bitldump = False
suppcreddump = False
optid = 0
ntof = None
lmof = None
csvof = None
reName = None

print("[+] Started at: %s" % time.strftime(
                                        "%a, %d %b %Y %H:%M:%S UTC",
                                        time.gmtime()))
print("[+] Started with options:")
for opt in sys.argv:
    if opt == "--name":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        name = sys.argv[optid + 1]
        reName = re.compile(name)
        print("\t[-] Computer name: %s" % name)
    if opt == "--syshive":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        syshive = sys.argv[optid + 1]
    if opt == "--passwordhashes":
        pwdump = True
        print("\t[-] Extracting password hashes")
    if opt == "--passwordhistory":
        pwhdump = True
        print("\t[-] Extracting password history")
    if opt == "--supplcreds":
        suppcreddump = True
        print("\t[-] Extracting supplemental credentials")
    if opt == "--bitlocker":
        bitldump = True
        print("\t[-] Extracting BitLocker recovery information")
    if opt == "--lmoutfile":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        lmoutfile = sys.argv[optid + 1]
        print("\t[-] LM hash output filename: " + sys.argv[optid + 1])
    if opt == "--ntoutfile":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        ntoutfile = sys.argv[optid + 1]
        print("\t[-] NT hash output filename: " + sys.argv[optid + 1])
    if opt == "--pwdformat":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        pwdformat = sys.argv[optid + 1]
        print("\t[-] Hash output format: " + sys.argv[optid + 1])
    if opt == "--csvoutfile":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        csvoutfile = sys.argv[optid + 1]
        print("\t[-] CSV output filename: " + sys.argv[optid + 1])
    optid += 1

# Setting up the environment
if not checkfile(sys.argv[1]):
    print("[!] Error! datatable cannot be found!")
    sys.exit(1)
wd = ensure_dir(sys.argv[2])

if pwdump or pwhdump or suppcreddump:
    if syshive == "":
        print("[!] Error! Missing path to system hive! Use --syshive option.")
        usage()
        sys.exit(1)

if pwdump == True or pwhdump == True:
    if pwdformat == "":
        print("[!] Error! Missing password hash output format! Use --pwdformat option.")
        sys.exit(1)
    if ntoutfile == "":
        print("[!] Error! Missing password hash output file! Use --ntoutfile option.")
        sys.exit(1)
    if pwdformat == "john" and lmoutfile == "":
        print("[!] Error! Missing LM hash output file! Use --lmoutfile option.")
        sys.exit(1)

if csvoutfile != "":
    init_csv(path.join(wd, csvoutfile))
    
if pwdump is True or pwhdump is True:
    ntof = open(path.join(wd, ntoutfile), 'a')
    if pwdformat == 'john':
        lmof = open(path.join(wd, lmoutfile), 'a')

db = dsInitDatabase(sys.argv[1], wd)

if pwdump is True or pwhdump is True or suppcreddump is True:
    dsInitEncryption(syshive)
        
if csvoutfile != "":
    write_csv(["Record ID", "Computer name", "DNS name", "GUID",
            "SID", "OS name", "OS version", "When created", "When changed",
            "Bitlocker recovery name", "Bitlocker recovery GUID",
            "Bitlocker volume GUID", "Bitlocker when created",
            "Bitlocker when changed", "Bitlocker recovery password", "Dial-In Permission"
            ])

print("List of computers:")
print("==================")
for recordid in dsMapRecordIdByTypeId[dsGetTypeIdByTypeName(db, "Computer")]:
    computer = None
    try:
        computer = dsComputer(db, recordid)
    except KeyboardInterrupt:
        raise KeyboardInterrupt
    except:
        print("[!] Unable to instantiate user object (record id: %d)" % recordid)
        continue
    if reName != None and not reName.search(computer.Name):
        computer = None
        continue

    processComputer(computer)

if csvoutfile != "":
    close_csv()

if ntof != None:
    ntof.close()
if lmof != None:
    lmof.close()

