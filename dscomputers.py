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
    print("\nDSComputers v" + str(ntds.version.version))
    print("\nExtracts information related to computer objects")
    print("\n\nusage: %s <datatable> <work directory> [option]" % sys.argv[0])
    print("\n\n  datatable")
    print("\n    The path to the file called datatable extracted by esedbexport")
    print("\n  work directory")
    print("\n    The path to the directory where ntdsxtract should store its")
    print("\n    cache files and output files. If the directory does not exist")
    print("\n    it will be created.")
    print("\n  options:")
    print("\n    --name <computer name regexp>")
    print("\n          List computers identified by the regular expression")
    print("\n    --syshive <path to system hive>")
    print("\n          Required for password hash, history and supplemental credentials extraction")
    print("\n          This option should be specified before the password hash")
    print("\n          and password history extraction options!")
    print("\n    --lmoutfile <path to the LM hash output file>")
    print("\n    --ntoutfile <path to the NT hash output file>")
    print("\n    --pwdformat <format of the hash output>")
    print("\n          ophc - OphCrack format")
    print("\n                 When this format is specified the NT output file will be used")
    print("\n          john - John The Ripper format")
    print("\n    --passwordhashes")
    print("\n    --passwordhistory")
    print("\n    --supplcreds")
    print("\n    --bitlocker")
    print("\n          Extract Bitlocker recovery information (recovery password)")
    print("\n    --csvoutfile <name of the CSV output file>")
    print("\n          The filename of the csv file to which ntdsxtract should write the")
    print("\n          output")
    print("\n    --debug")
    print("\n          Turn on detailed error messages and stack trace")
    print("\n")

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
    
    if pwdump == True:
        print("\nPassword hashes:")
        (lm, nt) = computer.getPasswordHashes()
        if nt != '':
            if pwdformat == 'john':
                print("\n\t" + format_john(computer.Name,computer.SID,nt,'NT'))
                ntof.writelines(format_john(computer.Name, computer.SID, nt, 'NT') + "\n")
            if lm != '':
                if pwdformat == 'john':
                    print("\n\t" + format_john(computer.Name,computer.SID,lm,'LM'))
                    lmof.writelines(format_john(computer.Name, computer.SID, lm, 'LM') + "\n")
                if pwdformat == 'ophc':
                    print("\n\t" + format_ophc(computer.Name,computer.SID, lm, nt))
                    ntof.writelines(format_ophc(computer.Name,computer.SID, lm, nt) + "\n")
    
    if pwhdump == True:
        print("\nPassword history:")
        lmhistory = None
        nthistory = None
        (lmhistory, nthistory) = computer.getPasswordHistory()
        if nthistory != None:
            if pwdformat == 'john':
                hashid = 0
                for nthash in nthistory:
                    print("\n\t" + format_john(computer.Name + "_nthistory" + str(hashid),computer.SID, nthash, 'NT'))
                    ntof.writelines(format_john(computer.Name + "_nthistory" + str(hashid), nthash,computer.SID, 'NT') + "\n")
                    hashid += 1
                if lmhistory != None:
                    hashid = 0
                    for lmhash in lmhistory:
                        print("\n\t" + format_john(computer.Name + "_lmhistory" + str(hashid),computer.SID, lmhash, 'LM'))
                        lmof.writelines(format_john(computer.Name + "_lmhistory" + str(hashid),computer.SID, lmhash, 'LM') + "\n")
                        hashid += 1
            if pwdformat == 'ophc':
                if lmhistory != None:
                    for hashid in range(0,len(lmhistory)):
                        print("\n\t" + format_ophc(computer.Name + "_history" + str(hashid),computer.SID, lmhistory[hashid], nthistory[hashid]))
                        ntof.writelines(format_ophc(computer.Name + "_history" + str(hashid), computer.SID, lmhistory[hashid], nthistory[hashid]) + "\n")

    if bitldump == True:
        print("\nRecovery information:")
        for rinfo in computer.getRecoveryInformations(db):
            print("\n\t" + rinfo.Name)
            print("\n\tRecovery GUID: " + str(rinfo.RecoveryGUID))
            print("\n\tVolume GUID:   " + str(rinfo.VolumeGUID))
            print("\n\tWhen created: " + dsGetDSTimeStampStr(rinfo.WhenCreated))
            print("\n\tWhen changed: " + dsGetDSTimeStampStr(rinfo.WhenChanged))
            print("\n\tRecovery password: " + rinfo.RecoveryPassword)
            print("\n\tFVE Key package:\n" + dump(unhexlify(rinfo.FVEKeyPackage),16, 16))
            print("\n\n")
            
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
            print("\nSupplemental credentials:\n")
            creds.Print("  ")

    print("\n")

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

print("\n[+] Started at: %s" % time.strftime(
                                        "%a, %d %b %Y %H:%M:%S UTC",
                                        time.gmtime()))
print("\n[+] Started with options:")
for opt in sys.argv:
    if opt == "--name":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        name = sys.argv[optid + 1]
        reName = re.compile(name)
        print("\n\t[-] Computer name: %s" % name)
    if opt == "--syshive":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        syshive = sys.argv[optid + 1]
    if opt == "--passwordhashes":
        pwdump = True
        print("\n\t[-] Extracting password hashes")
    if opt == "--passwordhistory":
        pwhdump = True
        print("\n\t[-] Extracting password history")
    if opt == "--supplcreds":
        suppcreddump = True
        print("\n\t[-] Extracting supplemental credentials")
    if opt == "--bitlocker":
        bitldump = True
        print("\n\t[-] Extracting BitLocker recovery information")
    if opt == "--lmoutfile":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        lmoutfile = sys.argv[optid + 1]
        print("\n\t[-] LM hash output filename: " + sys.argv[optid + 1])
    if opt == "--ntoutfile":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        ntoutfile = sys.argv[optid + 1]
        print("\n\t[-] NT hash output filename: " + sys.argv[optid + 1])
    if opt == "--pwdformat":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        pwdformat = sys.argv[optid + 1]
        print("\n\t[-] Hash output format: " + sys.argv[optid + 1])
    if opt == "--csvoutfile":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        csvoutfile = sys.argv[optid + 1]
        print("\n\t[-] CSV output filename: " + sys.argv[optid + 1])
    optid += 1

# Setting up the environment
if not checkfile(sys.argv[1]):
    print("\n[!] Error! datatable cannot be found!\n")
    sys.exit(1)
wd = ensure_dir(sys.argv[2])

if pwdump or pwhdump or suppcreddump:
    if syshive == "":
        print("\n[!] Error! Missing path to system hive! Use --syshive option.\n")
        usage()
        sys.exit(1)

if pwdump == True or pwhdump == True:
    if pwdformat == "":
        print("\n[!] Error! Missing password hash output format! Use --pwdformat option.\n")
        sys.exit(1)
    if ntoutfile == "":
        print("\n[!] Error! Missing password hash output file! Use --ntoutfile option.\n")
        sys.exit(1)
    if pwdformat == "john" and lmoutfile == "":
        print("\n[!] Error! Missing LM hash output file! Use --lmoutfile option.\n")
        sys.exit(1)

if csvoutfile != "":
    init_csv(path.join(wd, csvoutfile))
    
if pwdump == True or pwhdump == True:
    ntof = open(path.join(wd, ntoutfile), 'a')
    if pwdformat == 'john':
        lmof = open(path.join(wd, lmoutfile), 'a')

db = dsInitDatabase(sys.argv[1], wd)

if pwdump == True or pwhdump == True or suppcreddump == True:
    dsInitEncryption(syshive)
        
if csvoutfile != "":
    write_csv(["Record ID", "Computer name", "DNS name", "GUID",
            "SID", "OS name", "OS version", "When created", "When changed",
            "Bitlocker recovery name", "Bitlocker recovery GUID",
            "Bitlocker volume GUID", "Bitlocker when created",
            "Bitlocker when changed", "Bitlocker recovery password", "Dial-In Permission"
            ])

print("\n\nList of computers:")
print("\n==================")
for recordid in dsMapRecordIdByTypeId[dsGetTypeIdByTypeName(db, "Computer")]:
    computer = None
    try:
        computer = dsComputer(db, recordid)
    except KeyboardInterrupt:
        raise KeyboardInterrupt
    except:
        print("\n[!] Unable to instantiate user object (record id: %d)" % recordid)
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

