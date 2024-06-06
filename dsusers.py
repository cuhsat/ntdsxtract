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
from os import path
import re
from ntds.version import *
from ntds.dsdatabase import *
from ntds.dsrecord import *
from ntds.dslink import *
from ntds.dstime import *
from ntds.dsobjects import *
from ntds.lib.dump import *
from ntds.lib.fs import *
from ntds.lib.hashoutput import *
from ntds.lib.csvoutput import *

def usage():
    print("DSUsers v" + str(ntds.version.version))
    print("Extracts information related to user objects\n")
    print("usage: %s <datatable> <linktable> <work directory> [option]\n" % sys.argv[0])
    print("  datatable")
    print("    The path to the file called datatable extracted by esedbexport")
    print("  linktable")
    print("    The path to the file called linktable extracted by esedbexport")
    print("  work directory")
    print("    The path to the directory where ntdsxtract should store its")
    print("    cache files and output files. If the directory does not exist")
    print("    it will be created.")
    print("  options:")
    print("    --sid <user sid>")
    print("          List user identified by SID")
    print("    --guid <user guid>")
    print("          List user identified by GUID")
    print("    --name <user name regexp>")
    print("          List user identified by the regular expression")
    print("    --active")
    print("          List only active accounts. This option cannot be used")
    print("          with --flags.")
    print("    --locked")
    print("          List only locked accounts. This option cannot be used")
    print("          with --flags.")
    print("    --uac <UserAccountControl flag combination as hex>")
    print("          List only the accounts that have the specified UAC flag")
    print("          combination. This option cannot be used with --active or")
    print("          --locked")
    print("    --syshive <path to system hive>")
    print("          Required for password hash and history extraction")
    print("          This option should be specified before the password hash")
    print("          and password history extraction options!")
    print("    --lmoutfile <name of the LM hash output file>")
    print("    --ntoutfile <name of the NT hash output file>")
    print("    --pwdformat <format of the hash output>")
    print("          ophc - OphCrack format")
    print("                 When this format is specified the NT output file will be used")
    print("          john - John The Ripper format")
    print("          ocl  - oclHashcat format")
    print("                 When this format is specified the NT output file will be used")
    print("    --passwordhashes")
    print("          Extract password hashes")
    print("    --passwordhistory")
    print("          Extract password history")
    print("    --certificates")
    print("          Extract certificates")
    print("    --supplcreds")
    print("          Extract supplemental credentials (e.g.: clear text passwords,")
    print("          kerberos keys)")
    print("    --membership")
    print("          List groups of which the user is a member")
    print("    --csvoutfile <name of the CSV output file>")
    print("          The filename of the csv file to which ntdsxtract should write the")
    print("          output")
    print("    --debug")
    print("          Turn on detailed error messages and stack trace\n")

def processUser(user):
    print(str(user))

    str_anc = ""
    str_uac = ""
    if csvoutfile != "":
        for uac in user.getUserAccountControl():
            str_uac = str_uac + uac + "|"
    for ancestor in user.getAncestors(db):
            str_anc = str_anc + ancestor.Name + "|"

    if csvoutfile != "":
        write_csv([user.RecordId, user.Name, user.PrincipalName, user.SAMAccountName,
               user.getSAMAccountType(), str(user.GUID), str(user.SID),
               dsGetDSTimeStampStr(user.WhenCreated), dsGetDSTimeStampStr(user.WhenChanged),
               dsGetDSTimeStampStr(user.AccountExpires), dsGetDSTimeStampStr(user.PasswordLastSet),
               dsGetDSTimeStampStr(user.LastLogon), dsGetDSTimeStampStr(user.LastLogonTimeStamp),
               dsGetDSTimeStampStr(user.BadPwdTime), user.LogonCount, user.BadPwdCount, str_uac, str_anc,
               str(user.DialInAccessPermission), "", "", "", ""
               ])

    if pwdump == True:
        print("Password hashes:")
        (lm, nt) = user.getPasswordHashes()
        if nt != '':
            if pwdformat == 'john':
                print("\t" + format_john(user.SAMAccountName,str(user.SID),nt,'NT'))
                ntof.writelines(format_john(user.SAMAccountName, str(user.SID), nt, 'NT') + "\n")
            if lm != '':
                if pwdformat == 'john':
                    print("\t" + format_john(user.SAMAccountName,str(user.SID),lm,'LM'))
                    lmof.writelines(format_john(user.SAMAccountName, str(user.SID), lm, 'LM') + "\n")
                if pwdformat == 'ocl':
                    print("\t" + format_ocl(user.SAMAccountName, lm))
                    lmof.writelines(format_ocl(user.SAMAccountName, lm) + "\n")
            if pwdformat == 'ophc':
                if lm != '':
                    print("\t" + format_ophc(user.SAMAccountName,str(user.SID),lm,nt))
                    ntof.writelines(format_ophc(user.SAMAccountName, str(user.SID), lm, nt) + "\n")
                else:
                    print("\t" + format_ophc(user.SAMAccountName,str(user.SID),"",nt))
                    ntof.writelines(format_ophc(user.SAMAccountName, str(user.SID), "", nt) + "\n")
            if pwdformat == 'ocl':
                print("\t" + format_ocl(user.SAMAccountName, nt))
                ntof.writelines(format_ocl(user.SAMAccountName, nt) + "\n")
                
    
    if pwhdump == True:
        print("Password history:")
        lmhistory = None
        nthistory = None
        (lmhistory, nthistory) = user.getPasswordHistory()
        if nthistory != None:
            if pwdformat == 'john':
                hashid = 0
                for nthash in nthistory:
                    print("\t" + format_john(user.SAMAccountName + "_nthistory" + str(hashid), str(user.SID), nthash, 'NT'))
                    ntof.writelines(format_john(user.SAMAccountName + "_nthistory" + str(hashid), str(user.SID), nthash, 'NT') + "\n")
                    hashid += 1
                if lmhistory != None:
                    hashid = 0
                    for lmhash in lmhistory:
                        print("\t" + format_john(user.SAMAccountName + "_lmhistory" + str(hashid), str(user.SID), lmhash, 'LM'))
                        lmof.writelines(format_john(user.SAMAccountName + "_lmhistory" + str(hashid), str(user.SID), lmhash, 'LM') + "\n")
                        hashid += 1
            if pwdformat == 'ocl':
                hashid = 0
                for nthash in nthistory:
                    print("\t" + format_ocl(user.SAMAccountName + "_nthistory" + str(hashid), nthash))
                    ntof.writelines(format_ocl(user.SAMAccountName + "_nthistory" + str(hashid), nthash) + "\n")
                    hashid += 1
                if lmhistory != None:
                    hashid = 0
                    for lmhash in lmhistory:
                        print("\t" + format_ocl(user.SAMAccountName + "_lmhistory" + str(hashid), lmhash))
                        lmof.writelines(format_ocl(user.SAMAccountName + "_lmhistory" + str(hashid), lmhash) + "\n")
                        hashid += 1
            if pwdformat == 'ophc':
                if lmhistory != None:
                    for hashid in range(0,len(nthistory) - 1):
                        print("\t" + format_ophc(user.SAMAccountName + "_history" + str(hashid), str(user.SID), lmhistory[hashid], nthistory[hashid]))
                        ntof.writelines(format_ophc(user.SAMAccountName + "_history" + str(hashid), str(user.SID), lmhistory[hashid], nthistory[hashid]) + "\n")                        

    
    if certdump == True and user.Certificate != "":
        print("Certificate:")
        print(dump(user.Certificate,16,16))
        
    if suppcreddump == True:
        creds = None
        creds = user.getSupplementalCredentials()
        if creds != None:
            print("Supplemental credentials:")
            creds.Print("  ")
    
    if grpdump == True:
        print("Member of:")
        if user.PrimaryGroupID != -1:
            for g in groups:
                if g.SID.RID == user.PrimaryGroupID:
                    if csvoutfile != "":
                        write_csv([user.RecordId, user.Name, user.PrincipalName, user.SAMAccountName,
                           user.getSAMAccountType(), str(user.GUID), str(user.SID),
                           dsGetDSTimeStampStr(user.WhenCreated), dsGetDSTimeStampStr(user.WhenChanged),
                           dsGetDSTimeStampStr(user.AccountExpires), dsGetDSTimeStampStr(user.PasswordLastSet),
                           dsGetDSTimeStampStr(user.LastLogon), dsGetDSTimeStampStr(user.LastLogonTimeStamp),
                           dsGetDSTimeStampStr(user.BadPwdTime), user.LogonCount, user.BadPwdCount, str_uac, str_anc,
                           str(user.DialInAccessPermission), g.Name, str(g.SID), "Y", ""
                           ])
                    print("\t%s (%s) (P)" % (g.Name, str(g.SID)))
        grouplist = user.getMemberOf()
        for groupdata in grouplist:
            (groupid, deltime) = groupdata
            group = None
            try:
                group = dsGroup(db, groupid)
            except:
                print("[!] Unable to instantiate group object (record id: %d)" % groupid)
                continue
            if deltime == -1:
                if csvoutfile != "":
                    write_csv([user.RecordId, user.Name, user.PrincipalName, user.SAMAccountName,
                           user.getSAMAccountType(), str(user.GUID), str(user.SID),
                           dsGetDSTimeStampStr(user.WhenCreated), dsGetDSTimeStampStr(user.WhenChanged),
                           dsGetDSTimeStampStr(user.AccountExpires), dsGetDSTimeStampStr(user.PasswordLastSet),
                           dsGetDSTimeStampStr(user.LastLogon), dsGetDSTimeStampStr(user.LastLogonTimeStamp),
                           dsGetDSTimeStampStr(user.BadPwdTime), user.LogonCount, user.BadPwdCount, str_uac, str_anc,
                           str(user.DialInAccessPermission), group.Name, str(group.SID), "N", ""
                           ])
                print("\t%s (%s)" % (group.Name, group.SID))
            else:
                if csvoutfile != "":
                    write_csv([user.RecordId, user.Name, user.PrincipalName, user.SAMAccountName,
                           user.getSAMAccountType(), str(user.GUID), str(user.SID),
                           dsGetDSTimeStampStr(user.WhenCreated), dsGetDSTimeStampStr(user.WhenChanged),
                           dsGetDSTimeStampStr(user.AccountExpires), dsGetDSTimeStampStr(user.PasswordLastSet),
                           dsGetDSTimeStampStr(user.LastLogon), dsGetDSTimeStampStr(user.LastLogonTimeStamp),
                           dsGetDSTimeStampStr(user.BadPwdTime), user.LogonCount, user.BadPwdCount, str_uac, str_anc,
                           str(user.DialInAccessPermission), group.Name, str(group.SID), "Y", dsGetDSTimeStampStr(dsConvertToDSTimeStamp(deltime))
                           ])
                print("\t%s (%s) - Deleted: %s" % (group.Name, group.SID,
                            dsGetDSTimeStampStr(dsConvertToDSTimeStamp(deltime))))

    print("")

if len(sys.argv) < 4:
    usage()
    sys.exit(1)

#rid = -1
#name = ""
sid  = ""
guid = ""
syshive = ""
ntoutfile = ""
lmoutfile = ""
pwdformat = ""
csvoutfile = ""
pwdump = False
pwhdump = False
certdump = False
suppcreddump = False
grpdump = False
optid = 0
ntof = None
lmof = None
csvof = None
reName = None
only_active = False
only_locked = False
uac_flags = None


print("[+] Started at: %s" % time.strftime(
                                        "%a, %d %b %Y %H:%M:%S UTC",
                                        time.gmtime()))
print("[+] Started with options:")
for opt in sys.argv:
#     if opt == "--rid":
#         if len(sys.argv) < optid + 2:
#             usage()
#             sys.exit(1)
#         rid = int(sys.argv[optid + 1])
#         print("\t[-] User RID: %d" % rid)
    if opt == "--name":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        name = sys.argv[optid + 1]
        reName = re.compile(name)
        print("\t[-] User name: %s" % name)
    if opt == "--active":
        if uac_flags != None:
            print("[!] Error! This option cannot be used with --uac!")
            sys.exit(1)
        only_active = True
        print("\t[-] Extracting only active accounts")
    if opt == "--locked":
        if uac_flags != None:
            print("[!] Error! This option cannot be used with --uac!")
            sys.exit(1)
        only_locked = True
        print("\t[-] Extracting only locked accounts")
    if opt == "--uac":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        uac_flags = int(sys.argv[optid + 1], 16)
        print("\t[-] Extracting only accounts with UAC flags: " + sys.argv[optid + 1])
    if opt == "--sid":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        sid = sys.argv[optid + 1]
        print("\t[-] User SID: %s" % sid)
    if opt == "--guid":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        guid = sys.argv[optid + 1]
        print("\t[-] User GUID: %s" % guid)
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
    if opt == "--certificates":
        certdump = True
        print("\t[-] Extracting certificates")
    if opt == "--supplcreds":
        suppcreddump = True
        print("\t[-] Extracting supplemental credentials")
    if opt == "--membership":
        grpdump = True
        print("\t[-] Extracting memberships")
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

if (pwdump or pwhdump) and syshive == "":
    print("[!] Error! syshive not specified!")
    usage()
    sys.exit(1)
    
if suppcreddump == True and syshive == "":
    print("[!] Error! syshive not specified!")
    usage()
    sys.exit(1)

# Setting up the environment
if not checkfile(sys.argv[1]):
    print("[!] Error! datatable cannot be found!")
    sys.exit(1)
if not checkfile(sys.argv[2]):
    print("[!] Error! linktable cannot be found!")
    sys.exit(1)
wd = ensure_dir(sys.argv[3])

if pwdump == True or pwhdump == True:
    if pwdformat == "":
        print("[!] Error! Missing password hash output format!")
        sys.exit(1)
    if ntoutfile == "":
        print("[!] Error! Missing password hash output file!")
        sys.exit(1)
    if (pwdformat == "john" or pwdformat == "ocl") and lmoutfile == "":
        print("[!] Error! Missing LM hash output file!")
        sys.exit(1)

if csvoutfile != "":
    init_csv(path.join(wd, csvoutfile))

if pwdump == True or pwhdump == True:
    ntof = open(path.join(wd, ntoutfile), 'a')
    if pwdformat == 'john' or pwdformat == 'ocl':
        lmof = open(path.join(wd, lmoutfile), 'a')

# Initializing engine
db = dsInitDatabase(sys.argv[1], wd)
dl = dsInitLinks(sys.argv[2], wd)
    
if pwdump or pwhdump or suppcreddump:
    dsInitEncryption(syshive)

utype = -1
utype = dsGetTypeIdByTypeName(db, "Person")
if utype == -1:
    print("[!] Unable to get type id for Person")
    sys.exit(1)

gtype = -1
gtype = dsGetTypeIdByTypeName(db, "Group")
if gtype == -1:
    print("[!] Unable to get type id for Group")
    sys.exit(1)

groups = []
if grpdump == True:
    print("[+] Extracting group objects...")
    for recordid in dsMapLineIdByRecordId:
        if int(dsGetRecordType(db, recordid)) == gtype:
            groups.append(dsGroup(db, recordid))

if csvoutfile != "":
    write_csv(["Record ID", "User name", "User principal name", "SAM account name",
            "SAM account type", "GUID", "SID", 
            "When created", "When changed",
            "Account expires", "Password last set",
            "Last logon", "Last logon timestamp",
            "Bad password time", "Logon count", "Bad password count", "User Account Control",
            "Ancestors", "Dial-In Permission", "Member of", "Group SID", "Primary group", "Membership deletion time"
            ])

print("List of users:")
print("==============")

if sid != "":
    recordid = int(dsMapRecordIdBySID[sid])
    if int(dsGetRecordType(db, recordid)) == utype:
        user = None
        try:
            user = dsUser(db, recordid)
        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except:
            print("[!] Unable to instantiate user object (record id: %d)" % recordid)
            sys.exit(1)
        
        if only_active == True:
            if user.isActive == True:
                processUser(user)
        elif only_locked == True:
            if user.isLocked == True or user.isDisabled == True:
                processUser(user)
        else:
            processUser(user)
elif guid !="":
    recordid = int(dsMapRecordIdByGUID[guid])
    if int(dsGetRecordType(db, recordid)) == utype:
        user = None
        try:
            user = dsUser(db, recordid)
        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except:
            print("[!] Unable to instantiate user object (record id: %d)" % recordid)
            sys.exit(1)
        
        if only_active == True:
            if user.isActive == True:
                processUser(user)
        elif only_locked == True:
            if user.isLocked == True or user.isDisabled == True:
                processUser(user)
        else:
            processUser(user)
else:
    for recordid in dsMapRecordIdByTypeId[utype]:
        user = None
        try:
            user = dsUser(db, recordid)
        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except:
            print("[!] Unable to instantiate user object (record id: %d)" % recordid)
            continue
            
        if reName != None and \
           not reName.search(user.Name) and \
           not reName.search(user.SAMAccountName) and \
           not reName.search(user.PrincipalName):
            user = None
            continue
        
        if only_active == True:
            if user.isActive == True:
                processUser(user)
        elif only_locked == True:
            if user.isLocked == True or user.isDisabled == True:
                processUser(user)
        elif uac_flags != None:
            if user.UserAccountControl & uac_flags == uac_flags:
                processUser(user)
        else:
            processUser(user)

if csvoutfile != "":
    close_csv()

if ntof != None:
    ntof.close()
if lmof != None:
    lmof.close()
