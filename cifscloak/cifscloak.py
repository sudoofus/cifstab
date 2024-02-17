#!/usr/bin/env python3

import os
import sys
import stat
import time
import json
import regex
import pexpect
import sqlite3
import argparse
from syslog import syslog
from getpass import getpass
from string import Template
from cryptography.fernet import Fernet

version = '1.0.34'

class Cifscloak():

    cifstabschema = '''
        CREATE TABLE IF NOT EXISTS cifstab(
        name,
        address,
        sharename,
        mountpoint,
        options,
        user,
        password,
        PRIMARY KEY (name)
        )
        '''

    retryschema = {
        'mount': {'2':'No such file or directory - allow retry, likely to happen at boot with systemd'},
        'umount': ['target is busy.']
        }

    accepterrschema = {
        'umount':['not mounted.']
    }

    systemdtemplate = Template('''$comment\n[Unit]\nAfter=multi-user.target\nDescription=cifscloak\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=$path mount $mounts -r 6\nExecStop=$path mount -u $mounts\n\n[Install]\nWantedBy=multi-user.target''')
    
    def __init__(self,cifstabdir=os.environ.get('CIFSCLOAK_HOME',os.path.expanduser("~"))+os.sep+'.cifstab',keyfile='.keyfile',cifstab='.cifstab.db',retries=3,waitsecs=5):
        self.status = { 'error':0, 'successcount':0, 'failedcount':0, 'success':[], 'failed': [], 'attempts': {}, 'messages':[] }
        self.mountprocs = {}
        self.retries = retries
        self.waitsecs = waitsecs
        self.cifstabdir = cifstabdir
        self.cifstab = self.cifstabdir+os.sep+cifstab
        self.keyfile = self.cifstabdir+os.sep+keyfile
        self.exit = 0

        try:
            if not os.path.exists(self.cifstabdir): os.makedirs(self.cifstabdir)
        except PermissionError:
            print('PermissionError - must be root user to read cifstab')
            sys.exit(1)

        os.chmod(self.cifstabdir,stat.S_IRWXU)
        self.db = sqlite3.connect(self.cifstab)
        self.cursor = self.db.cursor()
        self.cursor.execute("PRAGMA auto_vacuum = FULL")
        self.cursor.execute(self.cifstabschema)

        if not os.path.exists(self.keyfile):
            with open(self.keyfile,'wb') as f:
                f.write(Fernet.generate_key())
            os.chmod(self.keyfile,stat.S_IRUSR)
        self.key = Fernet(open(self.keyfile,'rb').read())

    def checkstatus(self):
        if self.status['error']:
            print(json.dumps(self.status,indent=4))

    def addmount(self,args):
        if args.password is not None:
            password = args.password
        else:
            password = getpass()

        try:
            self.cursor.execute('''
            INSERT INTO cifstab (name,address,sharename,mountpoint,options,user,password)
            VALUES (?,?,?,?,?,?,?)''',
            (args.name,self.encrypt(args.ipaddress),self.encrypt(args.sharename),self.encrypt(args.mountpoint),self.encrypt(args.options),self.encrypt(args.user),self.encrypt(password)))
            self.db.commit()
        except sqlite3.IntegrityError:
            print("Cifs mount name must be unique\nExisting names:")
            self.listmounts(None)

    def removemounts(self,args):
        for name in args.names:
            self.cursor.execute('''DELETE FROM cifstab WHERE name = ?''',(name,))
            self.db.commit()
    
    def listmounts(self,args,quiet=False):
        mounts = {}
        self.cursor.execute('''SELECT name,address,sharename,mountpoint,options FROM cifstab''')
        for r in self.cursor:
            mounts[r[0]] = { 'name':r[0], 'host':self.decrypt(r[1]), 'share':self.decrypt(r[2]), 'mountpoint':self.decrypt(r[3]), 'options':('',self.decrypt(r[4]))[self.decrypt(r[4])!=' '] }        
        if not quiet:
            print(json.dumps(mounts,indent=4))

        return mounts

    def mount(self,args):

        if args.all:
            mounts = self.listmounts(None)
        else:
            mounts = list(dict.fromkeys(args.names))

        for name in mounts:
            cifsmount = self.getcredentials(name)
            if not len(cifsmount):
                message = "cifs name {} not found in cifstab".format(name)
                syslog(message)
                print(message)
                self.status['messages'].append(message)
                self.status['error'] = 1
                continue
            if args.u:
                syslog("Attempting umount {}".format(name))
                cifscmd = "umount {}".format(cifsmount['mountpoint'])
                retryon = list(self.retryschema['umount'])
                accepterr = list(self.accepterrschema.get('umount',[]))
                operation = "umount"
            else:
                syslog("Attempting mount {}".format(name))
                if not os.path.exists(cifsmount['mountpoint']):
                    os.makedirs(cifsmount['mountpoint'])
                cifscmd = "mount -t cifs -o username={},{} //{}/{} {}".format(cifsmount['user'],cifsmount['options'],cifsmount['address'],cifsmount['sharename'],cifsmount['mountpoint'])
                retryon = list(self.retryschema['mount'])
                accepterr = list(self.accepterrschema.get('mount',[]))
                operation = "mount"
            self.execute(cifscmd,name,cifsmount['password'],operation,retryon,accepterr)

    def encrypt(self,plain):
        return self.key.encrypt(bytes(plain,encoding='utf-8'))

    def decrypt(self,encrypted):
        return self.key.decrypt(encrypted).decode('utf-8')

    def getcredentials(self,name):
        credentials = {}
        self.cursor.execute('''SELECT name,address,sharename,mountpoint,options,user,password from cifstab WHERE name = ?''',(name,))
        for r in self.cursor:
            credentials = { 'name':r[0], 'address':self.decrypt(r[1]), 'sharename':self.decrypt(r[2]), 'mountpoint':self.decrypt(r[3]), 'options':self.decrypt(r[4]), 'user':self.decrypt(r[5]), 'password':self.decrypt(r[6]) }
        return credentials

    def execute(self,cmd,name,passwd,operation,retryon=[],accepterr=[],expectedreturn=0,pexpecttimeout=3):

        returncode = None
        self.status['attempts'][name] = 0
        while returncode != expectedreturn and self.status['attempts'][name] < self.retries:
            child = pexpect.spawn(cmd, timeout=pexpecttimeout)
            if operation == "mount":
                if child.expect([pexpect.TIMEOUT, "Password.*"]) != 1:
                    raise Exception("Password prompt not detected")
                child.sendline(passwd)
            output = [row.strip() for row in list(filter(None,child.read().decode("utf-8").split('\n')))]
            if operation == "mount": output.pop(0)
            output = '\n'.join(output)
            child.expect(pexpect.EOF)
            child.close()
            returncode = child.exitstatus
            if returncode and returncode != expectedreturn:
                try:
                    mounterr = regex.search(r'(?|error\((\d+)\)|.+:.+:\s{1}(.+))',output).group(1)
                except:
                    mounterr = output
                syslog('Error: {}'.format(output))
                syslog('Returned: {}'.format(returncode))
                syslog('MountErr: {}'.format(mounterr))

                if str(mounterr) not in accepterr:
                    self.status['attempts'][name] += 1
                    self.status['error'] = 1
                    self.status['messages'].append('{}: {}'.format(name,output))
                    sys.stderr.write(output)
                    if str(mounterr) in retryon:
                        time.sleep(self.waitsecs)
                    else:
                        message = 'mounterr {} not in retryschema, no retry attempt will be made'.format(mounterr)
                        syslog(message)
                        break
                else:
                    break

            self.status['attempts'][name] += 1

        if returncode != expectedreturn and str(mounterr) not in accepterr:
            self.status['error'] = 1
            self.status['failed'].append(name)
            self.status['failedcount'] += 1
        else:
            self.status['successcount'] += 1
            self.status['success'].append(name)

    def systemdfile(self,args):
        template = { 'path':sys.argv[0], 'comment':'# Generated by cifscloak' }
        notpresent = []
        listmounts = self.listmounts(None,quiet=True)
        if args.all:
            template['mounts'] = '-a'
        else:
            for mount in list(dict.fromkeys(args.names)):
                if mount not in listmounts:
                    notpresent.append(mount)
            if len(notpresent):
                comment = '# ! WARNING ! Not in the cifstab: {}'.format(' '.join(notpresent))
                template['comment'] = comment
            mounts = '-n {}'.format(' '.join(list(dict.fromkeys(args.names))))
            template['mounts'] = mounts
            
        systemdfile = self.systemdtemplate.substitute(template)
        print(systemdfile)

def main():
    defaultRetries = 3
    defaultWaitSecs = 5
    parser = argparse.ArgumentParser(description='cifscloak {} | Command line utility for mounting cifs shares using encrypted passwords'.format(version))
    subparsers = parser.add_subparsers(help='Subcommands', dest='subcommand')
    subparsers.required = True
    parser_addmount = subparsers.add_parser('addmount', help="Add cifs mount to cifstab, addmount -h for help")
    parser_addmount.add_argument("-n", "--name", help="Connection name e.g identifying server name", required=True)
    parser_addmount.add_argument("-s", "--sharename", help="Share name", required=True)
    parser_addmount.add_argument("-i", "--ipaddress", help="Server address or ipaddress", required=True)
    parser_addmount.add_argument("-m", "--mountpoint", help="Mount point", required=True)
    parser_addmount.add_argument("-u", "--user", help="User name", required=True)
    parser_addmount.add_argument("-p", "--password", help="Allows a password to be specified on the command line, otherwise getpass is used and password entry is hidden", default=None, required=False)
    parser_addmount.add_argument("-o", "--options", help="Quoted csv options e.g. \"domain=mydomain,ro\"", default=' ', required=False)
    parser_mount = subparsers.add_parser('mount', help="Mount cifs shares, mount -h for help")
    parser_mount.add_argument("-u", action='store_true', help="Unmount the named cifs shares, e.g -a films music", required=False )
    parser_mount.add_argument("-r", "--retries", help="Optional ( default: 3 ) - Retry count, useful when systemd is in play", required=False, default=3, type=int )
    parser_mount.add_argument("-w", "--waitsecs", help="Optional ( default: 5 seconds ) - Wait time in seconds between retries", required=False, default=5, type=int )
    group = parser_mount.add_mutually_exclusive_group(required=True)
    group.add_argument("-n", "--names", nargs="+", help="Mount reference names, e.g -n films music. --names and --all are mutually exclusive", required=False)
    group.add_argument("-a", "--all", action='store_true', help="Mount everything in the cifstab.", required=False)
    parser_removemounts = subparsers.add_parser('removemounts', help="Remove cifs mounts from cifstab. removemount -h for help")
    parser_removemounts.add_argument("-n", "--names", nargs="+", help="Remove cifs mounts from cifstabe.g. -a films music", required=True)
    parser_listmounts = subparsers.add_parser('listmounts', help="Display cifstab shares")
    parser_systemdfile = subparsers.add_parser('systemdfile', help="Generate systemd unit file output")
    systemdgroup = parser_systemdfile.add_mutually_exclusive_group(required=True)
    systemdgroup.add_argument("-n","--names", nargs="+", help="Add named shares to the systemd unit file")
    systemdgroup.add_argument("-a","--all", action='store_true', help="Add all cifstab shares to the systemd unit file")
    args = parser.parse_args()
    cifscloak = Cifscloak(retries=getattr(args,'retries',defaultRetries),waitsecs=getattr(args,'waitsecs',defaultWaitSecs))
    getattr(cifscloak, args.subcommand)(args)
    cifscloak.checkstatus()
    parser.exit(status=cifscloak.status['error'])

if __name__ == "__main__":
    main()
