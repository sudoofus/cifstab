#!/usr/bin/env python3

import os
import sys
import stat
import time
import json
import regex
import sqlite3
import argparse
import subprocess
from syslog import syslog
from getpass import getpass
from cryptography.fernet import Fernet

class Cifscloak():

    retryschema = {
        'mount': {'16':'Device or resource busy'},
        'umount': ['target is busy.']
        }

    def __init__(self,cifstabdir='/root/.cifstab',keyfile='.keyfile',cifstab='.cifstab.db',retries=3,waitsecs=5):
        self.status = { 'error':0, 'successcount':0, 'failedcount':0, 'success':[], 'failed': [], 'attempts': {}, 'messages':[] }
        self.mountprocs = {}
        self.exit = 0
        self.retries = retries
        self.waitsecs = waitsecs
        self.cifstabdir = cifstabdir
        self.cifstab = self.cifstabdir+os.sep+cifstab
        self.keyfile = self.cifstabdir+os.sep+keyfile
        if not os.path.exists(self.cifstabdir): os.makedirs(self.cifstabdir)
        os.chmod(self.cifstabdir,stat.S_IRWXU)
        self.db = sqlite3.connect(self.cifstab)
        self.cursor = self.db.cursor()
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS cifstab(alias,address,sharename,mountpoint,options,user,password,PRIMARY KEY (alias))''')
        if not os.path.exists(self.keyfile):
            with open(self.keyfile,'wb') as f:
                f.write(Fernet.generate_key())
            os.chmod(self.keyfile,stat.S_IRUSR)
        self.key = Fernet(open(self.keyfile,'rb').read())

    def checkstatus(self):
        if self.status['error']:
            print(json.dumps(self.status,indent=4))
        parser.exit(status=cifscloak.status['error'])

    def addmount(self,args):
        password = getpass()
        try:
            self.cursor.execute('''
            INSERT INTO cifstab (alias,address,sharename,mountpoint,options,user,password)
            VALUES (?,?,?,?,?,?,?)''',
            (args.alias,self.encrypt(args.ipaddress),self.encrypt(args.sharename),self.encrypt(args.mountpoint),self.encrypt(args.options),self.encrypt(args.user),self.encrypt(password)))
            self.db.commit()
        except sqlite3.IntegrityError:
            print("Cifs mount alias must be unique\nExisting aliases:")
            self.listmounts(None)

    def removemounts(self,args):
        for alias in args.aliases:
            self.cursor.execute('''DELETE FROM cifstab WHERE alias = ?''',(alias,))
            self.db.commit()
    
    def listmounts(self,args):
        self.cursor.execute('''SELECT alias FROM cifstab''')
        for r in self.cursor:
            print(r[0])

    def mount(self,args):
        for alias in list(dict.fromkeys(args.aliases)):
            cifsmount = self.getcredentials(alias)
            if not len(cifsmount):
                message = "cifs alias {} not found in cifstab".format(alias)
                syslog(message)
                print(message)
                self.status['messages'].append(message)
                self.status['error'] = 1
                continue
            if args.u:
                syslog("Attempting umount {}".format(alias))
                cifscmd = "umount {}".format(cifsmount['mountpoint'])
                retryon = list(self.retryschema['umount'])
            else:
                syslog("Attempting mount {}".format(alias))
                if not os.path.exists(cifsmount['mountpoint']):
                    os.makedirs(cifsmount['mountpoint'])
                cifscmd = "mount -t cifs -o username={},password={},{} //{}/{} {}".format(cifsmount['user'],cifsmount['password'],cifsmount['options'],cifsmount['address'],cifsmount['sharename'],cifsmount['mountpoint'])
                retryon = list(self.retryschema['mount'])
            self.execute(cifscmd,alias,retryon)

    def encrypt(self,plain):
        return self.key.encrypt(bytes(plain,encoding='utf-8'))

    def decrypt(self,encrypted):
        return self.key.decrypt(encrypted).decode('utf-8')

    def getcredentials(self,alias):
        credentials = {}
        self.cursor.execute('''SELECT alias,address,sharename,mountpoint,options,user,password from cifstab WHERE alias = ?''',(alias,))
        for r in self.cursor:
            credentials = { 'alias':r[0], 'address':self.decrypt(r[1]), 'sharename':self.decrypt(r[2]), 'mountpoint':self.decrypt(r[3]), 'options':self.decrypt(r[4]), 'user':self.decrypt(r[5]), 'password':self.decrypt(r[6]) }
        return credentials

    def execute(self,cmd,alias,retryon=[],expectedreturn=0):
        returncode = None
        self.status['attempts'][alias] = 0
        while returncode != expectedreturn and self.status['attempts'][alias] < self.retries:
            
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, shell=True)
            stdout, stderr = proc.communicate()
            returncode = proc.returncode
            if proc.returncode and proc.returncode != expectedreturn:
                mounterr = regex.search(r'(?|error\((\d+)\)|.+:.+:\s{1}(.+))',stderr).group(1)
                syslog('Error: {}'.format(stderr))
                syslog('Returned: {}'.format(proc.returncode))
                syslog('MountErr: {}'.format(mounterr))
                self.status['error'] = 1
                self.status['messages'].append('{}: {}'.format(alias,stderr))
                sys.stderr.write(stderr)
                if str(mounterr) in retryon:
                    time.sleep(self.waitsecs)
                else:
                    message = 'mounterr {} not in retryschema, no retry attempt will be made'.format(mounterr)
                    syslog(message)
                    break

            self.status['attempts'][alias] += 1
                
        if returncode != expectedreturn:
            self.status['error'] = 1
            self.status['failed'].append(alias)
            self.status['failedcount'] += 1
        else:
            self.status['successcount'] += 1
            self.status['success'].append(alias)


if __name__ == "__main__":

    defaultRetries = 3
    defaultWaitSecs = 5
    
    parser = argparse.ArgumentParser(description='cifscloak - command line utility for mounting cifs shares using encrypted passwords')
    subparsers = parser.add_subparsers(help='Subcommands', dest='subcommand', required=True)   
    parser_addmount = subparsers.add_parser('addmount', help="Add a cifs mount to encrypted cifstab. addmount -h for help")
    parser_addmount.add_argument("-u", "--user", help="User name", required=True)
    parser_addmount.add_argument("-s", "--sharename", help="Share name", required=True)
    parser_addmount.add_argument("-m", "--mountpoint", help="Mount point", required=True)
    parser_addmount.add_argument("-o", "--options", help="Quoted csv options e.g. \"domain=mydomain,ro\"", default=' ', required=False)
    parser_addmount.add_argument("-i", "--ipaddress", help="Server address or ipaddress", required=True)
    parser_addmount.add_argument("-a", "--alias", help="Connection name e.g identifying server name", required=True)
    
    parser_removemounts = subparsers.add_parser('removemounts', help="Remove cifs mounts from encrypted cifstab. removemount -h for help")
    parser_removemounts.add_argument("-a", "--aliases", nargs="+", help="Remove cifs mounts e.g. -n mnt1 mnt2", required=True)

    parser_listmounts = subparsers.add_parser('listmounts', help="List cifs mounts in encrypted cifstab")

    parser_mount = subparsers.add_parser('mount', help="mount -h for help")
    parser_mount.add_argument("-a", "--aliases", nargs="+", help="Mount reference names, e.g -n mnt1 mnt2", required=True)
    parser_mount.add_argument("-u", action='store_true', help="Unmount the named cifs shares, e.g -n mnt1 mnt2", required=False )
    parser_mount.add_argument("-r", "--retries", help="Retry count, useful when systemd is in play", required=False, default=3, type=int )
    parser_mount.add_argument("-w", "--waitsecs", help="Wait time in seconds between retries", required=False, default=5, type=int )

    args = parser.parse_args()
    retries = getattr(args, 'retries', defaultRetries)
    waitsecs = getattr(args, 'waitsecs', defaultWaitSecs)
    cifscloak = Cifscloak(retries=retries,waitsecs=waitsecs)
    getattr(cifscloak, args.subcommand)(args)
    cifscloak.checkstatus()

