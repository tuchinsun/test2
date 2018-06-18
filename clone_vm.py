#!/usr/bin/env python2
# -*- coding: utf-8 -*-


#
# Cloning container
#

import argparse
import subprocess
import string
import re
import os
import json
import mysql.connector

prlctl = '/usr/bin/prlctl'

db = {
    'user': 'cluster',
    'pass': 'icBcTHAxUQuw',
    'host': '192.168.0.3',
    'name': 'pdns',
}

def run_cmd(cmd):
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    return stdout

def get_container_ip(container):
    cmd = '/usr/bin/prlctl list -j ' + container
    data = run_cmd(cmd)
    vps = json.loads(data)[0]
    return vps['ip_configured']


parser = argparse.ArgumentParser(description='Clone manager', add_help=True)
parser.add_argument('job', nargs='?', help='Work with [add|del]')
parser.add_argument('--co', dest='name_old', required=1, help='Old Container name. Specify if you need delete also.')
parser.add_argument('--cn', dest='name_new', help='New Container name')
parser.add_argument('--hn', dest='hostname_new', help='Hostname for the new Container')
parser.add_argument('--ip', help='New container IP')

args = parser.parse_args()
#print (args)

cnx = mysql.connector.connect(host=db['host'], user=db['user'], passwd=db['pass'], database=db['name'])
cursor = cnx.cursor()

add_host = ("INSERT INTO records (domain_id,name,type,content,ttl,prio,auth)"
            " VALUES(4, 'www.lab1.jelastic.team', 'A', %(ip)s, 3600, 0, 1)")
            
del_host = ("DELETE FROM records WHERE name='www.lab1.jelastic.team' AND content=%(ip)s")

if args.job == 'add':
    print '-- Add container'
    if re.search('\d+\.\d+\.\d+\.\d+', args.ip):
        print 'IP for new container: ', args.ip
        cnt = {
            'name_old': args.name_old,
            'name_new': args.name_new,
            'ip_old': get_container_ip(args.name_old),
            'ip_new': args.ip,
            'hostname_new': args.hostname_new,
        }
        
        #
        # clone VM
        #
        
        # prlctl clone ct1 --name ct2
        print ' Clone container ', cnt['name_old']
        cmd = prlctl + ' clone ' + cnt['name_old'] + ' --name ' + cnt['name_new']
        run_cmd(cmd)
        
        # prlctl set ct2 --ipdel 192.168.0.161/24
        print ' Delete old IP', cnt['ip_old']
        cmd = prlctl + ' set ' + cnt['name_new'] + ' --ipdel ' + cnt['ip_old'] + '/24'
        run_cmd(cmd)
        
        # prlctl set ct2 --ipadd 192.168.0.162/24
        print ' Add new IP', cnt['ip_new']
        cmd = prlctl + ' set ' + cnt['name_new'] + ' --ipadd ' + cnt['ip_new'] + '/24'
        run_cmd(cmd)
        
        # prlctl set ct1 --hostname ct2
        print ' Set new hostname'
        cmd = prlctl + ' set ' + cnt['name_new'] + ' --hostname ' + cnt['hostname_new']
        run_cmd(cmd)
        
        # prlctl start ct2
        print ' Start container ', cnt['name_new']
        cmd = prlctl  + ' start ' + cnt['name_new']
        run_cmd(cmd)
        
        #
        # add rr to zone
        #
        
        # pdnsutil add-record lab1.jelastic.team www A 192.168.1.1
        data = {
            'ip': cnt['ip_new'],
        }
        cursor.execute(add_host, data)
        cnx.commit()
        
    else:
        print 'You should specify IP for new container!'
        exit(0)
elif args.job == 'del':
    print '-- Delete container'
    ip = get_container_ip(args.name_old)

    # prlctl stop ct1
    print ' Stop container ', args.name_old
    cmd = prlctl + ' stop ' + args.name_old
    run_cmd(cmd)
        
    # prlctl delete ct1
    print ' Delete container ', args.name_old
    cmd = prlctl + ' delete ' + args.name_old
    run_cmd(cmd)
    
    data = {
        'ip': ip,
    }
    
    cursor.execute(del_host, data)
    cnx.commit()

else:
    print 'Specify job: add or del'
    exit(0)
    

cnx.close()

# END
