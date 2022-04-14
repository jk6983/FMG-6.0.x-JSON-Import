#!/usr/bin/python
#Script Notes:
#   Sept 6, 2019
#   Written by Mark Kellerman, Fortinet Pro Services, mkellerman@fortinet.com
#       Purpose:  Script Automation using JSON/API Calls directly to FMG
#       JSON API Calls - based on FMG 6.0.x
#       rpc-admin enabled account must exist on FMG
#       verify at FMG CLI with command: show system admin user <JSON_api_user>
#       EX:  show system admin user admin
#       Output to verify:     set rpc-permit read-write
#       rpc-permit must be set to read-write on the user account that you are using in this script.
#       You will be prompted for the rpc-admin enabled account as well as password
#       IP Address must be defined below.  Modify it accordingly to match your FMG
#       Be sure to update hostIP below to correct IP addresss
#   
 
import re
import csv
import json
import os
import os.path
import sys
import time
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

requests.packages.urllib3.disable_warnings()

# Global VARs, change to match your local
# Define IP Address of FMG to make JSON/API Calls against
hostIP = '172.20.10.218'

url = 'https://' + hostIP + '/jsonrpc/json'
session = ''
state = 0
adomRAW = ''
fgtLIST = []
adomLIST = []
taskID = ''
adomLISTraw = []
option = ''
adom = ''
workspacemode = False
continuescript = True

def fmg_login():
    global session
    
    hostADMIN = input("Enter JSON Username of FMG" + "\n")
    hostPASSWD = input("Enter Password for FMG" + "\n")
    
    body = {
        "id": 1,
        "method": "exec",
        "params": [{
            "url": "sys/login/user",
            "data": [{
                "user": hostADMIN,
                "passwd": hostPASSWD
            }]
        }],
        "session": 1
    }
    r = requests.post(url, json=body, verify=False)
    json_resp = json.loads(r.text)
    session = json_resp['session']
    print ('--> Logging into FMG: %s' % hostIP)
    print ('<-- Hcode: %d Jmesg: %s' %
           (r.status_code, json_resp['result'][0]['status']['message']))
    print ("\n")

####################
def fmg_logout():

    body = {
    "id": 35,
            "method": "exec",
            "params": [{
                    "url": "sys/logout",
            
            }],
            "session": session
    }
    r = requests.post(url, json=body, verify=False)
    json_resp = json.loads(r.text)
    print ('--> Logging out of FMG: %s' % hostIP)
    print ('<-- Hcode: %d Jmesg: %s' %
           (r.status_code, json_resp['result'][0]['status']['message']))

############################
def create_address_object():
    global session
    with open('address-objects.txt', 'r') as csv_file:
        csvreader = csv.DictReader(csv_file, delimiter='\t')

        #url = 'https://' + hostIP + '/jsonrpc/json'

        adom = input("Enter FMG ADOM that objects should be imported into." + "\n")

        Eout = open("JSON-SpecificErrors-Add-AddressObjects.txt", "w")

        if (workspacemode):
            workspace_lock(adom)

        for row in csvreader:

            addrname = row['Name'].strip()
            addripv4 = row['IPv4'].strip()
            addrmask = row['Mask'].strip()
            #addrcomments = row['Comments'].strip()

            
            ##################
            print('Importing Following Address Object into FMG: ' + addrname + ' for ADOM: ' + adom)

            ##########################################################################
            # Create JSON API Call Structure - To Add Network Address  Objects
            ##########################################################################

            body = {
                "id": 2,
                "method": "add",
                "params": [{
                    "url": "pm/config/adom/" + adom + "/obj/firewall/address",
                    "data": [{
                        "name": addrname,
                        "subnet": [addripv4, addrmask]
                    }]

                }],
                "session": session
            }
            r = requests.post(url, json=body, verify=False)
            json_resp = json.loads(r.text)

            statusmsg = json_resp['result'][0]['status']['message']
            #Does json_resp contain a match for 'datasrc invalid' - if so write it to error file
            m = re.search("datasrc invalid", statusmsg)
            #If match then call function to write error to Error file with import/update function and error message
            if m:

                function = "Import of Address Objects"
                errormsg = json_resp['result'][0]['status']['message']
               
                #Uncomment for debugging purposes
                #print ("TEST CONDITION MET: " + errormsg + "\n")
                Eout.write(function + ":\t" + errormsg + "\n")

            print ('<-- Hcode: %d Jmesg: %s' %
                    (r.status_code, json_resp['result'][0]['status']['message']))
        
        #Commit changes and unlock FMG DB
        if (workspacemode):
            workspace_commit(adom)
            workspace_unlock(adom)

###########################
def create_host_object():
    global session
    with open('host-objects.txt', 'r') as csv_file:
        csvreader = csv.DictReader(csv_file, delimiter='\t')

        adom = input("Enter FMG ADOM that objects should be imported into." + "\n")
        
        Eout = open("JSON-SpecificErrors-Add-HostObjects.txt", "w")
        
        if (workspacemode):
            workspace_lock(adom)

        for row in csvreader:

            addrname = row['Name'].strip()
            addripv4 = row['IPV4'].strip()
        
            ##################
            print('Importing Following Host Objects into FMG: ' + addrname + ' for ADOM: ' + adom)

            ##########################################################################
            # Create JSON API Call Structure - To Add Host  Objects
            ##########################################################################

            body = {
                "id": 3,
                "method": "add",
                "params": [{
                    "url": "pm/config/adom/" + adom + "/obj/firewall/address",
                    "data": [{
                        "name": addrname,
                        "subnet": [addripv4, "255.255.255.255"]
                    }]

                }],
                "session": session
            }
            r = requests.post(url, json=body, verify=False)
            json_resp = json.loads(r.text)

            statusmsg = json_resp['result'][0]['status']['message']
            #Does json_resp contain a match for 'datasrc invalid' - if so write it to error file
            m = re.search("datasrc invalid", statusmsg)
            #If match then call function to write error to Error file with import/update function and error message
            if m:

                function = "Import of Host Objects"
                errormsg = json_resp['result'][0]['status']['message']
             
                #Uncomment for debugging purposes
                #print ("TEST CONDITION MET: " + errormsg + "\n")
                Eout.write(function + ":\t" + errormsg + "\n")

            print ('<-- Hcode: %d Jmesg: %s' %
                    (r.status_code, json_resp['result'][0]['status']['message']))

        #Commit changes and unlock FMG DB
        if (workspacemode):
            workspace_commit(adom)
            workspace_unlock(adom)

###########################
def create_iprange_object():
    global session
    with open('iprange.txt', 'r') as csv_file:
        csvreader = csv.DictReader(csv_file, delimiter='\t')

        adom = input("Enter FMG ADOM that objects should be imported into." + "\n")

        Eout = open("JSON-SpecificErrors-Add-IPRange-Objects.txt", "w")

        if (workspacemode):
            workspace_lock(adom)

        for row in csvreader:

            iprangename = row['Name'].strip()
            startipv4 = row['StartIP'].strip()
            endipv4 = row['EndIP'].strip()
            iprangecomments = row['Comments'].strip()

            
            ##################
            print('Importing Following IP Range Object into FMG: ' + iprangename + ' for ADOM: ' + adom)

            ##########################################################################
            # Create JSON API Call Structure - To Add IP Range Address  Objects
            ##########################################################################

            body = {
                "id": 4,
                "method": "add",
                "params": [{
                    "url": "pm/config/adom/" + adom + "/obj/firewall/address",
                    "data": [{
                        "name": iprangename,
                        "type": "iprange",
                        "start-ip": startipv4,
                        "end-ip": endipv4,
                        "comment": iprangecomments
                    }]

                }],
                "session": session
            }
            r = requests.post(url, json=body, verify=False)
            json_resp = json.loads(r.text)

            statusmsg = json_resp['result'][0]['status']['message']
            #Does json_resp contain a match for 'datasrc invalid' - if so write it to error file
            m = re.search("datasrc invalid", statusmsg)
            #If match then call function to write error to Error file with import/update function and error message
            if m:

                function = "Import of IP Range Address Objects"
                errormsg = json_resp['result'][0]['status']['message']
               
                #Uncomment for debugging purposes
                #print ("TEST CONDITION MET: " + errormsg + "\n")
                Eout.write(function + ":\t" + errormsg + "\n")

            print ('<-- Hcode: %d Jmesg: %s' %
                    (r.status_code, json_resp['result'][0]['status']['message']))

        #Commit changes and unlock FMG DB
        if (workspacemode):
            workspace_commit(adom)
            workspace_unlock(adom)

###########################
def create_service_object():
    global session
    with open('service-objects.txt', 'r') as csv_file:
        csvreader = csv.DictReader(csv_file, delimiter='\t')

        adom = input("Enter FMG ADOM that objects should be imported into." + "\n")

        Eout = open("JSON-SpecificErrors-Add-ServiceObjects.txt", "w")

        if (workspacemode):
            workspace_lock(adom)

        for row in csvreader:

            servicename = row['Name'].strip()
            serviceproto = row['Protocol'].strip()
            serviceport = row['Port'].strip()
            servicecomments = row['Comments'].strip()

            print('Importing Following Service Object into FMG: ' + servicename + ' for ADOM: ' + adom)

            #########################################################
            # Create JSON API Call Structure - To Add Service Objects
            #########################################################

            # If protocol is blank (Indicated TCP and UDP),  then create JSON API Structure for both tcp-portrange and udp-portrange definition
            if ((serviceproto != 'tcp') and (serviceproto != 'udp')):

                body = {
                    "id": 5,
                    "method": "add",
                    "params": [{
                        "url": "pm/config/adom/" + adom + "/obj/firewall/service/custom",
                        "data": [{
                            "name": servicename,
                            "tcp-portrange": serviceport,
                            "udp-portrange": serviceport,
                            "comment": servicecomments
                        }]

                    }],
                    "session": session
                }
                r = requests.post(url, json=body, verify=False)
                json_resp = json.loads(r.text)

                print ('<-- Hcode: %d Jmesg: %s' %
                        (r.status_code, json_resp['result'][0]['status']['message']))

            # If protocol is TCP ONLY, then create JSON API Structure for setting tcp-portange
            if (serviceproto == 'tcp'):

                body = {
                    "id": 6,
                    "method": "add",
                    "params": [{
                        "url": "pm/config/adom/" + adom + "/obj/firewall/service/custom",
                        "data": [{
                            "name": servicename,
                            "tcp-portrange": serviceport,
                            "comment": servicecomments
                        }]

                    }],
                    "session": session
                }
                r = requests.post(url, json=body, verify=False)
                json_resp = json.loads(r.text)

                print ('<-- Hcode: %d Jmesg: %s' %
                        (r.status_code, json_resp['result'][0]['status']['message']))

            # If protocol is UDP ONLY, then create JSON API Structure for setting udp-portange
            if (serviceproto == 'udp'):

                body = {
                    "id": 7,
                    "method": "add",
                    "params": [{
                        "url": "pm/config/adom/" + adom + "/obj/firewall/service/custom",
                        "data": [{
                            "name": servicename,
                            "udp-portrange": serviceport,
                            "comment": servicecomments
                        }]

                    }],
                    "session": session
                }
                r = requests.post(url, json=body, verify=False)
                json_resp = json.loads(r.text)

                statusmsg = json_resp['result'][0]['status']['message']
                #Does json_resp contain a match for 'datasrc invalid' - if so write it to error file
                m = re.search("datasrc invalid", statusmsg)
                #If match then call function to write error to Error file with import/update function and error message
                if m:

                    function = "Import of Service Objects"
                    errormsg = json_resp['result'][0]['status']['message']
                
                    #Uncomment for debugging purposes
                    #print ("TEST CONDITION MET: " + errormsg + "\n")
                    Eout.write(function + ":\t" + errormsg + "\n")

                print ('<-- Hcode: %d Jmesg: %s' %
                        (r.status_code, json_resp['result'][0]['status']['message']))

        #Commit changes and unlock FMG DB
        if (workspacemode):
            workspace_commit(adom)
            workspace_unlock(adom)

#######################
def create_address_groups():

    global session
    with open('addrgrp.txt', 'r') as csv_file:
        csvreader = csv.DictReader(csv_file, delimiter='\t')

        adom = input("Enter FMG ADOM that objects should be imported into." + "\n")

        Eout = open("JSON-SpecificErrors-Add-AddressGroups.txt", "w")
        
        if (workspacemode):
            workspace_lock(adom)

        for row in csvreader:

            addrgrpname = row['Name'].strip()
            grpmembers = row['Members'].strip()
        
            ##################
            print('Importing Following Address Groups into FMG: ' + addrgrpname + ' for ADOM: ' + adom)

            ##########################################################################
            # Create JSON API Call Structure - To Add Address Group  Objects
            ##########################################################################

            # With Quotatoins Added
            addrgrp_list = (',').join(['"' + item.strip() + '"' for item in grpmembers.split(
                ';') if not item.strip().startswith('!') and not item.strip() == ""])
            # Strip of Quotations
            addrgrp_list1 = [x.strip('"') for x in addrgrp_list.split(",")]

            body = {
                "id": 8,
                "method": "add",
                "params": [{
                    "url": "pm/config/adom/" + adom + "/obj/firewall/addrgrp",
                    "data": [{
                        "name": addrgrpname,
                        "member": addrgrp_list1
                    }]

                }],
                "session": session
            }
            r = requests.post(url, json=body, verify=False)
            json_resp = json.loads(r.text)

            statusmsg = json_resp['result'][0]['status']['message']
            #Does json_resp contain a match for 'datasrc invalid' - if so write it to error file
            m = re.search("datasrc invalid", statusmsg)
            #If match then call function to write error to Error file with import/update function and error message
            if m:

                function = "Import of Address Groups"
                errormsg = json_resp['result'][0]['status']['message']
                ### write_error_file(errormsg, function)
                #Uncomment for debugging purposes
                #print ("TEST CONDITION MET: " + errormsg + "\n")
                Eout.write(function + ":\t" + errormsg + "\n")


            print ('<-- Hcode: %d Jmesg: %s' %
                    (r.status_code, json_resp['result'][0]['status']['message']))

        #Commit changes and unlock FMG DB
        if (workspacemode):
            workspace_commit(adom)
            workspace_unlock(adom)

#######################
def create_service_groups():

    global session
    with open('servicegrp.txt', 'r') as csv_file:
        csvreader = csv.DictReader(csv_file, delimiter='\t')

        adom = input("Enter FMG ADOM that objects should be imported into." + "\n")

        Eout = open("JSON-SpecificErrors-Add-ServiceGroups.txt", "w")
        
        workspace_lock(adom)

        for row in csvreader:

            svcgrpname = row['Name'].strip()
            svcgrpmembers = row['Members'].strip()
        
            ##################
            print('Importing Following Service Groups into FMG: ' + svcgrpname + ' for ADOM: ' + adom)

            ##########################################################################
            # Create JSON API Call Structure - To Add Service Group  Objects
            ##########################################################################

            # With Quotatoins Added
            svcgrp_list = (',').join(['"' + item.strip() + '"' for item in svcgrpmembers.split(
                ';') if not item.strip().startswith('!') and not item.strip() == ""])
            # Strip of Quotations
            svcgrp_list1 = [x.strip('"') for x in svcgrp_list.split(",")]

            body = {
                "id": 9,
                "method": "add",
                "params": [{
                    "url": "pm/config/adom/" + adom + "/obj/firewall/service/group",
                    "data": [{
                        "name": svcgrpname,
                        "member": svcgrp_list1
                    }]

                }],
                "session": session
            }
            r = requests.post(url, json=body, verify=False)
            json_resp = json.loads(r.text)

            statusmsg = json_resp['result'][0]['status']['message']
            #Does json_resp contain a match for 'datasrc invalid' - if so write it to error file
            m = re.search("datasrc invalid", statusmsg)
            #If match then call function to write error to Error file with import/update function and error message
            if m:

                function = " Import of Service Groups"
                errormsg = json_resp['result'][0]['status']['message']
                ### write_error_file(errormsg, function)
                #Uncomment for debugging purposes
                #print ("TEST CONDITION MET: " + errormsg + "\n")
                Eout.write(function + ":\t" + errormsg + "\n")

            print ('<-- Hcode: %d Jmesg: %s' %
                    (r.status_code, json_resp['result'][0]['status']['message']))

        #Commit changes and unlock FMG DB
        if (workspacemode):
            workspace_commit(adom)
            workspace_unlock(adom)

#######################
def create_vip_object():
    global session
    with open('vip.txt', 'r') as csv_file:
        csvreader = csv.DictReader(csv_file, delimiter='\t')

        adom = input("Enter FMG ADOM that objects should be imported into." + "\n")

        Eout = open("JSON-SpecificErrors-Add-VIP Objects.txt", "w")

        if (workspacemode):
            workspace_lock(adom)

        for row in csvreader:

            vipname = row['Name'].strip()
            vipextip = row['ExtIP'].strip()
            vipmappedip = row['MappedIP'].strip()
            vipportforward = row['PortForward'].strip()
            vipprotocol = row['Protocol'].strip()
            vipextport = row['ExtPort'].strip()
            vipmappedport = row['MappedPort'].strip()
            vipcomments = row['Comments'].strip()

            
            #########################################################################
            print('Importing Following VIP Object into FMG: ' + vipname + ' for ADOM: ' + adom)

            ##########################################################################
            # Create JSON API Call Structure - To Add VIP (Virtual IP)  Objects
            ##########################################################################

            if (vipportforward == "disable"):

                body = {
                    "id": 17,
                    "method": "add",
                    "params": [{
                        "url": "pm/config/adom/" + adom + "/obj/firewall/vip",
                        "data": [{
                            "name": vipname,
                            "extip": vipextip,
                            "mappedip": [vipmappedip],
                            "extintf": "any",
                            "portforward": "disable",
                            "comment": vipcomments
                        }]

                    }],
                    "session": session
                }

            if (vipportforward == "enable"):

                body = {
                    "id": 17,
                    "method": "add",
                    "params": [{
                        "url": "pm/config/adom/" + adom + "/obj/firewall/vip",
                        "data": [{
                            "name": vipname,
                            "extip": vipextip,
                            "mappedip": [vipmappedip],
                            "extintf": "any",
                            "portforward": vipportforward,
                            "protocol": vipprotocol,
                            "extport": vipextport,
                            "mappedport": vipmappedport,
                            "comment": vipcomments
                        }]

                    }],
                    "session": session
                }

            r = requests.post(url, json=body, verify=False)
            json_resp = json.loads(r.text)

            statusmsg = json_resp['result'][0]['status']['message']
            #Does json_resp contain a match for 'datasrc invalid' - if so write it to error file
            m = re.search("datasrc invalid", statusmsg)
            #If match then call function to write error to Error file with import/update function and error message
            if m:

                function = "Import of VIP Objects"
                errormsg = json_resp['result'][0]['status']['message']
               
                #Uncomment for debugging purposes
                #print ("TEST CONDITION MET: " + errormsg + "\n")
                Eout.write(function + ":\t" + errormsg + "\n")

            print ('<-- Hcode: %d Jmesg: %s' %
                    (r.status_code, json_resp['result'][0]['status']['message']))
        
        #Commit changes and unlock FMG DB
        if (workspacemode):
            workspace_commit(adom)
            workspace_unlock(adom)

#######################
def create_ippool_object():
    global session
    with open('ippool.txt', 'r') as csv_file:
        csvreader = csv.DictReader(csv_file, delimiter='\t')

        adom = input("Enter FMG ADOM that objects should be imported into." + "\n")

        Eout = open("JSON-SpecificErrors-Add-IPPool-Objects.txt", "w")

        workspace_lock(adom)

        for row in csvreader:

            poolname = row['Name'].strip()
            pooltype = row['Type'].strip()
            poolstartip = row['StartIP'].strip()
            poolendip = row['EndIP'].strip()
            poolarpreply = row['ArpReply'].strip()
            poolcomments = row['Comments'].strip()

            #########################################################################
            print('Importing Following IPPool Object into FMG: ' + poolname + ' for ADOM: ' + adom)

            ##########################################################################
            # Create JSON API Call Structure - To Add SNAT IPPool  Objects
            ##########################################################################

            body = {
                "id": 18,
                "method": "add",
                "params": [{
                    "url": "pm/config/adom/" + adom + "/obj/firewall/ippool",
                    "data": [{
                        "name": poolname,
                        "startip": poolstartip,
                        "endip": poolendip,
                        "arp-reply": poolarpreply,
                        "type": "overload",
                        "comments": poolcomments  
                    }]

                }],
                "session": session
            }

            r = requests.post(url, json=body, verify=False)
            json_resp = json.loads(r.text)

            #print(r.text)

            statusmsg = json_resp['result'][0]['status']['message']
            #Does json_resp contain a match for 'datasrc invalid' - if so write it to error file
            m = re.search("invalid", statusmsg)
            #If match then call function to write error to Error file with import/update function and error message
            if m:

                function = "Import of IPPool Objects"
                errormsg = json_resp['result'][0]['status']['message']
               
                #Uncomment for debugging purposes
                #print ("TEST CONDITION MET: " + errormsg + "\n")
                Eout.write(function + ":\t" + errormsg + "\n")

            print ('<-- Hcode: %d Jmesg: %s' %
                    (r.status_code, json_resp['result'][0]['status']['message']))

        #Commit changes and unlock FMG DB
        if (workspacemode):
            workspace_commit(adom)
            workspace_unlock(adom)

#######################
def add_policy_rules():
    global session

    with open('rulebase.txt', 'r') as csv_file:
        csvreader = csv.DictReader(csv_file, delimiter='\t')
        
        #Excel Column Headers
        #   No.     Name     Source    Destination     Services & Applications     Nat     Ippool     Action     Track
        #TAB Delimited Excel File

        adom = input("Enter FMG ADOM that rulebase should be imported into." + "\n")
        pkg = input("Enter the Policy Package Name to apply the rulebase to." + "\n")

        Eout = open("JSON-SpecificErrors-Add-PolicyRules.txt", "w")

        if (workspacemode):
            workspace_lock(adom)

        for row in csvreader:

            polid = row['No.'].strip()
            name = row['Name'].strip()
            src = row['Source'].strip()
            dst = row['Destination'].strip()
            service = row['Services'].strip()
            nat = row['Nat'].strip()
            ippool = row['Ippool'].strip()
            action = row['Action'].strip()
            track = row['Track'].strip()
 
            print('Creating NEW PolicyID into FMG: ' + polid + ' for ADOM ' + adom + "\n")
            
            #Avoid - Duplicate Name Errors - concatenate name value with policy id
            if name:
                name1 = name + ":" + polid
            else:
                name1 = name
            ###############################################################################
            # Create JSON API Call Structure - To Add Security Profiles to Existing Rules #
            ###############################################################################

            #Debugging Script Purposes
            #print ("Policy ID is: " + polid + "\n")
            #print ("Source Addr is: " + srcaddr + "\n")
            #print ("Dest Addr is: " + dstaddr + "\n")
            #print ("Services is: " + service + "\n")
            #print ("Nat is: " + nat + "\n")
            #print ("Ippool is: " + ippool + "\n")
            #print ("Action is: " + action + "\n")
            #print ("Track is: " + polid + "\n")

            #Modify values for Check Point's particular export values - Accept=accept and Drop=deny
            #Note - Changing the column in the spreadsheet to 'IGNORE' will prevent the rule from being created in the CLI/FortiSpeak code
            if((action == 'Accept') or (action == 'Drop')):

                if (action == 'Accept'):
                
                    action = 'accept'
            
                if (action == 'Drop'):

                    action = "deny"

            #Modify value "Any" for either Source or Destination
            #Any=all
            if (src == 'Any'):

                src = 'all'

            if (dst == 'Any'):

                dst = 'all'

            #Modify value for "Any" for service

            if (service == "Any"):

                service = "ALL"
                
            if (service == "dns"):
            
            	service = "DNS"
            
            if (service == "http"):
            
            	service = "HTTP"
            	
            if (service == "https"):
            
            	service = "HTTPS"
            	
            if (service == "traceroute"):
            
            	service = "TRACEROUTE"
            	
            if (service == "icmp-requests"):
            
            	service == "echo"

            # With Quotatoins Added
            src_list = (',').join(['"' + item.strip() + '"' for item in src.split(
                ';') if not item.strip().startswith('!') and not item.strip() == ""])
            # Strip of Quotations
            src_list1 = [x.strip('"') for x in src_list.split(",")]

            # With Quotations Added
            dst_list = (',').join(['"' + item.strip() + '"' for item in dst.split(
                ';') if not item.strip().startswith('!') and not item.strip() == ""])
            # Strip off quotations
            dst_list1 = [x.strip('"') for x in dst_list.split(",")]
            
            # With Quotations Added
            service_list = (',').join(['"' + item.strip() + '"' for item in service.split(
                ';') if not item.strip().startswith('!') and not item.strip() == ""])
            # Strip off quotations
            service_list1 = [x.strip('"') for x in service_list.split(",")]

            ######################################################################################
            # Create JSON API Call Structure - To Create/Add Security Rules into Policy Package (For Different Combinations)  
            ######################################################################################

            if src_list:

                #For Debugging
                #print ("Src List Value is : " + src_list1 + "\n")

                if dst_list:

                    #For Debugging
                    #print ("Dst List Value is :" + dst_list1 + "\n")

                    #Template to use for JSON API
                    #Src Addr and Dst Addr Present
                    body = {
                        "id": 10,
	                    "method" : "add",	
	                        "params" : [{                  
		                        "url" : "/pm/config/adom/" + adom + "/pkg/" + pkg + "/firewall/policy",                  
		                        "data" : [{
                                    "policyid" : polid,
                                    "name" : name1,
                                    "srcintf" : ["any"],
                                    "dstintf" : ["any"],
                                    "srcaddr" : src_list1,
                                    "dstaddr" : dst_list1,
                                    "service" : service_list1,
                                    "action" : action,
                                    "logtraffic" : "all",
                                    "nat" : "disable",
                                    "schedule" : ["always"],
                                    "status" : "enable"                                       
                                }]          
		    	            }],
                            "session" : session    
                    }

                    r = requests.post(url, json=body, verify=False)
                    json_resp = json.loads(r.text)

                    statusmsg = json_resp['result'][0]['status']['message']
                    #Does json_resp contain a match for 'datasrc invalid' - if so write it to error file
                    m = re.search("datasrc invalid", statusmsg)
                    #If match then call function to write error to Error file with import/update function and error message
                    if m:

                        
                        function = "Import of Rulebase Policy"
                        errormsg = json_resp['result'][0]['status']['message']
                        ### write_error_file(errormsg, function)
                        #Uncomment for debugging purposes
                        print ("TEST CONDITION MET: " + errormsg + "\n")
                        Eout.write(function + ":\t" + errormsg + "\n")

                    print ('<-- Hcode: %d Jmesg: %s' %
                            (r.status_code, json_resp['result'][0]['status']['message']))

        #Commit changes and unlock FMG DB
        if (workspacemode):
            workspace_commit(adom)
            workspace_unlock(adom)

###########################
def add_security_profile():
    global session

    with open('securityprofile-rules.txt', 'r') as csv_file:
        csvreader = csv.DictReader(csv_file, delimiter='\t')
        
        #Excel Column Headers
        #   PolicyID    IPS    AppControl    Web    AV
        #TAB Delimited Excel File

        adom = input("Enter FMG ADOM that objects should be imported into." + "\n")
        pkg = input("Enter the Policy Package Name to apply the Security Profiles to." + "\n")

        Eout = open("JSON-SpecificErrors-Update-SecurityProfiles.txt", "w")
    
        if (workspacemode):
            workspace_lock(adom)

        for row in csvreader:

            polid = row['PolicyID'].strip()
            ips = row['IPS'].strip()
            appcontrol = row['AppControl'].strip()
            web = row['Web'].strip()
            av = row['AV'].strip()

            print('Updating Following PolicyID into FMG: ' + polid + ' for ADOM ' + adom + "\n")

            ###############################################################################
            # Create JSON API Call Structure - To Add Security Profiles to Existing Rules
            ###############################################################################

            if ips:

                print ("Updating Policy ID Rule " + polid + " for IPS and assigning profile " + ips + "\n")

                body = {
                    "id": 10,
                    "method" : "update",    
                    "params" : [{                 
                        "url" : "/pm/config/adom/" + adom + "/pkg/" + pkg + "/firewall/policy",                 
                        "data" : [{
                            "policyid" : polid,
                            "ips-sensor" : [ips],
                            "utm-status" : "enable"                               
                        }]         
                    }],
                    "session" : session

                }

                r = requests.post(url, json=body, verify=False)
                json_resp = json.loads(r.text)

                statusmsg = json_resp['result'][0]['status']['message']
                #Does json_resp contain a match for 'datasrc invalid' - if so write it to error file
                m = re.search("datasrc invalid", statusmsg)
                #If match then call function to write error to Error file with import/update function and error message
                if m:

                    function = "Addition of IPS Sensor to Existing Rule"
                    errormsg = json_resp['result'][0]['status']['message']
                    ### write_error_file(errormsg, function)
                    #Uncomment for debugging purposes
                    #print ("TEST CONDITION MET: " + errormsg + "\n")
                    Eout.write(function + ":\t" + errormsg + "\n")

                print ('<-- Hcode: %d Jmesg: %s' %
                            (r.status_code, json_resp['result'][0]['status']['message']))
                print ("\n")

                
            if appcontrol:

                print ("Updating Policy ID Rule " + polid + " for App Control and assigning profile " + appcontrol + "\n")

                body = {
                    "id": 11,
                    "method" : "update",    
                    "params" : [{                 
                        "url" : "/pm/config/adom/" + adom + "/pkg/" + pkg + "/firewall/policy",                 
                        "data" : [{
                            "policyid" : polid,
                            "application-list" : [appcontrol],
                            "utm-status" : "enable"                               
                        }]         
                    }],
                    "session" : session

                }

                r = requests.post(url, json=body, verify=False)
                json_resp = json.loads(r.text)

                statusmsg = json_resp['result'][0]['status']['message']
                #Does json_resp contain a match for 'datasrc invalid' - if so write it to error file
                m = re.search("datasrc invalid", statusmsg)
                #If match then call function to write error to Error file with import/update function and error message
                if m:

                    function = "Addition of App Control Profile to Existing Rule"
                    errormsg = json_resp['result'][0]['status']['message']
                    ### write_error_file(errormsg, function)
                    #Uncomment for debugging purposes
                    #print ("TEST CONDITION MET: " + errormsg + "\n")
                    Eout.write(function + ":\t" + errormsg + "\n")

                print ('<-- Hcode: %d Jmesg: %s' %
                            (r.status_code, json_resp['result'][0]['status']['message']))
                print ("\n")

            if web:

                print ("Updating Policy ID Rule " + polid + " for Web Content Filtering and assigning profile " + web + "\n")

                body = {
                    "id": 12,
                    "method" : "update",    
                    "params" : [{                 
                        "url" : "/pm/config/adom/" + adom + "/pkg/" + pkg + "/firewall/policy",                 
                        "data" : [{
                            "policyid" : polid,
                            "webfilter-profile" : [web],
                            "utm-status" : "enable"                               
                        }]         
                    }],
                    "session" : session

                }

                r = requests.post(url, json=body, verify=False)
                json_resp = json.loads(r.text)

                statusmsg = json_resp['result'][0]['status']['message']
                #Does json_resp contain a match for 'datasrc invalid' - if so write it to error file
                m = re.search("datasrc invalid", statusmsg)
                #If match then call function to write error to Error file with import/update function and error message
                if m:

                    function = "Addition of Web Content Filter Profile to Existing Rule"
                    errormsg = json_resp['result'][0]['status']['message']
                    ### write_error_file(errormsg, function)
                    #Uncomment for debugging purposes
                    #print ("TEST CONDITION MET: " + errormsg + "\n")
                    Eout.write(function + ":\t" + errormsg + "\n")

                print ('<-- Hcode: %d Jmesg: %s' %
                            (r.status_code, json_resp['result'][0]['status']['message']))
                print ("\n")

            if av:

                print ("Updating Policy ID Rule " + polid + " for AntiVirus and assigning profile " + av + "\n")

                body = {
                    "id": 13,
                    "method" : "update",    
                    "params" : [{                 
                        "url" : "/pm/config/adom/" + adom + "/pkg/" + pkg + "/firewall/policy",                 
                        "data" : [{
                            "policyid" : polid,
                            "av-profile" : [av],
                            "utm-status" : "enable"                               
                        }]         
                    }],
                    "session" : session

                }

                r = requests.post(url, json=body, verify=False)
                json_resp = json.loads(r.text)

                statusmsg = json_resp['result'][0]['status']['message']
                #Does json_resp contain a match for 'datasrc invalid' - if so write it to error file
                m = re.search("datasrc invalid", statusmsg)
                #If match then call function to write error to Error file with import/update function and error message
                if m:

                    function = "Addition of AntiVirus Profile to Existing Rule"
                    errormsg = json_resp['result'][0]['status']['message']
                    ### write_error_file(errormsg, function)
                    #Uncomment for debugging purposes
                    #print ("TEST CONDITION MET: " + errormsg + "\n")
                    Eout.write(function + ":\t" + errormsg + "\n")

                print ('<-- Hcode: %d Jmesg: %s' %
                        (r.status_code, json_resp['result'][0]['status']['message']))
                print ("\n")

        #Commit changes and unlock FMG DB
        if (workspacemode):            
            workspace_commit(adom)
            workspace_unlock(adom)

#################
def update_rulebase_snat():
    global session
    with open('rulebase.txt', 'r') as csv_file:
        csvreader = csv.DictReader(csv_file, delimiter='\t')

        adom = input("Enter FMG ADOM that SNAT Update should occur." + "\n")
        pkg = input("Enter the Policy Package Name to apply the SNAT update to." + "\n")

        Eout = open("JSON-SpecificErrors-Update-NAT-Objects-Existing-Rulebase.txt", "w")

        if (workspacemode):
            workspace_lock(adom)

        for row in csvreader:

            polid = row['No.'].strip()
            name = row['Name'].strip()
            src = row['Source'].strip()
            dst = row['Destination'].strip()
            service = row['Services'].strip()
            nat = row['Nat'].strip()
            ippool = row['Ippool'].strip()
            action = row['Action'].strip()
            track = row['Track'].strip()

            #########################################################################################
            # Create JSON API Call Structure - To Update Existing Policy Rules with IP Pool - SNATs
            #########################################################################################

            if ((nat == "enable") and (ippool)):

                print('Updating Following NAT-IPPool Objects into FMG for existing PolicyID Rule: ' + polid + ' for ADOM: ' + adom)

                body = {
                    "id": 19,
                    "method": "update",
                    "params": [{
                        "url" : "/pm/config/adom/" + adom + "/pkg/" + pkg + "/firewall/policy",
                        "data": [{
                            "policyid": [polid],
                            "nat": "enable",
                            "ippool": "enable",
                            "poolname": ippool
                        }]

                    }],
                    "session": session
                }

                r = requests.post(url, json=body, verify=False)
                json_resp = json.loads(r.text)

                statusmsg = json_resp['result'][0]['status']['message']
                #Does json_resp contain a match for 'datasrc invalid' - if so write it to error file
                m = re.search("datasrc invalid", statusmsg)
                #If match then call function to write error to Error file with import/update function and error message
                if m:

                    function = "Update of SNAT - IP Pool on existing Rules"
                    errormsg = json_resp['result'][0]['status']['message']
               
                    #Uncomment for debugging purposes
                    #print ("TEST CONDITION MET: " + errormsg + "\n")
                    Eout.write(function + ":\t" + errormsg + "\n")

                print ('<-- Hcode: %d Jmesg: %s' %
                        (r.status_code, json_resp['result'][0]['status']['message']))
            
            elif (nat == "enable"):

                print('Updating Following NAT-IPPool Objects into FMG for existing PolicyID Rule: ' + polid + ' for ADOM: ' + adom)

                body = {
                    "id": 19,
                    "method": "update",
                    "params": [{
                        "url" : "/pm/config/adom/" + adom + "/pkg/" + pkg + "/firewall/policy",
                        "data": [{
                            "policyid": [polid],
                            "nat": "enable"      
                        }]

                    }],
                    "session": session
                }

                r = requests.post(url, json=body, verify=False)
                json_resp = json.loads(r.text)

                statusmsg = json_resp['result'][0]['status']['message']
                #Does json_resp contain a match for 'datasrc invalid' - if so write it to error file
                m = re.search("datasrc invalid", statusmsg)
                #If match then call function to write error to Error file with import/update function and error message
                if m:

                    function = "Update of SNAT - IP Pool on existing Rules"
                    errormsg = json_resp['result'][0]['status']['message']
               
                    #Uncomment for debugging purposes
                    #print ("TEST CONDITION MET: " + errormsg + "\n")
                    Eout.write(function + ":\t" + errormsg + "\n")

                print ('<-- Hcode: %d Jmesg: %s' %
                        (r.status_code, json_resp['result'][0]['status']['message']))
            
        
        #Commit changes and unlock FMG DB
        if (workspacemode):
            workspace_commit(adom)
            workspace_unlock(adom)

#################
def workspace_lock(adom):
        json_url = "pm/config/adom/" + adom + "/_workspace/lock"
        body = {
                "id": 14,
                "method": "exec",
                "params": [{
                        "url": json_url
                }],
                "session": session
        }
        r = requests.post(url, json=body, verify=False)
        json_resp = json.loads(r.text)
        print ('--> Locking ADOM %s' % adom)
        print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
        print ("\n")
   
#################
def workspace_unlock(adom):
        json_url = "pm/config/adom/" + adom + "/_workspace/unlock"
        body = {
                "id": 15,
                "method": "exec",
                "params": [{
                   "url": json_url
                }],
                "session": session
        }
        r = requests.post(url, json=body, verify=False)
        json_resp = json.loads(r.text)

        print ('--> Unlocking ADOM %s' % adom)
        print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
        print ("\n")

####################
def workspace_commit(adom):
        json_url = "pm/config/adom/" + adom + "/_workspace/commit"
        body = {
                "id": 16,
                "method": "exec",
                "params": [{
                    "url": json_url
                }],
                "session": session
        }
        r = requests.post(url, json=body, verify=False)
        json_resp = json.loads(r.text)

        print("\n")
        print('--Saved All Changes in ADOM %s' % (adom))
        print("\n")


################################
#All functions defined above
################################
#Start of Main Program Flow Logic
###############################
fmg_login()
#Gather input - If enabled set Boolean Workspace Mode flag
workspace = input("Is Workspace Mode Locking enabled for FMG Database?. Answer Y if it is enabled, otherwise press any key if it is not. Unlock ADOM BEFORE Invoking this Script!!!" + "\n" )
    
if (workspace == "Y"):
    workspacemode = True
else:
    workspacemode = False

while (continuescript):
    
    #Call various functions based on user input
    print ("\n" + "This program will allow you to make API calls to FMG with spreadsheets as input data")
    print ("IMPORTANT NOTE:   ALL Spreadsheets for each option below must be TAB delimited" + "\n")
    print ("The following options are available:")
    print ("1 - Import address objects from Excel Spreadsheet.  Spreadsheet name:  address-objects.txt")
    print ("2 - Import host objects from Excel Spreadsheet.  Spreadsheet name:   host-objects.txt")
    print ("3 - Import IP Range Address objects from Excel Spreadsheet.  Spreadsheet name:   iprange.txt")
    print ("4 - Import service objects from Excel Spreadsheet.  Spreadsheet name:   service-objects.txt")
    print ("5 - Import address group objects from Excel Spreadsheet.  Spreadsheet name:   addrgrp.txt")
    print ("6 - Import service group objects from Excel Spreadsheet.  Spreadsheet name:   servicegrp.txt")
    print ("7 - Import VIP objects from Excel Spreadsheet.  Spreadsheet name:   vip.txt") 
    print ("8 - Import IPPool objects from Excel Spreadsheet.  Spreadsheet name:   ippool.txt")
    print ("9 - Import Policy Rules from Excel Spreadsheet.  Does NOT apply NAT/IPPool. Spreadsheet name:   rulebase.txt")
    print ("10 - Apply NAT/IPPools from Excel Spreadsheet. NOTE - Uses spreadsheet from Option 9. Spreadsheet name:   rulebase.txt")
    print ("11 - Assign Existing Security Profiles to Existing Policy Rules. Spreadsheet name:   securityprofile-rules.txt" + "\n")
    print ("IMPORTANT NOTE: Excel Spreadsheets have specific requirements around the column headers and must ALL be TAB delimited")
    option = input("Enter your numeric choice from the menu above" + "\n")
    ###
    if option == "1":
        create_address_object()
    if option == "2":
        create_host_object()
    if option == "3":
        create_iprange_object()
    if option == "4":
        create_service_object()
    if option == "5":
        create_address_groups()
    if option == "6":
        create_service_groups()
    if option == "7":
        create_vip_object()
    if option == "8":
        create_ippool_object()
    if option == "9":
        add_policy_rules()
    if option == "10":
        update_rulebase_snat()
    elif option == "11":
        add_security_profile()

    #Print Ask End User would they like to continue with another option
    request_to_continue = input("Would you like to continue script with another option." + "\n" + "If so, answer 'Y' followed by ENTER, otherwise press ENTER Alone to exit script" + "\n")
    
    if (request_to_continue == 'Y'):

        continuescript = True

    else:   

        continuescript = False

#Result of falling out of while/continue loop request.  Logout of FMG and Exit Script.       
fmg_logout()







