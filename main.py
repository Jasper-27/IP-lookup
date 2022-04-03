#!/usr/bin/python 

import sys # for handeling arguments
import requests
import csv
import socket
import pycountry
import ipaddress 


# Colors 
class bcolors:
    SERVICE_TITLE = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ENDC = '\033[0m'


# Reading in the API keys 
ipqs_key = ""
ipinfo_key = ""
AbuseIPDB_key = ""
ipinfo_pro_key = ""

with open('keys.csv', newline='') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        if row['name'] == "ipqs": ipqs_key = row['key']
        if row['name'] == "ipinfo": ipinfo_key = row['key']
        if row['name'] == "AbuseIPDB": AbuseIPDB_key = row['key']


# Section for the History feature 

history_file_name = "History.txt"

history = []


# Get the country name, and return blank string if it doesn't work 
def get_country_name(country_code): 
    result = ""
    try: 
        result = pycountry.countries.get(alpha_2=str(country_code)).name
    except: 
        pass

    return result


# Get the known IP addresses from a file 
def get_history(): 
    try: 
        with open(history_file_name, newline='') as ip_file: 
            result = ip_file.readlines()
            stripped_result = []
            for ip in result: 
                stripped_result.append(ip.strip()) # Gotta remove those annoying '\n's 

        return stripped_result

    except: 
        # Need to create the file here if it doesn't work 
        open(history_file_name, 'a').close()

        get_history()

# Add an IP address to history (array, and file)
def add_ip_to_history(IP): 
    history.append(IP)
    history_file = open(history_file_name, 'a')
    history_file.write(IP + "\n")

    history_file.close() # Good boys close their files 

# www.ipqualityscore.com
def ipqs(ip):

    # Return if no key 
    if ipqs_key == "": 
        return

    ipqs_baseURL ="https://ipqualityscore.com/api/json/ip/"
    ipqs_args = "?strictness=0&allow_public_access_points=true&fast=true&lighter_penalties=true&mobile=true"

    ipqs_URL = ipqs_baseURL + ipqs_key + "/" + ip + "/" + ipqs_args
    result = requests.get(ipqs_URL)

    # Printing output 
    # print("ipqualityscore.com")
    print(f"{bcolors.SERVICE_TITLE}www.ipqualityscore.com{bcolors.ENDC}")

    print("------------------------------------------------------------")

    if result.status_code == 200: 
        if result.json()["success"] == True: 

            # country_name = pycountry.countries.get(alpha_2=str(result.json()["country_code"])).name

            country_name = get_country_name(result.json()["country_code"])

            print("VPN:             " + str(result.json()["vpn"]))
            print("Fraud Score:     " + str(result.json()["fraud_score"]))
            print("Recent Abuse:    " + str(result.json()["recent_abuse"]))

            print("country_code:    " + str(result.json()["country_code"]) + " ( " + country_name + " )")
            print("region:          " + str(result.json()["region"]))
            print("city:            " + str(result.json()["city"]))
            print("ISP:             " + str(result.json()["ISP"]))

            print("tor:             " + str(result.json()["tor"]))
            print("active_vpn:      " + str(result.json()["active_vpn"]))
            print("active_tor:      " + str(result.json()["active_tor"]))
        
        # elif result.status_code == 404: 
        elif result.json()["success"] == False:
            print("Fail")
            print(str(result.json()["message"])) 


    else: 
        print(result.status_code)
    print()
    print()

# ipinfo.com
def ipinfo(ip): 
    if ipinfo_key == "": 
        return

    ipinfo_baseURL = "https://ipinfo.io/"
    ipinfo_secondbit = "?token="

    ipinfo_url = str(ipinfo_baseURL + ip + ipinfo_secondbit + ipinfo_key)

    result = requests.get(ipinfo_url)

    # print("IPInfo.com")
    print(f"{bcolors.SERVICE_TITLE}www.IPInfo.com{bcolors.ENDC}")
    print("------------------------------------------------------------")
    if result.status_code == 200: 
        # Printing output 
        
        country_string = ""
        try: country_string = " ( " + get_country_name(result.json()["country"]) + " )"
        except: pass

        try:    print("country:    " + str(result.json()["country"])  + country_string )
        except: pass

        try:    print("region:     " + str(result.json()["region"]))
        except: pass

        try:    print("city:       " + str(result.json()["city"]))
        except: pass

        try:    print("org:        " + str(result.json()["org"]))
        except: pass

        try:    print("hostname:   " + str(result.json()["hostname"]))
        except: pass
        
        try:    print("domain:     " + str(result.json()["asn"]["domain"]))
        except: pass
        
        try:    print("route:      " + str(result.json()["asn"]["route"]))
        except: pass
        
        try:    print("type:       " + str(result.json()["asn"]["type"]))
        except: pass

        # Pro
        try:    print("vpn:        " + str(result.json()["privacy"]["vpn"])) 
        except: pass

        try:    print("proxy:      " + str(result.json()["privacy"]["proxy"])) 
        except: pass

        try:    print("tor:        " + str(result.json()["privacy"]["tor"])) 
        except: pass

        try:    print("relay:      " + str(result.json()["privacy"]["relay"])) 
        except: pass

        try:    print("hosting:    " + str(result.json()["privacy"]["hosting"])) 
        except: pass

        try:    print("service:    " + str(result.json()["privacy"]["service"])) 
        except: pass

    elif result.status_code == 404: 
        print(str(result.json()["error"]["title"]))
        print(str(result.json()["error"]["message"]))
    else: 
        print("ERROR 😥")

    print()
    print()
    
# www.abuseipdb.com
def AbuseIPDP(ip): 

    if AbuseIPDB_key == "": 
        return
                
    # Defining the api-endpoint
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90' # age of report 
    }

    headers = {
        'Accept': 'application/json',
        'Key': AbuseIPDB_key, 
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring)

    # Printing output 
    # print("www.abuseipdb.com")
    print(f"{bcolors.SERVICE_TITLE}www.abuseipdb.com{bcolors.ENDC}")

    print("------------------------------------------------------------")
    if response.status_code == 200:

        # country_name = pycountry.countries.get(alpha_2=str(response.json()["data"]["countryCode"])).name
        country_name = " ( " + get_country_name(response.json()["data"]["countryCode"]) + " )"
        
        print("hostnames:       " + str(response.json()["data"]["hostnames"]))
        print("Abuse score:     " + str(response.json()["data"]["abuseConfidenceScore"]))
        print("usageType        " + str(response.json()["data"]["usageType"]))
        print("Country code:    " + str(response.json()["data"]["countryCode"]) + country_name )
        print("ISP:             " + str(response.json()["data"]["isp"]))
        print("totalReports:    " + str(response.json()["data"]["totalReports"]))
        print("Last report:     " + str(response.json()["data"]["lastReportedAt"]))
        print("is Whitelisted:  " + str(response.json()["data"]["isWhitelisted"]))

    else: 
        print("ERROR 😥")
        print(response.status_code)
   
    print()
    print()

# getipintel.net
def gipi(ip):
    string = "http://check.getipintel.net/check.php?ip={}&contact=peter.man@gmail.com&format=json&flags=m&oflags=bci".format(ip)
    response = requests.get(string)

    # Printing output 
    # print("www.getipintel.net")
    print(f"{bcolors.SERVICE_TITLE}www.getipintel.net{bcolors.ENDC}")
    print("------------------------------------------------------------")
    try: 

        # country_name = pycountry.countries.get(alpha_2= str(response.json()["Country"])).name
        country_name = get_country_name(response.json()["Country"])

        if response.status_code == 200: 
            print("Abuse score:         " + str(response.json()["result"]))
            print("Country Code:        " + str(response.json()["Country"]) + " ( " + country_name + " )")
            print("iCloud relay:        " + str(response.json()["iCloudRelayEgress"]))
            print("Bad IP:              " + str(response.json()["BadIP"]))
        else: 
            print("Error " + response.status_code)

    except: 
        print("ERROR")

    print()
    print()

# Check the IP address is Valid 
def ipCheck(ip):
    try: 
        ipaddress.ip_address(ip)
    except: 
        return True

    return False 

# Checks how many times the IP address has been checked
def historyCheck(ip): 
    print(f"{bcolors.SERVICE_TITLE}History{bcolors.ENDC}")
    print("------------------------------------------------------------")
    count = get_history().count(ip)

    print("This IP has been checked " + str(count) + " times")
    print("")


# Gets the history and stores it in RAM 
history = get_history()

# Exits the program, rather than error if you don't give it any args
if len(sys.argv) == 1: 
    print("Argument not found")
    print()
    print("Enter an IP address to look up that IP address")
    print("Enter 'i' to enter interactive mode")
    print("Enter 'dump' to see the history")
    print()
    exit()

# Mode that allows the user to enter a new IP repeatedly 
if sys.argv[1] == "i": # enter interactive mode

    print("Interactive mode. type 'EXIT' to exit")
    while(True): 

        ip = input("Enter IP: ")

        # Exit the program if the user enters exit
        if ip.lower() == "exit": 
            exit()

        # Make sure the IP address is valid 
        skip = False 
        skip = ipCheck(ip)

        
        
        if skip == False: 

            add_ip_to_history(ip)

            ipqs(ip)
            ipinfo(ip)
            AbuseIPDP(ip)
            gipi(ip)
            historyCheck(ip)
            
        else: 
            print("IP invalid")

# Dumps the known IP addresses 
if sys.argv[1] == "dump": 
    print(get_history())


else:
    ip = sys.argv[1] # set the IP as the first argument 

    ipqs(ip)
    ipinfo(ip)
    AbuseIPDP(ip)
    gipi(ip)

    add_ip_to_history(ip)
