import sys
import json
import socket
import time
import subprocess
import os
import glob
import pprint
import argparse
import atexit
import pyrebase
import re


def set_wifi():
    checkMon = subprocess.run("iwconfig | grep mon1", shell = True, capture_output = True, text = True)
    if checkMon.stdout.split().count("mon1") == 1:
        print("mon1 found and setup")
    else:
        os.system("airmon-ng start wlan1")
        os.system("iw phy phy1 interface add mon1 type monitor")
        os.system("ifconfig mon1 up")
            

def process_scan(time_window,dis,trial):
    output = ""
    fileNameToRead = ""
    for filename in glob.glob(tsharkfilename  +"*"):
        fileNameToRead = filename
    if fileNameToRead == "":
    	print("Loading data")
    	return {"signals": {}}
    cmd = subprocess.Popen(("tshark -r "+fileNameToRead+" -T fields -e frame.time_epoch -e wlan.sa -e wlan.bssid -e radiotap.dbm_antsignal -e radiotap.datarate -e wlan_radio.duration -e _ws.col.Protocol -e _ws.col.Info ").split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output += cmd.stdout.read().decode('utf-8')
    #print("output",output)
    
    timestamp_threshold = float(time.time()) - float(time_window)
    fingerprints = []
    
    for line in output.splitlines():
        try:
            timestamp, mac, mac2, power_levels, data_rate, duration, protocol, info = line.split("\t")
            
            if protocol != "ICMP":
            	continue
            	
            #print(timestamp, mac, mac2, power_levels, data_rate, duration, protocol, info)
            
            if mac == mac2 or float(timestamp)<timestamp_threshold or len(mac) == 0 :
                continue

            rssi = power_levels.split(',')[0]
            if len(rssi) == 0:
                continue
            if mac == "" or mac == "":
                #Insert MAC address of devices above
                fingerprints.append({"mac": mac, "rssi":int(power_levels), "timestamps": float(timestamp), "dataRate" : int(data_rate), "duration": int(duration) , "Protocol": protocol, "seq": re.search(r"seq=([1-9]+)",info)[1], "dir": re.split(r"\s",info)[2] })

        except:
            pass

    payload = {
    	"distance" : dis,
    	"trail" : trial,
        "node": socket.gethostname(),
        "signals": fingerprints}
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(payload)
    return payload


def tshark_is_running():
    ps_output = subprocess.Popen(
        "ps aux".split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ps_stdout = ps_output.stdout.read().decode('utf-8')
    isRunning = 'tshark' in ps_stdout and '[tshark]' not in ps_stdout
    return isRunning


def start_scan(wlan):
    if not tshark_is_running():
        subprocess.Popen(('/usr/bin/tshark  -i ' + wlan +' -b filesize:5000 -w ' + tsharkfilename).split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def main():
    # Check if SUDO
    if os.getuid() != 0:
        print("you must run sudo!")
        return

    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-g", "--group", default="testing", help="group name")
    parser.add_argument(
        "-i",
        "--interface",
        default="mon1",
        help="Interface to listen on - default mon0")
    parser.add_argument(
        "-t",
        "--time",
        default=3,
        help="scanning time in seconds (default 3)")
    parser.add_argument(
        "-tn",
        "--trail",
        default=1,
        help="Trail of the experiment")
    parser.add_argument(
        "-d",
        "--distance",
        default= 0,
        help="distance in meters (default 1)")
    args = parser.parse_args()
    
    print("Using group " + args.group)
    global tsharkfilename
    
    strdis = str(args.distance).replace(".","_") 
    tsharkfilename = "/home/" + args.group + "_"+ strdis + "_"+ str(args.trail) + "_"
    jsonfilename = "/home/" + args.group + ".json"
    
    try:
        print("Setting up server")
        config = {
            #########
            #Insert api key for firebase here
            #########
            #"apiKey": "",
            #"authDomain": "",
            #"databaseURL": "",
            #"storageBucket": ""
        }
        firebase = pyrebase.initialize_app(config)
        db = firebase.database()
        print("Setting up wifi")
        set_wifi()
        with open(jsonfilename,'w') as f:
        	json.dump([],f)
    except Exception:
        sys.exit(-1)
    while True:
        try:
            start_scan(args.interface)
            payload = process_scan(args.time,strdis,args.trail)
            if len(payload['signals']) > 0:
            	db.child(args.group).push(payload)
            	with open( jsonfilename, "r") as f:
                	data = json.load(f)
            	with open( jsonfilename, "w") as f:
                	data.append(payload)
                	json.dump(data,f, indent=4)
            time.sleep(.01)  # Wait before getting next window
        except Exception:
            print ("Failed restarting")
            time.sleep(.01)


def exit_handler():
    print("Exiting...stopping scan..")
    os.system("pkill -9 tshark")

if __name__ == "__main__":
    atexit.register(exit_handler)
    main()