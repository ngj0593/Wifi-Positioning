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
    
    jsonfilename = "/home/" + args.group + ".json"
    try:
        with open(jsonfilename,'w') as f:
            json.dump([],f)
    except Exception:
        sys.exit(-1)
        
    for filename in glob.glob("/home/" +"*"):
        if args.group not in filename or 'json' in filename:
            continue
        print(args.group,filename)
        props = filename.split('_')
        output = ""
        print(props)
        cmd = subprocess.Popen(("tshark -r "+filename+" -T fields -e frame.time_epoch -e wlan.sa -e wlan.bssid -e radiotap.dbm_antsignal -e radiotap.datarate -e wlan_radio.duration -e _ws.col.Protocol -e _ws.col.Info ").split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output += cmd.stdout.read().decode('utf-8')

        fingerprints = []
	
        for line in output.splitlines():
            try:
                timestamp, mac, mac2, power_levels, data_rate, duration, protocol, info = line.split("\t")
		    
                if protocol != "ICMP":
                    continue		    	
		    
                #print(timestamp, mac, mac2, power_levels, data_rate, duration, protocol, info)
		    
                if mac == mac2 or len(mac) == 0 :
                        continue

                rssi = power_levels.split(',')[0]
                if len(rssi) == 0:
                    continue
                print(timestamp, mac, mac2, power_levels, data_rate, duration, protocol, info)
                if mac == "" or mac == "":
                    #   Insert MAC of devices tested
                    fingerprints.append({"mac": mac, "rssi":int(power_levels), "timestamps": float(timestamp), "dataRate" : int(data_rate), "duration": int(duration) , "Protocol": protocol, "seq": re.search(r"seq=([1-9]+)",info)[1], "dir": re.split(r"\s",info)[2] })

            except:
                pass
	
        payload = {
            "distance" : props[1],
            "trail" : props[2],
	    "node": socket.gethostname(),
	    "signals": fingerprints}
        print(payload)
        with open( jsonfilename, "r") as f:
            	data = json.load(f)
        with open( jsonfilename, "w") as f:
            	data.append(payload)
            	json.dump(data,f, indent=4)
    	
    	

def exit_handler():
    print("Exiting...stopping scan..")
    os.system("pkill -9 tshark")

if __name__ == "__main__":
    atexit.register(exit_handler)
    main()