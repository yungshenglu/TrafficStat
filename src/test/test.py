#!/usr/bin/python3

from TrafficStat.TrafficStat import TrafficStat
from ipaddress import *


''' ENTRY POINT '''
if __name__ == "__main__":
    # Read PCAP file from specific path
    #targetPath = '../../MalwareTrafficClassification/2_PreprocessedTools/2_Session/AllLayers/Weibo-ALL'
    targetPath = './input/BitTorrent.pcap'
    stat = TrafficStat(targetPath)

    # Get the subnet mask of src IP address
    ipSubnetMask = stat.getSubnetMask(13)
    
    # Count the number of subnet mask of src IP address
    countSubnetMask = stat.countSubnetMask(13)
    print(countSubnetMask)
    
