#!/usr/bin/python3

from TrafficStat.TrafficStat import TrafficStat

def clusterIpAddr(ipAddr):
    # Count the IP address with prefix level
    ipAddrStat = [set() for i in range(16)]
    for ip in ipAddr:
        if (int(ip.split('.')[1]) == 1):
            ipAddrStat[int(int(ip.split('.')[3]) % 8)].add(ip)
        elif (int(ip.split('.')[1]) == 2):
            ipAddrStat[int(int(ip.split('.')[3]) % 8) + 8].add(ip)
    return ipAddrStat


''' ENTRY POINT '''
if __name__ == "__main__":
    # Read PCAP file from specific path
    targetPath = './input/'
    stat = TrafficStat(targetPath, True)
    
    '''
    # Read IP address from file
    ipAddrFile = 'allIpAddr.txt'
    with open(ipAddrFile, 'r') as f:
        line = f.readline()
        print(line)
        while line:
            if (ipAddrFile == 'srcIpAddr.txt'):
                stat.srcIpAddr.add(line[:-1])
            elif (ipAddrFile == 'dstIpAddr.txt'):
                stat.dstIpAddr.add(line[:-1])
            elif (ipAddrFile == 'allIpAddr.txt'):
                stat.allIpAddr.add(line[:-1])
            line = f.readline()
    '''

    # Cluster the IP address into 16 groups
    ipCluster = clusterIpAddr(stat.allIpAddr)
    
    # Compute arrival rate
    ipArrivalRate = stat.getArrivalRate()
    print(ipArrivalRate['1.1.0.1'])
    