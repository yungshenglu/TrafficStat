#!/usr/bin/python3

from scapy.all import *
import os
import collections as col
import ipaddress as ipaddr


class TrafficStat:
    def __init__(self, targetPath='./input/', readFile=True):
        if (readFile):
            # Determine whether the type of path is directory or file
            if (self.isPathValid(targetPath)):
                self.targetPath = targetPath
                self.targetPathType = self.pathType(targetPath)
            
            # Read PCAP file from specific folder
            self.pcapFiles = []
            if (self.targetPathType == 'D'):
                self.pcapFiles = self.readFromDir(self.targetPath)
            elif (self.targetPathType == 'F'):
                self.pcapFiles = self.readFromFile(self.targetPath)

            # Get the unique IP address from PCAP files
            self.srcIpAddr = self.getIpAddr('src')
            self.dstIpAddr = self.getIpAddr('dst')
            self.allIpAddr = self.getIpAddr('all')

            # Sort the IP address
            self.srcIpAddr = self.sortIpAddr('src')
            self.dstIpAddr = self.sortIpAddr('dst')
            self.allIpAddr = self.sortIpAddr('all')

            # Get the timestamp from the PCAP file
            self.pktTimestamp = self.getTimestamp()
            
        else:
            self.srcIpAddr = set()
            self.dstIpAddr = set()
            self.allIpAddr = set()
        

    def isPathValid(self, path):
        if (not os.path.exists(path)):
            raise ValueError('[ERROR] The path is invalid or not exist')
        return True
    
    def isIpAddrTypeValid(self, addrType):
        if (addrType != 'src' and addrType != 'dst' and addrType != 'all'):
            raise ValueError('[ERROR] The type of IP address is incorrect')
        return True

    def pathType(self, path):
        if (self.isPathValid(path)):
            if (os.path.isdir(path)):
                return 'D'
            elif (os.path.isfile(path)):
                return 'F'
            else:
                raise ValueError('[ERROR] The path is invalid')
    
    def readFromDir(self, path):
        if (self.isPathValid(path)):
            pcapFiles = []
            for root, dirs, files in os.walk(path):
                for fname in files:
                    pcap = {}
                    if (fname.endswith('.pcap')):
                        print('[INFO] Read the PCAP file: %s' % fname)
                        pcap['filename'] = os.path.join(root, fname)
                        pcap['packets'] = rdpcap(pcap['filename'])
                    pcapFiles.append(pcap)
            return pcapFiles
    
    def readFromFile(self, path):
        if (self.isPathValid(path)):
            pcap = {}
            print('[INFO] Read the PCAP file: %s' % path)
            pcap['filename'] = path
            pcap['packets'] = rdpcap(pcap['filename'])
            return [pcap]

    def getTotalPackets(self):
        return len(self.pcapFiles)

    def getIpAddr(self, addrType='src'):
        if (self.isIpAddrTypeValid(addrType)):
            ipAddr = set()
            for pcap in self.pcapFiles:
                for pkt in pcap['packets']:
                    if (addrType == 'src'):
                        ipAddr.add(pkt['IP'].src)
                    elif (addrType == 'dst'):
                        ipAddr.add(pkt['IP'].dst)
                    elif (addrType == 'all'):
                        ipAddr.add(pkt['IP'].src)
                        ipAddr.add(pkt['IP'].dst)
            return ipAddr
    
    def sortIpAddr(self, addrType='src'):
        ipAddr = []
        if (self.isIpAddrTypeValid(addrType)):
            if (addrType == 'src'):
                ipAddr = list(self.srcIpAddr)
            elif (addrType == 'dst'):
                ipAddr = list(self.dstIpAddr)
            elif (addrType == 'all'):
                ipAddr = list(self.allIpAddr)

        # Sort the IP address
        sortedIpAddr = []
        for ip in sorted(ipAddr, key=lambda ip: (
            int(ip.split('.')[0]), 
            int(ip.split('.')[1]),
            int(ip.split('.')[2]),
            int(ip.split('.')[3]))):
            sortedIpAddr.append(ip)
        return set(sortedIpAddr)
    
    def getTimestamp(self):
        pktTimestamp = []
        for pcap in self.pcapFiles:
            for pkt in pcap['packets']:
                pktTs = {
                    'src': pkt['IP'].src,
                    'dst': pkt['IP'].dst,
                    'ts': pkt.time
                }
                pktTimestamp.append(pktTs)
        return pktTimestamp

    def getPktArrival(self):
        pktArrival = {}
        for pkt in self.pktTimestamp:
            if (pkt['src'] in pktArrival):
                pktArrival[pkt['src']].append(pkt['ts'])
            else:
                pktArrival[pkt['src']] = []
                pktArrival[pkt['src']].append(pkt['ts'])

        # Sort the timestamp of arrival
        for arrivalTs in pktArrival:
            sorted(arrivalTs)
        return pktArrival