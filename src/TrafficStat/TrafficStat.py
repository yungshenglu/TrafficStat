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
            self.srcIpAddrSet = self.getIpAddrSet('src')
            self.dstIpAddrSet = self.getIpAddrSet('dst')

            # Sort the IP address
            self.srcIpAddr = self.sortIpAddr('src')
            self.dstIpAddr = self.sortIpAddr('dst')

            # Get the timestamp from the PCAP file
            self.pktTimestamp = self.getIpTimestamp()
        else:
            self.srcIpAddr = set()
            self.dstIpAddr = set()
        

    def isPathValid(self, path):
        if (not os.path.exists(path)):
            raise ValueError('[ERROR] The path is invalid or not exist')
        return True
    
    def isAddrTypeValid(self, addrType):
        if (addrType != 'src' and addrType != 'dst'):
            raise ValueError('[ERROR] The type of address is incorrect')
        return True

    def isPortTypeValid(self, portType):
        if (portType != 's' and portType != 'd'):
            raise ValueError('[ERROR] The type of port is incorrect')
        return True

    def isLayerExist(self, packet, layer):
        if (not packet.haslayer(layer)):
            raise ValueError('[ERROR] ' + layer + ' not exist')
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
            print('[INFO] Read the PCAP file: %s' % path)
            pcap = {}
            pcap['filename'] = path
            pcap['packets'] = rdpcap(pcap['filename'])
            return [pcap]

    def getTotalPackets(self):
        return len(self.pcapFiles)

    def getEthType(self):
        ethType = []
        for pcap in self.pcapFiles:
            for pkt in pcap['packets']:
                if (self.isLayerExist(pkt, 'Ethernet')):
                    ethType.append(pkt['Ethernet'].type)
        return ethType

    def getEthAddr(self, addrType='src'):
        if (self.isAddrTypeValid(addrType)):
            ethAddr = []
            for pcap in self.pcapFiles:
                for pkt in pcap['packets']:
                    if (self.isLayerExist(pkt, 'Ethernet')):
                        if (addrType == 'src'):
                            ethAddr.append(pkt['Ethernet'].src)
                        elif (addrType == 'dst'):
                            ethAddr.append(pkt['Ethernet'].dst)
            return ethAddr

    def getIpVersion(self):
        ipVersion = []
        for pcap in self.pcapFiles:
            for pkt in pcap['packets']:
                if (self.isLayerExist(pkt, 'IP')):
                    ipVersion.append(pkt['IP'].version)
        return ipVersion

    def getIpAddr(self, addrType='src'):
        if (self.isAddrTypeValid(addrType)):
            ipAddr = []
            for pcap in self.pcapFiles:
                for pkt in pcap['packets']:
                    if (self.isLayerExist(pkt, 'IP')):
                        if (addrType == 'src'):
                            ipAddr.append(pkt['IP'].src)
                        elif (addrType == 'dst'):
                            ipAddr.append(pkt['IP'].dst)
            return ipAddr
    
    def getIpAddrSet(self, addrType='src'):
        if (self.isAddrTypeValid(addrType)):
            ipAddrSet = set()
            for pcap in self.pcapFiles:
                for pkt in pcap['packets']:
                    if (self.isLayerExist(pkt, 'IP')):
                        if (addrType == 'src'):
                            ipAddrSet.add(pkt['IP'].src)
                        elif (addrType == 'dst'):
                            ipAddrSet.add(pkt['IP'].dst)
            return ipAddrSet
    
    def sortIpAddr(self, addrType='src'):
        if (self.isAddrTypeValid(addrType)):
            ipAddr = []
            if (addrType == 'src'):
                ipAddr = list(ipAddr)
            elif (addrType == 'dst'):
                ipAddr = list(ipAddr)
            
            sortedIpAddr = []
            for ip in sorted(ipAddr, key=lambda ip: (
                int(ip.split('.')[0]), 
                int(ip.split('.')[1]),
                int(ip.split('.')[2]),
                int(ip.split('.')[3]))):
                sortedIpAddr.append(ip)
            return sortedIpAddr
    
    def getUdpPort(self, portType='s'):
        if (self.isPortTypeValid(portType)):
            udpPort = []
            for pcap in self.pcapFiles:
                for pkt in pcap['packets']:
                    if (self.isLayerExist(pkt, 'UDP')):
                        if (portType == 's'):
                            udpPort.append(pkt['UDP'].sport)
                        elif (portType == 'd'):
                            udpPort.append(pkt['UDP'].dport)
            return udpPort

    def getUdpPortSet(self, portType='s'):
        if (self.isPortTypeValid(portType)):
            udpPortSet = set()
            for pcap in self.pcapFiles:
                for pkt in pcap['packets']:
                    if (self.isLayerExist(pkt, 'UDP')):
                        if (portType == 's'):
                            udpPortSet.add(pkt['UDP'].sport)
                        elif (portType == 'd'):
                            udpPortSet.add(pkt['UDP'].dport)
            return udpPortSet

    def getTimestamp(self):
        timestamp = []
        for pcap in self.pcapFiles:
            for pkt in pcap['packets']:
                timestamp.append(pkt.time)
        return timestamp

    def getIpTimestamp(self):
        timestamp = []
        for pcap in self.pcapFiles:
            for pkt in pcap['packets']:
                pktTs = {
                    'src': pkt['IP'].src,
                    'dst': pkt['IP'].dst,
                    'ts': pkt.time
                }
                timestamp.append(pktTs)
        return timestamp