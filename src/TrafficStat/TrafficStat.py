#!/usr/bin/python3

from scapy.all import *
from collections import defaultdict
import os
import collections as col
import ipaddress as ipaddr


class TrafficStat:
    def __init__(self, targetPath='./input/'):
        self.subnetMaskPrefix = ['255', '254', '252', '248', '240', '224', '192', '128']
        
        # Determine whether the type of path is directory or file
        if (self.isPathValid(targetPath)):
            self.targetPath = targetPath
            self.targetPathType = self.pathType(targetPath)

        self.numPackets = []
        
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

        # Get th global time
        self.startTime, self.endTime = self.getGlobalTime()
        self.interval = self.endTime - self.startTime

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
                    self.numPackets.append(len(pcap))
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
    
    def getTcpPort(self, portType='s'):
        if (self.isPortTypeValid(portType)):
            tcpPort = []
            for pcap in self.pcapFiles:
                for pkt in pcap['packets']:
                    if (self.isLayerExist(pkt, 'TCP')):
                        if (portType == 's'):
                            tcpPort.append(pkt['TCP'].sport)
                        elif (portType == 'd'):
                            tcpPort.append(pkt['TCP'].dport)
            return tcpPort

    def getTcpPortSet(self, portType='s'):
        if (self.isPortTypeValid(portType)):
            tcpPortSet = set()
            for pcap in self.pcapFiles:
                for pkt in pcap['packets']:
                    if (self.isLayerExist(pkt, 'TCP')):
                        if (portType == 's'):
                            tcpPortSet.add(pkt['TCP'].sport)
                        elif (portType == 'd'):
                            tcpPortSet.add(pkt['TCP'].dport)
            return tcpPortSet

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

    def getGlobalTime(self):
        timestamp = self.getTimestamp()
        return min(timestamp), max(timestamp)

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

    def getIpArrival(self):
        arrivalTimestamp = {}
        for pcap in self.pcapFiles:
            for pkt in pcap['packets']:
                if (pkt['IP'].src in arrivalTimestamp):
                    arrivalTimestamp[pkt['IP'].src].append(pkt.time)
                else:
                    arrivalTimestamp[pkt['IP'].src] = []
                    arrivalTimestamp[pkt['IP'].src].append(pkt.time)
        for pcap in self.pcapFiles:
            for pkt in pcap['packets']:
                sorted(arrivalTimestamp[pkt['IP'].src])
        return arrivalTimestamp

    def getIpArrivalRate(self):
        arrivalTimestamp = self.getIpArrival()
        arrivalRate = {}
        for key, value in arrivalTimestamp.items():
            arrivalRate[key] = len(arrivalTimestamp[key]) / self.interval
        return arrivalRate
    
    def getSubnetMask(self, subnetLength, addrType='src'):
        if (self.isAddrTypeValid(addrType)):
            subnetMask = {}
            for pcap in self.pcapFiles:
                for pkt in pcap['packets']:
                    addr = pkt['IP'].src + '/'
                    for _ in range(3 - int(subnetLength / 8)):
                        addr += '255.'
                    addr += self.subnetMaskPrefix[int(subnetLength % 8)]
                    if (subnetLength > 7):
                        for _ in range(int(subnetLength / 8)):
                            addr += '.0' 
                    net = ipaddr.ip_network(addr, strict=False)
                    subnetMask[pkt['IP'].src] = str(ipaddr.ip_address(net.network_address))
            return subnetMask

    def countSubnetMask(self, subnetLength, addrType='src'):
        # Get the subnet mask of each IP address
        subnetMask = self.getSubnetMask(subnetLength, addrType)
        # Statisitc
        if (self.isAddrTypeValid(addrType)):
            subnetMaskCounter = defaultdict(int)
            for key, value in subnetMask.items():
                subnetMaskCounter[value] += 1
            return subnetMaskCounter

    def getSubnetMaskArrival(self, subnetLength, addrType='src'):
        ipSubnetMask = self.getSubnetMask(subnetLength, addrType)
        arrivalTimestamp = {}
        for pcap in self.pcapFiles:
            for pkt in pcap['packets']:
                if (ipSubnetMask[pkt['IP'].src] in arrivalTimestamp):
                    arrivalTimestamp[ipSubnetMask[pkt['IP'].src]].append((pkt.time - self.startTime)*1000)
                else:
                    arrivalTimestamp[ipSubnetMask[pkt['IP'].src]] = []
                    arrivalTimestamp[ipSubnetMask[pkt['IP'].src]].append((pkt.time - self.startTime)*1000)
        for pcap in self.pcapFiles:
            for pkt in pcap['packets']:
                sorted(arrivalTimestamp[ipSubnetMask[pkt['IP'].src]])
        return arrivalTimestamp
    
    def getSubnetMaskArrivalRate(self, subnetLength, addrType='src'):
        arrivalTimestamp = self.getSubnetMaskArrival(subnetLength, addrType)
        arrivalRate = {}
        for key, value in arrivalTimestamp.items():
            arrivalRate[key] = len(arrivalTimestamp[key]) / self.interval
        return arrivalRate