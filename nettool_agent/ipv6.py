"""Passive Ethernet IPv6 Router Advertisement and DHCPv6 evidence, RFC 4861/8415."""
from __future__ import annotations
import ipaddress
import socket
import struct
import time


def checksum(data: bytes):
    if len(data)%2:data+=b'\0'
    total=sum(struct.unpack('!'+str(len(data)//2)+'H',data))
    while total>>16:total=(total&65535)+(total>>16)
    return (~total)&65535


def decode(frame: bytes):
    if len(frame)<54:return None
    offset=14;kind=int.from_bytes(frame[12:14],'big')
    for _ in range(2):
        if kind not in (0x8100,0x88a8):break
        if len(frame)<offset+4:return None
        kind=int.from_bytes(frame[offset+2:offset+4],'big');offset+=4
    if kind!=0x86dd or len(frame)<offset+40:return None
    ip=frame[offset:];length=int.from_bytes(ip[4:6],'big')
    if ip[0]>>4!=6 or len(ip)<40+length:return None
    next_header=ip[6];payload=ip[40:40+length]
    source=str(ipaddress.IPv6Address(ip[8:24]));destination=str(ipaddress.IPv6Address(ip[24:40]))
    # Deliberately reject fragments and extension headers instead of misparsing them.
    if next_header==58 and len(payload)>=16 and payload[0]==134 and payload[1]==0:
        pseudo=ip[8:40]+len(payload).to_bytes(4,'big')+b'\0\0\0\x3a'
        if ip[7]!=255 or not ipaddress.IPv6Address(source).is_link_local or checksum(pseudo+payload)!=0:return None
        record={'kind':'router-advertisement','source':source,'destination':destination,'managed':bool(payload[5]&128),'other':bool(payload[5]&64),'routerLifetime':int.from_bytes(payload[6:8],'big'),'prefixes':[],'dns':[]}
        cursor=16
        while cursor<len(payload):
            if cursor+2>len(payload):return None
            size=payload[cursor+1]*8
            if size==0 or cursor+size>len(payload):return None
            option=payload[cursor:cursor+size]
            if option[0]==3:
                if size!=32 or option[2]>128:return None
                record['prefixes'].append({'prefix':str(ipaddress.IPv6Address(option[16:32]))+'/'+str(option[2]),'onLink':bool(option[3]&128),'autonomous':bool(option[3]&64),'validLifetime':int.from_bytes(option[4:8],'big'),'preferredLifetime':int.from_bytes(option[8:12],'big')})
            elif option[0]==25:
                if size<24 or (size-8)%16:return None
                record['dns'] += [str(ipaddress.IPv6Address(option[i:i+16]))for i in range(8,size,16)]
            cursor+=size
        return record
    if next_header==17 and len(payload)>=12:
        source_port,dest_port,udp_length,_=struct.unpack('!HHHH',payload[:8])
        if {source_port,dest_port}!={546,547} or udp_length!=len(payload):return None
        pseudo=ip[8:40]+len(payload).to_bytes(4,'big')+b'\0\0\0\x11'
        if payload[6:8]==b'\0\0' or checksum(pseudo+payload)!=0:return None
        dhcp=payload[8:]
        names={1:'SOLICIT',2:'ADVERTISE',3:'REQUEST',5:'RENEW',6:'REBIND',7:'REPLY',8:'RELEASE',9:'DECLINE',11:'INFORMATION-REQUEST'}
        if dhcp[0]not in names:return None
        options=[];cursor=4
        while cursor<len(dhcp):
            if cursor+4>len(dhcp):return None
            code,size=struct.unpack('!HH',dhcp[cursor:cursor+4]);cursor+=4
            if cursor+size>len(dhcp)or len(options)>=128:return None
            # Only option presence and length; no DUID/client identifiers are retained.
            options.append({'code':code,'length':size});cursor+=size
        return {'kind':'dhcpv6','source':source,'destination':destination,'message':names[dhcp[0]],'transactionID':dhcp[1:4].hex(),'options':options}
    return None


def capture(interface: str):
    if not hasattr(socket,'AF_PACKET'):raise ValueError('Passive IPv6 capture requires Linux and CAP_NET_RAW.')
    observations=[];seen=set();packets=0;end=time.monotonic()+5
    with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)) as sock:
        sock.bind((interface,0));sock.settimeout(.2)
        while time.monotonic()<end and packets<10000 and len(observations)<128:
            try:frame=sock.recv(65535)
            except socket.timeout:continue
            packets+=1;record=decode(frame)
            if record:
                key=str(record)
                if key not in seen:seen.add(key);observations.append(record)
    return {'observations':observations,'packetsExamined':packets,'seconds':5,'limitations':['Passive five-second sample on the configured agent interface. No packets transmitted.','No promiscuous mode; unicast DHCPv6 between other clients and routers may not be visible.','Fragmented IPv6 and extension headers are not decoded. No raw packets or DUIDs are retained.']}
