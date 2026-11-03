"""Bounded customer-requested checks. Never executes shell text or changes routers."""
from __future__ import annotations
import ipaddress
import json
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_RESPONSE = 1_048_576
KINDS = {'tcp', 'http', 'dns', 'ping', 'iperf', 'ssdp', 'wol', 'ipv6-observe', 'openwrt', 'dhcp'}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def target_host(value: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 253 or value.startswith('-') or any(c.isspace() or ord(c) < 33 for c in value) or any(c in value for c in '/?#@\\'):
        raise ValueError('Provide a hostname or IP address without a URL, credentials or spaces.')
    return value


def resolve(host: str, ipv6: bool = False) -> list[str]:
    target_host(host)
    # A child process makes an unresponsive system resolver cancellable by timeout.
    code = 'import socket,json,sys; a=socket.getaddrinfo(sys.argv[1],None,int(sys.argv[2]),socket.SOCK_STREAM); print(json.dumps(sorted(set(x[4][0] for x in a))[:32]))'
    result = subprocess.run([sys.executable, '-c', code, host, str(int(socket.AF_INET6 if ipv6 else socket.AF_INET))], capture_output=True, text=True, timeout=5, check=False)
    if result.returncode != 0:
        raise ValueError('System DNS resolution failed for the selected address family.')
    return json.loads(result.stdout)


def url(value: str, *, https_only=False):
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in (('https',) if https_only else ('https', 'http')) or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or len(value) > 2048:
        raise ValueError('Use an HTTP(S) URL without credentials or fragment.')
    return parsed


def http_json(address: str, payload: dict, cafile: str | None = None) -> dict:
    url(address, https_only=True)
    context = ssl.create_default_context(cafile=cafile)
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(address, data=json.dumps(payload).encode(), headers={'Content-Type': 'application/json'}, method='POST')
    with opener.open(request, timeout=5) as response:
        raw = response.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise ValueError('Response exceeds 1 MiB.')
    return json.loads(raw)


def openwrt(router: dict) -> dict:
    # Credentials come only from the customer's protected config, never from API responses.
    def call(session, obj, method, args):
        data = http_json(router['url'], {'jsonrpc':'2.0','id':1,'method':'call','params':[session,obj,method,args]}, router.get('caFile'))
        result = data.get('result', [])
        if len(result) < 2 or result[0] != 0:
            raise ValueError('Router refused the read-only RPC. Check the NetTool rpcd ACL.')
        return result[1]
    login = call('0'*32, 'session', 'login', {'username':router['username'],'password':router['password'],'timeout':30})
    session = login['ubus_rpc_session']
    result = {}
    for obj, method in [('system','board'),('network.interface','dump'),('dhcp','ipv4leases'),('dhcp','ipv6leases')]:
        try:
            result[obj + '.' + method] = call(session, obj, method, {})
        except ValueError as exc:
            result[obj + '.' + method] = {'unavailable': str(exc)}
    try:
        values = call(session, 'uci', 'get', {'config':'dhcp'}).get('values', {})
        # Never return arbitrary UCI settings or Wi-Fi configuration/passwords.
        fields = {'.type','name','interface','ip','mac','hostid','duid','start','limit','leasetime','ignore','dynamicdhcp'}
        result['dhcp.configuration'] = [{key:value for key,value in item.items() if key in fields}
            for item in values.values() if isinstance(item,dict) and item.get('.type') in ('host','dhcp')][:512]
    except ValueError as exc:
        result['dhcp.configuration'] = {'unavailable': str(exc)}
    try:
        devices = call(session, 'iwinfo', 'devices', {}).get('devices', [])[:8]
        result['wifi.clients'] = {}
        for device in devices:
            if isinstance(device,str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}',device):
                try: result['wifi.clients'][device] = call(session, 'iwinfo', 'assoclist', {'device':device})
                except ValueError as exc: result['wifi.clients'][device] = {'unavailable':str(exc)}
    except ValueError as exc:
        result['wifi.clients'] = {'unavailable': str(exc)}
    return result


def ssdp(interface: str) -> list[dict]:
    packet = b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'
    results = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        if hasattr(socket, 'SO_BINDTODEVICE'):
            sock.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,interface.encode()+b'\0')
        sock.setsockopt(socket.IPPROTO_IP,socket.IP_MULTICAST_TTL,2)
        sock.settimeout(.2)
        sock.sendto(packet,('239.255.255.250',1900))
        end=time.monotonic()+2
        while time.monotonic()<end and len(results)<64:
            try: data, peer=sock.recvfrom(8192)
            except socket.timeout: continue
            lines=data.decode('utf-8','replace').split('\r\n')
            if not lines[0].startswith('HTTP/1.1 200'): continue
            headers={k.lower():v.strip()[:512] for line in lines[1:] if ':' in line for k,v in [line.split(':',1)]}
            record={'address':peer[0], **{k:headers[k] for k in ['usn','st','server','location'] if k in headers}}
            results[(peer[0],headers.get('usn',''))]=record
    # Never follows untrusted device-provided LOCATION URLs automatically.
    return list(results.values())


def wake(target: str, mac: str, port: int, interface: str):
    address=ipaddress.IPv4Address(target)
    if address.is_multicast or address.is_unspecified:
        raise ValueError('Use the device or its subnet broadcast IPv4 address.')
    compact=re.sub(r'[:-]','',mac)
    if not re.fullmatch('[0-9a-fA-F]{12}',compact): raise ValueError('Invalid MAC address.')
    raw=bytes.fromhex(compact)
    if raw[0]&1: raise ValueError('A unicast device MAC is required.')
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        if hasattr(socket,'SO_BINDTODEVICE'): sock.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,interface.encode()+b'\0')
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
        sock.sendto(b'\xff'*6+raw*16,(str(address),port))
    return 'Magic Packet sent; delivery and wake-up are not acknowledged by UDP.'


def run(spec: dict, interface: str, routers: dict) -> dict:
    started=time.monotonic()
    kind=spec['kind']; target=spec.get('target',''); value=None; status='passed'
    if kind=='tcp':
        address=resolve(target,spec.get('ipv6',False))[0]
        with socket.create_connection((address,spec.get('port',443)),timeout=3): pass
        detail='TCP connection established.'
    elif kind=='dns':
        value={'addresses':resolve(target,spec.get('ipv6',False))};detail=', '.join(value['addresses'])
    elif kind=='http':
        url(target)
        request=urllib.request.Request(target,method='HEAD',headers={'User-Agent':'NetTool-Agent/1'})
        opener=urllib.request.build_opener(NoRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        try:
            with opener.open(request,timeout=5) as response: code=response.status
        except urllib.error.HTTPError as exc: code=exc.code;exc.close()
        status='passed' if 200<=code<400 else 'failed'
        value={'httpStatus':code};detail=f'HTTP {code}; redirects not followed; HTTPS uses system trust.'
    elif kind=='ping':
        executable=shutil.which('ping')
        if not executable: raise ValueError('Install iputils-ping on the agent.')
        address=resolve(target,spec.get('ipv6',False))[0]
        result=subprocess.run([executable,'-n','-c','3','-W','1',address],capture_output=True,text=True,timeout=6)
        status='passed' if result.returncode==0 else 'warning';detail=result.stdout[-4096:] or 'No ICMP replies. Filtering and loss cannot be distinguished.'
    elif kind=='iperf':
        executable=shutil.which('iperf3')
        if not executable: raise ValueError('Install iperf3 on the agent.')
        address=resolve(target,spec.get('ipv6',False))[0]
        arguments=[executable,'-c',address,'-p',str(spec.get('port',5201)),'-t','3','-P','1','-b','100M','-J','--connect-timeout','3000','--rcv-timeout','5000','--snd-timeout','3000']
        if spec.get('reverse'): arguments.append('-R')
        result=subprocess.run(arguments,capture_output=True,text=True,timeout=15)
        if len(result.stdout)>MAX_RESPONSE: raise ValueError('iperf output too large.')
        value=json.loads(result.stdout)
        if result.returncode or value.get('error'): raise ValueError('iperf measurement failed: '+str(value.get('error','connection failed'))[:200])
        value=value.get('end',{});detail='iperf3 TCP between agent and chosen server; maximum requested rate 100 Mbit/s for three seconds.'
    elif kind=='ssdp':
        value={'devices':ssdp(interface)};detail=f"{len(value['devices'])} SSDP advertisements observed; not a complete inventory."
    elif kind=='dhcp':
        from .dhcp import discover
        value=discover(interface,3)
        status='passed' if value['offers'] else 'warning'
        detail=f"{len(value['offers'])} matching DHCP offers observed. No lease requested; absence of an offer does not prove server failure."
    elif kind=='wol':
        detail=wake(target,spec.get('mac',''),spec.get('port',9),interface);status='warning'
    elif kind=='ipv6-observe':
        from .ipv6 import capture
        value=capture(interface);detail=f"{len(value['observations'])} RA/DHCPv6 observations. No response does not prove absence."
    elif kind=='openwrt':
        if target not in routers: raise ValueError('Configure this OpenWrt router alias on the agent first.')
        value=openwrt(routers[target]);detail='Read-only OpenWrt ubus snapshot; unsupported or denied calls are marked unavailable.'
    else: raise ValueError('Unsupported check kind.')
    return {'status':status,'detail':detail,'durationMS':round((time.monotonic()-started)*1000,3),'data':value}


def run_isolated(spec: dict, interface: str, routers: dict) -> dict:
    selected = {spec['target']: routers[spec['target']]} if spec['kind']=='openwrt' and spec['target'] in routers else {}
    child = subprocess.run([sys.executable, '-m', 'nettool_agent.checks'], input=json.dumps({'spec':spec,'interface':interface,'routers':selected}), capture_output=True, text=True, timeout=25)
    if child.returncode or len(child.stdout)>MAX_RESPONSE:
        raise ValueError('Measurement process failed or exceeded its output limit.')
    value=json.loads(child.stdout)
    if 'error' in value: raise ValueError(value['error'])
    return value

if __name__ == '__main__':
    try:
        request=json.loads(sys.stdin.read(65537))
        result=run(request['spec'],request['interface'],request['routers'])
        encoded=json.dumps(result,allow_nan=False)
        if len(encoded)>MAX_RESPONSE:raise ValueError('Measurement exceeds the response limit.')
        print(encoded)
    except Exception as exc:
        print(json.dumps({'error':str(exc)[:500] if isinstance(exc,ValueError) else 'Measurement failed: '+type(exc).__name__}))
