"""Opt-in outbound Monitor relay. No inbound WAN port or remote shell."""
from datetime import datetime, timezone
import getpass
import json
import os
from pathlib import Path
import re
import ssl
import threading
import urllib.request
from urllib.parse import urlsplit


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def base_url(value):
    parsed = urlsplit(value)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('','/'):
        raise ValueError('Monitor requires an HTTPS base URL without credentials, path or query.')
    return value.rstrip('/')


def request(base, path, body, token=None):
    data = json.dumps(body, allow_nan=False).encode()
    if len(data)>262144:raise ValueError('Monitor upload exceeds 256 KiB.')
    headers={'Content-Type':'application/json','User-Agent':'NetTool-Agent/1'}
    if token:headers['Authorization']='Bearer '+token
    req=urllib.request.Request(base_url(base)+path,data=data,headers=headers,method='POST')
    opener=urllib.request.build_opener(NoRedirect,urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(req,timeout=15) as response:
        raw=response.read(262145)
        if len(raw)>262144:raise ValueError('Monitor response exceeds 256 KiB.')
        result=json.loads(raw)
        if result.get('schemaVersion')!=1:raise ValueError('Unsupported Monitor protocol.')
        return result


def save_config(path,value):
    temporary=path.with_suffix('.tmp')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(fd,'w') as stream:
        json.dump(value,stream);stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,path)


class Relay:
    def __init__(self, engine, transport=request):
        self.engine,self.transport=engine,transport
        self.path=engine.directory/'monitor.json'
        self.stop_event=threading.Event();self.thread=None

    def config(self):
        if not self.path.exists():return None
        if self.path.stat().st_size>32768:raise ValueError('Monitor configuration is too large.')
        value=json.loads(self.path.read_text())
        base_url(value['baseURL'])
        if not isinstance(value.get('token'),str) or not value['token'].startswith('nta_'):raise ValueError('Invalid agent key.')
        if not isinstance(value.get('checkIDs'),list) or len(value['checkIDs'])>16 or not all(isinstance(x,str) for x in value['checkIDs']):raise ValueError('Select at most sixteen check IDs.')
        return value

    def tick(self):
        config=self.config()
        if not config:return
        after=int(self.engine.metadata('monitor-sequence') or 0)
        rows=self.engine.history(limit=50,after=after)['events']
        selected=set(config['checkIDs'])
        events=[]
        for event in rows:
            if event['checkID'] not in selected:continue
            # Explicit allowlist: packet data, router output, passwords and tokens never leave the LAN.
            summary={key:event[key] for key in ('id','checkID','name','kind','target','timestamp','status','detail','source','durationMS')}
            summary['detail']=summary['detail'][:2000]
            summary['changed']=event.get('changed',False)
            if summary['durationMS'] is not None:summary['durationMS']=float(summary['durationMS'])
            events.append(summary)
        pending=json.loads(self.engine.metadata('monitor-command-acks') or '[]')
        remote=config.get('allowRemoteChecks') is True
        response=self.transport(config['baseURL'],'/v1/agent/events',{'events':events,'remote':remote,'acknowledgements':pending[-10:]},config['token'])
        accepted=set(response.get('accepted',[]))
        if not all(event['id'] in accepted for event in events):raise ValueError('Monitor did not acknowledge the complete batch.')
        if rows:self.engine.metadata('monitor-sequence',rows[-1]['sequence'])
        self.engine.metadata('monitor-command-acks','[]')
        self.engine.metadata('monitor-last-success',datetime.now(timezone.utc).isoformat())
        self.engine.metadata('monitor-last-error','')
        for command in response.get('commands',[])[:5]:
            if not remote or not isinstance(command,dict):continue
            cid=command.get('id','');check_id=command.get('checkID')
            if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',cid):continue
            try:
                expires=datetime.fromisoformat(command['expiresAt'].replace('Z','+00:00'))
                if expires.tzinfo is None or expires<=datetime.now(timezone.utc):continue
            except (KeyError,ValueError,TypeError):continue
            executed=json.loads(self.engine.metadata('monitor-executed') or '[]')
            pending=json.loads(self.engine.metadata('monitor-command-acks') or '[]')
            pending.append(cid);self.engine.metadata('monitor-command-acks',json.dumps(pending[-10:]))
            if cid in executed:continue
            # Persist before running: a restart cannot execute a command twice.
            self.engine.metadata('monitor-executed',json.dumps((executed+[cid])[-100:]))
            spec=next((c for c in self.engine.status()['checks'] if c['id']==check_id and c['id'] in selected and c['kind'] in ('tcp','http','dns','ping')),None)
            if spec:
                try:self.engine.run(check_id)
                except (ValueError,RuntimeError):pass

    def start(self):
        if self.thread:return
        def loop():
            while not self.stop_event.is_set():
                try:self.tick()
                except Exception as error:
                    self.engine.metadata('monitor-last-error',type(error).__name__)
                self.stop_event.wait(30)
        self.thread=threading.Thread(target=loop,name='nettool-monitor',daemon=True);self.thread.start()

    def close(self):
        self.stop_event.set()
        if self.thread:self.thread.join(timeout=50)


def main():
    import argparse
    parser=argparse.ArgumentParser(description='Pair this customer-operated agent with optional NetTool Monitor. No remote shell is provided.')
    parser.add_argument('--data-dir',type=Path,required=True)
    parser.add_argument('--base-url',default='https://nettool.d-r.dev')
    parser.add_argument('--check',action='append',default=[],help='Explicit check ID whose summary may leave the LAN; repeat for each check')
    parser.add_argument('--allow-remote-checks',action='store_true',help='Allow only selected, configured TCP/HTTP/DNS/ICMP checks to be requested from the app')
    args=parser.parse_args()
    if not args.data_dir.is_dir():parser.error('Start the agent first, then use its existing data directory.')
    if len(args.check)>16:parser.error('Select at most sixteen checks.')
    code=getpass.getpass('Pairing code shown in NetTool (hidden): ').strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]{43}',code):parser.error('Invalid pairing code.')
    try:
        result=request(args.base_url,'/v1/pairings/claim',{'code':code,'remote':args.allow_remote_checks})
        save_config(args.data_dir/'monitor.json',{'baseURL':base_url(args.base_url),'token':result['token'],'id':result['id'],'checkIDs':args.check,'allowRemoteChecks':args.allow_remote_checks})
    except Exception as error:parser.exit(1,'Pairing failed: '+type(error).__name__+'\n')
    print('Paired. Only selected check summaries are uploaded; the relay reloads within 30 seconds. Keep monitor.json private. Delete it and revoke the agent in the app to disconnect.')


if __name__=='__main__':main()
