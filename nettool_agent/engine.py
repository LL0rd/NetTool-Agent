"""Local schedules and durable evidence; no cloud account is needed for local use."""
from __future__ import annotations
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
import time
import uuid
from . import checks


def validate_checks(values):
    if not isinstance(values,list) or len(values)>16: raise ValueError('Configure at most 16 checks.')
    ids=set(); result=[]
    allowed={'id','name','kind','target','port','intervalSeconds','enabled','ipv6','reverse','mac'}
    for item in values:
        if not isinstance(item,dict) or set(item)-allowed: raise ValueError('Unknown check fields.')
        identifier=item.get('id','')
        if not isinstance(identifier,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',identifier) or identifier in ids: raise ValueError('Each check needs a unique ID (letters, digits, dash or underscore).')
        ids.add(identifier)
        name=item.get('name',identifier); kind=item.get('kind');target=item.get('target','')
        if not isinstance(name,str) or not 1<=len(name)<=80 or kind not in checks.KINDS: raise ValueError('Invalid check name or kind.')
        if not isinstance(target,str) or len(target)>2048: raise ValueError('Invalid target.')
        if kind in {'tcp','dns','ping','iperf'}: checks.target_host(target)
        elif kind=='http': checks.url(target)
        elif kind=='wol':
            import ipaddress
            ipaddress.IPv4Address(target)
            if not re.fullmatch(r'(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}',item.get('mac','')): raise ValueError('A valid device MAC is required.')
        elif kind=='openwrt' and not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',target): raise ValueError('Use the configured router alias.')
        interval=item.get('intervalSeconds',300)
        if type(interval)is not int or not 60<=interval<=86400: raise ValueError('Intervals must be 60–86400 seconds.')
        port=item.get('port',5201 if kind=='iperf' else 9 if kind=='wol' else 443)
        if type(port)is not int or not 1<=port<=65535: raise ValueError('Port must be 1–65535.')
        for flag in ['enabled','ipv6','reverse']:
            if flag in item and type(item[flag])is not bool: raise ValueError('Check flags must be booleans.')
        if kind in {'wol','iperf'} and item.get('enabled',False): raise ValueError('Wake-on-LAN and throughput tests are manual only.')
        minimum = 3600 if kind=='dhcp' else 300 if kind in {'ssdp','ipv6-observe','openwrt'} else 60
        if item.get('enabled',False) and interval < minimum: raise ValueError(f'This observation requires an interval of at least {minimum} seconds.')
        result.append(dict(item,id=identifier,name=name,kind=kind,target=target,port=port,intervalSeconds=interval,enabled=item.get('enabled',False)))
    return result


class Engine:
    def __init__(self, directory: Path, interface: str, config: dict | None=None, *, runner=checks.run_isolated, clock=time.time):
        self.directory=Path(directory);self.directory.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.interface=interface;self.config=config or {};self.runner=runner;self.clock=clock
        self._lock=threading.RLock();self._probe=threading.Lock();self._stop=threading.Event();self._next={};self._manual_next=0
        self._config_path=self.directory/'checks.json'
        raw=json.loads(self._config_path.read_text()) if self._config_path.exists() else self.config.get('checks',[])
        self._checks=validate_checks(raw)
        self._db=sqlite3.connect(self.directory/'history.sqlite',check_same_thread=False,timeout=5)
        self._db.execute('PRAGMA journal_mode=WAL')
        self._db.execute('CREATE TABLE IF NOT EXISTS events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL, timestamp REAL NOT NULL, payload TEXT NOT NULL)')
        self._db.execute('CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)');self._db.commit()
        retention=self.config.get('retentionDays',30)
        if type(retention)is not int or not 1<=retention<=365:raise ValueError('retentionDays must be 1–365.')
        self.retention=retention
        self._dhcp_lock=threading.Lock();self._dhcp_next=0
        self._thread=None

    def status(self):
        with self._lock:
            return {'schemaVersion':1,'source':'nettool-agent','interface':self.interface,'checks':self._checks.copy(),'retentionDays':self.retention,'running':self._probe.locked(),'routerAliases':sorted(self.config.get('routers',{})),'cloudConfigured':(self.directory/'monitor.json').exists(),'cloudLastSuccess':self.metadata('monitor-last-success'),'cloudLastError':self.metadata('monitor-last-error')}

    def set_checks(self,values,expected=None):
        candidate=validate_checks(values)
        with self._lock:
            if expected is not None and validate_checks(expected)!=self._checks:raise RuntimeError('Configuration changed; reload before saving.')
            temporary=self._config_path.with_suffix('.tmp')
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
            with os.fdopen(fd,'w') as stream:json.dump(candidate,stream);stream.flush();os.fsync(stream.fileno())
            os.replace(temporary,self._config_path)
            self._checks=candidate;self._next={}
            live={'observations:'+c['id'] for c in candidate}
            for row in self._db.execute("SELECT key FROM metadata WHERE key LIKE 'observations:%'").fetchall():
                if row[0] not in live:self._db.execute('DELETE FROM metadata WHERE key=?',(row[0],))
            self._db.commit()
        return self.status()

    def observation_changed(self, spec, result):
        """Compare evidence, never infer disappearance from a short passive sample."""
        data=result.get('data') or {};kind=spec['kind'];observations={}
        if result.get('status')!='passed':return False
        if kind=='ssdp':
            observations={str((d.get('address'),d.get('usn'))):True for d in data.get('devices',[])}
        elif kind=='dhcp':
            for offer in data.get('offers',[]):
                observations[offer['serverIdentifier']]={k:v for k,v in offer.get('options',{}).items() if k in ('1','3','6','15','51','58','59','119','121')}
        elif kind=='ipv6-observe':
            for row in data.get('observations',[]):
                if row.get('kind')=='router-advertisement':
                    observations[row['source']]={'managed':row['managed'],'other':row['other'],'active':row['routerLifetime']>0,
                        'dns':sorted(row['dns']),'prefixes':sorted((p['prefix'],p['onLink'],p['autonomous'],p['validLifetime']>0) for p in row['prefixes'])}
        elif kind=='openwrt':
            configuration=data.get('dhcp.configuration')
            if isinstance(configuration,list):observations['dhcp']=sorted(configuration,key=lambda x:json.dumps(x,sort_keys=True))
        if not observations:return False
        # A new target/configuration establishes a new baseline for this check.
        import hashlib
        signature=hashlib.sha256(json.dumps([spec['kind'],spec['target']],sort_keys=True).encode()).hexdigest()
        key='observations:'+spec['id']
        current=json.loads(json.dumps(observations,sort_keys=True))
        previous=self.metadata(key)
        saved=json.loads(previous) if previous else {}
        known=saved.get('values',{}) if saved.get('signature')==signature else {}
        changed=bool(known) and any(k not in known or known[k]!=v for k,v in current.items())
        known.update(current)
        # Bound persistent discoveries. Old identities may be observed as new again after eviction.
        self.metadata(key,json.dumps({'signature':signature,'values':dict(list(known.items())[-512:])},sort_keys=True))
        return changed

    def run_dhcp_probe(self, operation, cooldown=60):
        """One DHCP attempt per minute across legacy requests and saved checks."""
        if not self._dhcp_lock.acquire(blocking=False):raise RuntimeError('One DHCP probe is already running.')
        try:
            now=self.clock()
            if now<self._dhcp_next:raise RuntimeError('Wait before starting another DHCP probe.')
            self._dhcp_next=now+max(60,cooldown)
            return operation()
        finally:self._dhcp_lock.release()

    def run(self,identifier: str,*,scheduled=False):
        with self._lock:
            spec=next((dict(c)for c in self._checks if c['id']==identifier),None)
        if spec is None:raise ValueError('Unknown configured check.')
        if not self._probe.acquire(blocking=False):raise RuntimeError('Another check is running.')
        try:
            if not scheduled:
                if self.clock()<self._manual_next:raise RuntimeError('Wait three seconds before another check.')
                self._manual_next=self.clock()+3
            try:
                operation=lambda:self.runner(spec,self.interface,self.config.get('routers',{}))
                result=self.run_dhcp_probe(operation) if spec['kind']=='dhcp' else operation()
            except Exception as exc:
                # Avoid leaking router passwords, tokens or raw request bodies.
                detail='Check failed: '+type(exc).__name__
                if isinstance(exc,ValueError):detail=str(exc)[:500]
                result={'status':'unavailable','detail':detail,'data':None,'durationMS':None}
            timestamp=self.clock()
            changed=self.observation_changed(spec,result)
            if changed:result['detail']='New or changed observation compared with the stored baseline. '+result['detail']
            event={'id':str(uuid.uuid4()),'checkID':identifier,'name':spec['name'],'kind':spec['kind'],'target':spec['target'],'timestamp':datetime.fromtimestamp(timestamp,timezone.utc).isoformat(),'source':'LAN-Agent · '+self.interface,**result}
            event['changed']=changed
            encoded=json.dumps(event,allow_nan=False,separators=(',',':'))
            if len(encoded)>1_048_576:raise ValueError('Measurement exceeds the storage limit.')
            with self._lock:
                cursor=self._db.execute('INSERT INTO events(id,timestamp,payload) VALUES(?,?,?)',(event['id'],timestamp,encoded))
                event['sequence']=cursor.lastrowid
                self._db.execute('DELETE FROM events WHERE timestamp < ?',(timestamp-self.retention*86400,))
                self._db.execute('DELETE FROM events WHERE sequence <= (SELECT MAX(sequence)-100000 FROM events)')
                self._db.commit()
            return {'schemaVersion':1,'source':'nettool-agent','event':event}
        finally:self._probe.release()

    def history(self,limit=100,after=None):
        if type(limit)is not int or not 1<=limit<=200:raise ValueError('limit must be 1–200.')
        if after is not None and (type(after)is not int or after<0):raise ValueError('after must be a non-negative sequence.')
        with self._lock:
            query='SELECT sequence,payload FROM events';parameters=[]
            if after is not None:query+=' WHERE sequence > ?';parameters.append(after)
            query+=' ORDER BY sequence '+('ASC' if after is not None else 'DESC')+' LIMIT ?';parameters.append(limit)
            rows=self._db.execute(query,parameters).fetchall()
        return {'schemaVersion':1,'source':'nettool-agent','events':[dict(json.loads(payload),sequence=sequence)for sequence,payload in rows]}

    def delete_history(self):
        with self._lock:self._db.execute('DELETE FROM events');self._db.commit()
        return {'schemaVersion':1,'deleted':True}

    def metadata(self,key,value=None):
        with self._lock:
            if value is not None:self._db.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)',(key,str(value)));self._db.commit()
            row=self._db.execute('SELECT value FROM metadata WHERE key=?',(key,)).fetchone()
            return row[0] if row else None

    def tick(self):
        now=self.clock()
        with self._lock:scheduled=[dict(c)for c in self._checks if c['enabled'] and self._next.get(c['id'],0)<=now]
        for spec in scheduled:
            if self._stop.is_set():break
            self._next[spec['id']]=now+spec['intervalSeconds']
            try:self.run(spec['id'],scheduled=True)
            except RuntimeError:pass

    def start(self):
        if self._thread:return
        def loop():
            while not self._stop.is_set():
                try:self.tick()
                except Exception:pass # next scheduled run can recover; no sensitive exception dump.
                self._stop.wait(1)
        self._thread=threading.Thread(target=loop,name='nettool-scheduler',daemon=True);self._thread.start()

    def close(self):
        self._stop.set()
        if self._thread:self._thread.join(timeout=30)
        with self._probe:
            with self._lock:self._db.close()
