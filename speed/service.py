"""Bounded, anonymous throughput endpoint: at most 2 GiB/day across the service."""
import asyncio
import hashlib
import os
import secrets
import time
from fastapi import HTTPException, Request
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

MIB=1024*1024


class SpeedRequest(BaseModel):
    model_config=ConfigDict(strict=True,extra='forbid')
    bytes: int=Field(ge=MIB,le=25*MIB)


class SpeedService:
    def __init__(self,store):
        self.store=store;self.sessions={};self.chunk=os.urandom(65536)
        with store.tx() as db:
            db.execute('CREATE TABLE IF NOT EXISTS speed_budget(day INTEGER NOT NULL,bucket TEXT NOT NULL,used INTEGER NOT NULL,PRIMARY KEY(day,bucket))')

    @staticmethod
    def ip(request):return request.headers.get('x-nettool-client',request.client.host if request.client else 'unknown')

    def reserve(self,ip,size):
        day=int(self.store.clock()//86400)
        bucket=hashlib.sha256((str(day)+':'+ip).encode()).hexdigest()
        now=self.store.clock()
        self.sessions={k:v for k,v in self.sessions.items() if v['expires']>now}
        if len(self.sessions)>=100:raise HTTPException(429,'The speed service is busy. Try again later.')
        with self.store.tx() as db:
            db.execute('DELETE FROM speed_budget WHERE day<?',(day-1,))
            for key,maximum in ((bucket,100*MIB),('global',2*1024*MIB)):
                row=db.execute('SELECT used FROM speed_budget WHERE day=? AND bucket=?',(day,key)).fetchone()
                if (row['used'] if row else 0)+2*size>maximum:
                    raise HTTPException(429,'Daily transfer allowance exhausted. NetTool permits 100 MiB per public IP and 2 GiB across the service each UTC day, including reserved/failed tests. Use your own compatible endpoint or try tomorrow.')
            for key in (bucket,'global'):
                db.execute('INSERT INTO speed_budget VALUES(?,?,?) ON CONFLICT(day,bucket) DO UPDATE SET used=used+excluded.used',(day,key,2*size))
        token=secrets.token_urlsafe(32)
        self.sessions[token]={'ip':ip,'expires':now+120,'bytes':size,'download':False,'upload':False}
        return {'schemaVersion':1,'token':token,'bytes':size,'expiresIn':120}

    def claim(self,request,kind):
        token=request.headers.get('authorization','').removeprefix('Bearer ')
        session=self.sessions.get(token)
        if not session or session['expires']<self.store.clock() or session['ip']!=self.ip(request):
            raise HTTPException(401,'Speed session expired or invalid.')
        if session[kind]:raise HTTPException(409,'This transfer has already been used.')
        session[kind]=True
        return session['bytes']

    def install(self,app):
        @app.post('/v1/speed/session')
        async def reserve(value:SpeedRequest,request:Request):return self.reserve(self.ip(request),value.bytes)

        @app.get('/v1/speed/latency')
        async def latency():return Response(content=b'0',media_type='application/octet-stream',headers={'Cache-Control':'no-store,no-transform'})

        @app.get('/v1/speed/download')
        async def download(request:Request):
            count=self.claim(request,'download')
            async def chunks():
                remaining=count
                while remaining:
                    part=self.chunk[:min(remaining,len(self.chunk))];remaining-=len(part)
                    yield part
                    await asyncio.sleep(0)
            return StreamingResponse(chunks(),media_type='application/octet-stream',headers={'Content-Length':str(count),'Cache-Control':'no-store,no-transform','Content-Encoding':'identity'})

        @app.post('/v1/speed/upload')
        async def upload(request:Request):
            count=self.claim(request,'upload')
            if request.headers.get('content-length')!=str(count):raise HTTPException(422,'Upload length must match the reserved test.')
            received=0
            try:
                async with asyncio.timeout(25):
                    async for chunk in request.stream():
                        received+=len(chunk)
                        if received>count:raise HTTPException(413,'Upload exceeded its reservation.')
            except TimeoutError:raise HTTPException(408,'Upload deadline exceeded.')
            if received!=count:raise HTTPException(400,'Upload incomplete.')
            return {'schemaVersion':1,'receivedBytes':received}
