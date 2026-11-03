"""Optional independent NetTool speed endpoint, no account or RevenueCat dependency."""
from contextlib import contextmanager
from pathlib import Path
import os
import sqlite3
import threading
import time
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from .service import SpeedService

class BudgetStore:
    clock=staticmethod(time.time)
    def __init__(self):
        path=Path(os.environ.get('NETTOOL_SPEED_DATABASE','data/speed.sqlite'))
        path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.db=sqlite3.connect(path,check_same_thread=False,timeout=5)
        self.db.row_factory=sqlite3.Row
        self.lock=threading.RLock()
    @contextmanager
    def tx(self):
        with self.lock,self.db:yield self.db

app=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)
@app.middleware('http')
async def boundaries(request:Request,call_next):
    # Do not trust a client-supplied IP header on a standalone installation.
    request.scope['headers']=[(k,v) for k,v in request.scope['headers'] if k.lower()!=b'x-nettool-client']
    if request.method=='POST':
        length=request.headers.get('content-length','')
        if not length.isascii() or not length.isdigit() or len(length)>8 or int(length)>25*1024*1024:
            return JSONResponse({'error':'body_limit'},413)
        kind='application/octet-stream' if request.url.path=='/v1/speed/upload' else 'application/json'
        if request.headers.get('content-type','').split(';')[0]!=kind:return JSONResponse({'error':'content_type'},415)
    response=await call_next(request)
    response.headers['Cache-Control']='no-store,no-transform'
    response.headers['X-Content-Type-Options']='nosniff'
    return response
SpeedService(BudgetStore()).install(app)
