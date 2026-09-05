#!/usr/bin/env python3
"""Isolated macOS accepted-reset-socket TCP_NODELAY observation, no Kasumi code."""
import json, socket, struct, platform, time
from pathlib import Path
observations=[]
for delay in (0.01, 0.1, 0.5):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0));listener.listen(4)
        with socket.socket() as client:
            client.connect(listener.getsockname())
            client.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0))
        time.sleep(delay)
        accepted,_=listener.accept()
        with accepted:
            try:
                accepted.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
                result={'success':True}
            except OSError as error:
                result={'success':False,'errno':error.errno,'message':error.strerror}
        observations.append({'delay_seconds':delay,'result':result})
print(json.dumps({'platform':platform.platform(),'observed_unix_seconds':time.time(),'scenario':'client reset queued before accept; configure accepted socket TCP_NODELAY','observations':observations,'scope':'reproduces matching OS error; original benchmark did not record its syscall'},indent=2))
