import hashlib,http.client,json,pathlib,ssl
profile=json.loads(pathlib.Path('/acceptance/recovered-admin/database-a558a49e-5b37-4355-9878-0a54c4a74e60.json').read_text())
context=ssl.create_default_context(cafile=profile['server_ca'])
context.minimum_version=ssl.TLSVersion.TLSv1_3
context.maximum_version=ssl.TLSVersion.TLSv1_3
context.load_cert_chain(profile['identity']['certificate'], profile['identity']['private_key'])
token=pathlib.Path(profile['bearer_file']).read_text().strip()

def request(method,path,payload=None):
    connection=http.client.HTTPSConnection('localhost',9443,context=context,timeout=15)
    headers={'Authorization':'Bearer '+token,'Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2026-07-28'}
    body=None
    if payload is not None:
        headers['Content-Type']='application/json'
        headers['Mcp-Method']=payload['method']
        payload['params']['_meta']={'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientInfo':{'name':'kasumi-linux-offline-acceptance','version':'1'},'io.modelcontextprotocol/clientCapabilities':{}}
        body=json.dumps(payload).encode()
    connection.request(method,path,body,headers)
    version=connection.sock.version()
    reply=connection.getresponse();status=reply.status
    raw=reply.read((1<<20)+1);connection.close()
    assert len(raw)<=1<<20
    assert status==200,('unexpected HTTP status',status,raw.decode(errors='replace'))
    if raw.startswith(b'event:') or raw.startswith(b'data:'):
        messages=[json.loads(line[5:].strip()) for line in raw.splitlines() if line.startswith(b'data:')]
        assert len(messages)==1;decoded=messages[0]
    else: decoded=json.loads(raw)
    return version,decoded

version,discovered=request('POST','/mcp',{'jsonrpc':'2.0','id':1,'method':'server/discover','params':{}})
assert discovered['result']['supportedVersions']==['2026-07-28'], discovered
_,listed=request('POST','/mcp',{'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}})
assert listed['result']['tools']
_,metadata=request('GET','/.well-known/oauth-protected-resource/mcp')
assert not metadata.get('authorization_servers'), 'local deployment falsely advertises an authorization server'
print(json.dumps({'tls':version,'protocol':'2026-07-28','tools':len(listed['result']['tools']),'local_oauth_authorization_servers':metadata.get('authorization_servers',[])}))
