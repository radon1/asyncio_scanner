import asyncio
import json
import aiohttp
from aiohttp import web
from aiohttp_validate import validate
import sys
import uuid
import aioredis


async def basic(request):
    print(request)
    return web.Response(text="for scanning ports use a post method with payload")


@validate(
    request_schema={
        "title": "Scan schema",
        "description": "Scanning schema",
        "type": "object",
        "properties": {
            "addrs": {
                "description": "List of addresses",
                "type": "array",
                "items": {
                    "type": "string"
                },
                "minItems": 1,
                "uniqueItems": True
            },
            "ports": {
                "description": "List of ports",
                "type": "array",
                "items": {
                    "type": "integer"
                },
                "minItems": 1,
                "iniqueItems": True
            },
            "timeout": {
                "description": "The scan timeout",
                "type": "integer",
                "minimum": 5,
                "maximum": 30
            },
        },
        "required": ["addrs", "ports", "timeout"]
    })
async def scan(request, *args):
    redis = await aioredis.create_redis_pool(('localhost', 6379))
    addrs = request['addrs']
    ports = request['ports']
    timeout = request['timeout']
    uu_id = str(uuid.uuid4())
    request['uuid'] = uu_id
    url = f'/{uu_id}'
    await redis.publish('incoming', json.dumps(request))
    return web.Response(status=202, headers={'Location': url})


async def check_port(addr, port, timeout):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(
            addr, port,), timeout=timeout)
        print(f'Connected, to {addr}:{port}')
        writer.close()
        return f'{addr}:{port}'
    except:
        print(f'Couldnt connect to {addr}:{port}')
        return False


async def main(addrs, ports, timeout):
    coroutines = []
    for addr in addrs:
        for port in ports:
            task = asyncio.create_task(check_port(addr, port, timeout))
            coroutines.append(task)
    result = await asyncio.gather(*coroutines)
    result = [x for x in result if x]
    return result


async def worker():
    redis = await aioredis.create_redis_pool(('localhost', 6379))
    ch = await redis.subscribe('incoming')
    ch = ch[0]
    while await ch.wait_message():
        msg = await ch.get()
        msg = json.loads(msg.decode('utf-8'))
        results = await main(msg['addrs'], msg['ports'], msg['timeout'])
        await redis.hset('results', msg['uuid'], json.dumps(results))
    redis.close()
    await redis.wait_closed()


async def status(request):
    redis = await aioredis.create_redis_pool(('localhost', 6379))
    result = await redis.hget('results', request.match_info['uuid'])
    print('result', result)
    if result == None:
        return web.Response(status=404, text='Not found')
    else:
        return web.Response(status=200, text=result.decode())


if __name__ == '__main__':
    if len(sys.argv) >= 2 and sys.argv[1] == 'web':
        app = web.Application()
        app.add_routes([
            web.get('/', basic, allow_head=False),
            web.post('/', scan),
            web.get('/{uuid}', status)
        ])
        web.run_app(app, port=8888)
    elif len(sys.argv) >= 2 and sys.argv[1] == 'worker':
        asyncio.run(worker())
    else:
        print('please invoke web or worker mode')

