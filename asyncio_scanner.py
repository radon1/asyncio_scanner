import os
import asyncio
import asyncpg
import datetime
import json
import time
import base64
from base64 import b64decode
import aiohttp
import bcrypt
from aiohttp import web
from aiohttp_validate import validate
import sys
import uuid
import aioredis
from cryptography import fernet
import aiohttp_session
from aiohttp_session import SimpleCookieStorage, session_middleware, get_session, setup, redis_storage
from aiohttp_session.redis_storage import RedisStorage
from gino import Gino


async def handler_session(request):
    session = await get_session(request)
    last_visit = session['last_visit'] if 'last_visit' in session else None
    user_agent = session['user-agent'] if 'user-agent' in session else 'your browser'
    text = f'Last visited: {last_visit}, browser: {user_agent}'
    session['last_visit'] = time.time()
    session['user-agent'] = request.headers['user-agent']
    return web.Response(text=text)


async def make_session():
    app = web.Application()
    redis = await aioredis.create_redis_pool((os.getenv('REDIS_ADDRESS'), os.getenv('REDIS_PORT')))
    setup(app, RedisStorage(redis, cookie_name='RSESSION_ID'))
    app.router.add_routes([
        web.get('/', basic, allow_head=False),
        web.post('/', handler_scan),
        web.get('/session', handler_session),
        web.post('/register', handler_register),
        web.get('/{uuid}', status),
    ])
    return app


db = Gino()


class AuthUsers(db.Model):
    __tablename__ = 'auth_users'

    id = db.Column(db.Integer(), primary_key=True, nullable=False)
    username = db.Column(db.Unicode())
    email = db.Column(db.Unicode(), nullable=False)
    password = db.Column(db.Text(), nullable=False)
    salt = db.Column(db.Unicode())



async def check_user(request):
    try:
        data = request.headers.get('authorization').split(' ')[1].encode()
    except:
        return False
    username, password = b64decode(data).decode().split(':')
    await db.set_bind(os.getenv('POSTGRES_URL'))
    get_user = await AuthUsers.query.where(AuthUsers.username == username).gino.first()
    if get_user is None:
        return False
    hashed_password = bcrypt.hashpw(password.encode(), get_user.salt.encode()).decode()
    if hashed_password == get_user.password:
        return True
    else:
        return False


@validate(
    request_schema={
        "title": "Register user",
        "description": "Register",
        "type": "object",
        "properties": {
            "username": {
                "description": "username",
                "type": "string",
                "minLength": 3,
                "maxLength": 15,
            },
            "email": {
                "description": "Email",
                "type": "string",
                "pattern": "[a-z0-9\._%+!$&*=^|~#%{}\\-]+@([a-z0-9\-]+\.){1,}([a-z]{2,22})",
            },
            "password": {
                "description": "Password",
                "type": "string",
                "pattern": "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[$@#!%*?&])[A-Za-z\d$@$!%*?&]{8,20}$",
            },
        },
        "required": ["username", "email", "password"]
    })
async def handler_register(request, *args):
    await register_user(request['username'], request['email'], request['password'])
    return web.Response()


async def register_user(username, email, password):
    salt = bcrypt.gensalt()
    password_hashed = bcrypt.hashpw(password.encode(), salt).decode()
    sql = f'insert into auth_users(username, email, password, salt) values($1, $2, $3, $4)'
    values = (username, email, password_hashed, salt.decode())
    await postgres(sql, values)


async def postgres(sql, values):
    conn = await asyncpg.connect(os.getenv('POSTGRES_URL'))
    result = await conn.execute(sql, *values)
    await conn.close()
    return result


async def basic(request):
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
    redis = await aioredis.create_redis_pool((os.getenv('REDIS_ADDRESS'), os.getenv('REDIS_PORT')))
    uu_id = str(uuid.uuid4())
    request['uuid'] = uu_id
    url = f'/{uu_id}'
    return web.Response(status=202, headers={'Location': url})


async def handler_scan(request):
    if await check_user(request) == False:
        return web.Response(status=403, text='incorrect credentials')
    return await scan(request)


async def check_port(addr, port, timeout):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(
            addr, port, ), timeout=timeout)
        writer.close()
        return f'{addr}:{port}'
    except:
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
    redis = await aioredis.create_redis_pool((os.getenv('REDIS_ADDRESS'), os.getenv('REDIS_PORT')))
    ch = await redis.subscribe('incoming')
    ch = ch[0]
    while await ch.wait_message():
        msg = await ch.get()
        asyncio.create_task(do_scan(msg.decode('utf-8')))
    redis.close()
    await redis.wait_closed()


async def do_scan(msg):
    msg = json.loads(msg)
    results = await main(msg['addrs'], msg['ports'], msg['timeout'])
    redis = await aioredis.create_redis_pool((os.getenv('REDIS_ADDRESS'), os.getenv('REDIS_PORT')))
    await redis.hset('results', msg['uuid'], json.dumps(results))


async def status(request):
    redis = await aioredis.create_redis_pool((os.getenv('REDIS_ADDRESS'), os.getenv('REDIS_PORT')))
    result = await redis.hget('results', request.match_info['uuid'])
    if result == None:
        return web.Response(status=404, text='Not found')
    else:
        return web.Response(status=200, text=result.decode())


if __name__ == '__main__':
    if len(sys.argv) >= 2 and sys.argv[1] == 'web':
        web.run_app(make_session(), port=8888)
    elif len(sys.argv) >= 2 and sys.argv[1] == 'worker':
        asyncio.run(worker())
    else:
        print('please invoke web or worker mode')
