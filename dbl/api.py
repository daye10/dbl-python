
from python_socks.async_.asyncio import Proxy
import asyncio
import json
import logging
import random
import socket
import ssl
import time

from . import scream
from urllib.request import getproxies

class Client():
    apihost = 'ul2ahv9ohheiyu3t.dblgnds.channel.or.jp'
    apiport = 34210
    apitimeout = 10 # seconds
    apiversion = 275

    def __init__(self, creds_file):
        self.notificationStatus = {}
        with open(creds_file, 'r') as fd:
            self.creds = json.loads(fd.read())

    def current_time_ms(self, now=time.time()):
        return round(now * 1000)

    """
    Gets HTTP proxy information from HTTP_PROXY environment variable, or else from
    from System Configuration for macOS and Windows Systems Registry for Windows.
    """
    def get_http_proxy(self) -> tuple:
        host = None
        port = None
        proxy_envs = getproxies()
        try:
            proxy = proxy_envs['http']
            if proxy.startswith('http://'):
                proxy = proxy[7:]
            (host, port) = proxy.split(':')
            host = host if len(host) > 0 else None
            try:
                port = int(port)
            except ValueError:
                pass
        except KeyError:
            pass
        return (host, port)

    """
    Returns SSL context.
    XXX Disabled server certification authentication, because it uses a certificate
        that is not certified by any common authority.
    """
    def ssl_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    """
    Connects to the API server at given IP and port.
    """
    async def connect(self, ip, port=None):
        self.sequence_number = 1
        if port is None:
            port = self.apiport
        proxy_host, proxy_port = self.get_http_proxy()
        if proxy_host is not None and proxy_port is not None:
            logging.info(f'Using proxy {proxy_host}:{proxy_port}')
            proxy = Proxy.from_url(f'http://{proxy_host}:{proxy_port}')
            sock = await proxy.connect(dest_host=ip, dest_port=port)
            logging.info(f"Connecting to {ip}:{port}")
            self.reader, self.writer = await asyncio.open_connection(
                host=None,
                port=None,
                sock=sock,
                ssl=self.ssl_context(),
                server_hostname=ip,
                ssl_handshake_timeout=self.apitimeout,
            )
        else:
            logging.info(f"Connecting to {ip}:{port}")
            self.reader, self.writer = await asyncio.open_connection(
                ip,
                port,
                ssl=self.ssl_context(),
                ssl_handshake_timeout=self.apitimeout,
            )

    """
    Disconnects from the API server.
    """
    async def close(self):
        self.writer.close()
        await self.writer.wait_closed()

    async def send_request(self, req: scream.Request):
        req.seqNumber = self.sequence_number
        logging.debug(req)
        packet = scream.Packet.encode(req.serialize())
        self.writer.write(packet)
        await self.writer.drain()
        self.sequence_number += 1

    async def recv_response(self):
        packet = await self.reader.read(8192)
        payload, packetLen = scream.Packet.decode(packet)
        resp = scream.Response.parse(payload)
        logging.debug(resp)
        return resp

    async def call_request(self, req):
        await self.send_request(req)
        while True:
            resp = await self.recv_response()
            if resp.seqNumber == req.seqNumber:
                break
        return resp

    """
    Waits for a specific time while receiving pings from server
    """
    async def wait_for(self, reason, seconds):
        logging.info(f'Waiting for {seconds:.2f} second(s) to {reason}')
        loop = asyncio.get_running_loop()
        try:
            elapsed = 0
            timeout = seconds
            start = loop.time()
            while timeout >= 0:
                resp = await asyncio.wait_for(self.recv_response(), timeout=timeout)
                end = loop.time()
                timeout = seconds - (end - start)
        except asyncio.TimeoutError:
            pass

    """
    Waits for a random time choosen between a and b seconds
    while receiving pings from server
    """
    async def wait_rand(self, reason, a, b):
        return await self.wait_for(reason, random.uniform(a, b))

    """
    Checks if some new data has to be downloaded (fake)
    """
    def has_to_download_new_data(self):
        chance = 3/10
        return random.random() < chance

    """
    Checks if the notification shows we got presents.
    """
    def has_presents(self):
        return not self.notificationStatus.get('presentCount') == 0

    """
    Gets limited login bonuses.
    """
    async def get_limited_login_bonuses(self, resp: scream.CheckNewDayResponse):
        bonus_ids = [bonus['eventId'] for bonus in resp.limitedLoginBonusResult]
        if len(bonus_ids) == 0:
            return

        logging.info(f'Received {len(bonus_ids)} limited login bonus(es)')
        for bonus_id in bonus_ids:
            page = 1
            while True:
                req = scream.GetLimitedLoginBonusRequest(bonus_id, page)
                resp = await self.call_request(req)
                if resp.lastPage > page:
                    page += 1
                else:
                    break

        await self.wait_rand('simulate looking at limited login bonuses', 10, 20)

    """
    Chooses what will be your next limited login bonus.
    It just selects the first item(s).
    """
    async def choose_next_limited_login_bonus(self, resp: scream.CheckNewDayResponse):
        next_bonuses = resp.nextLoginBonusItem.get('itemList')
        next_bonuses_num = resp.nextLoginBonusItem.get('itemSelectCount')
        nextLoginBonusItemList = []

        for i in range(next_bonuses_num):
            try:
                next_bonus = next_bonuses[i]
            except IndexError:
                logging.warning(f"Couldn't choose next login bonus, i={i}, next_bonuses={next_bonuses}")
                continue
            next_bonus = {key: next_bonus[key] for key in ['categoryId', 'itemId', 'itemCount']}
            nextLoginBonusItemList.append(next_bonus)

        next_bonuses_num = len(nextLoginBonusItemList)
        if next_bonuses_num > 0:
            logging.info(f'Choosing {next_bonuses_num} next login bonus(es): {nextLoginBonusItemList}')
            nonce = self.current_time_ms()
            req = scream.SetNextLoginBonusItemRequest(nextLoginBonusItemList, nonce)
            await self.call_request(req)

            await self.wait_rand('simulate choosing next login bonus', 5, 10)

    """
    Logs into DBL.
    """
    async def login(self):
        # Connect to API host
        ip = socket.gethostbyname(self.apihost)
        await self.connect(ip)

        # Send login request
        req = scream.RequestLoginRequest(
            self.apiversion,
            self.creds['guid_'],
            self.creds['key_'],
            self.creds['region_'],
            self.creds['loginLanguage_'],
        )
        resp = await self.call_request(req)

        # Connect to agent provided in response
        await self.close()
        newhost, newport = resp.agentEndPoint
        await self.connect(newhost, newport)

        # Send hello request
        req = scream.HelloRequest(resp.token)
        await self.call_request(req)

        # Log in
        req = scream.LoginUserRequest(self.creds['deviceId'], self.creds['region_'], self.creds['currency'], '', self.creds['platformId'])
        await self.call_request(req)

        # Get version information
        req = scream.GetVersionRequest()
        await self.call_request(req)

        logging.info('Login complete')

    """
    Perform post login requests.
    """
    async def post_login(self):
        req = scream.GetValueRequest(['gdpr_last_date', 'gdpr_last_ver'])
        await self.call_request(req)

        req = scream.GetValueRequest(['capy_status'])
        await self.call_request(req)

        if self.has_to_download_new_data():
            await self.wait_rand('simulate game data download', 10, 20)

        req = scream.GetDataVersionRequest()
        await self.call_request(req)

        req = scream.GetStoryModeStatusVersionRequest()
        await self.call_request(req)

        req = scream.GetPremiumPassStatusRequest()
        await self.call_request(req)

        req = scream.GetStoryClearCountDayRequest(1)
        await self.call_request(req) # TODO maybe get other pages if resp.lastPage > 1?

        req = scream.GetAvailableVipIdListRequest()
        await self.call_request(req)

        req = scream.GetUserItemAndPointRequest(1)
        await self.call_request(req) # TODO maybe get other pages if resp.lastPage > 1?

        req = scream.CheckNewDayRequest(self.current_time_ms())
        new_day_resp = await self.call_request(req)

        req = scream.GetValueRequest(['game_mode_convert_version'])
        await self.call_request(req)

        req = scream.GetValueRequest(['gamemode_unlock'])
        await self.call_request(req)

        if len(new_day_resp.limitedLoginBonusResult) > 0:
            await self.get_limited_login_bonuses(new_day_resp)
            await self.choose_next_limited_login_bonus(new_day_resp)

        req = scream.GetMissionSetInfoRequest(1)
        await self.call_request(req) # TODO maybe get other pages if resp.lastPage > 1?

        missionSetIdList = [0]
        page = 1
        req = scream.GetMissionInfoRequest(missionSetIdList, page)
        await self.call_request(req) # TODO maybe get other pages if resp.lastPage > 1?

        # TODO find where this list comes from
        missionSetIdList = [0, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026, 2027, 2028, 2029, 2030, 2031, 2032, 2039, 2033, 2040, 2034, 2041, 2035, 2042, 2036, 2043, 2037, 2044, 2038, 2200, 2201, 2202, 2203, 2204, 2205, 2206, 2207, 2208, 2209, 1]
        page = 1
        req = scream.GetMissionGainInfoRequest(missionSetIdList, page)
        await self.call_request(req) # TODO maybe get other pages if resp.lastPage > 1?

        req = scream.GetHomeInfoRequest()
        resp = await self.call_request(req)
        self.notificationStatus = resp.notificationStatus

        req = scream.GetVersionRequest()
        await self.call_request(req)

        logging.info('Post-login complete')

    """
    Get all received presents.
    """
    async def get_all_presents(self):
        # TODO maybe handle pagination
        req = scream.GetPresentBoxRequest(1)
        resp = await self.call_request(req)

        await self.call_request(scream.GetVersionRequest())

        present_ids = [p['presentBoxId'] for p in resp.presentBoxList]
        num_presents = len(present_ids)
        if num_presents > 0:
            logging.info(f"Getting {num_presents} present(s)")
            req = scream.ReceivePresentBoxRequest(present_ids)
            await self.call_request(req)
