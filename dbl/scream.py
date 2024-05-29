
import base64
import logging
import struct
import socket
import sys

from enum import Enum
from . import dbdata

class PacketDecodingError(Exception):
    pass

class PacketTooBig(PacketDecodingError):
    pass

class InvalidCRC(PacketDecodingError):
    pass

class LoginError(Exception):
    pass

class CommandEnum(Enum):
    RequestLogin = 0
    Hello = 1
    CheckAlive = 144
    GetVersion = 4097
    GetUserItemAndPoint = 4108
    GetValue = 4109
    CheckNewDay = 4113
    SetNextLoginBonusItem = 4114
    LoginUser = 4119
    GetLimitedLoginBonus = 4120
    GetDataVersion = 4138
    GetHomeInfo = 4353
    ReceivePresentBox = 4355
    GetPresentBox = 4354
    GetPersonalMessage = 4370
    GetStoryModeStatusVersion = 4448
    GetStoryClearCountDay = 4449
    GetAvailableVipIdList = 5385
    GetPremiumPassStatus = 5393
    GetMissionSetInfo = 5457
    GetMissionInfo = 5458
    GetMissionGainInfo = 5463

class Command():
    cmdId = None
    seqNumber = None

    @classmethod
    def get_class_by_cmd_id(cls, cmd_id):
        try:
            basename = CommandEnum(cmd_id).name
        except ValueError:
            basename = 'Unknown'
        clsname = basename + cls.__name__
        return getattr(sys.modules[__name__], clsname)

    def serialize_header(self) -> bytes:
        return struct.pack('<Hq', self.cmdId, self.seqNumber)

    def serialize_contents(self) -> bytes:
        return b''

    def serialize(self) -> bytes:
        return self.serialize_header() + self.serialize_contents()

    def unserialize_seq(self, serialized: bytes) -> int:
        fmt = '<q'
        self.seqNumber, = struct.unpack_from(fmt, serialized)
        return struct.calcsize(fmt)

    def unserialize_contents(self, serialized: bytes):
        pass

    def unserialize(self, serialized: bytes):
        start = self.unserialize_seq(serialized)
        self.unserialize_contents(serialized[start:])

    def __repr__(self):
        me = type(self).__name__
        attrs = dict(self.__dict__)
        try:
            seqNumber = attrs['seqNumber']
            del attrs['seqNumber']
        except KeyError:
            seqNumber = ''
        try:
            del attrs['cmdId']
        except KeyError:
            pass
        sep = ': ' if len(attrs) else ''
        return f'[{seqNumber}] {me}({self.cmdId}){sep}' + ', '.join([f'{k}={v}' for k, v in attrs.items()])

class Request(Command):
    def __init__(self, *args, **kwargs):
        if self.cmdId is None:
            cmd_name = type(self).__name__.removesuffix('Request')
            self.cmdId = CommandEnum[cmd_name].value

        if len(args) == 0 and 'payload' in kwargs:
            self.unserialize(kwargs['payload'])
        else:
            self.assignParams(*args)

    def assignParams(self, *args):
        pass

    @staticmethod
    def parse(packet: bytes):
        cmd_id, = struct.unpack_from('<H', packet)
        i = 2
        cls = Request.get_class_by_cmd_id(cmd_id)
        cls.cmdId = cmd_id
        req = cls(payload=packet[i:])
        return req

class UnknownRequest(Request):
    pass

class CheckAliveRequest(Request):
    pass

class RequestLoginRequest(Request):
    def assignParams(self, apiVersion, guid, key, regionId, languageId):
        self.apiVersion = apiVersion
        self.guid = guid
        self.key = key
        self.regionId = regionId
        self.languageId = languageId

    def unserialize_contents(self, data: bytes):
        self.guid = dbdata.unserialize_uuid(data[0:16])
        self.key  = dbdata.unserialize_uuid(data[16:32])
        self.apiVersion, = struct.unpack('<H', data[32:34])
        self.regionId, tail = dbdata.unserialize_string(data[34:])
        self.languageId, tail = dbdata.unserialize_string(data[34+tail:])

    def serialize_contents(self) -> bytes:
        guid = dbdata.serialize_uuid(self.guid)
        key = dbdata.serialize_uuid(self.key)
        return (guid
                + key
                + struct.pack('<H', self.apiVersion)
                + dbdata.serialize_string(self.regionId)
                + dbdata.serialize_string(self.languageId))

class HelloRequest(Request):
    def assignParams(self, token):
        self.token = token

    def unserialize_contents(self, data: bytes) -> bytes:
        self.token, = struct.unpack('<16s', data)

    def serialize_contents(self) -> bytes:
        return struct.pack('<16s', self.token)

class LoginUserRequest(Request):
    def assignParams(self, platformUserId: str, countryCode: str, currencyCode: str, adId: str, platformId: int, romType=2 ):
        self.romType = romType # jp=1, glb=2
        self.platformId = platformId # android=1, ios=2
        self.platformUserId = platformUserId
        self.countryCode = countryCode
        self.currencyCode = currencyCode
        self.adId = adId # advertizing identifier

    def unserialize_contents(self, data: bytes):
        fmt = '<BB'
        start = struct.calcsize(fmt)
        self.romType, self.platformId = struct.unpack(fmt, data[0:start])
        self.platformUserId, tail = dbdata.unserialize_string(data[start:])
        start = start + tail
        self.countryCode, tail = dbdata.unserialize_string(data[start:])
        start = start + tail
        self.currencyCode, tail = dbdata.unserialize_string(data[start:])
        start = start + tail
        self.adId, tail = dbdata.unserialize_string(data[start:])

    def serialize_contents(self) -> bytes:
        deviceId = dbdata.serialize_string(self.platformUserId)
        country = dbdata.serialize_string(self.countryCode)
        currency = dbdata.serialize_string(self.currencyCode)
        adId = dbdata.serialize_string(self.adId)
        return (struct.pack('<BB', self.romType, self.platformId)
                + deviceId
                + country
                + currency
                + adId)

class GetVersionRequest(Request):
    pass

class GetValueRequest(Request):
    def assignParams(self, keys: list):
        self.keys = keys

    def serialize_contents(self) -> bytes:
        return dbdata.serialize_vlong(len(self.keys)) + b''.join([dbdata.serialize_string(key) for key in self.keys])

    def unserialize_contents(self, data: bytes):
        self.keys = []
        n, start = dbdata.unserialize_vlong(data)
        for i in range(0, n):
            key, tail = dbdata.unserialize_string(data[start:])
            self.keys.append(key)
            start = start + tail

class GetDataVersionRequest(Request):
    pass

class GetStoryModeStatusVersionRequest(Request):
    pass

class GetPremiumPassStatusRequest(Request):
    pass

class GetStoryClearCountDayRequest(Request):
    def assignParams(self, page: int):
        self.page = page

    def serialize_contents(self) -> bytes:
        return struct.pack('<i', self.page)

    def unserialize_contents(self, data: bytes):
        self.page, = struct.unpack('<i', data)

class GetAvailableVipIdListRequest(Request):
    pass

class GetUserItemAndPointRequest(Request):
    def assignParams(self, page: int):
        self.page = page

    def serialize_contents(self) -> bytes:
        return struct.pack('<i', self.page)

    def unserialize_contents(self, data: bytes):
        self.page, = struct.unpack('<i', data)

class CheckNewDayRequest(Request):
    def assignParams(self, nonce: int):
        self.nonce = nonce

    def serialize_contents(self) -> bytes:
        return struct.pack('<q', self.nonce)

    def unserialize_contents(self, data: bytes):
        self.nonce, = struct.unpack('<q', data)

class GetLimitedLoginBonusRequest(Request):
    def assignParams(self, loginBonusEventId: int, page: int):
        self.loginBonusEventId = loginBonusEventId
        self.page = page

    def serialize_contents(self) -> bytes:
        return struct.pack('<ii', self.loginBonusEventId, self.page)

    def unserialize_contents(self, data: bytes):
        self.loginBonusEventId, self.page = struct.unpack('<ii', data)

class GetMissionSetInfoRequest(Request):
    def assignParams(self, page: int):
        self.page = page

    def serialize_contents(self) -> bytes:
        return struct.pack('<i', self.page)

    def unserialize_contents(self, data: bytes):
        self.page, = struct.unpack('<i', data)

class GetMissionInfoRequest(Request):
    def assignParams(self, missionSetIdList: list, page: int):
        self.missionSetIdList = missionSetIdList
        self.page = page

    def serialize_contents(self) -> bytes:
        n = len(self.missionSetIdList)
        return (
            dbdata.serialize_vlong(n)
            + struct.pack(f'<{n}i', *self.missionSetIdList)
            + struct.pack('<i', self.page)
        )

    def unserialize_contents(self, data: bytes):
        n, start = dbdata.unserialize_vlong(data)
        self.missionSetIdList, start = dbdata.unpack_fmt(f'<{n}i', data, start)
        self.missionSetIdList = list(self.missionSetIdList)
        (self.page,), start = dbdata.unpack_fmt('<i', data, start)

class GetMissionGainInfoRequest(GetMissionInfoRequest):
    pass

class GetHomeInfoRequest(Request):
    pass

class GetPersonalMessageRequest(Request):
    def assignParams(self, checkMessageId: int, doNotShowAgain: int):
        self.checkMessageId = checkMessageId
        self.doNotShowAgain = doNotShowAgain

    def serialize_contents(self) -> bytes:
        return struct.pack('<qb', self.checkMessageId, self.doNotShowAgain)

    def unserialize_contents(self, data: bytes):
        self.checkMessageId, self.doNotShowAgain = struct.unpack('<qb', data)

class GetPresentBoxRequest(GetMissionSetInfoRequest):
    pass

class ReceivePresentBoxRequest(Request):
    def assignParams(self, presentBoxIds: list):
        self.presentBoxIds = presentBoxIds

    def serialize_contents(self) -> bytes:
        return dbdata.serialize_list('q', self.presentBoxIds)

    def unserialize_contents(self, data: bytes):
        self.presentBoxIds, start = dbdata.unserialize_list('q', data, 0)

class SetNextLoginBonusItemRequest(Request):
    def assignParams(self, nextLoginBonusItemList: list, nonce: int):
        self.nextLoginBonusItemList = nextLoginBonusItemList
        self.nonce = nonce

    def serialize_contents(self) -> bytes:
        return (
            dbdata.serialize_list(dbdata.serialize_item, self.nextLoginBonusItemList)
            + struct.pack('<q', self.nonce)
        )

    def unserialize_contents(self, data: bytes):
        self.nextLoginBonusItemList, start = dbdata.unserialize_list(dbdata.unserialize_item, data, 0)

        self.nonce, = struct.unpack_from('<q', data, start)

class Response(Command):
    def unserialize_common_response(self, data: bytes, start: int):
        start += 2 # TODO
        fmt = '<q'
        self.serverTime, = struct.unpack_from(fmt, data, start)
        start += struct.calcsize(fmt)

        self.userDataVersion, start = dbdata.unserialize_data_version_list(data, start)

        fmt = '<b'
        self.achievedMissionFlg, = struct.unpack_from(fmt, data, start)
        start += struct.calcsize(fmt)

        return start

    @staticmethod
    def parse(packet: bytes):
        cmd_id, = struct.unpack_from('<H', packet)
        i = 2
        cls = Response.get_class_by_cmd_id(cmd_id)
        cls.cmdId = cmd_id
        resp = cls()
        try:
            resp.unserialize(packet[i:])
        except struct.error as e:
            packet_hex = packet.hex(' ')
            logging.exception(f'Error while unserializing response {cls.__name__}, packet = {packet_hex}')
        return resp

class UnknownResponse(Response):
    pass

class CheckAliveResponse(Response):
    pass

class RequestLoginResponse(Response):
    def unserialize_contents(self, payload: bytes):
        status, = struct.unpack_from('<H', payload)
        i = 2
        if status == 0:
            self.uid, ip, port, self.token = struct.unpack_from('<Q4sL16s', payload, i)
            self.agentEndPoint = (socket.inet_ntoa(ip), port)
        else:
            raise LoginError(f'Login returned error response, status={status}, payload={payload}')

class HelloResponse(Response):
    def unserialize_contents(self, payload: bytes):
        status, self.uid = struct.unpack_from('<HQ', payload)
        if status != 0:
            raise LoginError(f'Hello returned error response, status={status}, payload={payload}')

class LoginUserResponse(Response):
    def unserialize_contents(self, data: bytes):
        start = self.unserialize_common_response(data, 0)

        (self.status,), start = dbdata.unpack_fmt('<b', data, start)

        self.nonce, size = dbdata.unserialize_string(data[start:])
        self.nonce = base64.urlsafe_b64decode(self.nonce)

class GetVersionResponse(Response):
    def unserialize_contents(self, data: bytes):
        start = self.unserialize_common_response(data, 0)
        self.masterCdnVersion, self.assetVersion, self.androidRomVersion, self.iosRomVersion = struct.unpack_from('<iiii', data, start)

class GetValueResponse(Response):
    def unserialize_contents(self, data: bytes):
        start = self.unserialize_common_response(data, 0)
        self.entryList, start = dbdata.unserialize_list(dbdata.unserialize_kvs_entry, data, start)

class GetDataVersionResponse(Response):
    def unserialize_contents(self, data: bytes):
        start = self.unserialize_common_response(data, 0)
        self.versions, start = dbdata.unserialize_data_version_list(data, start)

class GetStoryModeStatusVersionResponse(Response):
    def unserialize_contents(self, data: bytes):
        start = self.unserialize_common_response(data, 0)
        self.version, self.cacheEnableFlg = struct.unpack_from('<ib', data, start)

class GetPremiumPassStatusResponse(Response):
    def unserialize_contents(self, data: bytes):
        start = self.unserialize_common_response(data, 0)

        self.productId, size = dbdata.unserialize_string(data[start:])
        start += size

        (self.status,
         self.updateCount,
         self.expireDate,
         self.accountHoldExpireDate,
         self.existsReward,
         self.storeNotifyStatusCode,
         self.storeLastNotifiedDate,
         self.freeTrialFlg) = struct.unpack_from('<billbhlb', data, start)

class GetStoryClearCountDayResponse(Response):
    def unserialize_contents(self, data: bytes):
        start = self.unserialize_common_response(data, 0)

        (self.page, self.pageSize, self.lastPage), start = dbdata.unpack_fmt('<iii', data, start)

        self.storyClearCountDays, start = dbdata.unserialize_list(dbdata.unserialize_story_clear_count_day, data, start)

class GetAvailableVipIdListResponse(Response):
    def unserialize_contents(self, data: bytes):
        start = self.unserialize_common_response(data, 0)
        self.vipIdList, start = dbdata.unserialize_list('i', data, start)

class GetUserItemAndPointResponse(Response):
    def unserialize_contents(self, data: bytes):
        start = self.unserialize_common_response(data, 0)

        (self.page, self.pageSize, self.lastPage, self.zeny), start = dbdata.unpack_fmt('<iiiq', data, start)

        self.stone, start = dbdata.unserialize_stone_status(data, start)

        self.medal = dbdata.unserialize_list(dbdata.unserialize_user_item, data, start)

        self.skipTicket, start = dbdata.unserialize_list(dbdata.unserialize_user_item_with_date, data, start)

class CheckNewDayResponse(Response):
    def unserialize_contents(self, data: bytes):
        start = self.unserialize_common_response(data, 0)

        (self.newDay, self.totalLoginCount, self.continuousLoginCount), start = dbdata.unpack_fmt('<bii', data, start)

        self.firstLoginBonusItem, start = dbdata.unserialize_first_login_bonus_item(data, start)

        self.comebackLoginBonusItems, start = dbdata.unserialize_list(dbdata.unserialize_comeback_login_bonus_item, data, start)

        self.limitedLoginBonusResult, start = dbdata.unserialize_list(dbdata.unserialize_limited_login_bonus_result, data, start)

        self.loginBonusItems, start = dbdata.unserialize_list(dbdata.unserialize_reward_result, data, start)

        self.nextLoginBonusItem, start = dbdata.unserialize_next_login_bonus_item(data, start)

        self.selectLoginBonusItem, start = dbdata.unserialize_next_login_bonus_item(data, start)

        (self.expiredVipCount,), start = dbdata.unpack_fmt('<h', data, start)

        self.staminaInfo, start = dbdata.unserialize_stamina_info(data, start)

        (self.missionPlanStatus,
         self.releaseEquipment,
         self.moveEquipment,
         self.comebackUser,
         self.comebackDaysLeft), start = dbdata.unpack_fmt('<bbbbi', data, start)

        self.unreceivedRewardIdList, start = dbdata.unserialize_list('b', data, start)

        (self.rouletteGashaCount, self.pickUpCount), start = dbdata.unpack_fmt('<ii', data, start)

class GetLimitedLoginBonusResponse(Response):
    def unserialize_contents(self, data: bytes):
        start = self.unserialize_common_response(data, 0)

        (self.currentPage,
         self.lastPage,
         self.pageSize,
         self.loginBonusEventId,
         self.beginDate,
         self.endDate), start = dbdata.unpack_fmt('<iiiiqq', data, start)

        self.assetName, size = dbdata.unserialize_string(data[start:])
        start += size

        (self.loopCount,), start = dbdata.unpack_fmt('<i', data, start)

        self.limitedLoginBonusSquares, start = dbdata.unserialize_list(dbdata.unserialize_limited_login_bonus_square, data, start)

class GetMissionSetInfoResponse(Response):
    def unserialize_contents(self, data: bytes):
        start = self.unserialize_common_response(data, 0)

        (self.page, self.pageSize, self.lastPage), start = dbdata.unpack_fmt('<iii', data, start)

        self.missionSetInfoList, start = dbdata.unserialize_list(dbdata.unserialize_mission_set_info, data, start)

class GetMissionInfoResponse(Response):
    def unserialize_contents(self, data: bytes):
        start = self.unserialize_common_response(data, 0)

        (self.page, self.pageSize, self.lastPage), start = dbdata.unpack_fmt('<iii', data, start)

        self.missionInfoList, start = dbdata.unserialize_list(dbdata.unserialize_mission_info, data, start)

class GetMissionGainInfoResponse(Response):
    def unserialize_contents(self, data: bytes):
        start = self.unserialize_common_response(data, 0)

        (self.page, self.pageSize, self.lastPage), start = dbdata.unpack_fmt('<iii', data, start)

        self.missionGainInfoList, start = dbdata.unserialize_list(dbdata.unserialize_mission_gain_info, data, start)

class GetHomeInfoResponse(Response):
    def unserialize_contents(self, data: bytes):
        start = self.unserialize_common_response(data, 0)

        self.userStatus, start = dbdata.unserialize_user_status(data, start)

        self.staminaInfo, start = dbdata.unserialize_stamina_info(data, start)

        self.notificationStatus, start = dbdata.unserialize_notification_status(data, start)

        self.stone, start = dbdata.unserialize_stone_status(data, start)

        self.holdingEventIdList, start = dbdata.unserialize_list(dbdata.unserialize_event_banner, data, start)

        (self.titleItemId,
         self.tournamentSetId,
         self.tournamentStartTime,
         self.tournamentEndTime,
         self.tournamentEntryStatus), start = dbdata.unpack_fmt('<iiqqh', data, start)

        self.tournamentScheduleList, start = dbdata.unserialize_list(dbdata.unserialize_tournament_schedule, data, start)

        (self.inSessionAnniversaryEventFlg,
         self.guildMaintenance,
         self.guildUnlocked,
         self.guildMissionRewardUnReceived,
         self.guildEntryRequest,
         self.guildId,
         self.guildMemeberStatus), start = dbdata.unpack_fmt('<ibbiiqi', data, start)

        self.missionPlanStatusList, start = dbdata.unserialize_list(dbdata.unserialize_mission_plan_status_info, data, start)

        (self.tactMaintenance,), start = dbdata.unpack_fmt('<b', data, start)

        self.tactStaminaInfo, start = dbdata.unserialize_tact_stamina_info(data, start)

        (self.worldMissionUnlockFlg,
         self.worldMissionRewardUnReceived), start = dbdata.unpack_fmt('<bh', data, start)

        self.completedDailyMissionIdList, start = dbdata.unserialize_list('i', data, start)

        (self.remainFirstWinBonus,
         self.favoriteCharacterId,
         self.buffableEquipmentDropFlagOfRating,
         self.remainRatingLimitedRewardCount), start = dbdata.unpack_fmt('<bhbb', data, start)

        self.timeZone, size = dbdata.unserialize_string(data[start:])
        start += size

        (self.warningFlag,), start = dbdata.unpack_fmt('<b', data, start)

class GetPersonalMessageResponse(Response):
    def unserialize_contents(self, data: bytes):
        start = self.unserialize_common_response(data, 0)

        (self.messageId,
         self.messageType,
         self.mustCheckFlag,
         self.doNotShowAgainFlag), start = dbdata.unpack_fmt('<qbbb', data, start)

        self.messageText, size = dbdata.unserialize_string(data[start:])
        start += size

        self.additionalMessageText, size = dbdata.unserialize_string(data[start:])
        start += size

        (self.receiveDate,
         self.notifyEndDate,
         self.otherMessageCount), start = dbdata.unpack_fmt('<qqh', data, start)

class GetPresentBoxResponse(Response):
    def unserialize_contents(self, data: bytes):
        start = self.unserialize_common_response(data, 0)

        self.presentBoxList, start = dbdata.unserialize_list(dbdata.unserialize_present_box, data, start)

        (self.pageSize,
         self.page,
         self.isNextPage), start = dbdata.unpack_fmt('<iib', data, start)

class ReceivePresentBoxResponse(Response):
    def unserialize_contents(self, data: bytes):
        start = self.unserialize_common_response(data, 0)

        self.givenItemList, start = dbdata.unserialize_list(dbdata.unserialize_pb_reward_result, data, start)

        (self.zeny,), start = dbdata.unpack_fmt('<q', data, start)

class SetNextLoginBonusItemResponse(Response):
    def unserialize_contents(self, data: bytes):
        self.unserialize_common_response(data, 0)

class Packet():
    MAX_PACKET_SIZE = 5000

    @classmethod
    def unsigned_to_signed_char(cls, byte):
        # Code below is just a more efficient way to perform
        # return struct.unpack('<b', int.to_bytes(byte))[0]
        if byte > 0x7f:
            byte -= 0x100
        return byte

    @classmethod
    def calc_crc(cls, data):
        num = 0
        for byte in data:
            num += cls.unsigned_to_signed_char(byte)
        if num < 0:
            num += 1
        return (num % 0xffff) ^ 0xffff

    @classmethod
    def pack(cls, payload: bytes, isOuter=False) -> bytes:
        length = len(payload)
        if isOuter:
            length = -length
        length = dbdata.serialize_vlong(length)
        crc = cls.calc_crc(payload)
        crc = struct.pack('<H', crc)
        return length + payload + crc

    @classmethod
    def encode(cls, payload: bytes) -> bytes:
        inner = cls.pack(payload)
        return cls.pack(inner, isOuter=True)

    @classmethod
    def unpack(cls, frame: bytes) -> tuple:
        # Unpack payload
        (length, start) = dbdata.unserialize_vlong(frame)
        isOuter = length < 0
        if isOuter:
            length = -length
        if length > cls.MAX_PACKET_SIZE:
            raise PacketTooBig(f'Received a packet with a presented size of {length} bytes but maximum is {cls.MAX_PACKET_SIZE}')
        payload = frame[start : start+length]

        # Check CRC
        fmt = '<H'
        presentedCrc, = struct.unpack_from('<H', frame, start+length)
        computedCrc = cls.calc_crc(payload)
        if computedCrc != presentedCrc:
            raise InvalidCRC(f'Received a packet with invalid CRC: presented={presentedCrc}, computed={computedCrc}, packet={frame}')

        packetLen = start + length + struct.calcsize(fmt)
        return isOuter, payload, packetLen

    @classmethod
    def decode(cls, data: bytes) -> bytes:
        isOuter, payload, packetLen = cls.unpack(data)
        if isOuter:
            isOuter, payload, _ = cls.unpack(payload)
            if isOuter != False:
                raise PacketDecodingError('Inner packet has outer flag')
        return payload, packetLen
