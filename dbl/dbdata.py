import struct

def serialize_vlong(num: int) -> bytes:
    bytestream = bytearray(10)

    # build byte stream
    if num < 0:
        num ^= -1
        signflag = 64
    else:
        signflag = 0
    bytestream[0] = (num &  63) | signflag
    bytestream[1] = (num >>  6) & 0x7f
    bytestream[2] = (num >> 13) & 0x7f
    bytestream[3] = (num >> 20) & 0x7f
    bytestream[4] = (num >> 27) & 0x7f
    bytestream[5] = (num >> 34) & 0x7f
    bytestream[6] = (num >> 41) & 0x7f
    bytestream[7] = (num >> 48) & 0x7f
    bytestream[8] = (num >> 55) & 0x7f
    bytestream[9] = (num >> 62) & 0x01

    # find bytestream end position
    tail = 9
    while bytestream[tail] == 0 and tail > 0:
        tail -= 1

    # add bytestream termination marker
    bytestream[tail] += 128

    # return meaningful part only
    return bytestream[0:tail+1]

def unserialize_vlong(serialized: bytes) -> tuple:
    # find bytestream end position
    bytestream = bytearray(10)
    i = 0
    while True:
        b = serialized[i]
        bytestream[i] = b
        i += 1
        if not ((b & 128) == 0 and i < 10):
            break
    tail = i

    # read bytestream from tail to head
    num = 0
    if tail > 1:
        i = tail - 1
        num = bytestream[i] & 127
        i -= 1
        while i > 0:
            num = (num << 7 | bytestream[i])
            i -= 1
        num = (num << 6)
    num += bytestream[0] & 63

    # apply sign flag
    signFlag = (bytestream[0] & 64) == 64
    if signFlag:
        num = num ^ -1

    # return decoded number along with bytestream length
    return (num, tail)

def serialize_string(s: str) -> bytes:
    return serialize_vlong(len(s)) + s.encode('utf-8')

def unserialize_string(encoded: bytes) -> tuple:
    (length, start) = unserialize_vlong(encoded)
    string = encoded[start : start+length].decode('utf-8')
    return string, start+length

def serialize_uuid(hexstr):
    uuid = bytes.fromhex(hexstr.replace('-', ''))
    uuid = bytearray(reversed(uuid[0:4])) + bytearray(reversed(uuid[4:6])) + bytearray(reversed(uuid[6:8])) + uuid[8:16]
    return uuid

def unserialize_uuid(encoded: bytes) -> str:
    parts = bytes(reversed(encoded[0:4])).hex(), bytes(reversed(encoded[4:6])).hex(), bytes(reversed(encoded[6:8])).hex(), encoded[8:10].hex(), encoded[10:16].hex()
    uuid = '-'.join(parts)
    return uuid

def unserialize_list_cb(func: callable, data: bytes, start: int):
    n, size = unserialize_vlong(data[start:])
    start += size
    items = []
    for i in range(n):
        item, start = func(data, start)
        items.append(item)
    return items, start

def unserialize_list_simple(fmt: str, data: bytes, start: int):
    n, size = unserialize_vlong(data[start:])
    start += size
    fmt = f'<{n}{fmt}'
    items = struct.unpack_from(fmt, data, start)
    start += struct.calcsize(fmt)
    return items, start

def unserialize_list(mixed, data: bytes, start: int):
    if callable(mixed):
        return unserialize_list_cb(mixed, data, start)
    elif type(mixed) is str:
        return unserialize_list_simple(mixed, data, start)
    else:
        raise Exception(f"First parameter type is '{type(mixed).__name__}', expected 'str' or 'callable'")

def serialize_list_cb(func: callable, l: list):
    n = len(l)
    return serialize_vlong(n) + b''.join(map(func, l))

def serialize_list_simple(fmt: str, l: list):
    n = len(l)
    fmt = f'<{n}{fmt}'
    items = struct.pack(fmt, *l)
    return serialize_vlong(n) + items

def serialize_list(mixed, l: list):
    if callable(mixed):
        return serialize_list_cb(mixed, l)
    elif type(mixed) is str:
        return serialize_list_simple(mixed, l)
    else:
        raise Exception(f"First parameter type is '{type(mixed).__name__}', expected 'str' or 'callable'")

def unpack_fmt(fmt: str, data: bytes, start: int):
    stuff = struct.unpack_from(fmt, data, start)
    return stuff, start + struct.calcsize(fmt)

def unpack_fmt_dict(fmt: str, fieldNames: list, data: bytes, start: int):
    data, start = unpack_fmt(fmt, data, start)
    data = dict([(fieldNames[i], data[i]) for i in range(len(data))])
    return data, start

def unserialize_data_version(data: bytes, start: int):
    return unpack_fmt_dict('<hi', ('categoryId', 'dataVersionNum'), data, start)

def unserialize_data_version_list(data: bytes, start: int):
    return unserialize_list(unserialize_data_version, data, start)

def unserialize_kvs_entry(data: bytes, start: int):
    entry = {}
    entry['keyname'], size = unserialize_string(data[start:])
    start += size

    entry['value'], size = unserialize_string(data[start:])
    start += size

    return entry, start

def unserialize_story_clear_count_day(data: bytes, start: int):
    return unpack_fmt_dict('<ii', ('storyMasterId', 'clearCountDay'), data, start)

def unserialize_user_item(data: bytes, start: int):
    return unpack_fmt_dict('<ii', ('itemId', 'itemNum'), data, start)

def unserialize_user_item_with_date(data: bytes, start: int):
    fields = ('itemType', 'itemId', 'itemNum', 'beginDate', 'endDate')
    return unpack_fmt_dict('<biiqq', fields, data, start)

def unserialize_item_ins(data: bytes, start: int):
    fields = ('insId', 'itemType', 'itemId')
    itemIns, start = unpack_fmt_dict('<qhi', fields, data, start)

    n, size = unserialize_vlong(data[start:])
    start += size
    itemIns['itemNum'], start = unpack_fmt(f'<{n}b', data, start)

    rest, start = unpack_fmt_dict('<ii', ('itemVar', 'realVar'), data, start)
    itemIns.update(rest)

    return itemIns, start

def unserialize_reward_result(data: bytes, start: int):
    fields = ('resultCode', 'itemCategoryItem', 'itemId', 'itemCount')
    result, start = unpack_fmt_dict('<hhii', fields, data, start)

    result['itemInsList'], start = unserialize_list(unserialize_item_ins, data, start)

    return result, start

def unserialize_first_login_bonus_item(data: bytes, start: int):
    fields = ('loginBonusFirstId', 'loginBonusDayId')
    item, start = unpack_fmt_dict('<ib', fields, data, start)

    item['loginBonusItemList'], start = unserialize_list(unserialize_reward_result, data, start)

    (item['dayType'],), start = unpack_fmt('<b', data, start)

    return item, start

def unserialize_comeback_login_bonus_item(data: bytes, start: int):
    item = {}
    (item['acquiredKbn'],), start = unpack_fmt('<h', data, start)

    item['comebackLoginBonusItems'], start = unserialize_list(unserialize_reward_result, data, start)

    return item, start

def unserialize_limited_login_bonus_result(data: bytes, start: int):
    fields = ('eventId', 'eventDays')
    bonus, start = unpack_fmt_dict('<ih', fields, data, start)

    bonus['result'], start = unserialize_list(unserialize_reward_result, data, start)

    return bonus, start

def unserialize_login_bonus_item(data: bytes, start: int):
    fields = (
        'bonusType',
        'vipFlag',
        'selectType',
        'categoryId',
        'itemId',
        'itemCount',
    )
    return unpack_fmt_dict('<hhhhii', fields, data, start)

def unserialize_next_login_bonus_item(data: bytes, start: int):
    fields = ('bannerId', 'itemSelectCount')
    bonus, start = unpack_fmt_dict('<ih', fields, data, start)

    bonus['itemList'], start = unserialize_list(unserialize_login_bonus_item, data, start)

    return bonus, start

def unserialize_limited_login_bonus_item(data: bytes, start: int):
    fields = ('sortParam', 'categoryId', 'itemId', 'itemCount')
    return unpack_fmt_dict('<ihii', fields, data, start)

def unserialize_limited_login_bonus_square(data: bytes, start: int):
    fields = (
        'loginBonusEventId',
        'loginBonusEventDays',
        'state',
        'dayType',
        'targetDay',
        'loginBonusEventDetailId'
    )
    bonus, start = unpack_fmt_dict('<ihhhhi', fields, data, start)

    bonus['itemList'], start = unserialize_list(unserialize_limited_login_bonus_item, data, start)

    return bonus, start

def unserialize_mission_set_info(data: bytes, start: int):
    fields = (
        'missionSetId',
        'iconType',
        'missionRewardCount',
        'missionCountCompleted',
        'missionCountTotal',
        'rewardReceiveEndDate',
        'stoneConsumeStatus',
        'unlockStatus',
    )
    return unpack_fmt_dict('<ihiiiqbb', fields, data, start)

def unserialize_mission_gain_info(data: bytes, start: int):
    fields = (
        'missionId',
        'gainStatus',
    )
    return unpack_fmt_dict('<ib', fields, data, start)

def unserialize_mission_info(data: bytes, start: int):
    fields = (
        'missionStatus',
        'missionId',
        'missionClearCurrent',
    )
    return unpack_fmt_dict('<hii', fields, data, start)

def unserialize_stamina_info(data: bytes, start: int):
    fields = (
        'currentStamina',
        'maxStamina',
        'healingInterval',
        'nextHealingTime',
        'currentSubtank',
        'healingCount',
        'maxHealingCount',
    )
    return unpack_fmt_dict('<hhhqhhh', fields, data, start)

def unserialize_user_status(data: bytes, start: int):
    playerId, size = unserialize_string(data[start:])
    start += size

    playerName, size = unserialize_string(data[start:])
    start += size

    rest, start = unpack_fmt('<qi', data, start)

    return {
        'playerId': playerId,
        'playerName': playerName,
        'sparkingPoint': rest[0],
        'zlv': rest[1]
    }, start

def unserialize_limited_shop_item(data: bytes, start: int):
    return unpack_fmt_dict('<iq', ('rectangleBannerId', 'endTime'), data, start)

def unserialize_notification_status(data: bytes, start: int):
    status, start = unpack_fmt_dict('<hhhh', ('presentCount', 'missionCount', 'overallRankingMissionCount', 'friendCount'), data, start)

    status['limitedShopItemEndTime'], start = unserialize_list(unserialize_limited_shop_item, data, start)

    tact, start = unpack_fmt_dict('<h', ('tactSessionCount',), data, start)
    status.update(tact)

    return status, start

def unserialize_stone_status(data: bytes, start: int):
    return unpack_fmt_dict('<ii', ('paidStone', 'freeStone'), data, start)

def unserialize_event_banner(data: bytes, start: int):
    banner, start = unpack_fmt_dict('<ib', ('bannerId', 'actionType'), data, start)

    banner['actionInfo'], size = unserialize_string(data[start:])
    start += size

    banner['bannerResource'], size = unserialize_string(data[start:])
    start += size

    return banner, start

def unserialize_tournament_schedule(data: bytes, start: int):
    tournament = {}
    tournament['startTime'], size = unserialize_string(data[start:])
    start += size

    tournament['endTime'], size = unserialize_string(data[start:])
    start += size

    return tournament, start

def unserialize_mission_plan_status_info(data: bytes, start: int):
    fields = (
        'missionPlanId',
        'missionPlanGroupId',
        'missionPlanPoint',
        'missionPlanStatus',
        'missionPlanBeginDate',
        'missionPlanEndDate',
        'missionPlanRewardFlg',
    )
    return unpack_fmt_dict('<iiibqqb', fields, data, start)

def unserialize_tact_stamina_info(data: bytes, start: int):
    fields = (
        'currentStamina',
        'maxStamina',
        'healingValue',
        'healingInterval',
        'nextHealingTime',
        'maxHealingTime',
    )
    return unpack_fmt_dict('<hhhhqq', fields, data, start)

def serialize_item(item: dict):
    return struct.pack('<hii', item['categoryId'], item['itemId'], item['itemCount'])

def unserialize_item(data: bytes, start: int):
    return unpack_fmt_dict('<hii', ('categoryId', 'itemId', 'itemCount'), data, start)

def unserialize_present_box(data: bytes, start: int):
    fields = (
        'presentBoxId',
        'itemType',
        'itemId',
        'itemNum',
        'titleDefType',
        'titleId',
        'descriptionDefType',
        'descriptionId',
        'limitDate',
    )
    return unpack_fmt_dict('<qhiiiiiiq', fields, data, start)

def unserialize_pb_reward_result(data: bytes, start: int):
    result, start = unpack_fmt_dict('<hq', ('resultCode', 'presentBoxId'), data, start)
    result['item'], start = unserialize_item(data, start)
    result['itemInsList'], start = unserialize_list(unserialize_item_ins, data, start)
    return result, start
