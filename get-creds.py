#!/usr/bin/env python3

import argparse
import json
import re
import subprocess
import sys

def run_adb(cmd):
    return subprocess.run(f'adb {cmd}', shell=True, capture_output=True, check=True)

def check_prerequisites():
    try:
        process = run_adb('version')
    except subprocess.CalledProcessError as e:
        print(e)
        print('Error: unable to execute adb. Please check that adb is correctly installed.')
        sys.exit(1)

    try:
        process = run_adb('root')
    except subprocess.CalledProcessError as e:
        print(e)
        print('Error: unable to enable root.')
        sys.exit(1)

def run_adb_shell(cmd, decode=True):
    try:
        process = run_adb(f'shell {cmd}')
        output = process.stdout
        if decode:
            try:
                output = output.decode()
            except UnicodeDecodeError:
                output = output.decode('latin1')
        return output
    except subprocess.CalledProcessError as e:
        print(e)
        print('Error: unable to get command output.')
        sys.exit(1)

def get_file(path, decode=True):
    return run_adb_shell(f'cat {path}', decode=decode)

def bytes_inv(ba):
    mask = b'\xff' * len(ba)
    return bytes([_a ^ _b for _a, _b in zip(ba, mask)])

def get_device_id(uid, pkgname):
    device_id = None
    path = f'/data/system/users/{uid}/settings_ssaid.xml'
    file_type = run_adb_shell(f'file {path}')
    xml = get_file(path)
    if 'Android Binary XML v0' in file_type:
        match = re.search(pkgname + r'/....([0-9a-f]{16})', xml)
        if match is not None:
            device_id = match.group(1)
    else:
        for line in xml.split('\n'):
            match = re.search(f'<setting.* package="{pkgname}" defaultValue="([^"]+)"', line)
            if match is not None:
                device_id = match.group(1)
                break
    if device_id is None:
        print('Error: unable to get Android app id.')
        sys.exit(1)
    return device_id

def get_ecd(uid, pkgname):
    path = f'/mnt/runtime/read/emulated/{uid}/Android/data/{pkgname}/files/ecd1bb8b626d380e93748523485ef051'
    contents = get_file(path, decode=False)
    ecd = json.loads(bytes_inv(contents).decode())
    for key in ['guid_', 'key_', 'region_', 'loginLanguage_']:
        assert key in ecd
    return ecd

def get_currency():
    try:
        run_adb(f'push getCurrency.dex /data/local/tmp/')
    except subprocess.CalledProcessError as e:
        print('Error: unable to push dex file.')
        sys.exit(1)
    currency = run_adb_shell(f'CLASSPATH=/data/local/tmp/getCurrency.dex app_process / getCurrency')
    run_adb_shell(f'rm /data/local/tmp/getCurrency.dex')
    return currency

def get_creds(pkgname, uid):
    device_id = get_device_id(uid, pkgname)
    currency = get_currency()
    creds = get_ecd(uid, pkgname)
    creds['deviceId'] = device_id
    creds['currency'] = currency
    return creds

def save_token(creds_file, pkgname, uid):
    creds = get_creds(pkgname, uid)
    creds = json.dumps(creds)
    with open(creds_file, 'w') as fd:
        fd.write(creds)
    print(f'Credentials successfully saved into {creds_file}')

def main():
    # Get device id: https://stackoverflow.com/questions/65649831/two-different-android-ids-settings-secure-aml-settings-ssaid-xml
    # Connect ADB: https://stackoverflow.com/questions/51214825/adb-cant-connect-to-nox
    
    parser = argparse.ArgumentParser(description='Helper script to grab Dragon Ball Legends credentials from an Android phone that is connected with adb.')
    parser.add_argument('credentials', metavar='<file.json>', type=str, help='JSON file to write credentials to')
    parser.add_argument('-p', '--pkg-name', metavar='com.package.name', default='com.bandainamcoent.dblegends_ww', type=str, help='Android package name, e.g. com.bandainamcoent.dblegends_wx')
    parser.add_argument('-u', '--user-id', metavar='N', default='0', type=str, help='Android user id, in case of multiuser installation')
    args = parser.parse_args()
    check_prerequisites()
    save_token(args.credentials, args.pkg_name, args.user_id)

if __name__ == '__main__':
    main()
