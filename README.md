# dbl-python

An unofficial Python 3 client for Dragon Ball Legends.

## Requirements

* Python 3
* pip

## Installation

```
git clone https://github.com/jiru/dbl-python
cd dbl-python
python -m venv env
source env/bin/activate
pip install -r requirements.txt
```

## Usage

### Login

First grab credentials from an Android device where DBL is installed and logged in already. This requires a rooted device and `adb`.

1. If not running an emulator, connect the device to your computer with a USB cable.
2. Run `adb root`.
3. Eventually confirm the popup on the device.
4. Run `python get-creds.py creds.json`. See `python get-creds.py -h` for special setups.

After completing these steps, the necessary credentials to log in will be saved in the file `creds.json`.

### API example scripts

Log in using credentials from file `creds.json`

```
python login.py -c creds.json
```

### Proxy

Set the `HTTP_PROXY` environment variable to use an HTTP proxy (not SOCKS), e.g.:

```
HTTP_PROXY=127.0.0.1:8080 python login.py -c creds.json
```
