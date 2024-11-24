from discord.ext import commands, tasks
import discord, json, httpx, tls_client, threading, time, os
from time import sleep
from datetime import datetime
import dhooks, yaml, random
from threading import Lock
from tls_client import Session
import base64
from colorama import Fore, init
init()
from base64 import b64encode
from discord_webhook import DiscordWebhook, DiscordEmbed
import httpx,json,traceback
import os
import random, string
import portalocker
import sys
import platform
import hashlib
import importlib
from os import listdir
from base64 import b64encode
import random, string
from time import sleep
import colorama
from colorama import Fore
import urllib3
from data.keyauth import api
import webbrowser
import discord, datetime, time, flask, requests, json, threading, os, random, httpx, tls_client, sys
from flask import request
from pathlib import Path
from threading import Thread
from discord_webhook import DiscordWebhook, DiscordEmbed
from datetime import datetime
current_time = datetime.now().strftime("%H:%M:%S")
from flask import Flask, request, jsonify
import websocket
from yaml.representer import SafeRepresenter
import yaml
import sys
import re
import requests
from colorama import Fore, Style

r = Fore.RED
g = Fore.GREEN
w = Fore.WHITE
b = Fore.LIGHTBLACK_EX
lg = "\033[38;2;152;251;152m"
rc = "\033[0m"


urllib3.disable_warnings()

if sys.version_info.minor < 10:
    print(
        "[Security] - Python 3.10 or higher is recommended. The bypass will not work on 3.10+"
    )
    print(
        "You are using Python {}.{}".format(
            sys.version_info.major, sys.version_info.minor
        )
    )

if platform.system() == "Windows":
    os.system('cls & title "discord.gg/boostility | b00stility.com/ | Version 3.0.0"')
elif platform.system() == "Linux":
    os.system("clear")
    sys.stdout.write("\x1b]0;Boostility | Boost Bot v3\x07")
elif platform.system() == "Darwin":
    os.system("clear && printf '\e[3J'")
    os.system('''echo - n - e "\033]0;Boostility | Boost Bot v3\007"''')


def getchecksum():
    md5_hash = hashlib.md5()
    file = open("".join(sys.argv), "rb")
    md5_hash.update(file.read())
    digest = md5_hash.hexdigest()
    return digest

def load_api_key():
    try:
        with open("config.yaml", "r") as file:
            config = yaml.safe_load(file)
            return config.get("api_key", "")
    except FileNotFoundError:
        print("Error: config.yaml not found.")
        sys.exit(1)

import re
import requests
import sys
from colorama import Fore, Style

def fetch_keyauth_keys():
    try:
        response = requests.get("https://boostility.odoo.com/keyauth")
        if response.status_code == 200:
            content = response.text
            
            content = re.sub(r"<br\s*/?>", "\n", content)

            keys = re.findall(r"License:\s*(\S+)", content)

            if keys:
                
                return [key.strip() for key in keys]
            else:
                print(Fore.RED + "Error: No license keys found in response.")
                sys.exit(1)
        else:
            print(Fore.RED + f"Error: Unable to fetch keyauth keys. Status code: {response.status_code}")
            sys.exit(1)
    except requests.RequestException as e:
        print(Fore.RED + f"Error fetching keyauth keys: {e}")
        sys.exit(1)

def authenticate():
    print(Fore.CYAN + Style.BRIGHT + "Welcome to Boostility Boost Bot Authentication")
    print(Fore.YELLOW + "Please enter your License Key to proceed:\n")
    
    entered_key = input(Fore.GREEN + "License Key: ").strip()

    valid_keys = fetch_keyauth_keys()

    if entered_key.lower() in [key.lower() for key in valid_keys]:
        print(Fore.GREEN + Style.BRIGHT + "Authentication Successful. Starting the boost bot...\n")
    else:
        print(Fore.RED + "Authentication failed. Invalid License Key.\n")
        sys.exit(1)

def start_bot():
    print(Fore.CYAN + "Starting up Boost Bot..." + Style.BRIGHT)

if __name__ == "__main__":
    authenticate()  
    start_bot()

config_file_path = 'config.yaml'
if not os.path.exists(config_file_path):
    with open(config_file_path, 'w') as file:
        file.write("default_content: value\n")
with open(config_file_path, 'r') as file:
    config_data = yaml.safe_load(file)

botactivity = config_data['bot_activity']
api_key = config_data['api_key']
nickname = config_data['nickname']
change_bio = config_data['change_bio']
change_avatar = config_data['change_avatar']
change_banner = config_data['changer_banner']
change_nick = config_data['change_nick']
custom_bio = config_data['custom_bio']
owners = config_data['owners']
boost_webhook = config_data['boost_webhook']
bot_token = config_data['bot_token']
shop_name = config_data['shop_name']
onliner = config_data['onliner']




def quoted_presenter(dumper, data):
    if "\n" in data:
        return dumper.represent_scalar(u'tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar(u'tag:yaml.org,2002:str', data, style='"')

yaml.add_representer(str, quoted_presenter, Dumper=yaml.SafeDumper)


class Log:
    """
    A class to log messages to the console.
    
    """
    lock = Lock()
    log_file = None 
    @staticmethod
    def set_log_file(filename):
        Log.log_file = open(filename, 'a')

    @staticmethod
    def _log(level, prefix, message):
        timestamp = datetime.fromtimestamp(time.time()).strftime("%H:%M:%S")
        log_message = f"{Fore.LIGHTCYAN_EX}{timestamp}{Fore.RESET} {prefix} {message}"

        with Log.lock:
            if Log.log_file:
                Log.log_file.write(log_message + '\n')
                Log.log_file.flush()
            print(log_message)

    @staticmethod
    def Success(message, prefix=f"(+) {Fore.LIGHTCYAN_EX}Success:{Fore.RESET}", color=Fore.LIGHTGREEN_EX):
        Log._log("SUCCESS", f"{color}{prefix}{Fore.RESET}", message)

    @staticmethod
    def Error(message, prefix=f"(-) {Fore.LIGHTCYAN_EX}Error:{Fore.RESET}", color=Fore.LIGHTRED_EX):
        Log._log("ERROR", f"{color}{prefix}{Fore.RESET}", message)

    @staticmethod
    def Debug(message, prefix="(*) Debug", color=Fore.LIGHTYELLOW_EX):
        Log._log("DEBUG", f"{color}{prefix}{Fore.RESET}", message)

    @staticmethod
    def Info(message, prefix=f"(?) {Fore.LIGHTCYAN_EX}Info:{Fore.RESET}" , color=Fore.LIGHTWHITE_EX):
        Log._log("INFO", f"{color}{prefix}{Fore.RESET}", message)

    @staticmethod
    def Warning(message, prefix="(!)", color=Fore.LIGHTMAGENTA_EX):
        Log._log("WARNING", f"{color}{prefix}{Fore.RESET}", message)

    @staticmethod
    def info(message, prefix="(?)" , color=Fore.LIGHTWHITE_EX):
        Log._log("INFO", f"{color}{prefix}{Fore.RESET}", message)
    
    @staticmethod
    def error(message, prefix="(-)", color=Fore.LIGHTRED_EX):
        Log._log("ERROR", f"{color}{prefix}{Fore.RESET}", message)

    @staticmethod
    def warning(message, prefix="(!)", color=Fore.LIGHTMAGENTA_EX):
        Log._log("WARNING", f"{color}{prefix}{Fore.RESET}", message)
        


activity = discord.Activity(type=discord.ActivityType.listening, name=botactivity)
bot = commands.Bot(command_prefix=".",intents=discord.Intents.all(),activity=activity,status=discord.Status.idle,owners=owners)




def online(token, game, type, status):
    def keep_alive(ws):
        while True:
            time.sleep(10)
            if ws.connected:
                try:
                    ws.send(json.dumps({'op': 1, 'd': None}))
                except Exception as e:
                    print(f"An error occurred while sending heartbeat: {e}")
            else:
                print("WebSocket is closed, attempting to reconnect...")
                connect_and_auth(ws)

    def connect_and_auth(ws):
        try:
            ws.connect('wss://gateway.discord.gg/?v=6&encoding=json')
            hello = json.loads(ws.recv())
            heartbeat_interval = hello['d']['heartbeat_interval']
            activity_type = random.choice([1, 2, 3])
            if activity_type == 1:
                activity_name = "Boosting Servers"
            elif activity_type == 2:
                activity_name = "Boosting"
            else:
                activity_name = "Studying"

            gamejson = {"name": game, "type": activity_type}
            auth = {
                "op": 2,
                "d": {
                    "token": token,
                    "properties": {
                        "$os": "linux",
                        "$browser": "chrome",
                        "$device": "pc"
                    },
                    "presence": {
                        "game": gamejson,
                        "status": status,
                        "since": 0,
                        "afk": False
                    }
                }
            }
            ws.send(json.dumps(auth))
        except Exception as e:
            print(f"An error occurred during WebSocket connection/authentication: {e}")

    ws = websocket.WebSocket()
    connect_and_auth(ws)

    heartbeat_thread = threading.Thread(target=keep_alive, args=(ws,))
    heartbeat_thread.daemon = True
    heartbeat_thread.start()
    
    
    

def generate_invoice_id():
    parts = []
    for _ in range(3):
        part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        parts.append(part)
    return '-'.join(parts)


def save_data_to_json(boost_data):
    try:
        with open('database.json', 'r') as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        data = []
    data.append(boost_data)
    with open('database.json', 'w') as file:
        json.dump(data, file, indent=4)

@bot.event
async def on_ready():
    os.system("cls")
    Log.Info(f"Connected to {bot.user}")
    if debug:
        if onliner:
            Log.Debug(f"Online Is Enabled")
        else:
            Log.Debug(f"Onliner is disabled")
    if debug:
        if change_avatar:
            Log.Debug(f"Avatar Changer Is Enabled")
        else:
            Log.Debug(f'Avatar Changer is disabled')
    if debug:
        if change_banner:
            Log.Debug(f"Banner Changer Is Enabled")
        else:
            Log.Debug(f"Banner Changer is disabled")
    if debug:
        if change_bio:
            Log.Debug(f"Bio Changer Is Enabled")
        else:
            Log.Debug(f"Bio Changer is disabled")
    if debug:
        if change_nick:
            Log.Debug(f"Nick Changer Is Enabled")
        else:
            Log.Debug(f"Nick Changer is disabled")
    
    print()
    
def check_proxy(proxy: dict) -> bool:
    try:
        response = httpx.get("https://discord.com/", proxies=proxy, timeout=10)
        if response.status_code == 200:
            return True
        else:
            return False
    except:
        traceback.print_exc()
        return False


class solver:
    @staticmethod
    def solve(rqdata):
        Log.Info("Solving captcha")
        session = Session(client_identifier="chrome112")
        createTask_payload = {
            "task_type": "hcaptchaEnterprise",
            "api_key": api_key,
            "data": {
                "sitekey": "a9b5fb07-92ff-493f-86fe-352a2803b3df",
                "url": "https://discord.com/",
                "proxy": "beeCqoJoHnBUDZZL-r-gb-sn-a0cdf75b33ea-ts-30:beee8lxCsoa3TqM@hive.beeproxies.com:1337",
            }
        }

        createTask = session.post("https://api.hcoptcha.com/api/createTask", json=createTask_payload)
        try:
            createTask_ = createTask.json()
            if createTask.status_code == 200:
                taskId = createTask_['task_id']
                Log.Info(f"Task created {taskId}")
            else:
                return None
        except Exception as e:
            print("Error, while creating task: ", e)

        while True:
            try:
                getTask_payload = {
                    "api_key": api_key,
                    "task_id": str(taskId)
                }
                response = session.post("https://api.hcoptcha.com/api/getTaskData", json=getTask_payload)
                response_json = response.json()

                if response_json['task']['state'] == 'completed':
                    captcha_key = response_json['task']['captcha_key']
                    Log.Success(f'Captcha solved {captcha_key[:50]}xxxx')
                    return captcha_key
                             
                elif response_json['task']['state'] == 'processing':
                    pass
                else:
                    break
            except Exception as e:
                print("Error, while getting task result: ", e)
                break
            
def image_to_b64(path):
    try:
        with open(path, "rb") as file:
            binary_data = file.read()
            if binary_data:
                base64_data = base64.b64encode(binary_data).decode("utf-8")
                return f"data:image/png;base64,{base64_data}"
            else:
                print(f"Empty binary data in file: {path}")
                return None
    except FileNotFoundError:
        print(f"Failed to open image, check path: {path}")
        return None
    except Exception as e:
        print(f"Error: {str(e)}")
        return None

def checkInvite(invite: str):
    final_url = f"https://discord.com/api/v9/invites/{invite}?inputValue={invite}&with_counts=true&with_expiration=true"
    response = httpx.get(final_url)

    if response.status_code == 200:
        guild_id = response.json().get("guild", {}).get("id")
        if guild_id:
            if debug:
                Log.Info(f"Valid invite for guild ID: {guild_id}")
            return guild_id
        else:
            Log.Warning(f"Invite response didn't include guild ID: {response.text}")
            return False
    else:
        Log.Error(f"Invite check failed with status code {response.status_code}: {response.text}")
        return False


def remove(token: str, filename: str):
    tokens = getStock(filename)
    tokens.pop(tokens.index(token))
    f = open(filename, "w")

    for x in tokens:
        f.write(f"{x}\n")

    f.close()


def getStock(filename: str):
    tokens = []
    for i in open(filename, "r").read().splitlines():
        if ":" in i:
            i = i.split(":")[2]
            tokens.append(i)
        else:
            tokens.append(i)
    return tokens


failed = 0
class Booster:
    def __init__(self) -> None:
        self.getCookies()
        self.client_identifiers = [
            'safari_ios_16_0',
            'safari_ios_15_6',
            'safari_ios_15_5',
            'safari_16_0',
            'safari_15_6_1',
            'safari_15_3',
            'opera_90',
            'opera_89',
            'firefox_104',
            'firefox_102'
        ]
        self.client = Session(
            client_identifier=random.choice(self.client_identifiers),
            ja3_string="771,4866-4867-4865-49196-49200-49195-49199-52393-52392-159-158-52394-49327-49325-49326-49324-49188-49192-49187-49191-49162-49172-49161-49171-49315-49311-49314-49310-107-103-57-51-157-156-49313-49309-49312-49308-61-60-53-47-255,0-11-10-35-16-22-23-49-13-43-45-51-21,29-23-30-25-24,0-1-2",
            h2_settings={
                "HEADER_TABLE_SIZE": 65536,
                "MAX_CONCURRENT_STREAMS": 1000,
                "INITIAL_WINDOW_SIZE": 6291456,
                "MAX_HEADER_LIST_SIZE": 262144
            }
        )
        
        self.failed = []
        self.success = []
        self.captcha = []



    def set_proxy(self) -> None:
        with open("data/proxies.txt", "r") as file:
            proxies = file.read().splitlines()
        while True:
            try:
                proxy = random.choice(proxies)
            except IndexError:
                Log.Warning("No proxies remaining.")
                return
            if "http://" not in proxy:
                proxy = {"http": f"http://{proxy}"}
            if not check_proxy(proxy=proxy):
                proxies.remove(proxy.replace("http://", ""))
                continue
            else:
                self.client.proxies = proxy
                break
    
    def getCookies(self, session=None):
        headers = {
            "accept": "*/*",
            "accept-language": "en-US,en;q=0.5",
            "connection": "keep-alive",
            "host": "canary.discord.com",
            "referer": "https://canary.discord.com/",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "user-agent": "Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/85.8.5 (KHTML, like Gecko) Safari/85",
            "x-context-properties": "eyJsb2NhdGlvbiI6IkFjY2VwdCBJbnZpdGUgUGFnZSJ9",
            "x-debug-options": "bugReporterEnabled",
            "x-discord-locale": "en-US",
            "x-super-properties": "eyJvcyI6Ik1hYyBPUyBYIiwiYnJvd3NlciI6IlNhZmFyaSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJlbi1KTSIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChNYWNpbnRvc2g7IFU7IFBQQyBNYWMgT1MgWDsgZGUtZGUpIEFwcGxlV2ViS2l0Lzg1LjguNSAoS0hUTUwsIGxpa2UgR2Vja28pIFNhZmFyaS84NSIsImJyb3dzZXJfdmVyc2lvbiI6IiIsIm9zX3ZlcnNpb24iOiIiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTgxODMyLCJjbGllbnRfZXZlbnRfc291cmNlIjoibnVsbCJ9",
        }
        response = httpx.get(
            "https://canary.discord.com/api/v9/experiments", headers=headers
        )
        self.dcfduid = response.cookies.get("__dcfduid")
        self.sdcfduid = response.cookies.get("__sdcfduid")
        self.cfruid = response.cookies.get("__cfruid")
        
    def save_success_token(self, guild, token):
        os.makedirs(f'output/success', exist_ok=True)
        file_path = f'output/success/{guild}.txt'
        with open(file_path, 'a', encoding='utf-8') as f:
            portalocker.lock(f, portalocker.LOCK_EX)
            f.write(token + '\n')
            
    def save_failed_token(self, guild, token):
        os.makedirs(f'output/failed', exist_ok=True)
        file_path = f'output/failed/{guild}.txt'
        with open(file_path, 'a', encoding='utf-8') as f:
            portalocker.lock(f, portalocker.LOCK_EX)
            f.write(token + '\n')
    
    def save_captcha_token(self, guild, token):
        os.makedirs(f'output/captcha', exist_ok=True)
        file_path = f'output/captcha/{guild}.txt'
        with open(file_path, 'a', encoding='utf-8') as f:
            portalocker.lock(f, portalocker.LOCK_EX)
            f.write(token + '\n')

    def boost(self, token, invite, guild):
        if onliner:
            Thread(target=online, args=(token, f"{shop_name}", "1", "random",)).start()
            if debug:
                Log.Debug(f"Onliner Thread Running...")
        global failed

        headers = {
            "authority": "discord.com",
            "accept": "*/*",
            "accept-language": "fr-FR,fr;q=0.9",
            "authorization": token,
            "cache-control": "no-cache",
            "content-type": "application/json",
            "cookie": f"__dcfduid={self.dcfduid}; __sdcfduid={self.sdcfduid}; __cfruid={self.cfruid}; locale=en-US",
            "origin": "https://discord.com",
            "pragma": "no-cache",
            "referer": "https://discord.com/channels/@me",
            "sec-ch-ua": '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "user-agent": "Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/85.8.5 (KHTML, like Gecko) Safari/85",
            "x-debug-options": "bugReporterEnabled",
            "x-discord-locale": "en-US",
            "x-super-properties": "eyJvcyI6Ik1hYyBPUyBYIiwiYnJvd3NlciI6IlNhZmFyaSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJlbi1KTSIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChNYWNpbnRvc2g7IFU7IFBQQyBNYWMgT1MgWDsgZGUtZGUpIEFwcGxlV2ViS2l0Lzg1LjguNSAoS0hUTUwsIGxpa2UgR2Vja28pIFNhZmFyaS84NSIsImJyb3dzZXJfdmVyc2lvbiI6IiIsIm9zX3ZlcnNpb24iOiIiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTgxODMyLCJjbGllbnRfZXZlbnRfc291cmNlIjoibnVsbCJ9",
        }

        slots = httpx.get(
            "https://discord.com/api/v9/users/@me/guilds/premium/subscription-slots",
            headers=headers,
        )

        slot_json = slots.json()

        if slots.status_code == 401:
            Log.Error(f"Invalid token : {token}")
            self.save_failed_token(guild, token)
            self.failed.append(token)
            return

        if slots.status_code != 200 or len(slot_json) == 0:
            return

        r = self.client.post(
            f"https://discord.com/api/v9/invites/{invite}", headers=headers, json={}
        )

        if r.status_code == 200:
            Log.Success(f"Successfully Joined, guild {Fore.LIGHTBLACK_EX}{invite}{Fore.RESET}, token {Fore.LIGHTBLACK_EX}{token[:40]}xxx{Fore.RESET}")
            
            boostsList = []
            for boost in slot_json:
                boostsList.append(boost["id"])

            payload = {"user_premium_guild_subscription_slot_ids": boostsList}

            headers["method"] = "PUT"
            headers["path"] = f"/api/v9/guilds/{guild}/premium/subscriptions"

            boosted = self.client.put(f"https://discord.com/api/v9/guilds/{guild}/premium/subscriptions",json=payload, headers=headers)
            try:
                if boosted.status_code == 201:
                    Log.Success(f"Successfully Boosted, guild {Fore.LIGHTBLACK_EX}{invite}{Fore.RESET}, token {Fore.LIGHTBLACK_EX}{token[:40]}xxx{Fore.RESET}")
                    
                    self.success.append(token)
                    self.save_success_token(guild, token)
                    return True
                elif "cooldown" in boosted.text.lower():
                    failed += 1
                    Log.Error(f"Failed to boost, guild {Fore.LIGHTBLACK_EX}{invite}{Fore.RESET}, token {Fore.LIGHTBLACK_EX}{token[:30]}xxx{Fore.RESET}, reason {Fore.LIGHTBLACK_EX}Cooldown{Fore.RESET}")
                    self.failed.append(token)
                    self.save_failed_token(guild, token)
                else:
                    print(boosted.text)
                    failed += 1
                    self.failed.append(token)
                    self.save_failed_token(guild, token)
            except Exception as e:
                failed += 1
                Log.Error(f"Exception in Boost() {Fore.LIGHTBLACK_EX}{e}xxx")
                self.save_failed_token(guild, token)
                    
        elif r.status_code == 403:
            failed += 1
            Log.Error(f"Locked token : {token[:50]}")
            self.save_failed_token(guild, token)
            return
        elif "captcha_key" in r.json():
            failed += 1
            self.save_captcha_token(guild, token)
            self.captcha.append(token)
            Log.Warning(f"Captcha, guild {Fore.LIGHTBLACK_EX}{invite}{Fore.RESET}, token {Fore.LIGHTBLACK_EX}{token[:40]}xxx{Fore.RESET}")
            start = time.time()
            _r = r.json()
            captchaRqdata = _r['captcha_rqdata']
            solution = solver.solve(rqdata=captchaRqdata)
            attempt = 5
            attempted = 0
            while attempt >= attempted:
                if solution == None:
                    if attempted == attempt:
                        Log.Error(f"Failed to solve captcha")
                        break
                    attempted += 1
                    time.sleep(5)
                    continue
                
                elif '404: Not Found' in r.text:
                    Log.Error(f'404: Not Found')
                    break
                elif 'You are being rate limited.' in r.text:
                    Log.Error('You are being rate limited.')
                    break
                elif 'Unknown Invite' in r.text:
                    Log.Error(f"Unknown Invite")
                    break
                else:
                    
                    time_taken = round(time.time() - start, 2)
                    headers2 = {
                "authority": "discord.com",
                "accept": "*/*",
                "accept-language": "fr-FR,fr;q=0.9",
                "authorization": token,
                "cache-control": "no-cache",
                "content-type": "application/json",
                "cookie": f"__dcfduid={self.dcfduid}; __sdcfduid={self.sdcfduid}; __cfruid={self.cfruid}; locale=en-US",
                "origin": "https://discord.com",
                "pragma": "no-cache",
                "referer": "https://discord.com/channels/@me",
                "sec-ch-ua": '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
                "user-agent": "Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/85.8.5 (KHTML, like Gecko) Safari/85",
                "x-debug-options": "bugReporterEnabled",
                "x-discord-locale": "en-US",
                "x-super-properties": "eyJvcyI6Ik1hYyBPUyBYIiwiYnJvd3NlciI6IlNhZmFyaSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJlbi1KTSIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChNYWNpbnRvc2g7IFU7IFBQQyBNYWMgT1MgWDsgZGUtZGUpIEFwcGxlV2ViS2l0Lzg1LjguNSAoS0hUTUwsIGxpa2UgR2Vja28pIFNhZmFyaS84NSIsImJyb3dzZXJfdmVyc2lvbiI6IiIsIm9zX3ZlcnNpb24iOiIiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTgxODMyLCJjbGllbnRfZXZlbnRfc291cmNlIjoibnVsbCJ9",
                "x-captcha-key": solution,
                "x-captcha-rqtoken" : r.json()["captcha_rqtoken"]
            }
                    Log.Success(f"Successfully Solved Captcha {time_taken}, token{Fore.LIGHTBLACK_EX} {token[:40]}xxx")
                    r2 = self.client.post(F"https://discord.com/api/v9/invites/{invite}",headers=headers2,json={})
                    if r2.status_code == 200:
                        Log.Success(f"Successfully Joined, guild {Fore.LIGHTBLACK_EX}{invite}{Fore.RESET}, token {Fore.LIGHTBLACK_EX}{token[:40]}xxx{Fore.RESET}")
                        boostsList = []
                        for boost in slot_json:
                            boostsList.append(boost["id"])
                            payload = {"user_premium_guild_subscription_slot_ids": boostsList}
                            headers["method"] = "PUT"
                            headers["path"] = f"/api/v9/guilds/{guild}/premium/subscriptions"
                            boosted = self.client.put(
                    f"https://discord.com/api/v9/guilds/{guild}/premium/subscriptions",
                    json=payload,
                    headers=headers,
                )
                            if boosted.status_code == 201:
                                Log.Success(f"Successfully Boosted, guild {Fore.LIGHTBLACK_EX}{invite}{Fore.RESET}, token {Fore.LIGHTBLACK_EX}{token[:40]}xxx{Fore.RESET}")
                                self.success.append(token)
                                self.save_success_token(guild, token)
                                return True
                            
                            else:
                                self.failed.append(token)
                                self.save_failed_token(guild, token)
                    else:
                        self.captcha.append(token)
                        self.save_captcha_token(guild, token)
                        self.save_failed_token(guild, token)

    def nick(self, token, guild):
        headers = {
            "authority": "discord.com",
            "accept": "*/*",
            "accept-language": "fr-FR,fr;q=0.9",
            "authorization": token,
            "cache-control": "no-cache",
            "content-type": "application/json",
            "cookie": f"__dcfduid={self.dcfduid}; __sdcfduid={self.sdcfduid}; __cfruid={self.cfruid}; locale=en-US",
            "origin": "https://discord.com",
            "pragma": "no-cache",
            "referer": "https://discord.com/channels/@me",
            "sec-ch-ua": '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "user-agent": "Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/85.8.5 (KHTML, like Gecko) Safari/85",
            "x-debug-options": "bugReporterEnabled",
            "x-discord-locale": "en-US",
            "x-super-properties": "eyJvcyI6Ik1hYyBPUyBYIiwiYnJvd3NlciI6IlNhZmFyaSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJlbi1KTSIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChNYWNpbnRvc2g7IFU7IFBQQyBNYWMgT1MgWDsgZGUtZGUpIEFwcGxlV2ViS2l0Lzg1LjguNSAoS0hUTUwsIGxpa2UgR2Vja28pIFNhZmFyaS84NSIsImJyb3dzZXJfdmVyc2lvbiI6IiIsIm9zX3ZlcnNpb24iOiIiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTgxODMyLCJjbGllbnRfZXZlbnRfc291cmNlIjoibnVsbCJ9",
        }

        payload = {"nick": nickname}

        nick_response = httpx.patch(f"https://discord.com/api/v9/guilds/{guild}/members/@me", headers=headers,json=payload)

        if nick_response.status_code in [200, 204]:
            Log.Success(f"Successfully Watermarked token, nick {Fore.LIGHTBLACK_EX}{nickname}{Fore.RESET}, token {Fore.LIGHTBLACK_EX}{token[:40]}xxx{Fore.RESET}")
        else:
            Log.Error(f"Failed to watermark, nick{Fore.LIGHTBLACK_EX} {nickname}{Fore.RESET}, token{Fore.LIGHTBLACK_EX} {token[:40]}xxx{Fore.RESET}")

    def banner(self, token, guild):
        headers = {
            "authority": "discord.com",
            "accept": "*/*",
            "accept-language": "fr-FR,fr;q=0.9",
            "authorization": token,
            "cache-control": "no-cache",
            "content-type": "application/json",
            "cookie": f"__dcfduid={self.dcfduid}; __sdcfduid={self.sdcfduid}; __cfruid={self.cfruid}; locale=en-US",
            "origin": "https://discord.com",
            "pragma": "no-cache",
            "referer": "https://discord.com/channels/@me",
            "sec-ch-ua": '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "user-agent": "Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/85.8.5 (KHTML, like Gecko) Safari/85",
            "x-debug-options": "bugReporterEnabled",
            "x-discord-locale": "en-US",
            "x-super-properties": "eyJvcyI6Ik1hYyBPUyBYIiwiYnJvd3NlciI6IlNhZmFyaSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJlbi1KTSIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChNYWNpbnRvc2g7IFU7IFBQQyBNYWMgT1MgWDsgZGUtZGUpIEFwcGxlV2ViS2l0Lzg1LjguNSAoS0hUTUwsIGxpa2UgR2Vja28pIFNhZmFyaS84NSIsImJyb3dzZXJfdmVyc2lvbiI6IiIsIm9zX3ZlcnNpb24iOiIiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTgxODMyLCJjbGllbnRfZXZlbnRfc291cmNlIjoibnVsbCJ9",
        }
        banner_directory = "data/banners/"
        banner_files = [
            f
            for f in os.listdir(banner_directory)
            if os.path.isfile(os.path.join(banner_directory, f))
        ]
        banner_path = (
            os.path.join(banner_directory, random.choice(banner_files))
            if banner_files
            else None
        )
        if banner_path and os.path.exists(banner_path):
            banner_data = image_to_b64(banner_path)
            if banner_data:
                data = {"banner": banner_data}
                r2 = self.client.get("https://discord.com/api/v9/users/@me")
                response = self.client.patch(
                    f"https://discord.com/api/v9/guilds/{guild}/members/@me",
                    headers=headers,
                    json=data,
                )
                if response.status_code in (200, 201, 204):
                    Log.Success(f"Successfully Watermarked token, banner {Fore.LIGHTBLACK_EX}banner{Fore.RESET}, token {Fore.LIGHTBLACK_EX}{token[:40]}xxx{Fore.RESET}")
                else:
                    Log.Error(f"Failed to watermark, banner{Fore.LIGHTBLACK_EX} banner{Fore.RESET}, token{Fore.LIGHTBLACK_EX} {token[:40]}xxx{Fore.RESET}")
            else:
                Log.Error(f"Failed to encode banner image from path, token{Fore.LIGHTBLACK_EX}{token[:40]}xxx{Fore.RESET}")
        else:
            Log.Error(f"No banner images found in the specified directory or the specified directory does not exist")
    
    def avatar(self, token, guild):
        headers = {
            "authority": "discord.com",
            "accept": "*/*",
            "accept-language": "fr-FR,fr;q=0.9",
            "authorization": token,
            "cache-control": "no-cache",
            "content-type": "application/json",
            "cookie": f"__dcfduid={self.dcfduid}; __sdcfduid={self.sdcfduid}; __cfruid={self.cfruid}; locale=en-US",
            "origin": "https://discord.com",
            "pragma": "no-cache",
            "referer": "https://discord.com/channels/@me",
            "sec-ch-ua": '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "user-agent": "Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/85.8.5 (KHTML, like Gecko) Safari/85",
            "x-debug-options": "bugReporterEnabled",
            "x-discord-locale": "en-US",
            "x-super-properties": "eyJvcyI6Ik1hYyBPUyBYIiwiYnJvd3NlciI6IlNhZmFyaSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJlbi1KTSIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChNYWNpbnRvc2g7IFU7IFBQQyBNYWMgT1MgWDsgZGUtZGUpIEFwcGxlV2ViS2l0Lzg1LjguNSAoS0hUTUwsIGxpa2UgR2Vja28pIFNhZmFyaS84NSIsImJyb3dzZXJfdmVyc2lvbiI6IiIsIm9zX3ZlcnNpb24iOiIiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTgxODMyLCJjbGllbnRfZXZlbnRfc291cmNlIjoibnVsbCJ9",
        }
        avatars_directory = "data/avatars/"
        avatar_files = [
            f
            for f in os.listdir(avatars_directory)
            if os.path.isfile(os.path.join(avatars_directory, f))
        ]
        avatar_path = (
            os.path.join(avatars_directory, random.choice(avatar_files))
            if avatar_files
            else None
        )
        if avatar_path and os.path.exists(avatar_path):
            avatar_data = image_to_b64(avatar_path)
            if avatar_data:
                data = {"avatar": avatar_data}
                response = self.client.patch(
                    f"https://discord.com/api/v9/guilds/{guild}/members/@me",
                    headers=headers,
                    json=data,
                )
                if response.status_code == 200:
                    Log.Success(f"Successfully Watermarked token, avataar {Fore.LIGHTBLACK_EX}avatar{Fore.RESET}, token {Fore.LIGHTBLACK_EX}{token[:40]}xxx{Fore.RESET}")
                else:
                    Log.Error(f"Failed to watermark, avatar{Fore.LIGHTBLACK_EX} avatar{Fore.RESET}, token{Fore.LIGHTBLACK_EX} {token[:40]}xxx{Fore.RESET}")
            else:
                Log.Error(f"Failed to encode avatar image from path, token{Fore.LIGHTBLACK_EX}{token[:40]}xxx{Fore.RESET}")
                    
        else:
            Log.Error(f"No avatar images found in the specified directory or the specified directory does not exist")
                    
    def bio(self, token):
        headers = {
            "authority": "discord.com",
            "accept": "*/*",
            "accept-language": "fr-FR,fr;q=0.9",
            "authorization": token,
            "cache-control": "no-cache",
            "content-type": "application/json",
            "cookie": f"__dcfduid={self.dcfduid}; __sdcfduid={self.sdcfduid}; __cfruid={self.cfruid}; locale=en-US",
            "origin": "https://discord.com",
            "pragma": "no-cache",
            "referer": "https://discord.com/channels/@me",
            "sec-ch-ua": '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "user-agent": "Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/85.8.5 (KHTML, like Gecko) Safari/85",
            "x-debug-options": "bugReporterEnabled",
            "x-discord-locale": "en-US",
            "x-super-properties": "eyJvcyI6Ik1hYyBPUyBYIiwiYnJvd3NlciI6IlNhZmFyaSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJlbi1KTSIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChNYWNpbnRvc2g7IFU7IFBQQyBNYWMgT1MgWDsgZGUtZGUpIEFwcGxlV2ViS2l0Lzg1LjguNSAoS0hUTUwsIGxpa2UgR2Vja28pIFNhZmFyaS84NSIsImJyb3dzZXJfdmVyc2lvbiI6IiIsIm9zX3ZlcnNpb24iOiIiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTgxODMyLCJjbGllbnRfZXZlbnRfc291cmNlIjoibnVsbCJ9",
        }

        payload = {"bio": custom_bio}

        bio_response = httpx.patch(
            f"https://discord.com/api/v9/users/@me/profile",
            headers=headers,
            json=payload,
        )

        if bio_response.status_code in [200, 204]:
            Log.Success(f"Successfully Watermarked token, bio {Fore.LIGHTBLACK_EX}{custom_bio}{Fore.RESET}, token {Fore.LIGHTBLACK_EX}{token[:35]}xxx{Fore.RESET}")
        else:
            Log.Error(f"Failed to watermark, bio{Fore.LIGHTBLACK_EX} {custom_bio}{Fore.RESET}, token{Fore.LIGHTBLACK_EX} {token[:35]}xxx{Fore.RESET}")

    def nick_thread(self, tokens, guild):
        threads = []

        for i in range(len(tokens)):
            token = tokens[i]
            t = threading.Thread(target=self.nick, args=(token, guild))
            t.daemon = True
            threads.append(t)

        for i in range(len(tokens)):
            threads[i].start()

        for i in range(len(tokens)):
            threads[i].join()

        return True

    def banner_thread(self, tokens, guild):
        threads = []

        for i in range(len(tokens)):
            token = tokens[i]
            t = threading.Thread(target=self.banner, args=(token, guild))
            t.daemon = True
            threads.append(t)

        for i in range(len(tokens)):
            threads[i].start()

        for i in range(len(tokens)):
            threads[i].join()

        return True
    
    def avatar_thread(self, tokens, guild):
        threads = []

        for i in range(len(tokens)):
            token = tokens[i]
            t = threading.Thread(target=self.avatar, args=(token, guild))
            t.daemon = True
            threads.append(t)

        for i in range(len(tokens)):
            threads[i].start()

        for i in range(len(tokens)):
            threads[i].join()

        return True
    
    
    def bio_thread(self, tokens):
        threads = []

        for i in range(len(tokens)):
            token = tokens[i]
            t = threading.Thread(target=self.bio, args=(token,))
            t.daemon = True
            threads.append(t)

        for i in range(len(tokens)):
            threads[i].start()

        for i in range(len(tokens)):
            threads[i].join()

        return True
    


    def thread(self, invite, tokens, guild):
        """"""
        threads = []
        for i in range(len(tokens)):
            token = tokens[i]
            t = threading.Thread(target=self.boost, args=(token, invite, guild))
            t.daemon = True
            threads.append(t)

        for i in range(len(tokens)):
            threads[i].start()

        for i in range(len(tokens)):
            threads[i].join()

        return {
            "success": self.success,
            "failed": self.failed,
            "captcha": self.captcha,
        }


@bot.slash_command(
    name="boost", description="Boost a server."
)
async def boost(
    ctx,
    invitecodes: discord.Option(str, "Invite Link of server.", required=True),
    amount: discord.Option(
        int, "Amount of boosts [must be even]", required=True
    ),
    months: discord.Option(
        choices=[
            discord.OptionChoice(name="1 Month", value="1"),
            discord.OptionChoice(name="3 Month", value="3")
        ]),
):
    await ctx.response.defer(ephemeral=False)
    if ctx.author.id not in owners:
            await ctx.respond(
                embed=discord.Embed(
                    title="Error",
                    description="You are not an owner",
                    color=0x31373d,
                )
            )
            return
    
    if amount % 2 != 0:
        return await ctx.respond(
            embed= discord.Embed(
                title="Error",
                description=f"Amount should be even only [ For Example : 2, 4, 8, 14 ]",
                color=0x31373d
            )
        )
    
    invite = invitecodes.replace("https://", "").replace("discord.gg/", "").replace("discord.com/invite/", "")
    invitecheck = checkInvite(invite)
    
    if invitecheck == False:
        return await ctx.respond(
            embed= discord.Embed(
                title="Error",
                description=f"Invalid Invite Link Provided",
                color=0x31373d
            )
        )
    
    if months == "1":
        fileName = "input/1m_nitro.txt"
    else:
        fileName = "input/3m_nitro.txt"
    tokensStock = getStock(fileName)
    requiredStock = int(amount / 2)
    if requiredStock > len(tokensStock):
        return await ctx.respond(embed=discord.Embed(title="Error",description=f"Insufficient Stock"))
    
    boost = Booster()
    
    tokens = []
    for x in range(requiredStock):
        tokens.append(tokensStock[x])
        remove(tokensStock[x], fileName)
    invoice_id = generate_invoice_id()
    boost_data = {
        "invoice_id": invoice_id,
        "number_of_boosts": amount,
        "months": months,
        "guild": invitecheck
    }
    save_data_to_json(boost_data)

    await ctx.respond(
        embed=discord.Embed(
            title="**Success, We have started boosting the server provided...**", description=f"> **Boosting Server **\n> Status: **Pending**", color=0x31373d
        )
    )
    
    start = time.time()
    Log.Info(f"Boost Server, invite{Fore.LIGHTBLACK_EX} {invitecheck}{Fore.RESET}, amount{Fore.LIGHTBLACK_EX} {amount}{Fore.RESET}, months{Fore.LIGHTBLACK_EX} {months}M")
    status = boost.thread(invite, tokens, invitecheck)
    

    time_taken = round(time.time() - start, 2)
    Log.Success(f"Successfully completed boosting, invite{Fore.LIGHTBLACK_EX} {invitecheck}{Fore.RESET}, amount{Fore.LIGHTBLACK_EX} {amount}{Fore.RESET}, time taken{Fore.LIGHTBLACK_EX} {time_taken}s{Fore.RESET}")
    
    
    embed=discord.Embed(
        title="Server Boosted Successfully",
        description=f"Boosted the server as detailed below: \n\n> **Total Boosts Applied**: {amount} \n> **Boosts Duration**: {months} months \n> **Server Invite Link**: {invite} \n\nOverview of the process: \n> **Successfully Enhanced with**: {len(status['success'])} tokens \n> **Encountered Difficulties**: {len(status['failed'])} tokens \n> **Captcha Encountered for**: {len(status['captcha'])} tokens \n\n**Cumulative Time Expended**: {time_taken}s\n\n> Invoice ID: **{invoice_id}**",
        color=0x31373d,)
    if ctx.user.avatar:
        url = ctx.user.avatar.url
    else:
        url = None
    embed.set_thumbnail(url=url)
    embed.set_footer(text=f"© {shop_name} - All Rights Reserved.")
    await ctx.edit(embed=embed)
    
    
    e = {
    "embeds": [
        {
            "type": "rich",
            "title": "Activity Summary: Server Boosting",
            "description": "A summary of the recent server boosting activity is provided below.",
            "color": 0x31373d,
            "fields": [
                {"name": "Initiated By", "value": f"**{ctx.author}**", "inline": True},
                {"name": "Total Boosts", "value": f"**{amount}**", "inline": True},
                {"name": "Duration", "value": f"**{months} Month(s)**", "inline": True},
                {"name": "Destination Server", "value": f"[Join Here](https://discord.gg/{invite})", "inline": False},
                {"name": "Tokens Deployed", "value": f"**{requiredStock}**", "inline": True},
                {"name": "Boosts Applied", "value": f"**{len(status['success']) * 2}**", "inline": True},
                {"name": "Challenges Encountered", "value": f"**{len(status['failed'])}**", "inline": True},
                {"name": "Captcha Verifications", "value": f"**{len(status['captcha'])}**", "inline": True},
            ],
        }
    ]
}
    w = DiscordWebhook(url=boost_webhook)
    
    httpx.post(
        w.url,
        headers={"Content-type": "application/json"},
        json=e,
    )
    
    if change_nick:
        boost.nick_thread(tokens, invitecheck)
    if change_bio:
        boost.bio_thread(tokens)
    if change_banner:
        boost.banner_thread(tokens, invitecheck)
    if change_avatar:
        boost.avatar_thread(tokens, invitecheck)
    return True

@bot.slash_command(
    name="stock", description="The amount of boosts / tokens in stock"
)
async def stock(
    ctx,
    type: discord.Option(
        choices=[
            discord.OptionChoice(name="1 Month Tokens", value="1"),
            discord.OptionChoice(name="3 Month Tokens", value="3"),
            discord.OptionChoice(name="Combined Stock", value="all"),
        ],
        description="Select the type of stock to view.",
        required=True,
    ),
):
    await ctx.defer(ephemeral=False)
    
    stock1m, stock3m = 0, 0
    description = ""
    
    if type in ["1", "3"]:
        file_path = f"input/{type}m_nitro.txt"
        stock_count = len(open(file_path, "r").readlines())
        description = f"**{type} Month Tokens**"
        data = {description: {"tokens": stock_count, "boosts": stock_count * 2}}
    elif type == "all":
        file_path_1m = "input/1m_nitro.txt"
        file_path_3m = "input/3m_nitro.txt"
        stock1m = len(open(file_path_1m, "r").readlines())
        stock3m = len(open(file_path_3m, "r").readlines())
        description = "**Combined Stock**"
        data = {
            "**1 Month Tokens**": {"tokens": stock1m, "boosts": stock1m * 2},
            "**3 Month Tokens**": {"tokens": stock3m, "boosts": stock3m * 2}
        }

    embed = discord.Embed(
        title="Nitro Tokens Stock",
        description="> Here's the current **stock** for Nitro tokens:",
        color=0x31373d
    )
    
    for key, value in data.items():
        embed.add_field(
            name=key,
            value=f"> `📦`**Tokens**: `{value['tokens']}`\n> `🚀`**Boosts Available**: `{value['boosts']}`",
            inline=False
        )
    if ctx.user.avatar:
        url = ctx.user.avatar.url
    else:
        url = None
    embed.set_thumbnail(url=url)
    if ctx.bot.user.display_avatar:
        url2 = ctx.bot.user.display_avatar.url
    else:
        url2 = None
    embed.set_footer(text="Stock • ", icon_url=url2)
    embed.timestamp = datetime.utcnow()

    await ctx.edit(embed=embed)


@bot.slash_command(
    name="multi_boost",
    description="Boost multiple servers with specified amounts."
)
async def multi_boost(
    ctx,
    invites: discord.Option(str, "Comma-separated list of invite codes.", required=True),
    amounts: discord.Option(str, "Comma-separated list of boost amounts corresponding to each invite code.", required=True),
    months: discord.Option(
        choices=[
            discord.OptionChoice(name="1 Month", value="1"),
            discord.OptionChoice(name="3 Month", value="3")
        ],
        description="Duration of the boosts in months.",
        required=True
    )
):
    await ctx.defer(ephemeral=False)
    if ctx.author.id not in owners:
            await ctx.respond(
                embed=discord.Embed(
                    title="Error",
                    description="You are not an owner",
                    color=0x31373d,
                )
            )
            return

    invite_list = invites.split(',')
    amount_list = amounts.split(',')

    if len(invite_list) != len(amount_list):
        return await ctx.respond(
            embed=discord.Embed(
                title="Error",
                description="> The number of invites must match the number of amounts.",
                color=0x31373d
            )
        )

    for invite, amount_str in zip(invite_list, amount_list):
        try:
            amount = int(amount_str.strip())
            if amount % 2 != 0:
                raise ValueError("Amount must be an even number.")
        except ValueError:
            return await ctx.respond(
                embed=discord.Embed(
                    title="Error",
                    description=f"> Invalid amount '{amount_str}'. Amounts must be even.",
                    color=0x31373d
                )
            )

        invite = invite.replace("https://", "").replace("discord.gg/", "").replace("discord.com/invite/", "")
        invitecheck = checkInvite(invite)
        if invitecheck == False:
            continue
            
        
        if months == "1":
            fileName = "input/1m_nitro.txt"
        else:
            fileName = "input/3m_nitro.txt"
        tokensStock = getStock(fileName)
        requiredStock = int(amount / 2)
        if requiredStock > len(tokensStock):
            return await ctx.respond(embed=discord.Embed(title="Error",description=f"Insufficient Stock, please restock | [Retry]"))
        boost = Booster()
        invoice_id = generate_invoice_id()
        boost_data = {
        "invoice_id": invoice_id,
        "number_of_boosts": amount,
        "months": months,
        "guild": invitecheck
    }
        save_data_to_json(boost_data)
        tokens = []
        for x in range(requiredStock):
            tokens.append(tokensStock[x])
            remove(tokensStock[x], fileName)
            await ctx.respond(
        embed=discord.Embed(
            title="**Success, We have started boosting the server provided..**", description=f"> **Boosting Server**\n> Guild: {invite}\n> Invoice ID: {invoice_id}", color=0x31373d
        )
    )
            start = time.time()
            Log.Info(f"Boost Server, invite{Fore.LIGHTBLACK_EX} {invitecheck}{Fore.RESET}, amount{Fore.LIGHTBLACK_EX} {amount}{Fore.RESET}, months{Fore.LIGHTBLACK_EX} {months}M, invoice {Fore.LIGHTBLACK_EX}{invoice_id}{Fore.RESET}")
            w = Booster()
            status = w.thread(invite, tokens, invitecheck)
            time_taken = round(time.time() - start, 2)
            


    await ctx.send(
        embed=discord.Embed(
            title="Completed Boosting",
            description="> Status: **Completed**\n> All boosts have been completed.",
            color=0x31373d
        )
    )
    if change_nick:
        boost.nick_thread(tokens, invitecheck)
    if change_bio:
        boost.bio_thread(tokens)
    if change_banner:
        boost.banner_thread(tokens, invitecheck)
    if change_avatar:
        boost.avatar_thread(tokens, invitecheck)
    print()
    
    return True

@bot.slash_command(
    name="fetch-order",
    description="Fetch order details by invoice ID."
)
async def fetch_order(
    ctx,
    invoice_id: discord.Option(str, "Enter the invoice ID to fetch.", required=True)
):
    await ctx.defer(ephemeral=False)
    
    try:
        with open('database.json', 'r') as file:
            orders = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        await ctx.respond(embed=discord.Embed(title="Error", description="No orders found.", color=0x31373d))
        return

    order = next((item for item in orders if item["invoice_id"] == invoice_id), None)

    if order is None:
        await ctx.respond(embed=discord.Embed(title="Order Not Found", description="No order found with the given invoice ID.", color=0x31373d))
    else:
        embed = discord.Embed(
            title="Order Details",
            description=f"Here are the details for the order with invoice ID: {invoice_id}",
            color=0x31373d
        )
        
        embed.add_field(name="Invoice ID", value=order['invoice_id'], inline=False)
        embed.add_field(name="Number of Boosts", value=order['number_of_boosts'], inline=True)
        embed.add_field(name="Months", value=order['months'], inline=True)
        embed.add_field(name="Guild", value=order['guild'], inline=True)
        
        if ctx.user.avatar:
            url = ctx.user.avatar.url
        else:
            url = None
        embed.set_footer(text=f"Requested by {ctx.author}", icon_url=url)
        embed.timestamp = datetime.utcnow()

        await ctx.respond(embed=embed)



@bot.slash_command(
    name="unboost",
    description="Leave a server by all tokens that successfully boosted it."
)
async def unboost(
    ctx,
    guild_id: discord.Option(str, "Enter the guild ID to unboost.", required=True)
):
    await ctx.defer(ephemeral=False)
    
    file_path = f'output/success/{guild_id}.txt'
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            tokens = f.read().splitlines()
    except FileNotFoundError:
        await ctx.respond(f"No success tokens found for guild ID {guild_id}.")
        return

    left_count = 0
    for token in tokens:
        if leave_guild(token, guild_id):
            left_count += 1
     
    emb = discord.Embed(
        title="Success",
        description=f"Successfuly left guild\n> Guild : {guild_id}\n> Left: {left_count} tokens",
        color=0x31373d
    )
    await ctx.respond(embed=emb)

def leave_guild(token, guild_id):
    """Attempts to leave the guild using the given token. Returns True if successful."""
    client = tls_client.Session(
            client_identifier="chrome_107",
            ja3_string="771,4866-4867-4865-49196-49200-49195-49199-52393-52392-49327-49325-49188-49192-49162-49172-163-159-49315-49311-162-158-49314-49310-107-106-103-64-57-56-51-50-157-156-52394-49326-49324-49187-49191-49161-49171-49313-49309-49233-49312-49308-49232-61-192-60-186-53-132-47-65-49239-49235-49238-49234-196-195-190-189-136-135-69-68-255,0-11-10-35-16-22-23-49-13-43-45-51-21,29-23-30-25-24,0-1-2",
            random_tls_extension_order=True
    )
    client.get(f"https://discord.com/api/v9/users/@me/{guild_id}", headers={"Authorization": token}).json()
    headerz = {
                    "Authority": "discord.com",
                    "Method": "DELETE",
                    "Path": f"/api/v9/users/@me/guilds/{guild_id}",
                    "Scheme": "https",
                    "Accept": "*/*",
                    "Accept-encoding": "gzip, deflate, br",
                    "Accept-language": "en-US,en;q=0.9",
                    "Authorization": token,
                    "Origin": "https://discord.com",
                    "Referer": "https://discord.com/channels/@me",
                    "Sec-Fetch-Dest": "empty",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Site": "same-origin",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.115 Safari/537.36",
                    "X-Debug-Options": "bugReporterEnabled",
                    "X-Discord-Locale": "en-US",
                    "X-Super-Properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEwMi4wLjUwMDUuMTE1IFNhZmFyaS81MzcuMzYiLCJicm93c2VyX3ZlcnNpb24iOiIxMDIuMC41MDA1LjExNSIsIm9zX3ZlcnNpb24iOiIxMCIsInJlZmVycmVyIjoiaHR0cHM6Ly93d3cuZ29vZ2xlLmNvbS8iLCJyZWZlcnJpbmdfZG9tYWluIjoid3d3Lmdvb2dsZS5jb20iLCJzZWFyY2hfZW5naW5lIjoiZ29vZ2xlIiwicmVmZXJyZXJfY3VycmVudCI6Imh0dHBzOi8vd3d3Lmdvb2dsZS5jb20vIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50Ijoid3d3Lmdvb2dsZS5jb20iLCJzZWFyY2hfZW5naW5lX2N1cnJlbnQiOiJnb29nbGUiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfYnVpbGRfbnVtYmVyIjoxMzYyNDAsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9"
                }
    try:
        response = client.delete(f"https://discord.com/api/v9/users/@me/guilds/{guild_id}", headers=headerz)
        
        if response.status_code in [204, 200]:
            Log.Info(f"Successfully left, guild {Fore.LIGHTBLACK_EX}{guild_id}{Fore.RESET}, token{Fore.LIGHTBLACK_EX} {token[:50]}xx{Fore.RESET}")
        elif response.status_code in [401, 403]:
            Log.Error(f'Failed to leave guild, token{Fore.LIGHTBLACK_EX} {token[:50]}xxx, {Fore.RESET}reason {Fore.LIGHTBLACK_EX}Locked or Invalid{Fore.RESET}')
        else:
            Log.Info(f"Failed to leave guild, reason{Fore.LIGHTBLACK_EX} {response.text[:70]}xx{Fore.RESET}")
    except Exception as e:
        Log.Error(f"Exception in leave_guild, reason{Fore.LIGHTBLACK_EX} {e}{Fore.RESET}")

    return response.status_code in [204, 200]


import os

@bot.slash_command(
    name="sendtokens",
    description="Send tokens from the token stock",
)
async def sendtokens(
    ctx,
    user: discord.Option(discord.Member, "User to send tokens", required=True),
    amount: discord.Option(int, "Amount of tokens to give", required=True),
    months: discord.Option(
        choices=[
            discord.OptionChoice(name="1 Month", value="1"),
            discord.OptionChoice(name="3 Month", value="3"),
        ]
    ),
):
    if ctx.author.id not in owners:
        await ctx.send(
            embed=discord.Embed(
                title="Error",
                description="You are not an owner",
                color=discord.Color.red(),
            )
        )
        return

    filename = None

    if months == "1":
        filename = "input/1m_nitro.txt"
    elif months == "3":
        filename = "input/3m_nitro.txt"
    else:
        return await ctx.respond(
            embed=discord.Embed(
                title="Invalid duration",
                description="Please specify a valid duration [1 or 3 months].",
                color=0x31373D,
            )
        )

    if filename is None:
        return await ctx.respond(
            embed=discord.Embed(
                title="Internal Error",
                description="An internal error occurred while processing your request.",
                color=0xFF0000,
            )
        )

    # Read all tokens from the file
    with open(filename, "r") as file:
        tokens = file.read().splitlines()

    if amount > len(tokens):
        return await ctx.respond(
            embed=discord.Embed(
                title="Not enough tokens",
                description=f"You are requesting {amount} tokens, but only {len(tokens)} tokens are available.",
                color=0x31373D,
            )
        )

    tokens_to_send = tokens[:amount]
    tokens = tokens[amount:]  # Remove sent tokens from the list

    # Write remaining tokens back to the file
    with open(filename, "w") as file:
        file.write("\n".join(tokens))

    outfile = f"{user.name}_{amount}_{months}_month_tokens.txt".replace(" ", "_")

    with open(outfile, "w") as file:
        for token in tokens_to_send:
            file.write(token + "\n")

    with open(outfile, "rb") as out_tokens:
        channel = await user.create_dm()
        await channel.send(file=discord.File(out_tokens, outfile))

    os.remove(outfile)

    return await ctx.respond(
        embed=discord.Embed(
            title="Success",
            description=f"Successfully sent {amount} {months} month(s) tokens to `{user}`",
            color=0x31373D,
        )
    )


@bot.slash_command(name="restock", description="Restocks tokens!")
async def restock(
    ctx,
    attachment: discord.Option(
        discord.Attachment, "Drag your file with tokens here", required=True
    ),
    months: discord.Option(
        choices=[
            discord.OptionChoice(name="1 Month", value="1"),
            discord.OptionChoice(name="3 Month", value="3"),
        ]
    ),
):
    if ctx.author.id not in owners:
        await ctx.send(
            embed=discord.Embed(
                title="Error",
                description="You are not an owner",
                color=discord.Color.red(),
            )
        )
        return

    filename = None

    if months == "1":
        filename = "input/1m_nitro.txt"
    elif months == "3":
        filename = "input/3m_nitro.txt"
    else:
        return await ctx.respond(
            embed=discord.Embed(
                title="Invalid duration",
                description="Please specify a valid duration [1 or 3 months].",
                color=0x31373D,
            )
        )

    tokens = await attachment.read()
    tokens = tokens.decode()
    with open(filename, "a") as tokens_input:
        for token in tokens.splitlines():
            tokens_input.write(token + "\n")

    embed = discord.Embed(
        title="Successfully Restocked",
        description=f"*> Restocked {len(tokens.splitlines())} tokens*",
        color=0x31373D,
    )

    await ctx.respond(embed=embed)

@bot.slash_command(name="add-owner", description="Add a new owner by their user ID.")
async def add_owner(ctx, user_id: discord.Option(str, "Enter the user ID to add as an owner.", required=True)):
    try:
        user_id = int(user_id)
    except ValueError:
        await ctx.respond("Invalid user ID. Please ensure you provide a dev user ID.")
        return

    with open('config.yaml', 'r') as file:
        config = yaml.safe_load(file)

    if ctx.author.id not in config['owners']:
        await ctx.respond("You don't have permission to add a new owner.")
        return

    user_id = int(user_id)
    if user_id in config['owners']:
        await ctx.respond("This user is already an owner.")
    else:
        config['owners'].append(user_id)

        with open('config.yaml', 'w') as file:
            yaml.dump(config, file, Dumper=yaml.SafeDumper, sort_keys=False)

        await ctx.respond(f"User ID {user_id} has been added as an owner.")

@bot.slash_command(name="remove-owner", description="Remove an existing owner by their user ID.")
async def remove_owner(ctx, user_id: discord.Option(str, "Enter the user ID to remove from owners.", required=True)):
    try:
        user_id = int(user_id)
    except ValueError:
        await ctx.respond("Invalid user ID. Please ensure you provide a dev user ID.")
        return

    with open('config.yaml', 'r') as file:
        config = yaml.safe_load(file)

    if ctx.author.id not in config['owners']:
        await ctx.respond("You don't have permission to remove an owner.")
        return

    user_id = int(user_id)
    if user_id in config['owners']:
        config['owners'].remove(user_id)

        with open('config.yaml', 'w') as file:
            yaml.dump(config, file, Dumper=yaml.SafeDumper, sort_keys=False)

        await ctx.respond(f"User ID {user_id} has been removed from owners.")
    else:
        await ctx.respond("This user is not an owner.")




def get_invite(invite_):
    if "discord.gg" not in invite_:
        return invite_
    if "discord.gg" in invite_:
        invite = invite_.split("discord.gg/")[1]
        return invite
    if "https://discord.gg" in invite_:
        invite = invite_.split("https://discord.gg/")[1]
        return invite

app = Flask(__name__)

    
orders = []
@app.route("/sellix", methods=["GET", "POST"])
def sellix():
    data = request.json
    if data in orders:    
        pass
    elif data not in orders:
        threading.Thread(target=start_sellix, args=[data, ]).start()
        orders.append(data)
    return '{"status": "received"}', 200

debug = config_data['debug']

def start_sellix(data):
    try:
        if 'boosts' in data['data']['product_title'].lower():
            nick = ''
            invite_link = ''

            for i in data['data']['custom_fields']:
                if i == config_data['field_name_invite']:
                    invite_link = data['data']['custom_fields'][i]
                    if debug:
                        if invite_link:
                            Log.Debug(f"Found invite link: {invite_link}")
                        else:
                            Log.Warning("Invite link not found in custom fields")

            if data['data']['product_title'].replace(" ", "-").split("-")[0].isdigit():
                amount = int(data['data']['product_title'].replace(" ", "-").split("-")[0])
                if debug:
                    if amount:
                        Log.Debug(f"Amount {amount}")
                    else:
                        Log.Warning(f"Failed to get Amount")

            months = 3 if "3" in data['data']['product_title'].split("[")[1] else 1
            if debug:
                Log.Debug(f"Months {months}")
            
            invite = invite_link.replace("https://", "").replace("discord.gg/", "").replace("discord.com/invite/", "")
            
            if months == 1:
                booststype = "1 month boosts"
                filename = "input/1m_nitro.txt"
            elif months == 3:
                booststype = "3 months boosts"
                filename = "input/3m_nitro.txt"
            tokensStock = getStock(filename)
            requiredStock = int(amount / 2)
            
            if requiredStock > len(tokensStock):
                Log.Error(f"Not Enough Tokens To Complete order | required {requiredStock}") 
            tokens = []
            for x in range(requiredStock):
                tokens.append(tokensStock[x])
                remove(tokensStock[x], filename)
                
            order_id = data['data']['uniqid']
            if debug:
                Log.Debug(f"Order Id {order_id}")
            customer_email = data['data']['customer_email']
            if debug:
                Log.Debug(f"email : {customer_email}")
            product_name = data['data']['product_title']
            if debug:
                Log.Debug(f"Product name : {product_name}")

            if amount % 2 != 0:
                amount += 1
                
            embed = DiscordEmbed(title = "**New Automated Order**", description = f"**Product Name: **{product_name}\n**Order UnquieID: **{order_id}\n**Client Email: **{customer_email}\n\n**Invite Link: **https://discord.gg/{invite}\n**Amount: **{amount} Boosts\n**Months: **{months} Months", color = 0x31373d)
            embed.set_timestamp()
            shop_name = config_data['shop_name']
            embed.set_footer(text=f"© {shop_name} - All Rights Reserved.")
            webhook = DiscordWebhook(url=config_data["boost_webhook"])
            webhook.add_embed(embed)
            webhook.execute()
            invitecheck = checkInvite(invite)
            if invitecheck == False:
                return
            Log.Info(f"Boosting, guild{Fore.LIGHTBLACK_EX} https://discord.gg/{invite}{Fore.RESET}, amount {Fore.LIGHTBLACK_EX}{amount}{Fore.RESET}, months{Fore.LIGHTBLACK_EX} {months}M{Fore.RESET}, deliveryType {Fore.LIGHTBLACK_EX}Automated{Fore.RESET}")
            start = time.time()
            print()
            boost = Booster()
            status = boost.thread(invite, tokens, invitecheck)
            end = time.time()
            if change_nick:
                boost.nick_thread(tokens, invitecheck)
            if change_bio:
                boost.bio_thread(tokens)
            if change_banner:
                boost.banner_thread(tokens, invitecheck)
            if change_avatar:
                boost.avatar_thread(tokens, invitecheck)
            print()
            
            time_taken = round(end - start, 2)
            if failed !=0:
                
                embed2 = DiscordEmbed(title = "**Boosts Unsuccessful**", description = f"**Boost Type: **Automatic\n**Order ID: **{order_id}\n**Product Name: **{product_name}\n**Customer Email: **{customer_email}\n\n**Invite Link: **https://discord.gg/{invite}\n**Amount: **{amount} Boosts\n**Months: **{months} Months\n\n**Time Taken: **{time_taken} seconds\n**Successful Tokens: **{len(status['success'])}\n**Successful Boosts: **{len(status['success'])*2}\n\n**Failed Tokens: **{len(status['failed'])}\n**Failed Boosts: **{len(status['failed'])*2}", color = 0x31373d)
                embed2.set_timestamp()
                embed.set_footer(text=f"© {shop_name} - All Rights Reserved.")
                webhook = DiscordWebhook(url=config_data["boost_webhook"])
                webhook.add_embed(embed2)
                webhook.execute()
                
                Log.Info(f"Boosts Failed , guild{Fore.LIGHTBLACK_EX} https://discord.gg/{invite}{Fore.RESET}, amount {Fore.LIGHTBLACK_EX}{amount}{Fore.RESET}, months{Fore.LIGHTBLACK_EX} {months}M{Fore.RESET}, time taken {Fore.LIGHTBLACK_EX}{time_taken}{Fore.RESET}")
                print()
                
            else:
                embed3 = DiscordEmbed(title = "**Boosts Successfull**", description = f"**Boost Type: **Automatic\n**Order ID: **{order_id}\n**Product Name: **{product_name}\n**Customer Email: **{customer_email}\n\n**Invite Link: **https://discord.gg/{invite}\n**Amount: **{amount} Boosts\n**Months: **{months} Months\n\n**Time Taken: **{time_taken} seconds\n**Successful Tokens: **{len(status['success'])}\n**Successful Boosts: **{len(status['success'])*2}\n\n**Failed Tokens: **{len(status['failed'])}\n**Failed Boosts: **{len(status['failed'])*2}", color = 0x31373d)
                embed3.set_timestamp()
                embed.set_footer(text=f"© {shop_name} - All Rights Reserved.")
                webhook = DiscordWebhook(url=config_data["boost_webhook"])
                webhook.add_embed(embed3)
                webhook.execute()
                Log.Info(f"Boosted Successfull, guild{Fore.LIGHTBLACK_EX} https://discord.gg/{invite}{Fore.RESET}, amount {Fore.LIGHTBLACK_EX}{amount}{Fore.RESET}, months{Fore.LIGHTBLACK_EX} {months}M{Fore.RESET}, time taken {Fore.LIGHTBLACK_EX}{time_taken}{Fore.RESET}")
                print()
    except IndexError as e:
        Log.Error(f"IndexError in processing Sellix data: {e}")
    except Exception as e:
        Log.Error(f"Exception in Automated delivery() {e}")





def run():
    app.run(host="0.0.0.0", port="8080")
    
    
def keep_alive():
    t = Thread(target=run)
    t.start()
keep_alive()


bot.run(bot_token)

