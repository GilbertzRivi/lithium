import requests
import os
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

ONION = os.getenv("ONION")
PORT = os.getenv("TOR_PORT")
PREFIX = os.getenv("PREFIX")


# Adres .onion serwera FastAPI
onion_url = f"https://{ONION}:{PORT}/{PREFIX}/"

# Użyj proxy SOCKS5 Tora
proxies = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}

response = requests.get(onion_url, proxies=proxies, verify=False)
print(response.json())
