# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "fastapi",
#     "uvicorn",
# ]
# ///

import argparse
import ipaddress
import json
import os
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request
import colorama
from pathlib import Path
from typing import Generator

from fastapi import FastAPI, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, StreamingResponse

DEFAULT_CACHE_FILE = "ip_geo_cache.json"
RATE_LIMIT_DELAY = 1.35
_last_request_time = 0.0

app = FastAPI(title="Real-Time Traceroute Map")

# ---------------------------------------------------------
# Core Traceroute & Geolocation Logic
# ---------------------------------------------------------

def is_public_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_global
    except ValueError:
        return False


def load_cache(cache_file: str) -> dict:
    if os.path.exists(cache_file):
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def save_cache(cache: dict, cache_file: str) -> None:
    temp_file = f"{cache_file}.tmp"
    try:
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write("{\n")
            items = list(cache.items())
            for i, (key, val) in enumerate(items):
                # Dump key and value to ensure valid JSON escaping
                comma = "," if i < len(items) - 1 else ""
                f.write(f"  {json.dumps(key)}: {json.dumps(val)}{comma}\n")
            f.write("}\n")
        os.replace(temp_file, cache_file)
    except OSError:
        pass


def get_ip_geo(ip: str, cache: dict, cache_file: str | None = None) -> dict | None:
    global _last_request_time

    if not is_public_ip(ip):
        return None

    if ip in cache:
        print(colorama.Fore.GREEN, end="")
        print(f"Cache hit for {ip}")
        print(colorama.Fore.RESET, end="")
        return cache[ip]

    
    print(colorama.Fore.RED, end="")
    print(f"Cache miss for {ip}")
    print(colorama.Fore.RESET, end="")

    elapsed = time.time() - _last_request_time
    if elapsed < RATE_LIMIT_DELAY:
        time.sleep(RATE_LIMIT_DELAY - elapsed)

    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,lat,lon"
    geo_data = None

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "TracerouteGeo/2.0"})
        _last_request_time = time.time()
        with urllib.request.urlopen(req, timeout=3.0) as response:
            data = json.loads(response.read().decode("utf-8"))
            if data.get("status") == "success":
                geo_data = data
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        geo_data = None

    cache[ip] = geo_data
    if cache_file:
        save_cache(cache, cache_file)

    return geo_data


def get_my_public_geo(cache: dict, cache_file: str) -> dict | None:
    """Fetch local machine's public geolocation to plot as Hop 0 (Origin)."""
    if "_self_" in cache:
        return cache["_self_"]
    try:
        req = urllib.request.Request("http://ip-api.com/json/?fields=status,query,country,city,lat,lon", headers={"User-Agent": "TracerouteGeo/2.0"})
        with urllib.request.urlopen(req, timeout=3.0) as response:
            data = json.loads(response.read().decode("utf-8"))
            if data.get("status") == "success":
                cache["_self_"] = data
                save_cache(cache, cache_file)
                return data
    except Exception:
        return None


def get_ip_address(target: str) -> str:
    return socket.gethostbyname(target)


def ping_ttl(target_ip: str, ttl: int, timeout: float = 2.0) -> tuple[int, str, float | None]:
    cmd = ["ping", "-c", "1", "-t", str(ttl), "-W", str(timeout), target_ip]
    start_time = time.perf_counter()
    process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    output = process.stdout + process.stderr

    if process.returncode == 0:
        return ttl, target_ip, elapsed_ms

    ip_match = re.search(r"From\s+([^\s:]+)", output)
    if ip_match:
        return ttl, ip_match.group(1), elapsed_ms

    return ttl, "*", None


def traceroute_stream(target: str, max_hops: int = 30, timeout: float = 2.0) -> Generator[str, None, None]:
    """Yields SSE events formatted as JSON."""
    geo_cache = load_cache(DEFAULT_CACHE_FILE)

    try:
        target_ip = get_ip_address(target)
    except socket.gaierror as e:
        yield f"event: error\ndata: {json.dumps({'message': f'Resolution error: {e}'})}\n\n"
        return

    # Yield Hop 0 (Local Origin)
    origin_geo = get_my_public_geo(geo_cache, DEFAULT_CACHE_FILE)
    if origin_geo:
        yield f"data: {json.dumps({'ttl': 0, 'ip': origin_geo.get('query', 'Localhost'), 'host': 'Your Network (Origin)', 'rtt_ms': 0.0, 'lat': origin_geo.get('lat'), 'lon': origin_geo.get('lon'), 'city': origin_geo.get('city'), 'country': origin_geo.get('country'), 'is_public': True})}\n\n"

    ttl = 1
    dead_ends = 0
    while True:
        if 0 < max_hops < ttl:
            break

        if dead_ends > 4:
            break

        ttl_res, hop_ip, rtt = ping_ttl(target_ip, ttl, timeout)

        host = ""
        if hop_ip != "*":
            dead_ends = 0
            try:
                host = socket.gethostbyaddr(hop_ip)[0]
            except (socket.herror, socket.gaierror):
                pass
        else:
            dead_ends += 1

        geo = get_ip_geo(hop_ip, geo_cache, DEFAULT_CACHE_FILE)

        hop_data = {
            "ttl": ttl_res,
            "ip": hop_ip,
            "host": host,
            "rtt_ms": round(rtt, 2) if rtt is not None else None,
            "lat": geo.get("lat") if geo else None,
            "lon": geo.get("lon") if geo else None,
            "city": geo.get("city") if geo else None,
            "country": geo.get("country") if geo else None,
            "is_public": is_public_ip(hop_ip) if hop_ip != "*" else False,
        }

        yield f"data: {json.dumps(hop_data)}\n\n"

        if hop_ip == target_ip:
            break

        ttl += 1

    yield f"event: done\ndata: {json.dumps({'target': target_ip, 'hops': ttl})}\n\n"


static_dir = Path(__file__).parent / "static"
static_dir.mkdir(exist_ok=True)

app.mount("/static", StaticFiles(directory=static_dir), name="static")

# ---------------------------------------------------------
# Web Endpoints & UI
# ---------------------------------------------------------

@app.get("/api/trace")
def api_trace(target: str = Query(..., description="Target host or IP"), max_hops: int = 30):
    return StreamingResponse(
        traceroute_stream(target=target, max_hops=max_hops),
        media_type="text/event-stream"
    )


@app.get("/", response_class=HTMLResponse)
def index():
    with open("homepage.html", "r", encoding="UTF-8") as f:
        page_content = f.read()
    return page_content

if __name__ == "__main__":
    import uvicorn
    print("Starting Web Traceroute UI at http://localhost:8000 ...")
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)