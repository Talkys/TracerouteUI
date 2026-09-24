# Real-Time Traceroute Visualizer

A modern, web-based network diagnostic tool that visualizes the path your internet traffic takes in **real time**. Built on **FastAPI**, it streams hops directly to your browser as they are discovered using Server-Sent Events (SSE) and maps them on an interactive world map.

## Key Changes in v2.0 (Real-Time Web Edition)

* **Real-Time Streaming**: Live streaming of network hops via Server-Sent Events (SSE) as each ICMP probe returns.
* **Web-Based UI**: Replaced the desktop GUI (PyQt5/Matplotlib) with a responsive web interface.
* **FastAPI Engine**: Powered by an asynchronous Python backend running on Uvicorn.
* **Local Origin Detection**: Automatically resolves and plots your public IP/geolocation as Hop 0.
* **Smart Geolocation Caching**: Persistent JSON-based IP caching (`ip_geo_cache.json`) with automated rate limiting to comply with API limits.

## Features

* **Cross-Platform Backend**: Supports Linux, macOS, and Windows ping-based probing.
* **Real-Time Progress**: Dynamic live updates for hops, hostnames, RTT (Round Trip Time), and geographic locations.
* **Interactive Map**: Renders live connection lines and markers from your local network origin to the target destination.
* **Reverse DNS Resolution**: Automatically resolves hostnames for encountered IP addresses.

## Requirements

* Python **3.10+** (PEP 723 script metadata supported)
* [uv](https://github.com/astral-sh/uv?utm_source=gemini) (recommended) or standard Python `pip`

## Installation & Setup

### Option 1: Run via `uv` (Recommended)

If you have `uv` installed, dependencies (`fastapi`, `uvicorn`, `colorama`) will be managed automatically from the inline script metadata:

```bash
uv run traceroute_ui.py

```

### Option 2: Standard Pip Installation

1. Clone the repository:
```bash
git clone https://github.com/Talkys/TracerouteUI.git
cd TracerouteUI

```


2. Install dependencies:
```bash
pip install fastapi uvicorn colorama

```


3. Run the application:
```bash
python traceroute_ui.py

```


4. Open your browser and navigate to:
```
http://localhost:8000

```



## Usage

1. Enter a target domain name or IP address (e.g., `google.com` or `1.1.1.1`).
2. Set the maximum hop limit (default: 30).
3. Click **Start Trace**.
4. Watch hops populate in real time both in the status list and live on the interactive map.

## API Reference

The server exposes a Server-Sent Events endpoint for real-time integration:

```http
GET /api/trace?target={hostname_or_ip}&max_hops=30
Content-Type: text/event-stream

```

### Event Payload Examples

* **Origin / Hop Data (`data`)**:
```json
{
  "ttl": 1,
  "ip": "93.184.216.34",
  "host": "example.com",
  "rtt_ms": 14.25,
  "lat": 42.3601,
  "lon": -71.0589,
  "city": "Boston",
  "country": "United States",
  "is_public": true
}

```


* **Completion Event (`event: done`)**:
```json
{ "target": "93.184.216.34", "hops": 12 }

```


* **Error Event (`event: error`)**:
```json
{ "message": "Resolution error: [Errno -2] Name or service not known" }

```



## Technical Details

* **Backend**: FastAPI & Uvicorn ASGI server.
* **Streaming**: Python `Generator` yielding SSE frames over `StreamingResponse`.
* **Probing**: Low-level `subprocess` ping executions manipulating TTL values (`ping -t` / `ping -c`).
* **Geolocation**: Free tier integration with [ip-api.com](http://ip-api.com?utm_source=gemini) with request throttle control (1.35s delay between cache misses).

## Limitations & Considerations

* **Permissions**: Depending on your platform, custom TTL ping manipulation may require elevated administrative privileges (`sudo` on Linux/macOS or run as Administrator on Windows).
* **Private IPs**: Local network hops (192.168.x.x, 10.x.x.x) and non-responsive routers (`*`) cannot be mapped geographically.
* **Firewalls**: Some networks/routers drop ICMP time-exceeded packets, showing consecutive `*` timeouts.

## License

MIT License — see [LICENSE](https://www.google.com/search?q=LICENSE&utm_source=gemini) for details.