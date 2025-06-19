| English | [日本語](README.ja.md) |

# DGC-DNS
A Practical and Lightweight Open-Source DNS Server

## About DGC-DNS
DGC-DNS is a practical and lightweight DNS server written in Python.

## Domain Resolution System
DGC-DNS includes the following two name resolution systems:

- **Local Resolution**: Responds using DNS records configured in DGC-DNS. If no matching record is found, it will try another resolution method before returning NXDOMAIN.
- **Resolution via Public DNS**: Automatically queries DNS servers on the internet, allowing resolution of domains that cannot be answered by local records.

  - You can use different public DNS servers by modifying the line `fallback_servers = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"]` in `main.py`.
  - When using public DNS resolution, the responses are automatically cached for faster responses to repeated requests. (You can disable this by removing `@lru_cache(maxsize=1024)` in `main.py`.)

### Location of DNS Records Used for Local Resolution
All DNS records are stored in `records.json` in the script directory and loaded as needed.
By using the DGC-DNS API described below, you can remotely reload, add, edit, or delete records and access various other features.

## DGC-DNS API
You can control DGC-DNS through its API.

### About Security
By default, it only responds to requests from itself (`localhost`).
This is one way to prevent external API access.
If you want to operate it from outside, stop using `localhost` and use a method such as passwords or API keys instead.

### Types of Operations
The following operations are available via the API:

- `GET /api/v1/status`: Endpoint to check if the server is running. If successful, it returns `{"status": "ok", "content": "ok"}`.
- `GET /api/v1/reload`: Reloads data from `records.json`. Use this after manual edits.
- `GET /api/v1/records`: Returns the contents of the currently loaded `records.json`.
- `POST /api/v1/records/append`: Adds a DNS record.
- `POST /api/v1/records/remove`: Removes a DNS record.
- `POST /api/v1/records/edit`: Edits a DNS record.

## Use Case
DGC-DNS is used by the developer (DiamondGotCat).
- `ns1.diamondgotcat.net` (under preparation): An alternative route to `35.208.247.170`.
- `35.208.247.170`: The DGC-DNS server that centrally manages the developer's domains.
  - Not yet configured with the registrar.

## License
This software is provided under the MIT License.

---
Copyright (c) 2025 DiamondGotCat
