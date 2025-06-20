#!/usr/bin/env python3
import os
import json
import uuid
import time
import socket
import logging
import threading
import geoip2.database
from dotenv import load_dotenv
from typing import Dict, Any
from functools import lru_cache
from socketserver import TCPServer, UDPServer, BaseRequestHandler
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from dnslib import (
    DNSRecord, DNSHeader, RR, QTYPE, RCODE,
    A, AAAA, CNAME, MX, NS, SOA, TXT, PTR,
    SRV, CAA, DNSKEY, DS, LOC, NAPTR, NSEC,
    RP, RRSIG, SSHFP, TLSA, EDNS0
)

DGC_DNS_TYPES = {
    "A": A, "AAAA": AAAA, "CNAME": CNAME, "MX": MX, "NS": NS, "SOA": SOA,
    "TXT": TXT, "PTR": PTR, "SRV": SRV, "CAA": CAA, "DNSKEY": DNSKEY, "DS": DS,
    "LOC": LOC, "NAPTR": NAPTR, "NSEC": NSEC, "RP": RP, "RRSIG": RRSIG,
    "SSHFP": SSHFP, "TLSA": TLSA
}

DGC_DNS_QTYPES = {
    "A": QTYPE.A, "AAAA": QTYPE.AAAA, "CNAME": QTYPE.CNAME, "MX": QTYPE.MX,
    "NS": QTYPE.NS, "SOA": QTYPE.SOA, "TXT": QTYPE.TXT, "PTR": QTYPE.PTR,
    "SRV": QTYPE.SRV, "CAA": QTYPE.CAA, "DNSKEY": QTYPE.DNSKEY, "DS": QTYPE.DS,
    "LOC": QTYPE.LOC, "NAPTR": QTYPE.NAPTR, "NSEC": QTYPE.NSEC, "RP": QTYPE.RP,
    "RRSIG": QTYPE.RRSIG, "SSHFP": QTYPE.SSHFP, "TLSA": QTYPE.TLSA
}

def _build_txt_rdata(text: str) -> TXT:
    raw = text.encode("utf-8")
    return TXT([chunk.decode("utf-8", errors="replace") for chunk in [raw[i:i + 255] for i in range(0, len(raw), 255)]])

def _is_record_match(qname: str, record_name: str, rtype: str) -> bool:
    q = qname.rstrip(".")
    r = record_name.rstrip(".")
    if rtype == "NS":
        return q == r or q.endswith("." + r)
    return q == r

def current_dgceanysec_base10():
    # DGC Epoch ANY Second
    # https://github.com/DiamondGotCat/DGC-Epoch/
    dgceanysec_base10 = int(time.time() - 946684800)
    return dgceanysec_base10

class DGC_DNS:
    def __init__(self, filepath: str):
        self.filepath = filepath
        if not os.path.exists(self.filepath):
            with open(self.filepath, "w", encoding="utf-8") as f:
                json.dump([], f)
        self.reload()

    def chFilePath(self, new: str):
        self.filepath = new
        self.reload()

    def reload(self):
        load_dotenv()
        self.SOA_SERIAL = current_dgceanysec_base10()
        self.DEFAULT_TTL = int(os.getenv("DEFAULT_TTL", "60"))
        self.GeoIP_USE = os.getenv("GeoIP_USE", "False").lower() == "true"
        self.GeoIP_Country_PATH = os.getenv("GeoIP_Country_PATH", "GeoLite2-Country.mmdb")
        self.GeoIP_SWITCHING = os.getenv("GeoIP_SWITCHING", "False").lower() == "true"
        self.SOA_EMAIL = os.getenv("SOA_EMAIL", "default@diamondgotcat.net")
        self.SOA_REFRESH = int(os.getenv("SOA_REFRESH", "3600"))
        self.SOA_RETRY = int(os.getenv("SOA_RETRY", "600"))
        self.SOA_EXPIRATION = int(os.getenv("SOA_EXPIRATION", "1209600"))
        self.SOA_MIN_TTL = int(os.getenv("SOA_MIN_TTL", "86400"))
        self.SOA_DNS_DOMAIN = os.getenv("SOA_DNS_DOMAIN", "ns1.diamondgotcat.net")

        with open(self.filepath, "r", encoding="utf-8") as f:
            self.filedata: list = json.load(f)

        script_dir = os.path.dirname(os.path.abspath(__file__))
        geoip_rule_path = os.path.join(script_dir, "geoip_rule.json")
        with open(geoip_rule_path, "r", encoding="utf-8") as f:
            self.geoip_rule: list = json.load(f)

    def isExist(self, rtype: str, name: str, exclude_id: str | None = None) -> bool:
        for record in self.filedata:
            if record["TYPE"] == rtype and record["NAME"] == name:
                if exclude_id is None or record["ID"] != exclude_id:
                    return True
        return False

    def append(self, data: Dict[str, Any]):
        rtype = data["TYPE"]
        if rtype not in DGC_DNS_TYPES:
            raise ValueError("Unsupported DNS record type.")

        if rtype == "TXT":
            if len(data["CONTENT"].encode("utf-8")) > 65535:
                raise ValueError("The total size of the TXT record must be less than 65535 bytes.")

        self.filedata.append(data)
        with open(self.filepath, "w", encoding="utf-8") as f:
            json.dump(self.filedata, f, ensure_ascii=False)
        self.reload()

    def remove(self, record_id: str):
        self.filedata = [r for r in self.filedata if r["ID"] != record_id]
        with open(self.filepath, "w", encoding="utf-8") as f:
            json.dump(self.filedata, f, ensure_ascii=False)
        self.reload()

    def edit(self, record_id: str, new: Dict[str, Any], force: bool = False):
        if "TYPE" in new and new["TYPE"] not in DGC_DNS_TYPES:
            raise ValueError("Unsupported DNS record type.")

        target = next((r for r in self.filedata if r["ID"] == record_id), None)
        if not target:
            raise ValueError("Record not found.")

        new_type = new.get("TYPE", target["TYPE"])
        new_name = new.get("NAME", target["NAME"])
        if self.isExist(new_type, new_name, exclude_id=record_id) and not force:
            raise ValueError("Duplicate record exists.")

        for k, v in new.items():
            target[k] = v

        with open(self.filepath, "w", encoding="utf-8") as f:
            json.dump(self.filedata, f, ensure_ascii=False)
        self.reload()

    def processGeoIP(self, ip):
        with geoip2.database.Reader(self.GeoIP_Country_PATH) as reader:
            try:
                response = reader.country(ip)
                name = response.country.name
                iso_code = response.country.iso_code
                return {"name": name, "iso_code": iso_code}
            except geoip2.errors.AddressNotFoundError:
                return {"name": "Unknown", "iso_code": "DEFAULT"}

    def genReply(self, data: bytes, client_address) -> DNSRecord:
        request = DNSRecord.parse(data)

        if not request.q:
            reply = DNSRecord(
                DNSHeader(id=request.header.id, qr=1, aa=1, ra=1)
            )
            reply.header.rcode = RCODE.FORMERR
            return reply

        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
            q=request.q
        )
        qname = str(request.q.qname)
        qtype = QTYPE.get(request.q.qtype, "A")

        if self.GeoIP_USE:
            GeoIP_Data = self.processGeoIP(client_address)
            logging.info(f"{qname} IN {qtype} (FROM {client_address} - {GeoIP_Data['name']} | {GeoIP_Data['iso_code']})")
        else:
            GeoIP_Data = {"name": "Unknown", "iso_code": "DEFAULT"}
            logging.info(f"{qname} IN {qtype} (FROM {client_address})")

        count = 0

        if not self.GeoIP_SWITCHING:

            for record in self.filedata:
                if not _is_record_match(qname, record["NAME"], record["TYPE"]):
                    continue

                rtype = record["TYPE"]

                if qtype != "ANY" and rtype != qtype:
                    continue

                ttl = record.get("TTL", self.DEFAULT_TTL)
                count += 1

                if rtype == "TXT":
                    rdata = _build_txt_rdata(record["CONTENT"])
                else:
                    rdata = DGC_DNS_TYPES[rtype](record["CONTENT"])

                reply.add_answer(
                    RR(record["NAME"], DGC_DNS_QTYPES[rtype], rdata=rdata, ttl=ttl)
                )

        reply.add_auth(
            RR(
                qname,
                QTYPE.SOA,
                rdata=SOA(self.SOA_DNS_DOMAIN.strip(), self.SOA_EMAIL.replace("@", ".") + ".", (self.SOA_SERIAL, self.SOA_REFRESH, self.SOA_RETRY, self.SOA_EXPIRATION, self.SOA_MIN_TTL)),
                ttl=self.DEFAULT_TTL
            )
        )

        if qtype == "SOA":
            count = 1

        if self.GeoIP_USE:
            count = 1
            forwarded = self._forward_query(data, GeoIP_Data["iso_code"])
            if forwarded:
                return DNSRecord.parse(forwarded)

            reply.header.rcode = RCODE.NXDOMAIN

        if count == 0:
            forwarded = self._forward_query(data)
            if forwarded:
                return DNSRecord.parse(forwarded)

            reply.header.rcode = RCODE.NXDOMAIN

        client_udp_len = 512
        have_opt = False
        ext_rcode = 0
        edns_ver = 0
        flag_bits = 0

        for ar in request.ar:
            if ar.rtype == QTYPE.OPT:
                have_opt = True
                client_udp_len = ar.rclass or 4096
                ttl = ar.ttl

                ext_rcode = (ttl >> 24) & 0xFF
                edns_ver  = (ttl >> 16) & 0xFF
                flag_bits = ttl & 0xFFFF
                break

        if have_opt:

            flag_names = []
            if flag_bits & 0x8000:
                flag_names.append("do")

            reply.add_ar(
                EDNS0(
                    udp_len=client_udp_len,
                    flags=" ".join(flag_names),
                    version=edns_ver,
                    ext_rcode=ext_rcode
                )
            )

        packed = reply.pack()
        if len(packed) > client_udp_len:
            reply.header.tc = 1
            reply.rr = []
            reply.auth = []
            reply.ar = [r for r in reply.ar if r.rtype == QTYPE.OPT]

        return reply

    @lru_cache(maxsize=1024)
    def _forward_query(self, data: bytes, location = "DEFAULT") -> bytes | None:
        fallback_servers = self.geoip_rule.get(location, self.geoip_rule.get("DEFAULT", ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"]))
        for server in fallback_servers:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(2.0)
                    s.sendto(data, (server, 53))
                    response, _ = s.recvfrom(4096)
                    return response
            except socket.timeout:
                logging.warning(f"Timeout querying fallback server {server}")
            except Exception as e:
                logging.error(f"Error querying fallback server {server}: {e}")
        return None

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://127.0.0.1"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

script_dir = os.path.dirname(os.path.abspath(__file__))
json_path = os.path.join(script_dir, "records.json")
log_path = os.path.join(script_dir, "dns.log")

logging.basicConfig(
    filename=log_path,
    level=logging.DEBUG,
    format="(%(asctime)s) [%(levelname)s] %(message)s"
)

console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("(%(asctime)s) [%(levelname)s] %(message)s"))
logging.getLogger().addHandler(console_handler)

dgc_dns = DGC_DNS(filepath=json_path)

class DNSHandler(BaseRequestHandler):
    def handle(self):
        try:
            data, sock = self.request
            reply = dgc_dns.genReply(data, self.client_address)
            sock.sendto(reply.pack(), self.client_address)
        except Exception as e:
            logging.exception(f"DNSHandler error: {e}")

def start_dns_tcp_server():
    server = TCPServer(("0.0.0.0", 53), DNSHandler)
    server.serve_forever()

def start_dns_udp_server():
    server = UDPServer(("0.0.0.0", 53), DNSHandler)
    server.serve_forever()

class RecordAppendRequest(BaseModel):
    content: Dict[str, Any]
    force: bool = False

class RecordEditRequest(BaseModel):
    content: Dict[str, Any]
    force: bool = False

class RecordRemoveRequest(BaseModel):
    content: Dict[str, str]

@app.get("/api/v1/status")
def api_status():
    return {"status": "ok", "content": "ok"}

@app.get("/api/v1/reload")
def api_reload():
    dgc_dns.reload()
    return {"status": "ok", "content": "reloaded"}

@app.get("/api/v1/records")
def api_records_get():
    return JSONResponse(content=dgc_dns.filedata)

@app.post("/api/v1/records/append")
def api_records_append(req: RecordAppendRequest):
    try:
        content = req.content
        force = req.force

        if not dgc_dns.isExist(content["TYPE"], content["NAME"]) or force:
            content["ID"] = str(uuid.uuid4())
            dgc_dns.append(content)
            return {"status": "ok", "content": content["ID"]}
        else:
            return {"status": "error", "content": "Exist record"}
    except Exception as e:
        logging.exception("append error")
        return {"status": "error", "content": str(e)}

@app.post("/api/v1/records/remove")
def api_records_remove(req: RecordRemoveRequest):
    try:
        record_id = req.content["id"]
        dgc_dns.remove(record_id)
        return {"status": "ok", "content": record_id}
    except Exception as e:
        logging.exception("remove error")
        return {"status": "error", "content": str(e)}

@app.post("/api/v1/records/edit")
def api_records_edit(req: RecordEditRequest):
    try:
        record_id = req.content["id"]
        new_data = req.content["new"]
        dgc_dns.edit(record_id, new_data, force=req.force)
        return {"status": "ok", "content": record_id}
    except Exception as e:
        logging.exception("edit error")
        return {"status": "error", "content": str(e)}

if __name__ == "__main__":
    import uvicorn
    dns_tcp_thread = threading.Thread(target=start_dns_tcp_server, daemon=True)
    dns_udp_thread = threading.Thread(target=start_dns_udp_server, daemon=True)
    dns_tcp_thread.start()
    dns_udp_thread.start()
    uvicorn.run(app, host="localhost", port=5380)
