import requests
import json
from rich.prompt import Prompt

BASE_URL = "http://localhost:5380/api/v1"

DGC_DNS_TYPE_KEYS = [
    "A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "PTR",
    "SRV", "CAA", "DNSKEY", "DS", "LOC", "NAPTR", "NSEC",
    "RP", "RRSIG", "SSHFP", "TLSA"
]

def print_help():
    print("""
Available commands:
  status                      - Check server status
  reload                      - Reload DNS records
  list                        - List all DNS records
  append                      - Add a new DNS record
  remove                      - Remove a DNS record by ID
  edit                        - Edit an existing DNS record
  help                        - Show this help message
  exit / quit                 - Exit the client
""")

def run_repl():
    print("DGC DNS API Client")
    print_help()

    while True:
        try:
            cmd = input("> ").strip().lower()

            if cmd in ("exit", "quit"):
                print("Goodbye.")
                break

            elif cmd == "status":
                res = requests.get(f"{BASE_URL}/status")
                print(res.json())

            elif cmd == "reload":
                res = requests.get(f"{BASE_URL}/reload")
                print(res.json())

            elif cmd.startswith("list"):
                _, *args = cmd.split()
                res = requests.get(f"{BASE_URL}/records")
                data = res.json()
                for record in data:
                    if args:
                        if not any(arg.upper() in (record["TYPE"], record["NAME"]) for arg in args):
                            continue
                    print(f"[{record['ID']}] ({record['TYPE']}) {record['NAME']} -> {record['CONTENT']} (TTL: {record['TTL']})")

            elif cmd == "append":
                print("Enter new DNS record fields:")
                rtype = Prompt.ask("TYPE", choices=DGC_DNS_TYPE_KEYS, default="A")
                name = Prompt.ask("NAME", default="diamondgotcat.net.")
                content = Prompt.ask("CONTENT", default="1.1.1.1")
                ttl = Prompt.ask("TTL", default="60")
                force = Prompt.ask("Force add if exists", choices=["y", "n"], default="y") == "y"

                record = {
                    "NAME": name,
                    "TYPE": rtype,
                    "CONTENT": content,
                }
                if ttl:
                    record["TTL"] = int(ttl)

                payload = {
                    "content": record,
                    "force": force
                }

                res = requests.post(f"{BASE_URL}/records/append", json=payload)
                print(res.json())

            elif cmd == "remove":
                rid = Prompt.ask("ID")
                payload = {"content": {"id": rid}}
                res = requests.post(f"{BASE_URL}/records/remove", json=payload)
                print(res.json())

            elif cmd == "edit":
                rid = Prompt.ask("ID")
                print("Enter updated fields (leave blank to skip):")
                new_type = Prompt.ask("TYPE", choices=DGC_DNS_TYPE_KEYS + [""], default="")
                new_name = Prompt.ask("NAME", default="")
                new_content = Prompt.ask("CONTENT", default="")
                new_ttl = Prompt.ask("TTL", default="")
                force = Prompt.ask("Force update if conflict", choices=["y", "n"], default="y") == "y"

                new_data = {}
                if new_name:
                    new_data["NAME"] = new_name
                if new_type:
                    new_data["TYPE"] = new_type
                if new_content:
                    new_data["CONTENT"] = new_content
                if new_ttl:
                    new_data["TTL"] = int(new_ttl)

                payload = {
                    "content": {
                        "id": rid,
                        "new": new_data
                    },
                    "force": force
                }

                res = requests.post(f"{BASE_URL}/records/edit", json=payload)
                print(res.json())

            elif cmd == "help":
                print_help()

            else:
                print("Unknown command. Type 'help' for options.")

        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    run_repl()
