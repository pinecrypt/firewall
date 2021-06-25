#!/usr/bin/env python
import asyncio
import os
import socket
import sys
import ipaddress
import pymongo
from motor.motor_asyncio import AsyncIOMotorClient

FQDN = socket.getfqdn()
DEBUG = os.getenv("DEBUG")
DISABLE_MASQUERADE = os.getenv("DISABLE_MASQUERADE")
MONGO_URI = os.getenv("MONGO_URI")
TCP_MSS_CLAMPING = int(os.getenv("TCP_MSS_CLAMPING", "1452"))
mongo_uri = pymongo.uri_parser.parse_uri(MONGO_URI)

ALLOW_MONGO_REPLICA_TRAFFIC = False

#IF more than one replicas in mongo url, enable mongo traffic between replcas in firewall
if len(mongo_uri["nodelist"]) > 1:
    ALLOW_MONGO_REPLICA_TRAFFIC = True


def generate_firewall_rules(disabled=False):
    default_policy = "REJECT" if DEBUG else "DROP"

    yield "*filter"
    yield ":INBOUND_BLOCKED - [0:0]"
    yield "-A INBOUND_BLOCKED -j %s -m comment --comment \"Default policy\"" % default_policy

    yield ":OUTBOUND_CLIENT - [0:0]"
    yield "-A OUTBOUND_CLIENT -m set ! --match-set ipset4-client-ingress dst -j SET --add-set ipset4-client-ingress dst"
    yield "-A OUTBOUND_CLIENT -j ACCEPT"

    yield ":INBOUND_CLIENT - [0:0]"
    yield "-A INBOUND_CLIENT -m set ! --match-set ipset4-client-ingress src -j SET --add-set ipset4-client-ingress src"
    yield "-A INBOUND_CLIENT -j ACCEPT"

    yield ":INPUT DROP [0:0]"
    yield "-A INPUT -i lo -j ACCEPT -m comment --comment \"Allow loopback\""
    yield "-A INPUT -p icmp -j ACCEPT -m comment --comment \"Allow ping\""
    yield "-A INPUT -p esp -j ACCEPT -m comment --comment \"Allow ESP traffic\""
    yield "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT -m comment --comment \"Allow returning packets\""
    yield "-A INPUT -p tcp --dport 22 -j ACCEPT -m comment --comment \"Allow SSH\""
    yield "-A INPUT -p udp --dport 53 -j ACCEPT -m comment --comment \"Allow GoreDNS over UDP\""
    yield "-A INPUT -p tcp --dport 53 -j ACCEPT -m comment --comment \"Allow GoreDNS over TCP\""
    yield "-A INPUT -p tcp --dport 80 -j ACCEPT -m comment --comment \"Allow insecure HTTP\""
    yield "-A INPUT -p tcp --dport 8443 -j ACCEPT -m comment --comment \"Allow mutually authenticated HTTPS\""

    if disabled:
        # 443 redirect handled in PREROUTING
        yield "-A INPUT -p udp --dport 1194 -j DROP -m comment --comment \"Drop OpenVPN UDP\""
        yield "-A INPUT -p udp --dport 500 -j DROP -m comment --comment \"Drop IPsec IKE\""
        yield "-A INPUT -p udp --dport 4500 -j DROP -m comment --comment \"Drop IPsec NAT traversal\""
    else:
        yield "-A INPUT -p tcp --dport 443 -j ACCEPT -m comment --comment \"Allow HTTPS / OpenVPN TCP\""
        yield "-A INPUT -p udp --dport 1194 -j ACCEPT -m comment --comment \"Allow OpenVPN UDP\""
        yield "-A INPUT -p udp --dport 500 -j ACCEPT -m comment --comment \"Allow IPsec IKE\""
        yield "-A INPUT -p udp --dport 4500 -j ACCEPT -m comment --comment \"Allow IPsec NAT traversal\""
    if ALLOW_MONGO_REPLICA_TRAFFIC:
        yield "-A INPUT -p tcp --dport 27017 -j ACCEPT -m set --match-set ipset4-mongo-replicas src -m comment --comment \"Allow MongoDB internode\""
    yield "-A INPUT -j INBOUND_BLOCKED"

    yield ":FORWARD DROP [0:0]"
    yield "-A FORWARD -i tun0 -j INBOUND_CLIENT -m comment --comment \"Inbound traffic from OpenVPN UDP clients\""
    yield "-A FORWARD -i tun1 -j INBOUND_CLIENT -m comment --comment \"Inbound traffic from OpenVPN TCP clients\""
    yield "-A FORWARD -m policy --dir in --pol ipsec  -j INBOUND_CLIENT -m comment --comment \"Inbound traffic from IPSec clients\""
    yield "-A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j OUTBOUND_CLIENT -m comment --comment \"Outbound traffic to clients\""
    yield "-A FORWARD -j %s -m comment --comment \"Default policy\"" % default_policy

    yield ":OUTPUT DROP [0:0]"
    yield "-A OUTPUT -j ACCEPT"
    yield "COMMIT"

    yield "*mangle"
    yield "-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN " \
        "-m tcpmss --mss %d:1536 -j TCPMSS --set-mss %d " \
        "-m comment --comment \"MSS clamping\"" % (TCP_MSS_CLAMPING+1, TCP_MSS_CLAMPING)
    yield "COMMIT"

    yield "*nat"
    yield ":PREROUTING ACCEPT [0:0]"
    if disabled:
        # Bypass OpenVPN when replica is disabled
        yield "-A PREROUTING -p tcp  --dport 443 -j REDIRECT --to-port 1443"
    yield ":INPUT ACCEPT [0:0]"
    yield ":OUTPUT ACCEPT [0:0]"
    yield ":POSTROUTING ACCEPT [0:0]"
    if not DISABLE_MASQUERADE:
        yield "-A POSTROUTING -j MASQUERADE"
    yield "COMMIT"


def apply_firewall_rules(**kwargs):
    with open("/tmp/rules4", "w") as fh:
        for line in generate_firewall_rules(**kwargs):
            fh.write(line)
            fh.write("\n")

    os.system("iptables-restore < /tmp/rules4")
    os.system("sed -e 's/ipset4/ipset6/g' -e 's/p icmp/p ipv6-icmp/g' /tmp/rules4 > /tmp/rules6")
    os.system("ip6tables-restore < /tmp/rules6")
    os.system("sysctl -w net.ipv6.conf.all.forwarding=1")
    os.system("sysctl -w net.ipv6.conf.default.forwarding=1")
    os.system("sysctl -w net.ipv4.ip_forward=1")


async def update_firewall_rules():
    print("Setting up firewall rules")
    if ALLOW_MONGO_REPLICA_TRAFFIC:
        # TODO: atomic update with `ipset restore`
        for replica in mongo_uri["nodelist"]:
            for fam, _, _, _, addrs in socket.getaddrinfo(replica[0], None):
                if fam == 10:
                    os.system("ipset add ipset6-mongo-replicas %s" % addrs[0])
                elif fam == 2:
                    os.system("ipset add ipset4-mongo-replicas %s" % addrs[0])

    os.system("ipset create -exist -quiet ipset4-client-ingress hash:ip timeout 3600 counters")
    os.system("ipset create -exist -quiet ipset6-client-ingress hash:ip family inet6 timeout 3600 counters")

    os.system("ipset create -exist -quiet ipset4-client-egress hash:ip timeout 3600 counters")
    os.system("ipset create -exist -quiet ipset6-client-egress hash:ip family inet6 timeout 3600 counters")

    os.system("ipset create -exist -quiet ipset4-mongo-replicas hash:ip")
    os.system("ipset create -exist -quiet ipset6-mongo-replicas hash:ip family inet6")

    db = AsyncIOMotorClient(MONGO_URI).get_default_database()

    q = {
        "common_name": FQDN,
        "status": "signed"
    }

    doc = await db.certidude_certificates.find_one(q)
    if not doc:
        print("Unable to lookup signed certificate for %s" % FQDN)
        sys.exit(1)

    apply_firewall_rules(disabled=doc["disabled"])

    flt = [{
        "$match": {
            "fullDocument.common_name": FQDN,
            "fullDocument.status": "signed",
            "$and": [{
                "updateDescription.updatedFields.disabled": {"$exists": True},
                "operationType": "update"
            }]
        }
    }]

    print("Waiting for updates...")
    async with db.certidude_certificates.watch(flt, full_document="updateLookup") as stream:
        async for event in stream:
            apply_firewall_rules(
                disabled=event["updateDescription"]["updatedFields"]["disabled"])


print("Starting main loop")
loop = asyncio.get_event_loop()
loop.run_until_complete(update_firewall_rules())
