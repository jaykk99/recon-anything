"""Port auditor: ~1000-port sweep + banner/version grab + dangerous-exposure flags.

Connect-only, never exploits. Resolves the target's own IPs and scans
only those (never ranges). Two-phase design:

  Phase 1: fast TCP connect sweep of ~1000 ports (tier-1 high-signal
           ports first), high concurrency, short timeouts.
  Phase 2: service detection ONLY on open ports - banner grabs, version
           parsing (SSH/FTP/SMTP/MySQL/Postgres/VNC/HTTP/Elasticsearch),
           TLS handshake probing on ANY open port (catches HTTPS on
           non-standard ports), and basic OS fingerprinting from banners.

Danger flags:
  HIGH:   databases on the open internet (MySQL, MSSQL, Oracle, Postgres,
          MongoDB, Redis, Memcached, Elasticsearch, CouchDB, ArangoDB,
          Cassandra, Neo4j, InfluxDB), plaintext remote access (Telnet,
          RDP, VNC, ADB), Docker daemon, kubelet/etcd, AJP Ghostcat,
          Geth RPC, TR-069/Mirai targets, router backdoors, NetBus/Radmin
  MEDIUM: FTP/TFTP/SMB/NFS/SNMP/K8s-API as before, plus MQTT, Kafka,
          ActiveMQ/RabbitMQ mgmt, Bitcoin/Electrum/Monero RPC, ICS/SCADA
          ports, RTSP/cameras, AJP, Jenkins-agent, SMB, NFS
  LOW:    everything else open, informational

Default-credential risk notes are attached (flag-only, never brute-forced):
services notorious for shipping with default/weak/no auth get a
"default_cred_risk" note in the finding evidence.

Passive mode: no packets, reports resolved IPs + note. Active mode does
the real sweep. Hard deadline keeps the whole run under ~55s.
"""
from __future__ import annotations

import asyncio
import json
import re
import socket
import ssl
import struct
import time
from typing import Dict, List, Optional, Tuple

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# ---------------------------------------------------------------------------
# Port lists. Tier 1 = highest-signal ports, scanned first. Tier 2 = extended
# sweep. Ranges expanded at import. PORTS is the ordered, deduped full list.
# ---------------------------------------------------------------------------

PRIORITY_PORTS: List[Tuple[int, str]] = [
    # --- web / http-alt -------------------------------------------------
    (80, "HTTP"), (443, "HTTPS"), (8080, "HTTP-alt"), (8443, "HTTPS-alt"),
    (8000, "HTTP-alt"), (8001, "HTTP-alt"), (8008, "HTTP-alt"), (8010, "HTTP-alt"),
    (8081, "HTTP-alt"), (8088, "HTTP-alt"), (8090, "HTTP-alt"), (8888, "HTTP-alt"),
    (9000, "HTTP-alt"), (9080, "HTTP-alt"), (9090, "Prometheus/HTTP-alt"),
    (10000, "Webmin"), (3000, "Node/Grafana"), (3001, "Node dev"), (4000, "Dev"),
    (4001, "Dev"), (4100, "Dev"), (4200, "Angular dev"), (4567, "Dev"),
    (5000, "Flask/dev"), (5001, "Dev/IPFS"), (5173, "Vite dev"), (6006, "TensorBoard"),
    (7000, "Dev"), (7001, "Dev"), (8002, "HTTP-alt"), (8043, "HTTPS-alt"),
    (8228, "HTTP-alt"), (8280, "HTTP-alt"), (8300, "Consul"), (8403, "HTTPS-alt"),
    (8500, "Consul"), (8600, "HTTP-alt"), (8800, "HTTP-alt"), (8900, "HTTP-alt"),
    (8983, "Solr"), (9200, "Elasticsearch"), (9300, "ES-cluster"), (9443, "HTTPS-alt"),
    (9999, "HTTP-alt"), (10443, "HTTPS-alt"), (18080, "HTTP-alt"), (4443, "HTTPS-alt"),
    (1313, "Hugo dev"), (2368, "Ghost"), (8020, "HTTP-alt"), (8100, "HTTP-alt"),
    (8181, "HTTP-alt"), (8200, "HTTP-alt"), (8880, "HTTP-alt"), (5601, "Kibana"),
    (8082, "HTTP-alt"), (4848, "GlassFish"), (9091, "Transmission"),
    (3002, "Dev"), (5002, "Dev"), (7002, "Dev"), (81, "HTTP-alt"), (82, "HTTP-alt"),
    # --- databases ------------------------------------------------------
    (3306, "MySQL"), (33060, "MySQL-X"), (5432, "PostgreSQL"), (5433, "PostgreSQL"),
    (1433, "MSSQL"), (1434, "MSSQL-mon"), (1521, "Oracle"), (1522, "Oracle"),
    (27017, "MongoDB"), (27018, "Mongo-shard"), (27019, "Mongo-config"),
    (6379, "Redis"), (6380, "Redis"), (11211, "Memcached"), (5984, "CouchDB"),
    (8529, "ArangoDB"), (9042, "Cassandra"), (9160, "Cassandra-thrift"),
    (7199, "Cassandra-JMX"), (7473, "Neo4j-HTTPS"), (7474, "Neo4j-HTTP"),
    (7687, "Neo4j-Bolt"), (8086, "InfluxDB"), (8088, "InfluxDB-RPC"),
    (3050, "Firebird"), (1527, "Derby"), (26379, "Redis-sentinel"),
    # --- remote access --------------------------------------------------
    (22, "SSH"), (23, "Telnet"), (2323, "Telnet-alt"), (992, "TelnetS"),
    (3389, "RDP"), (5985, "WinRM"), (5986, "WinRM-SSL"), (5631, "pcAnywhere"),
    (5632, "pcAnywhere"), (2222, "SSH-alt"), (2022, "SSH-alt"), (513, "rlogin"),
    (512, "rexec"), (5555, "ADB"), (5037, "ADB-server"), (37215, "Huawei-HG532"),
    (52869, "Realtek"), (7547, "TR-069"), (4899, "Radmin"), (12345, "NetBus"),
    # --- mail -----------------------------------------------------------
    (25, "SMTP"), (110, "POP3"), (143, "IMAP"), (465, "SMTPS"),
    (587, "SMTP-sub"), (993, "IMAPS"), (995, "POP3S"), (119, "NNTP"),
    (563, "NNTPS"), (26, "SMTP-alt"), (2525, "SMTP-alt"),
    # --- file / storage -------------------------------------------------
    (21, "FTP"), (69, "TFTP"), (873, "rsync"), (2049, "NFS"), (111, "RPCbind"),
    (445, "SMB"), (139, "NetBIOS"), (135, "MSRPC"), (137, "NetBIOS-NS"),
    (138, "NetBIOS-DGM"), (548, "AFP"), (3260, "iSCSI"), (901, "Samba-SWAT"),
    # --- directory / auth ----------------------------------------------
    (389, "LDAP"), (636, "LDAPS"), (3268, "AD-GC"), (3269, "AD-GC-SSL"),
    (88, "Kerberos"), (464, "kpasswd"), (53, "DNS"), (853, "DNS-TLS"),
    (1812, "RADIUS"), (1813, "RADIUS-acct"),
    # --- devops / infra -------------------------------------------------
    (2375, "Docker"), (2376, "Docker-TLS"), (6443, "K8s-API"), (10250, "kubelet"),
    (10255, "kubelet-ro"), (2379, "etcd"), (2380, "etcd"), (8009, "AJP13"),
    (9418, "git"), (3690, "SVN"), (2082, "cPanel"), (2083, "cPanel-SSL"),
    (2086, "WHM"), (2087, "WHM-SSL"), (2095, "webmail"), (2096, "webmail-SSL"),
    (10257, "kube-controller"), (10259, "kube-scheduler"), (8472, "VXLAN"),
    (50000, "Jenkins-agent"), (8081, "Nexus"),
    # --- message queues -------------------------------------------------
    (5672, "RabbitMQ"), (5671, "RabbitMQ-TLS"), (15672, "RabbitMQ-mgmt"),
    (61613, "ActiveMQ-STOMP"), (61616, "ActiveMQ"), (8161, "ActiveMQ-admin"),
    (1883, "MQTT"), (8883, "MQTT-TLS"), (4222, "NATS"), (8222, "NATS-mon"),
    (9092, "Kafka"), (2181, "Zookeeper"), (4369, "EPMD"),
    # --- vpn ------------------------------------------------------------
    (1194, "OpenVPN"), (1723, "PPTP"), (1701, "L2TP"),
    # --- voip -----------------------------------------------------------
    (5060, "SIP"), (5061, "SIP-TLS"), (1720, "H.323"), (2000, "SCCP"),
    (2427, "MGCP"), (2727, "MGCP"), (2944, "Megaco"), (4569, "IAX2"),
    (3478, "STUN"), (5349, "TURN-TLS"),
    # --- games ----------------------------------------------------------
    (25565, "Minecraft"), (25575, "Minecraft-RCON"), (27015, "Steam"),
    (27016, "Steam"), (27005, "Steam"), (7777, "Game"), (28015, "Rust"),
    # --- iot / cameras --------------------------------------------------
    (554, "RTSP"), (8554, "RTSP-alt"), (37777, "Dahua"), (8899, "Cam"),
    (34567, "Dahua-alt"),
    # --- printers -------------------------------------------------------
    (9100, "JetDirect"), (515, "LPD"), (631, "IPP"), (161, "SNMP"),
    (162, "SNMP-trap"), (280, "http-mgmt"),
    # --- ics / scada ----------------------------------------------------
    (102, "Siemens-S7"), (502, "Modbus"), (20000, "DNP3"), (44818, "EtherNet/IP"),
    (47808, "BACnet"), (5007, "MELSEC"), (789, "RedLion"),
    # --- crypto ---------------------------------------------------------
    (8332, "Bitcoin-RPC"), (8333, "Bitcoin-P2P"), (18332, "BTC-test-RPC"),
    (18333, "BTC-test-P2P"), (50001, "Electrum"), (50002, "Electrum-TLS"),
    (18081, "Monero-RPC"), (18083, "Monero-P2P"), (8545, "Geth-RPC"),
    (8546, "Geth-WS"), (30303, "Ethereum-P2P"), (4001, "IPFS"),
    (26656, "Tendermint-P2P"), (26657, "Tendermint-RPC"),
]

EXTENDED_PORTS: List[Tuple[int, str]] = [
    # --- more http-alt --------------------------------------------------
    (83, "HTTP-alt"), (84, "HTTP-alt"), (85, "HTTP-alt"), (86, "HTTP-alt"),
    (87, "HTTP-alt"), (88, "Kerberos/HTTP"), (89, "HTTP-alt"), (90, "HTTP-alt"),
    (91, "HTTP-alt"), (92, "HTTP-alt"), (93, "HTTP-alt"), (95, "HTTP-alt"),
    (96, "HTTP-alt"), (97, "HTTP-alt"), (98, "HTTP-alt"), (99, "HTTP-alt"),
    (300, "HTTP-alt"), (308, "HTTP-alt"), (3128, "Squid"), (4444, "Metasploit/HTTP"),
    (7070, "HTTP-alt"), (7171, "HTTP-alt"), (8003, "HTTP-alt"), (8004, "HTTP-alt"),
    (8005, "HTTP-alt"), (8006, "HTTP-alt"), (8007, "HTTP-alt"), (8011, "HTTP-alt"),
    (8012, "HTTP-alt"), (8013, "HTTP-alt"), (8014, "HTTP-alt"), (8015, "HTTP-alt"),
    (8016, "HTTP-alt"), (8017, "HTTP-alt"), (8018, "HTTP-alt"), (8019, "HTTP-alt"),
    (8021, "HTTP-alt"), (8022, "HTTP-alt"), (8030, "HTTP-alt"), (8031, "HTTP-alt"),
    (8040, "HTTP-alt"), (8041, "HTTP-alt"), (8042, "HTTP-alt"), (8050, "HTTP-alt"),
    (8060, "HTTP-alt"), (8070, "HTTP-alt"), (8083, "HTTP-alt"), (8084, "HTTP-alt"),
    (8086, "HTTP-alt"), (8087, "HTTP-alt"), (8089, "HTTP-alt"), (8091, "HTTP-alt"),
    (8092, "HTTP-alt"), (8093, "HTTP-alt"), (8101, "HTTP-alt"), (8123, "HTTP-alt"),
    (8140, "Puppet"), (8180, "HTTP-alt"), (8182, "HTTP-alt"), (8243, "HTTPS-alt"),
    (8260, "HTTP-alt"), (8281, "HTTP-alt"), (8383, "HTTP-alt"), (8400, "HTTP-alt"),
    (8444, "HTTPS-alt"), (8445, "HTTPS-alt"), (8446, "HTTPS-alt"), (8447, "HTTPS-alt"),
    (8450, "HTTP-alt"), (8463, "HTTP-alt"), (8470, "HTTP-alt"), (8480, "HTTP-alt"),
    (8484, "HTTP-alt"), (8490, "HTTP-alt"), (8501, "HTTP-alt"), (8510, "HTTP-alt"),
    (8520, "HTTP-alt"), (8530, "HTTP-alt"), (8531, "HTTP-alt"), (8540, "HTTP-alt"),
    (8550, "HTTP-alt"), (8560, "HTTP-alt"), (8570, "HTTP-alt"), (8580, "HTTP-alt"),
    (8590, "HTTP-alt"), (8601, "HTTP-alt"), (8610, "HTTP-alt"), (8620, "HTTP-alt"),
    (8630, "HTTP-alt"), (8640, "HTTP-alt"), (8650, "HTTP-alt"), (8660, "HTTP-alt"),
    (8670, "HTTP-alt"), (8680, "HTTP-alt"), (8690, "HTTP-alt"), (8700, "HTTP-alt"),
    (8710, "HTTP-alt"), (8720, "HTTP-alt"), (8730, "HTTP-alt"), (8740, "HTTP-alt"),
    (8750, "HTTP-alt"), (8760, "HTTP-alt"), (8770, "HTTP-alt"), (8780, "HTTP-alt"),
    (8790, "HTTP-alt"), (8801, "HTTP-alt"), (8810, "HTTP-alt"), (8820, "HTTP-alt"),
    (8830, "HTTP-alt"), (8834, "HTTP-alt"), (8840, "HTTP-alt"), (8850, "HTTP-alt"),
    (8860, "HTTP-alt"), (8870, "HTTP-alt"), (8881, "HTTP-alt"), (8882, "HTTP-alt"),
    (8889, "HTTP-alt"), (8890, "HTTP-alt"), (8891, "HTTP-alt"), (8892, "HTTP-alt"),
    (8893, "HTTP-alt"), (8894, "HTTP-alt"), (8895, "HTTP-alt"), (8896, "HTTP-alt"),
    (8897, "HTTP-alt"), (8898, "HTTP-alt"), (8901, "HTTP-alt"), (8902, "HTTP-alt"),
    (8910, "HTTP-alt"), (8920, "HTTP-alt"), (8930, "HTTP-alt"), (8940, "HTTP-alt"),
    (8950, "HTTP-alt"), (8960, "HTTP-alt"), (8970, "HTTP-alt"), (8980, "HTTP-alt"),
    (8981, "HTTP-alt"), (8982, "HTTP-alt"), (8984, "HTTP-alt"), (8985, "HTTP-alt"),
    (8986, "HTTP-alt"), (8987, "HTTP-alt"), (8988, "HTTP-alt"), (8989, "HTTP-alt"),
    (8990, "HTTP-alt"), (8991, "HTTP-alt"), (9001, "HTTP-alt"), (9002, "HTTP-alt"),
    (9003, "HTTP-alt"), (9004, "HTTP-alt"), (9005, "HTTP-alt"), (9006, "HTTP-alt"),
    (9007, "HTTP-alt"), (9008, "HTTP-alt"), (9009, "HTTP-alt"), (9010, "HTTP-alt"),
    (9020, "HTTP-alt"), (9030, "HTTP-alt"), (9040, "HTTP-alt"), (9041, "HTTP-alt"),
    (9043, "HTTP-alt"), (9050, "HTTP-alt"), (9060, "HTTP-alt"), (9070, "HTTP-alt"),
    (9081, "HTTP-alt"), (9082, "HTTP-alt"), (9093, "HTTP-alt"), (9101, "HTTP-alt"),
    (9102, "HTTP-alt"), (9103, "HTTP-alt"), (9110, "HTTP-alt"), (9120, "HTTP-alt"),
    (9130, "HTTP-alt"), (9140, "HTTP-alt"), (9150, "HTTP-alt"), (9161, "HTTP-alt"),
    (9170, "HTTP-alt"), (9180, "HTTP-alt"), (9190, "HTTP-alt"), (9191, "HTTP-alt"),
    (9192, "HTTP-alt"), (9201, "HTTP-alt"), (9210, "HTTP-alt"), (9220, "HTTP-alt"),
    (9230, "HTTP-alt"), (9240, "HTTP-alt"), (9250, "HTTP-alt"), (9260, "HTTP-alt"),
    (9270, "HTTP-alt"), (9280, "HTTP-alt"), (9290, "HTTP-alt"), (9301, "HTTP-alt"),
    (9310, "HTTP-alt"), (9320, "HTTP-alt"), (9330, "HTTP-alt"), (9340, "HTTP-alt"),
    (9350, "HTTP-alt"), (9360, "HTTP-alt"), (9370, "HTTP-alt"), (9380, "HTTP-alt"),
    (9390, "HTTP-alt"), (9392, "OpenVAS"), (9393, "HTTP-alt"), (9400, "HTTP-alt"),
    (9410, "HTTP-alt"), (9420, "HTTP-alt"), (9430, "HTTP-alt"), (9444, "HTTPS-alt"),
    (9445, "HTTPS-alt"), (9450, "HTTP-alt"), (9460, "HTTP-alt"), (9470, "HTTP-alt"),
    (9480, "HTTP-alt"), (9490, "HTTP-alt"), (9500, "HTTP-alt"), (9510, "HTTP-alt"),
    (9520, "HTTP-alt"), (9530, "HTTP-alt"), (9540, "HTTP-alt"), (9550, "HTTP-alt"),
    (9560, "HTTP-alt"), (9570, "HTTP-alt"), (9580, "HTTP-alt"), (9590, "HTTP-alt"),
    (9601, "HTTP-alt"), (9610, "HTTP-alt"), (9620, "HTTP-alt"), (9630, "HTTP-alt"),
    (9640, "HTTP-alt"), (9650, "HTTP-alt"), (9660, "HTTP-alt"), (9670, "HTTP-alt"),
    (9680, "HTTP-alt"), (9690, "HTTP-alt"), (9700, "HTTP-alt"), (9710, "HTTP-alt"),
    (9720, "HTTP-alt"), (9730, "HTTP-alt"), (9740, "HTTP-alt"), (9750, "HTTP-alt"),
    (9760, "HTTP-alt"), (9770, "HTTP-alt"), (9780, "HTTP-alt"), (9790, "HTTP-alt"),
    (9800, "HTTP-alt"), (9810, "HTTP-alt"), (9820, "HTTP-alt"), (9830, "HTTP-alt"),
    (9840, "HTTP-alt"), (9850, "HTTP-alt"), (9860, "HTTP-alt"), (9870, "HTTP-alt"),
    (9871, "HTTP-alt"), (9876, "HTTP-alt"), (9880, "HTTP-alt"), (9890, "HTTP-alt"),
    (9900, "HTTP-alt"), (9910, "HTTP-alt"), (9920, "HTTP-alt"), (9930, "HTTP-alt"),
    (9940, "HTTP-alt"), (9950, "HTTP-alt"), (9960, "HTTP-alt"), (9970, "HTTP-alt"),
    (9980, "HTTP-alt"), (9981, "HTTP-alt"), (9982, "HTTP-alt"), (9983, "HTTP-alt"),
    (9987, "TeamSpeak"), (9988, "HTTP-alt"), (9990, "HTTP-alt"), (9991, "HTTP-alt"),
    (9992, "HTTP-alt"), (9993, "HTTP-alt"), (9994, "HTTP-alt"), (9995, "HTTP-alt"),
    (9996, "HTTP-alt"), (9997, "HTTP-alt"), (9998, "HTTP-alt"),
    # --- well-known 1-1023 misc ------------------------------------------
    (1, "tcpmux"), (3, "compressnet"), (4, "unknown"), (6, "unknown"),
    (7, "echo"), (9, "discard"), (13, "daytime"), (17, "qotd"),
    (19, "chargen"), (20, "FTP-data"), (30, "unknown"), (32, "unknown"),
    (33, "DSP"), (37, "time"), (42, "WINS"), (43, "whois"), (49, "TACACS"),
    (70, "gopher"), (79, "finger"), (100, "uucp"), (106, "POP3PW"),
    (109, "POP2"), (113, "ident"), (125, "locus-map"), (144, "news"),
    (146, "unknown"), (163, "cmip-man"), (199, "SMUX"), (211, "914c-g"),
    (212, "anet"), (254, "unknown"), (255, "unknown"), (256, "FW1"),
    (259, "ESRO"), (264, "BGMP"), (301, "unknown"), (306, "unknown"),
    (311, "Mac-admin"), (340, "unknown"), (366, "ODMR"), (369, "rpc2portmap"),
    (370, "codaauth2"), (371, "clearcase"), (372, "ulistproc"), (406, "IMSP"),
    (407, "timbuktu"), (416, "silverplatter"), (417, "onmux"), (425, "icad-el"),
    (427, "svrloc"), (444, "SNPP"), (458, "appleqtc"), (475, "tcpnethaspsrv"),
    (497, "retrospect"), (541, "uucp-rlogin"), (543, "klogin"), (544, "kshell"),
    (545, "ekshell"), (555, "dsf"), (593, "http-rpc-epmap"), (616, "gii"),
    (617, "giop"), (625, "apple-admin"), (646, "LDP"), (648, "RRP"),
    (666, "doom"), (667, "unknown"), (668, "unknown"), (683, "corba-iiop"),
    (687, "asf-rmcp"), (691, "resvc"), (700, "EPP"), (705, "agentx"),
    (711, "cisco-tdp"), (714, "iris-xpc"), (720, "unknown"), (721, "unknown"),
    (729, "netviewdm1"), (731, "netviewdm2"), (741, "netgw"), (742, "netrcs"),
    (744, "flexlm"), (747, "flexlm"), (748, "ris-cm"), (751, "kerberos-adm"),
    (752, "qrh"), (754, "teld"), (758, "nlogin"), (760, "krbupdate"),
    (765, "webster"), (767, "phonebook"), (769, "vid"), (772, "mprm"),
    (773, "unknown"), (774, "rpasswd"), (775, "entomb"), (776, "wpages"),
    (777, "multiling-http"), (778, "unknown"), (779, "unknown"), (780, "unknown"),
    (781, "hp-collector"), (782, "conductor"), (783, "spamassassin"),
    (784, "unknown"), (785, "unknown"), (786, "unknown"), (787, "unknown"),
    (788, "unknown"), (790, "unknown"), (791, "unknown"), (792, "unknown"),
    (793, "unknown"), (794, "unknown"), (795, "unknown"), (796, "unknown"),
    (797, "unknown"), (798, "unknown"), (799, "unknown"), (800, "mdbs_daemon"),
    (801, "device"), (802, "unknown"), (803, "unknown"), (804, "omr"),
    (805, "unknown"), (806, "unknown"), (807, "unknown"), (808, "unknown"),
    (809, "unknown"), (810, "fcp"), (811, "fcp"), (812, "fcp"), (813, "fcp"),
    (814, "fcp"), (815, "fcp"), (816, "fcp"), (817, "fcp"), (818, "fcp"),
    (819, "fcp"), (820, "fcp"), (821, "fcp"), (822, "fcp"), (823, "fcp"),
    (824, "fcp"), (825, "fcp"), (826, "fcp"), (827, "fcp"), (828, "fcp"),
    (829, "fcp"), (830, "netconf-ssh"), (831, "unknown"), (832, "unknown"),
    (833, "unknown"), (834, "unknown"), (835, "unknown"), (836, "unknown"),
    (837, "unknown"), (838, "unknown"), (839, "unknown"), (840, "unknown"),
    (841, "unknown"), (842, "unknown"), (843, "flash-policy"), (844, "unknown"),
    (845, "unknown"), (846, "unknown"), (847, "dhcp-failover2"), (848, "unknown"),
    (849, "unknown"), (850, "unknown"), (851, "unknown"), (852, "unknown"),
    (854, "unknown"), (855, "unknown"), (856, "unknown"), (857, "unknown"),
    (858, "unknown"), (859, "unknown"), (860, "iSCSI"), (861, "unknown"),
    (862, "unknown"), (863, "unknown"), (864, "unknown"), (865, "unknown"),
    (866, "unknown"), (867, "unknown"), (868, "unknown"), (869, "unknown"),
    (870, "unknown"), (871, "unknown"), (872, "unknown"), (874, "unknown"),
    (875, "unknown"), (876, "unknown"), (877, "unknown"), (878, "unknown"),
    (879, "unknown"), (880, "unknown"), (881, "unknown"), (882, "unknown"),
    (883, "unknown"), (884, "unknown"), (885, "unknown"), (886, "unknown"),
    (887, "unknown"), (888, "accessbuilder"), (889, "unknown"), (890, "unknown"),
    (891, "unknown"), (892, "unknown"), (893, "unknown"), (894, "unknown"),
    (895, "unknown"), (896, "unknown"), (897, "brocadecp"), (898, "unknown"),
    (899, "unknown"), (900, "omginitialrefs"), (902, "VMware"), (903, "unknown"),
    (904, "unknown"), (905, "unknown"), (906, "unknown"), (907, "unknown"),
    (908, "unknown"), (909, "unknown"), (910, "unknown"), (911, "xactly"),
    (912, "apex-mes"), (913, "unknown"), (914, "unknown"), (915, "unknown"),
    (916, "unknown"), (917, "unknown"), (918, "unknown"), (919, "unknown"),
    (920, "unknown"), (921, "unknown"), (922, "unknown"), (923, "unknown"),
    (924, "unknown"), (925, "unknown"), (926, "unknown"), (927, "unknown"),
    (928, "unknown"), (929, "unknown"), (930, "unknown"), (931, "unknown"),
    (932, "unknown"), (933, "unknown"), (934, "unknown"), (935, "unknown"),
    (936, "unknown"), (937, "unknown"), (938, "unknown"), (939, "unknown"),
    (940, "unknown"), (941, "unknown"), (942, "unknown"), (943, "unknown"),
    (944, "unknown"), (945, "unknown"), (946, "unknown"), (947, "unknown"),
    (948, "unknown"), (949, "unknown"), (950, "unknown"), (951, "unknown"),
    (952, "unknown"), (953, "unknown"), (954, "unknown"), (955, "unknown"),
    (956, "unknown"), (957, "unknown"), (958, "unknown"), (959, "unknown"),
    (960, "unknown"), (961, "unknown"), (962, "unknown"), (963, "unknown"),
    (964, "unknown"), (965, "unknown"), (966, "unknown"), (967, "unknown"),
    (968, "unknown"), (969, "unknown"), (970, "unknown"), (971, "unknown"),
    (972, "unknown"), (973, "unknown"), (974, "unknown"), (975, "unknown"),
    (976, "unknown"), (977, "unknown"), (978, "unknown"), (979, "unknown"),
    (980, "unknown"), (981, "unknown"), (982, "unknown"), (983, "unknown"),
    (984, "unknown"), (985, "unknown"), (986, "unknown"), (987, "unknown"),
    (988, "unknown"), (991, "NAS"), (994, "IRCS"), (996, "vsinet"),
    (997, "unknown"), (998, "unknown"), (999, "garcon"),
    # --- more databases / big data ---------------------------------------
    (27015, "Game/DB"), (28017, "Mongo-web"), (7574, "Oracle"),
    (2483, "Oracle-SSL"), (2484, "Oracle-SSL"), (1830, "Oracle"),
    (2099, "RMI-registry"), (1099, "RMI-registry"), (4505, "Salt-master"),
    (4506, "Salt-minion"), (6379, "Redis"), (6381, "Redis"),
    (11212, "Memcached"), (11213, "Memcached"), (27020, "Mongo"),
    (27021, "Mongo"), (17500, "Dropbox"), (3483, "Unifi"),
    (8080, "HTTP-alt"), (8443, "HTTPS-alt"),
    # --- more remote / admin --------------------------------------------
    (2223, "SSH-alt"), (2224, "SSH-alt"), (2200, "SSH-alt"), (2292, "SSH-alt"),
    (5800, "VNC-HTTP"), (5801, "VNC-HTTP"), (5902, "VNC"), (5903, "VNC"),
    (3388, "RDP-alt"), (3390, "RDP-alt"), (6000, "X11"), (6001, "X11"),
    (7070, "AnyDesk"), (7071, "AnyDesk"), (5500, "VNC-listener"),
    (16992, "AMT"), (16993, "AMT-TLS"), (16994, "AMT"), (16995, "AMT"),
    (623, "IPMI"), (664, "unknown"), (4911, "unknown"),
    # --- more mail -------------------------------------------------------
    (24, "priv-mail"), (1025, "SMTP-alt"), (2526, "SMTP-alt"),
    (158, "mail"), (220, "IMAP3"), (406, "IMSP"),
    # --- more devops -----------------------------------------------------
    (2377, "Docker-swarm"), (7946, "Docker-swarm"), (4789, "VXLAN"),
    (10248, "kubelet-healthz"), (10249, "kube-proxy-metrics"),
    (10256, "kube-proxy"), (9100, "node-exporter/JetDirect"),
    (9283, "etcd-metrics"), (2381, "etcd"), (4001, "Dev"),
    (2379, "etcd"), (2380, "etcd"), (6444, "K8s-alt"),
    (30000, "K8s-NodePort"), (30001, "K8s-NodePort"), (30002, "K8s-NodePort"),
    (31000, "K8s-NodePort"), (32000, "K8s-NodePort"),
    (32600, "K8s-NodePort"), (32700, "K8s-NodePort"),
    (8009, "AJP13"), (8010, "HTTP-alt"), (18080, "HTTP-alt"),
    (61617, "ActiveMQ"), (1884, "MQTT-alt"), (8884, "MQTT-alt"),
    # --- more crypto -----------------------------------------------------
    (8334, "Bitcoin-alt"), (9332, "Litecoin-RPC"), (9333, "Litecoin-P2P"),
    (19332, "LTC-test-RPC"), (19333, "LTC-test-P2P"), (22555, "Doge-RPC"),
    (22556, "Doge-P2P"), (7076, "Stellar"), (7077, "Stellar-alt"),
    (1313, "Hugo/Monero-alt"), (18089, "Monero-P2P"), (18080, "Monero-RPC-alt"),
    # --- more iot / misc -------------------------------------------------
    (81, "HTTP-alt"), (82, "HTTP-alt"), (8000, "HTTP-alt"),
    (32764, "router-backdoor"), (31337, "BackOrifice"), (1241, "Nessus"),
    (1243, "SubSeven"), (1999, "cisco-tcp"), (2001, "Cisco"),
    (6001, "X11"), (6666, "IRC"), (6667, "IRC"), (6697, "IRC-TLS"),
    (7000, "Dev"), (8080, "HTTP-alt"), (8888, "HTTP-alt"),
    (10080, "HTTP-alt"), (10081, "HTTP-alt"), (10082, "HTTP-alt"),
    (10443, "HTTPS-alt"), (18080, "HTTP-alt"), (20000, "DNP3"),
    (30005, "Game"), (30006, "Game"), (40000, "Game"),
    (6112, "Game"), (6113, "Game"), (3074, "Xbox"), (3075, "Xbox"),
    (3478, "STUN"), (3479, "STUN"), (3480, "STUN"),
    (5350, "TURN"), (5351, "TURN"), (5004, "RTP"), (5005, "RTP"),
    (19302, "STUN"), (19303, "STUN"),
]

# Port ranges for services that bind multiple sequential ports
PORT_RANGES: List[Tuple[int, int, str]] = [
    (5900, 5910, "VNC"),          # VNC displays :0-:10
    (5800, 5810, "VNC-HTTP"),     # VNC java/http listener
    (6000, 6010, "X11"),          # X11 displays
    (6660, 6669, "IRC"),          # IRC servers
    (27000, 27020, "Steam/game"), # Steam + game servers
    (28000, 28020, "Game"),       # game servers (Rust etc.)
    (50000, 50010, "Jenkins/misc"),
    (32768, 32775, "RPC-dynamic"),  # SunRPC dynamic
    (49152, 49160, "ephemeral-RPC"),
    (61000, 61005, "ephemeral"),
    (20001, 20005, "misc"),
]


def _build_port_list() -> List[Tuple[int, str]]:
    """Tier-1 first, then tier-2, then ranges. Deduped, order preserved."""
    seen = set()
    out: List[Tuple[int, str]] = []
    for port, label in PRIORITY_PORTS + EXTENDED_PORTS:
        if port not in seen:
            seen.add(port)
            out.append((port, label))
    for start, end, label in PORT_RANGES:
        for port in range(start, end + 1):
            if port not in seen:
                seen.add(port)
                out.append((port, f"{label}:{port}"))
    return out


PORTS: List[Tuple[int, str]] = _build_port_list()
_TIER1: set = {p for p, _ in PRIORITY_PORTS}

# Ports where a plain HTTP probe is worth trying
HTTP_LABEL_HINTS = ("http", "web", "admin", "api", "dev", "node", "flask",
                    "grafana", "kibana", "solr", "consul", "nexus", "jenkins",
                    "glassfish", "transmission", "webmin", "couchdb", "rabbitmq",
                    "activemq", "hugo", "ghost", "tensorboard", "vite", "angular",
                    "sonar", "openvas", "teamspeak")
TLS_PORTS = {443, 8443, 9443, 10443, 4443, 8444, 8043, 8403, 465, 993, 995,
             636, 3269, 989, 990, 992, 8883, 5671, 7473, 5349, 5061, 50002,
             16993, 636}

# port -> (risk, title, remediation, bounty_key)
DANGEROUS: Dict[int, Tuple[str, str, str, str]] = {
    3306: ("high", "MySQL exposed to the internet",
           "Bind MySQL to 127.0.0.1 or a private network, firewall port 3306, "
           "enforce strong credentials and TLS.", "db_exposed"),
    33060: ("high", "MySQL X Protocol exposed",
            "Firewall port 33060; same hardening as MySQL.", "db_exposed"),
    1433: ("high", "MSSQL exposed to the internet",
           "Firewall port 1433, restrict to app servers only, disable sa "
           "account, enforce strong passwords.", "db_exposed"),
    1521: ("high", "Oracle DB exposed to the internet",
           "Firewall port 1521, restrict to private network, review listener "
           "configuration and default accounts (SYS/SYSTEM).", "db_exposed"),
    5432: ("high", "PostgreSQL exposed to the internet",
           "Bind to localhost/private net, firewall port 5432, use strong "
           "passwords and scram-sha-256 auth.", "db_exposed"),
    27017: ("high", "MongoDB exposed to the internet",
            "Bind to 127.0.0.1, enable authentication, firewall port 27017. "
            "Open MongoDB instances are routinely ransomed.", "db_exposed"),
    27018: ("high", "MongoDB shard exposed to the internet",
            "Same as MongoDB: bind localhost, enable auth, firewall it.",
            "db_exposed"),
    27019: ("high", "MongoDB config server exposed",
            "Bind localhost, enable auth, firewall port 27019.", "db_exposed"),
    6379: ("high", "Redis exposed to the internet",
           "Bind to 127.0.0.1, set requirepass, firewall port 6379. Open "
           "Redis is a classic RCE vector.", "db_exposed"),
    6380: ("high", "Redis (alt port) exposed to the internet",
           "Same as Redis: bind localhost, requirepass, firewall.", "db_exposed"),
    11211: ("high", "Memcached exposed to the internet",
            "Bind to localhost, firewall port 11211. Open Memcached is "
            "abused for DDoS amplification and has no auth.", "db_exposed"),
    9200: ("high", "Elasticsearch exposed (often unauthenticated)",
           "Put behind authentication/reverse proxy, firewall port 9200, "
           "enable X-Pack security.", "db_exposed"),
    9300: ("high", "Elasticsearch cluster port exposed",
           "Firewall port 9300 - cluster join should never be internet "
           "reachable.", "db_exposed"),
    5984: ("high", "CouchDB exposed (default admin party mode)",
           "Set admin credentials, bind localhost, firewall port 5984. "
           "CouchDB ships with no auth by default.", "db_exposed"),
    8529: ("high", "ArangoDB exposed",
           "Set root password, bind localhost, firewall port 8529.",
           "db_exposed"),
    9042: ("high", "Cassandra CQL exposed",
           "Enable PasswordAuthenticator, firewall port 9042.", "db_exposed"),
    7474: ("high", "Neo4j HTTP exposed (default neo4j/neo4j)",
           "Change default credentials, bind localhost, firewall port 7474.",
           "db_exposed"),
    7687: ("medium", "Neo4j Bolt exposed",
           "Firewall port 7687, enforce authentication.", "db_exposed"),
    8086: ("medium", "InfluxDB exposed",
           "Enable auth, firewall port 8086.", "db_exposed"),
    3050: ("high", "Firebird DB exposed",
           "Firewall port 3050, change default SYSDBA password.", "db_exposed"),
    23: ("high", "Telnet open (plaintext remote access)",
         "Disable Telnet entirely. Use SSH with key auth instead.",
         "telnet_open"),
    2323: ("high", "Telnet on alt port (Mirai target)",
           "Disable Telnet. Port 2323 is a known Mirai botnet target.",
           "telnet_open"),
    3389: ("high", "RDP exposed to the internet",
           "Put RDP behind VPN, enable NLA + MFA, firewall port 3389. "
           "Exposed RDP is brute-forced constantly.", "rdp_exposed"),
    5900: ("high", "VNC exposed to the internet",
           "Put VNC behind VPN/SSH tunnel, enforce strong passwords. "
           "VNC auth is weak and brute-forced.", "vnc_exposed"),
    5901: ("high", "VNC (display :1) exposed to the internet",
           "Put VNC behind VPN/SSH tunnel, enforce strong passwords.",
           "vnc_exposed"),
    5800: ("medium", "VNC HTTP listener exposed",
           "Firewall it; VNC should never be internet-reachable.", "vnc_exposed"),
    4899: ("high", "Radmin exposed (weak auth, brute-forced)",
           "Firewall port 4899, enforce strong passwords.", "radmin_exposed"),
    12345: ("high", "NetBus trojan port open",
            "Investigate immediately - NetBus is remote-access malware. "
            "Firewall and audit the host.", "netbus"),
    5555: ("high", "Android Debug Bridge (ADB) exposed - no auth",
           "Firewall port 5555 immediately. Exposed ADB = full device "
           "control with zero authentication.", "adb_exposed"),
    5037: ("medium", "ADB server port exposed",
           "Firewall port 5037.", "adb_exposed"),
    7547: ("high", "TR-069 exposed (Mirai botnet target)",
           "Firewall port 7547, change ISP/router default credentials. "
           "Mirai actively exploits TR-069.", "mirai_target"),
    37215: ("high", "Huawei HG532 backdoor port (Mirai variant)",
            "Patch/remove the device, firewall port 37215.", "mirai_target"),
    52869: ("high", "Realtek SDK miniigd - critical RCE",
            "Patch the device firmware, firewall port 52869.", "mirai_target"),
    32764: ("high", "Router backdoor port (Sercomm)",
            "Replace/patch the router, firewall port 32764.", "router_backdoor"),
    31337: ("medium", "BackOrifice trojan port",
            "Investigate - historically a RAT port. Audit the host.",
            "netbus"),
    2375: ("high", "Docker daemon exposed (unauthenticated root)",
           "Firewall port 2375 immediately. An open Docker socket is "
           "instant root. Use TLS-protected 2376 only.", "docker_exposed"),
    2376: ("medium", "Docker TLS port exposed",
           "Restrict to trusted hosts, verify TLS client certs are enforced.",
           "docker_exposed"),
    10250: ("high", "kubelet API exposed",
            "Restrict kubelet to cluster network, enforce authentication/ "
            "authorization. Exposed kubelet = cluster takeover.", "k8s_api_exposed"),
    10255: ("medium", "kubelet read-only port exposed",
            "Firewall port 10255.", "k8s_api_exposed"),
    2379: ("high", "etcd exposed (cluster secrets readable)",
           "Firewall ports 2379/2380, enable client-cert auth. etcd holds "
           "all Kubernetes secrets.", "k8s_api_exposed"),
    2380: ("medium", "etcd peer port exposed",
           "Firewall port 2380.", "k8s_api_exposed"),
    6443: ("medium", "Kubernetes API exposed",
           "Restrict K8s API to trusted networks, enforce RBAC + strong "
           "auth. Internet-facing K8s APIs are attacked.", "k8s_api_exposed"),
    8009: ("high", "AJP13 exposed (Ghostcat RCE)",
           "Firewall port 8009 or set requiredSecret on the AJP connector. "
           "Ghostcat (CVE-2020-1938) allows file read/RCE on Tomcat.",
           "ajp_ghostcat"),
    21: ("medium", "FTP open - check for anonymous login",
         "Disable anonymous FTP, use SFTP instead, enforce strong "
         "credentials.", "ftp_open"),
    69: ("medium", "TFTP open (unauthenticated file transfer)",
         "Disable TFTP if unneeded; it has no authentication. Firewall "
         "port 69.", "tftp_open"),
    445: ("medium", "SMB exposed to the internet",
          "Firewall ports 445/139. SMB must never be internet-reachable "
          "(WannaCry/EternalBlue class risk).", "smb_exposed"),
    139: ("medium", "NetBIOS/SMB exposed to the internet",
          "Firewall ports 445/139. SMB must never be internet-reachable.",
          "smb_exposed"),
    111: ("medium", "RPCbind exposed (NFS indicator)",
          "Firewall port 111. NFS/RPC services must not be internet "
          "reachable.", "nfs_exposed"),
    2049: ("medium", "NFS exposed to the internet",
           "Firewall port 2049. NFS must never be internet-reachable; "
           "restrict to trusted hosts with proper exports.", "nfs_exposed"),
    161: ("medium", "SNMP open - check community strings",
          "Use SNMPv3 with auth, disable public/private community strings, "
          "firewall port 161.", "snmp_open"),
    1883: ("medium", "MQTT broker exposed (often anonymous)",
           "Require authentication on the broker, firewall port 1883.",
           "mqtt_open"),
    8883: ("medium", "MQTT-TLS broker exposed",
           "Require authentication, firewall port 8883.", "mqtt_open"),
    9092: ("medium", "Kafka exposed (often no auth)",
           "Enable SASL/SSL auth, firewall port 9092.", "kafka_open"),
    15672: ("medium", "RabbitMQ management exposed (default guest/guest)",
            "Change default credentials, firewall port 15672.", "mq_mgmt_open"),
    61616: ("medium", "ActiveMQ exposed (default admin/admin)",
            "Change default credentials, firewall port 61616.", "mq_mgmt_open"),
    8161: ("medium", "ActiveMQ admin console exposed",
           "Change default admin/admin, firewall port 8161.", "mq_mgmt_open"),
    4222: ("low", "NATS exposed", "Firewall port 4222 if not needed publicly.",
           "port_open"),
    8332: ("medium", "Bitcoin RPC exposed",
           "Ensure strong rpcuser/rpcpassword, bind localhost, firewall "
           "port 8332.", "btc_rpc_open"),
    50001: ("medium", "Electrum server exposed",
            "Firewall port 50001 if not a public server.", "port_open"),
    18081: ("medium", "Monero RPC exposed",
            "Bind localhost, firewall port 18081.", "port_open"),
    8545: ("high", "Geth/Ethereum JSON-RPC exposed (often no auth)",
           "Firewall port 8545 immediately. Open Geth RPC has been used to "
           "drain wallets.", "geth_rpc_exposed"),
    8546: ("high", "Geth WebSocket RPC exposed",
           "Firewall port 8546 immediately.", "geth_rpc_exposed"),
    25575: ("medium", "Minecraft RCON exposed (brute-forced)",
            "Use a strong RCON password, firewall port 25575.", "rcon_open"),
    102: ("medium", "Siemens S7 (ICS) exposed",
          "ICS protocols must never be internet-reachable. Firewall "
          "immediately and audit.", "ics_exposed"),
    502: ("medium", "Modbus (ICS) exposed",
          "ICS protocols must never be internet-reachable.", "ics_exposed"),
    20000: ("medium", "DNP3 (ICS) exposed",
            "ICS protocols must never be internet-reachable.", "ics_exposed"),
    44818: ("medium", "EtherNet/IP (ICS) exposed",
            "ICS protocols must never be internet-reachable.", "ics_exposed"),
    47808: ("medium", "BACnet (ICS) exposed",
            "ICS protocols must never be internet-reachable.", "ics_exposed"),
    554: ("medium", "RTSP camera stream exposed",
          "Change default camera credentials, firewall port 554.",
          "iot_default_creds"),
    8554: ("medium", "RTSP alt port exposed",
          "Change default credentials, firewall port 8554.", "iot_default_creds"),
    37777: ("high", "Dahua DVR port exposed (default admin/admin)",
            "Change default credentials immediately, firewall port 37777.",
            "iot_default_creds"),
    34567: ("medium", "DVR port exposed",
            "Change default credentials, firewall it.", "iot_default_creds"),
    1723: ("medium", "PPTP VPN (broken crypto)",
           "Migrate to WireGuard/OpenVPN. PPTP's MS-CHAPv2 is broken.",
           "port_open"),
    10000: ("medium", "Webmin exposed (default root creds)",
            "Enforce strong passwords + 2FA, restrict to trusted IPs.",
            "port_open"),
    9418: ("low", "git daemon exposed (unauthenticated clone)",
           "Firewall port 9418 if not intentionally public.", "port_open"),
    1434: ("low", "MSSQL monitor exposed",
           "Firewall port 1434.", "port_open"),
}


def _danger_for(port: int) -> Optional[Tuple[str, str, str, str]]:
    """Danger mapping with range rules for multi-port services."""
    hit = DANGEROUS.get(port)
    if hit:
        return hit
    if 5900 <= port <= 5910:
        return ("high", "VNC exposed to the internet",
                "Put VNC behind VPN/SSH tunnel, enforce strong passwords.",
                "vnc_exposed")
    if 5800 <= port <= 5810:
        return ("medium", "VNC HTTP listener exposed",
                "Firewall it; VNC should never be internet-reachable.",
                "vnc_exposed")
    if 6000 <= port <= 6010:
        return ("medium", "X11 exposed (check xauth)",
                "Firewall X11 ports, ensure xauth is enforced.", "port_open")
    if 6660 <= port <= 6669:
        return ("low", "IRC server open", "Firewall if not needed publicly.",
                "port_open")
    return None


# Services notorious for default/weak/no auth. Flag-only: we never attempt
# logins. Attached to findings as evidence["default_cred_risk"].
DEFAULT_CRED_RISK: Dict[int, str] = {
    21: "FTP servers commonly allow anonymous or weak creds - verify auth",
    23: "Telnet devices (routers/cameras) commonly ship admin/admin",
    2323: "Alt-telnet - Mirai brute-forces default IoT creds here",
    3389: "RDP is brute-forced constantly - enforce NLA + MFA",
    5900: "VNC passwords are weak by design - tunnel over SSH/VPN",
    5800: "VNC HTTP listener - same weak VNC auth",
    22: "SSH - prefer key auth, disable password auth if possible",
    2222: "Alt SSH - check for password auth and weak creds",
    2022: "Alt SSH - check for password auth and weak creds",
    3306: "MySQL root accounts commonly have weak/empty passwords",
    1433: "MSSQL sa account is a top brute-force target",
    1521: "Oracle ships default SYS/SYSTEM accounts - verify changed",
    5432: "Postgres 'postgres' superuser - verify strong password",
    27017: "MongoDB historically ships with NO auth enabled",
    6379: "Redis has NO auth by default (requirepass often unset)",
    9200: "Elasticsearch historically ships with no authentication",
    5984: "CouchDB 'admin party' mode = no auth by default",
    8529: "ArangoDB root password often left unset",
    7474: "Neo4j default is neo4j/neo4j - must be changed",
    7687: "Neo4j Bolt - verify auth is enforced",
    8086: "InfluxDB - verify auth is enabled",
    3050: "Firebird default SYSDBA/masterkey - must be changed",
    15672: "RabbitMQ management default guest/guest",
    61616: "ActiveMQ default admin/admin",
    8161: "ActiveMQ console default admin/admin",
    1883: "MQTT brokers commonly allow anonymous clients",
    554: "IP cameras/DVRs ship with default admin creds",
    8554: "IP cameras/DVRs ship with default admin creds",
    37777: "Dahua DVRs default admin/admin - change immediately",
    34567: "DVRs commonly ship with default creds",
    7547: "TR-069 - ISP routers with default creds, Mirai target",
    5555: "ADB has NO authentication when exposed",
    10000: "Webmin defaults to system/root creds - enforce 2FA",
    10250: "kubelet API - verify authentication mode is not anonymous",
    2375: "Docker socket - NO auth, instant root if reachable",
    161: "SNMP commonly uses public/private community strings",
    162: "SNMP traps - verify community strings",
    25575: "Minecraft RCON is brute-forced - use strong password",
    9418: "git daemon allows unauthenticated clones by design",
    11211: "Memcached has no auth - also a DDoS amplifier",
    8009: "AJP - verify requiredSecret is set (Ghostcat)",
    8080: "Management consoles (Jenkins etc.) often have default admin creds",
    8081: "Nexus default admin/admin123",
    9000: "SonarQube older versions had no auth by default",
    4848: "GlassFish default admin/admin",
    2082: "cPanel - enforce strong passwords + 2FA",
    2086: "WHM - enforce strong passwords + 2FA",
    8332: "Bitcoin RPC - verify strong rpcuser/rpcpassword",
    8545: "Geth RPC often exposed with no auth - wallet drain risk",
    50001: "Electrum - verify it is intended public",
    18081: "Monero RPC - bind localhost unless public",
    1434: "MSSQL monitor - information disclosure",
    69: "TFTP has no authentication at all",
    111: "RPCbind - enumerate NFS shares only from trusted nets",
    2049: "NFS - check exports for no_root_squash/world-readable",
    445: "SMB - disable SMBv1, enforce signing",
    139: "NetBIOS - disable if not needed",
    135: "MSRPC - patch DCOM/RPC vulnerabilities",
    873: "rsync - verify modules require auth",
    25: "SMTP - check for open relay",
    110: "POP3 - enforce TLS, strong passwords",
    143: "IMAP - enforce TLS, strong passwords",
    389: "LDAP - verify anonymous bind is disabled",
    636: "LDAPS - verify anonymous bind is disabled",
    1812: "RADIUS - verify strong shared secrets",
    5060: "SIP - check for unauthorized registration",
    119: "NNTP - often no auth",
    512: "rexec/rlogin - plaintext, disable",
    513: "rlogin - plaintext, disable",
    514: "rsh/syslog - plaintext, disable",
    5901: "VNC display :1 - same weak VNC auth",
    5902: "VNC display :2 - same weak VNC auth",
    5903: "VNC display :3 - same weak VNC auth",
}

DEFAULT_REMEDIATION = ("Close this port at the firewall/security group if the "
                       "service is not needed publicly. If it must be public, "
                       "keep it patched and restrict management access to "
                       "trusted IPs.")

# ---------------------------------------------------------------------------
# Service detection helpers
# ---------------------------------------------------------------------------

_OS_PATTERNS = [
    (re.compile(r"ubuntu", re.I), "Ubuntu Linux"),
    (re.compile(r"debian", re.I), "Debian Linux"),
    (re.compile(r"centos", re.I), "CentOS Linux"),
    (re.compile(r"red\s*hat|rhel", re.I), "Red Hat Linux"),
    (re.compile(r"fedora", re.I), "Fedora Linux"),
    (re.compile(r"alpine", re.I), "Alpine Linux"),
    (re.compile(r"arch", re.I), "Arch Linux"),
    (re.compile(r"freebsd", re.I), "FreeBSD"),
    (re.compile(r"openbsd", re.I), "OpenBSD"),
    (re.compile(r"netbsd", re.I), "NetBSD"),
    (re.compile(r"microsoft|iis|windows|win32|win64", re.I), "Windows"),
    (re.compile(r"synology", re.I), "Synology DSM"),
    (re.compile(r"qnap", re.I), "QNAP QTS"),
    (re.compile(r"dahua", re.I), "Dahua (embedded)"),
    (re.compile(r"hikvision", re.I), "Hikvision (embedded)"),
    (re.compile(r"mikrotik|routeros", re.I), "MikroTik RouterOS"),
    (re.compile(r"ubiquiti|unifi|edgemax", re.I), "Ubiquiti"),
    (re.compile(r"cisco", re.I), "Cisco IOS"),
    (re.compile(r"juniper", re.I), "Juniper JunOS"),
    (re.compile(r"openwrt", re.I), "OpenWrt"),
    (re.compile(r"android", re.I), "Android"),
    (re.compile(r"darwin|mac os|macos", re.I), "macOS"),
]


def _os_hint(text: str) -> str:
    """Basic OS guess from banner text. Low confidence by design."""
    for pat, name in _OS_PATTERNS:
        if pat.search(text or ""):
            return name
    return ""


_SSH_RE = re.compile(r"SSH-[\d.]+\-([^\s\r\n]+)")
_FTP_RE = re.compile(r"^220[ -]([^\r\n]{1,80})", re.M)
_SMTP_RE = re.compile(r"^220[ -]([^\r\n]{1,80})", re.M)


def _parse_ssh_version(banner: str) -> str:
    m = _SSH_RE.search(banner or "")
    return m.group(1).strip()[:60] if m else ""


def _parse_mysql_version(data: bytes) -> str:
    """Parse MySQL/MariaDB handshake for the server version string."""
    try:
        if len(data) < 6:
            return ""
        # packet: 3-byte len, 1-byte seq, 1-byte protocol, null-term version
        rest = data[5:]
        ver = rest.split(b"\x00", 1)[0].decode("latin1", "replace").strip()
        return ver[:40] if ver and len(ver) < 40 else ""
    except Exception:
        return ""


def _parse_vnc_version(banner: str) -> str:
    m = re.search(r"RFB\s+(\d{3})\.(\d{3})", banner or "")
    if m:
        return f"RFB {int(m.group(1))}.{int(m.group(2))}"
    return ""


def _parse_http_info(text: str) -> Tuple[str, str, str]:
    """Returns (server_header, powered_by, title)."""
    server = powered = title = ""
    for line in text.split("\r\n"):
        low = line.lower()
        if low.startswith("server:") and not server:
            server = line.split(":", 1)[1].strip()[:80]
        elif low.startswith("x-powered-by:") and not powered:
            powered = line.split(":", 1)[1].strip()[:80]
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:60]
    return server, powered, title


def _parse_es_version(text: str) -> str:
    """Elasticsearch GET / returns JSON with version.number."""
    try:
        body = text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in text else text
        data = json.loads(body.strip().split("\n")[0])
        ver = data.get("version", {}).get("number", "")
        return str(ver)[:20]
    except Exception:
        return ""


async def _read_some(reader: asyncio.StreamReader, n: int,
                     timeout: float) -> bytes:
    try:
        return await asyncio.wait_for(reader.read(n), timeout=timeout)
    except Exception:
        return b""


async def _tls_probe(ip: str, port: int, hostname: str,
                     timeout: float = 5.0) -> Optional[Dict[str, str]]:
    """Attempt a TLS handshake on any open port. Returns cert info or None."""
    def _do() -> Optional[Dict[str, str]]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # also allow legacy for banner purposes
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except Exception:
            pass
        raw = socket.create_connection((ip, port), timeout=timeout)
        try:
            ssock = ctx.wrap_socket(raw, server_hostname=hostname or ip)
            try:
                tls_version = ssock.version() or ""
                cipher = ssock.cipher()[0] if ssock.cipher() else ""
                # CERT_NONE leaves getpeercert() empty; parse the DER form.
                cn = issuer = not_after = ""
                sans: List[str] = []
                try:
                    der = ssock.getpeercert(binary_form=True)
                    if der:
                        from cryptography import x509 as _x509
                        cert = _x509.load_der_x509_certificate(der)
                        try:
                            cn = cert.subject.get_attributes_for_oid(
                                _x509.NameOID.COMMON_NAME)[0].value
                        except Exception:
                            pass
                        try:
                            issuer = cert.issuer.get_attributes_for_oid(
                                _x509.NameOID.ORGANIZATION_NAME)[0].value
                        except Exception:
                            try:
                                issuer = cert.issuer.get_attributes_for_oid(
                                    _x509.NameOID.COMMON_NAME)[0].value
                            except Exception:
                                pass
                        not_after = cert.not_valid_after_utc.strftime(
                            "%b %d %H:%M:%S %Y %Z")
                        try:
                            ext = cert.extensions.get_extension_for_oid(
                                _x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                            sans = [v for v in ext.value.get_values_for_type(
                                _x509.DNSName)][:5]
                        except Exception:
                            pass
                except Exception:
                    pass
                info = {
                    "tls_version": tls_version,
                    "cipher": cipher,
                    "cn": str(cn)[:80],
                    "issuer": str(issuer)[:80],
                    "not_after": str(not_after),
                    "sans": ",".join(sans),
                }
            finally:
                try:
                    ssock.close()
                except Exception:
                    pass
            return info
        except Exception:
            try:
                raw.close()
            except Exception:
                pass
            return None

    try:
        return await asyncio.wait_for(asyncio.to_thread(_do), timeout=timeout + 2)
    except Exception:
        return None


async def _service_detect(ip: str, port: int, label: str, hostname: str,
                          timeout: float = 4.0) -> Dict[str, str]:
    """Connect and identify the service/version. Returns info dict."""
    info: Dict[str, str] = {"port": str(port), "service": label, "banner": "",
                            "version": "", "os_hint": "", "via": "banner"}
    low_label = label.lower()
    is_http = ("http" in low_label or port in {80, 8080, 8000, 8888, 9000,
               9080, 9090, 10000, 3000, 5000, 5601, 8983, 9200, 8300, 8500,
               4848, 9091, 2368} or "webmin" in low_label or "api" in low_label
               or "dev" in low_label or "admin" in low_label or "grafana" in low_label
               or "kibana" in low_label or "solr" in low_label or "consul" in low_label)

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout)
    except Exception:
        return info

    raw_banner = b""
    try:
        if is_http or port in TLS_PORTS:
            scheme_tls = port in TLS_PORTS
            if not scheme_tls:
                req = (f"GET / HTTP/1.0\r\nHost: {hostname or ip}\r\n"
                       f"User-Agent: ReconAnything/1.0\r\n\r\n")
                writer.write(req.encode())
                await writer.drain()
                data = await _read_some(reader, 4096, 3.0)
                text = data.decode("utf-8", "replace")
                looks_tls = text.startswith("\x15") or text.startswith("\x16")
                empty_https = (not text.strip() and
                               ("https" in low_label or "tls" in low_label))
                if looks_tls or empty_https:
                    # server spoke TLS (or nothing) to a plain probe - TLS retry
                    info["via"] = "tls-fallback"
                else:
                    server, powered, title = _parse_http_info(text)
                    banner = f"HTTP {server}".strip()
                    if powered:
                        banner += f" [{powered}]"
                    if title:
                        banner += f" | {title}"
                    info["banner"] = banner[:200]
                    info["version"] = server or powered
                    if port == 9200 or "elasticsearch" in low_label:
                        esv = _parse_es_version(text)
                        if esv:
                            info["version"] = f"Elasticsearch {esv}"
                    info["os_hint"] = _os_hint(server + " " + powered)
                    writer.close()
                    return info
            # TLS path (explicit TLS port, or plain probe got TLS bytes)
            writer.close()
            tls = await _tls_probe(ip, port, hostname, timeout)
            if tls:
                info["via"] = "tls"
                info["tls"] = (f"{tls['tls_version']} {tls['cipher']} "
                               f"CN={tls['cn']} issuer={tls['issuer']} "
                               f"exp={tls['not_after']}")
                info["banner"] = f"TLS {tls['tls_version']} CN={tls['cn']}"[:200]
                info["version"] = tls["tls_version"]
                # try HTTPS GET over TLS for server header
                https_info = await _https_get(ip, port, hostname, timeout)
                if https_info:
                    srv, powered, title = _parse_http_info(https_info)
                    b = f"HTTPS {srv}".strip()
                    if powered:
                        b += f" [{powered}]"
                    if title:
                        b += f" | {title}"
                    info["banner"] = b[:200] if b != "HTTPS" else https_info[:120]
                    if srv:
                        info["version"] = srv
                    oh = _os_hint(srv + " " + powered)
                    if oh:
                        info["os_hint"] = oh
            return info

        # --- non-HTTP services: read volunteered banner -------------------
        raw_banner = await _read_some(reader, 1024, 2.5)
        text = raw_banner.decode("utf-8", "replace").strip()
        text = re.sub(r"\s+", " ", text)[:200]

        if raw_banner[:2] == b"\x16\x03":
            # service speaks TLS on a non-standard port
            writer.close()
            tls = await _tls_probe(ip, port, hostname, timeout)
            if tls:
                info["via"] = "tls-detected"
                info["tls"] = (f"{tls['tls_version']} {tls['cipher']} "
                               f"CN={tls['cn']} issuer={tls['issuer']}")
                info["banner"] = f"TLS {tls['tls_version']} CN={tls['cn']}"[:200]
                info["version"] = tls["tls_version"]
            return info

        if port == 3306 or "mysql" in low_label:
            ver = _parse_mysql_version(raw_banner)
            info["banner"] = text or "MySQL handshake"
            info["version"] = f"MySQL {ver}" if ver else "MySQL (version needs auth)"
        elif port == 5432 or "postgres" in low_label:
            pg = await _postgres_check(ip, port, timeout)
            info["banner"] = text or pg or "PostgreSQL"
            info["version"] = pg or "PostgreSQL (version needs auth)"
        elif 5900 <= port <= 5910 or "vnc" in low_label:
            ver = _parse_vnc_version(text)
            info["banner"] = text or "VNC"
            info["version"] = ver or "VNC"
        elif "ssh" in low_label:
            ver = _parse_ssh_version(text)
            info["banner"] = text
            info["version"] = ver
            info["os_hint"] = _os_hint(text)
        elif "ftp" in low_label:
            m = _FTP_RE.search(text)
            info["banner"] = m.group(1)[:120] if m else text
            info["version"] = info["banner"]
            info["os_hint"] = _os_hint(text)
        elif "smtp" in low_label or port in (25, 587, 465, 2525):
            m = _SMTP_RE.search(text)
            info["banner"] = m.group(1)[:120] if m else text
            info["version"] = info["banner"]
            info["os_hint"] = _os_hint(text)
        elif "telnet" in low_label:
            info["banner"] = text
            info["os_hint"] = _os_hint(text)
        elif "redis" in low_label:
            info["banner"] = "Redis (no banner - verify requirepass)"
            info["version"] = "Redis (version needs INFO/auth)"
        elif "mongo" in low_label:
            info["banner"] = "MongoDB (binary protocol - verify auth)"
            info["version"] = "MongoDB (version needs auth)"
        elif "rdp" in low_label:
            info["banner"] = "RDP (binary protocol)"
        elif "smb" in low_label or "netbios" in low_label or "msrpc" in low_label:
            info["banner"] = "SMB/NetBIOS (binary protocol)"
            info["os_hint"] = "Windows" if port in (135, 139, 445) else ""
        else:
            info["banner"] = text
            info["os_hint"] = _os_hint(text)
        writer.close()
    except Exception:
        try:
            writer.close()
        except Exception:
            pass
    return info


async def _https_get(ip: str, port: int, hostname: str,
                     timeout: float = 4.0) -> str:
    """GET / over TLS on a non-standard port. Returns raw header text."""
    def _do() -> str:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((ip, port), timeout=timeout)
        try:
            ssock = ctx.wrap_socket(raw, server_hostname=hostname or ip)
            try:
                ssock.settimeout(timeout)
                req = (f"GET / HTTP/1.0\r\nHost: {hostname or ip}\r\n"
                       f"User-Agent: ReconAnything/1.0\r\n\r\n")
                ssock.sendall(req.encode())
                data = b""
                try:
                    while len(data) < 4096:
                        chunk = ssock.recv(1024)
                        if not chunk:
                            break
                        data += chunk
                except Exception:
                    pass
                return data.decode("utf-8", "replace")
            finally:
                try:
                    ssock.close()
                except Exception:
                    pass
        except Exception:
            try:
                raw.close()
            except Exception:
                pass
            return ""

    try:
        return await asyncio.wait_for(asyncio.to_thread(_do), timeout=timeout + 2)
    except Exception:
        return ""


async def _postgres_check(ip: str, port: int, timeout: float = 4.0) -> str:
    """Send a Postgres SSLRequest. 'S' back = confirmed PostgreSQL."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout)
        try:
            # SSLRequest: Int32(8), Int32(80877103)
            writer.write(struct.pack("!II", 8, 80877103))
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(1), timeout=3)
            if resp == b"S":
                return "PostgreSQL (SSL accepted - version needs auth)"
            if resp == b"N":
                return "PostgreSQL (no SSL - version needs auth)"
            return "PostgreSQL (version needs auth)"
        finally:
            try:
                writer.close()
            except Exception:
                pass
    except Exception:
        return ""


async def _ftp_anonymous_ok(host: str, timeout: float = 5.0) -> Optional[bool]:
    """Check if FTP allows anonymous login. Connect-only, no file access."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, 21), timeout=timeout)

        async def _readline() -> str:
            line = await asyncio.wait_for(reader.readline(), timeout=3)
            return line.decode("utf-8", "replace").strip()

        await _readline()  # banner
        writer.write(b"USER anonymous\r\n")
        await writer.drain()
        resp = await _readline()
        if resp.startswith("331"):
            writer.write(b"PASS recon@anythi.ng\r\n")
            await writer.drain()
            resp2 = await _readline()
            writer.close()
            return resp2.startswith("230")
        writer.close()
        return False
    except Exception:
        return None

class PortAuditPlugin(Plugin):
    id = "port_audit"
    label = "Port Auditor"
    accepts = ["domain", "url", "ip"]
    passive = False
    cost = Cost.FREE
    group = "network"
    description = ("~1000-port sweep with banner/version grabs, OS hints, "
                   "TLS-on-any-port detection, and dangerous-exposure flags "
                   "(databases, RDP/VNC/Telnet/ADB, Docker, K8s, ICS, crypto).")
    timeout_s = 55

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain and target.type != "ip":
            return self._skipped("no host for this target type")
        host = domain or target.normalized
        sni_host = domain or ""
        findings: List[Finding] = []
        mode = self.module_mode(ctx)

        # -- resolve target's own IPs (scan these only, never ranges) -------
        ips: List[str] = []
        try:
            infos = await asyncio.get_event_loop().getaddrinfo(
                host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
            seen = set()
            for info in infos:
                ip = info[4][0]
                if ip.startswith(("127.", "::1", "fe80:")):
                    continue
                if ip not in seen:
                    seen.add(ip)
                    ips.append(ip)
            ips = ips[:4]
        except Exception:
            pass
        if not ips:
            ips = [host]

        if mode == "passive":
            if ips != [host]:
                findings.append(self._f(
                    "infra", "target_ips",
                    f"Target resolves to: {', '.join(ips)} - run in active "
                    f"mode for the full port audit",
                    source="DNS", confidence=95, passive=True))
            dur = int((time.monotonic() - t0) * 1000)
            res = self._ok(findings, "passive: port audit needs active mode")
            res.duration_ms = dur
            return res

        deadline = t0 + 50  # hard ceiling: whole sweep finishes < 60s

        # -- phase 1: fast connect sweep, tier-1 first, high concurrency ---
        tier1 = [(p, l) for p, l in PORTS if p in _TIER1]
        tier2 = [(p, l) for p, l in PORTS if p not in _TIER1]
        sem = asyncio.Semaphore(250)

        async def _probe(ip: str, port: int) -> Optional[Tuple[str, int]]:
            if time.monotonic() > deadline:
                return None
            async with sem:
                if time.monotonic() > deadline:
                    return None
                try:
                    r, w = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=1.2)
                    try:
                        w.close()
                    except Exception:
                        pass
                    return (ip, port)
                except Exception:
                    return None

        opens: List[Tuple[str, int]] = []
        for wave in (tier1, tier2):
            if time.monotonic() > deadline:
                break
            results = await asyncio.gather(*[
                _probe(ip, port) for ip in ips for port, _ in wave
            ])
            opens.extend([r for r in results if r])

        label_by_port = {p: l for p, l in PORTS}

        # -- phase 2: service detection only on open ports ------------------
        sem2 = asyncio.Semaphore(30)

        async def _detect(ip: str, port: int) -> Optional[Dict[str, str]]:
            if time.monotonic() > deadline:
                return None
            async with sem2:
                if time.monotonic() > deadline:
                    return None
                d = await _service_detect(ip, port, label_by_port.get(port, "?"),
                                          sni_host or ip, timeout=3.5)
                d["ip"] = ip
                return d

        detected = await asyncio.gather(*[_detect(ip, p) for ip, p in opens])
        detected = [d for d in detected if d]

        # -- build findings --------------------------------------------------
        os_guesses: Dict[str, str] = {}
        tls_ports: List[str] = []
        n_high = n_med = 0

        for d in detected:
            ip, port = d["ip"], int(d["port"])
            service, banner = d["service"], d["banner"]
            version, os_hint = d.get("version", ""), d.get("os_hint", "")
            tls_info = d.get("tls", "")
            danger = _danger_for(port)
            cred_risk = DEFAULT_CRED_RISK.get(port, "")
            if os_hint and ip not in os_guesses:
                os_guesses[ip] = os_hint
            if tls_info and port not in TLS_PORTS:
                tls_ports.append(f"{ip}:{port} ({tls_info[:80]})")

            detail = banner or service
            if version and version not in detail:
                detail += f" [{version}]"
            if os_hint:
                detail += f" (OS hint: {os_hint})"

            evidence: Dict[str, object] = {
                "port": port, "service": service, "ip": ip,
                "banner": banner[:200], "version": version,
                "os_hint": os_hint, "tls": tls_info,
                "via": d.get("via", ""),
            }
            if cred_risk:
                evidence["default_cred_risk"] = cred_risk

            if port == 21:
                anon = await _ftp_anonymous_ok(ip)
                if anon is True:
                    danger = ("medium", "FTP allows ANONYMOUS login",
                              "Disable anonymous FTP immediately, use SFTP instead.",
                              "ftp_open")
                elif anon is False:
                    danger = None
                    detail += " (anonymous refused)"

            if danger:
                risk, title, remediation, bkey = danger
                if risk == "high":
                    n_high += 1
                elif risk == "medium":
                    n_med += 1
                if cred_risk:
                    remediation = remediation + " " + cred_risk
                evidence.update({
                    "severity": risk, "remediation": remediation,
                    "exploitability": ("weaponized" if port in
                                       (2375, 6379, 27017, 10250, 2379, 8009, 8545)
                                       else "public_poc" if risk == "high"
                                       else "theoretical"),
                })
                findings.append(self._f(
                    "infra", bkey,
                    f"{title} on {ip}:{port} ({service}) - {detail}",
                    source="port audit", confidence=95, passive=False,
                    bounty_value=("high" if risk == "high"
                                  else "medium" if risk == "medium" else "low"),
                    evidence=evidence))
            else:
                evidence.update({"severity": "low", "remediation": DEFAULT_REMEDIATION,
                                 "exploitability": "unknown"})
                findings.append(self._f(
                    "infra", "port_open",
                    f"Port {port} ({service}) OPEN on {ip} - {detail}",
                    source="port audit", confidence=90, passive=False,
                    bounty_value="low", evidence=evidence))

        if tls_ports:
            findings.append(self._f(
                "infra", "tls_nonstandard",
                "TLS on non-standard port(s): " + "; ".join(tls_ports[:8]),
                source="port audit", confidence=90, passive=False,
                evidence={"severity": "medium", "remediation":
                          "Verify TLS on these ports is intentional and uses "
                          "valid certificates.",
                          "exploitability": "unknown"}))
            n_med += 1
        if os_guesses:
            for ip, guess in os_guesses.items():
                findings.append(self._f(
                    "infra", "os_guess",
                    f"OS fingerprint for {ip}: {guess} (banner-based, low confidence)",
                    source="port audit", confidence=50, passive=False,
                    evidence={"severity": "low", "os": guess,
                              "remediation": "Informational - use for scoping.",
                              "exploitability": "unknown"}))

        n_open = len(detected)
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(
            findings,
            f"swept {len(PORTS)} ports on {len(ips)} IP(s): {n_open} open, "
            f"{n_high} high / {n_med} medium danger")
        res.duration_ms = dur
        return res
