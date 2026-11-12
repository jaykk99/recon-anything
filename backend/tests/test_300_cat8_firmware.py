"""Cat-8 (300-expansion) Firmware & Hardware IoT Protocols.

Per plugin: fires on a VULN fixture, silent on a CLEAN fixture, no
crash on malformed input. Fixtures are synthetic in-test artifacts
(SquashFS superblock + compressed metadata, struct-built DTB blobs,
U-Boot env blocks with real CRC32, shadow files, NVRAM stores, TLV
streams, Modbus/CoAP/MQTT packet bytes, pcaps). Masked-evidence
plugins are asserted to never leak the raw secret.
"""
import asyncio
import json
import os
import struct
import sys
import zlib

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.cache import Cache  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402

IDS = [
    "unblob_carver_wrapper", "uboot_env_block_parser",
    "jtag_pinout_bruteforcer", "uart_baudrate_autosniff",
    "squashfs_image_mounter", "dtb_device_tree_decompiler",
    "firmware_password_shadow_crack", "spi_flash_dump_analyzer",
    "ble_gatt_char_explorer", "zigbee_frame_decrypt_tool",
    "mqtt_broker_payload_spy", "coap_request_fuzzer",
    "can_bus_id_mapper", "modbus_register_scanner",
    "firmware_sig_override_finder", "nvram_parameter_dumper",
    "jffs2_file_system_extractor", "ghidra_v850_architecture_pack",
    "i2c_bus_traffic_logger", "upnp_device_descriptor_miner",
    "hnap_protocol_exploiter", "vxworks_symbol_table_restorer",
    "cisco_ios_config_decryptor", "ubiquiti_mct_packet_decoder",
    "hardware_watchdog_disabler", "intel_me_firmware_cleaner",
    "amlogic_burning_tool_protocol", "tlv_packet_structure_parser",
    "firmware_hardcoded_api_keys", "secure_boot_key_status_check",
]

MODULES = {pid: pid for pid in IDS}


def analyze(pid, data):
    import importlib
    mod = importlib.import_module(f"app.plugins.{MODULES[pid]}")
    return mod.analyze(data, "fixture.bin")


def keys(pid, data):
    return {h["key"] for h in analyze(pid, data)}


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

def build_dtb(children, root_props=None):
    prop_names = []

    def collect(nodes, props=None):
        for k in (props or {}):
            if k not in prop_names:
                prop_names.append(k)
        for n in nodes:
            collect(n.get("children", []), n.get("props", {}))

    collect(children, root_props)
    strtab = b"".join(k.encode() + b"\x00" for k in prop_names)
    offsets, pos = {}, 0
    for k in prop_names:
        offsets[k] = pos
        pos += len(k) + 1

    def pad4(b):
        return b + b"\x00" * ((-len(b)) % 4)

    def node_bytes(name, props, kids):
        out = struct.pack(">I", 1) + pad4(name.encode() + b"\x00")
        for k, v in (props or {}).items():
            if isinstance(v, str):
                v = v.encode() + b"\x00"
            out += struct.pack(">III", 3, len(v), offsets[k]) + pad4(v)
        for kid in kids:
            out += node_bytes(kid["name"], kid.get("props", {}),
                              kid.get("children", []))
        return out + struct.pack(">I", 2)

    struct_block = node_bytes("", root_props, children) + \
        struct.pack(">I", 9)
    off_struct = 56
    off_strings = off_struct + len(struct_block)
    header = struct.pack(
        ">10I", 0xD00DFEED, off_strings + len(strtab), off_struct,
        off_strings, 40, 17, 16, 0, len(strtab), len(struct_block))
    return header + b"\x00" * 16 + struct_block + strtab


def build_pcap(packets, linktype=1):
    out = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535,
                      linktype)
    for p in packets:
        out += struct.pack("<IIII", 0, 0, len(p), len(p)) + p
    return out


def uboot_env(pairs):
    region = b"\x00".join(
        f"{k}={v}".encode() for k, v in pairs)
    crc = zlib.crc32(region) & 0xFFFFFFFF
    return b"\xff" * 64 + struct.pack("<I", crc) + region + b"\x00\x00"


def squashfs(names):
    payload = b"\x00".join(n.encode() for n in names) + b"\x00"
    comp = zlib.compressobj(9, zlib.DEFLATED, -15)
    block = comp.compress(payload) + comp.flush()
    meta = struct.pack("<H", len(block)) + block
    bytes_used = 96 + len(meta)
    sb = struct.pack(
        "<4sIIIIHHHHHHQQQQQQQQ", b"hsqs", 42, 0, 131072, 3, 1, 17,
        0, 0, 4, 0, 0, bytes_used, 0, 0xFFFFFFFFFFFFFFFF, 96, 96, 0,
        0xFFFFFFFFFFFFFFFF)
    return sb + meta


def mqtt_packet(ptype, body):
    return bytes([ptype << 4, len(body)]) + body


def mqtt_connect(user=None, password=None):
    flags = 0x02
    payload = struct.pack(">H", 10) + b"recon-test"
    if user:
        flags |= 0x80
        payload += struct.pack(">H", len(user)) + user.encode()
    if password:
        flags |= 0x40
        payload += struct.pack(">H", len(password)) + password.encode()
    body = b"\x00\x04MQTT" + bytes([4, flags, 0, 60]) + payload
    return mqtt_packet(1, body)


def modbus_adu(pdu, tid=1):
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, 1) + pdu


def jffs2_dirent(name, ino=2):
    nb = name.encode()
    totlen = 40 + len(nb)
    node = struct.pack("<HHII", 0x1985, 0x0002, totlen, 0)
    node += struct.pack("<IIII", 1, 1, ino, 0)
    node += struct.pack("<BBHII", len(nb), 1, 0, 0, 0) + nb
    return node + b"\x00" * ((-totlen) % 4)


# ---------------------------------------------------------------------------
# 211-218
# ---------------------------------------------------------------------------

def test_unblob_carver():
    vuln = b"FWIMG" + b"\x00" * 256 + b"hsqs" + b"\x00" * 64 + \
        b"PK\x03\x04" + b"\x00" * 64
    assert "unblob_nested_filesystem" in keys(
        "unblob_carver_wrapper", vuln)
    assert analyze("unblob_carver_wrapper", b"plain text " * 40) == []


def test_uboot_env():
    vuln = uboot_env([
        ("bootargs", "console=ttyS0,115200 root=/dev/mtdblock2 "
                     "init=/bin/sh"),
        ("bootcmd", "tftp 0x8000 uImage; bootm"),
        ("serverip", "192.168.1.1"),
        ("http_passwd", "Sup3rSecret!")])
    ks = keys("uboot_env_block_parser", vuln)
    assert "uboot_bootargs_shell" in ks
    assert "uboot_network_boot" in ks
    blob = json.dumps([h for h in analyze("uboot_env_block_parser",
                                          vuln)], default=str)
    assert "Sup3rSecret!" not in blob
    clean = uboot_env([("bootcmd", "bootm 0x8000"),
                       ("bootargs", "root=/dev/mtdblock2 ro")])
    assert analyze("uboot_env_block_parser", clean) == []


def test_jtag_detection_only():
    vuln = build_dtb([{"name": "jtag@0",
                       "props": {"status": "okay"}}])
    assert "jtag_dt_node_enabled" in keys(
        "jtag_pinout_bruteforcer", vuln)
    txt = b"board config: readout protection disabled for debug"
    assert "jtag_rdp_disabled" in keys("jtag_pinout_bruteforcer", txt)
    clean = build_dtb([{"name": "jtag@0",
                        "props": {"status": "disabled"}}])
    assert analyze("jtag_pinout_bruteforcer", clean) == []


def test_uart_autosniff():
    vuln = (b"U-Boot 2021.01\nHit any key to stop autoboot: 3\n"
            b"bootargs console=ttyS0,115200\nStarting kernel...\n/ # \n")
    ks = keys("uart_baudrate_autosniff", vuln)
    assert "uart_serial_console_enabled" in ks
    assert "uart_root_shell_capture" in ks
    clean = b"login: user\nPassword:\nWelcome\nuser@host:~$ \n"
    assert analyze("uart_baudrate_autosniff", clean) == []


def test_squashfs_mounter():
    vuln = squashfs(["etc", "passwd", "shadow", "init", "telnetd",
                     "rcS", "busybox"])
    ks = keys("squashfs_image_mounter", vuln)
    assert "squashfs_rootfs_opened" in ks
    assert "squashfs_sensitive_files" in ks
    assert analyze("squashfs_image_mounter", b"\x11" * 200) == []


def test_dtb_decompiler():
    vuln = build_dtb([
        {"name": "chosen",
         "props": {"bootargs": "console=ttyS0 init=/bin/sh"}},
        {"name": "uart@1000", "props": {"status": "okay"}}])
    ks = keys("dtb_device_tree_decompiler", vuln)
    assert "dtb_bootargs_shell" in ks
    assert "dtb_debug_node_enabled" in ks
    clean = build_dtb([{"name": "cpu@0", "props": {"status": "okay"}}])
    assert analyze("dtb_device_tree_decompiler", clean) == []


def test_shadow_posture_no_cracking():
    vuln = (
        "root:$1$salt$qJH7H.n4xBDSM8pAyz7wj.:19000:0:99999:7:::\n"
        "admin::19000:0:99999:7:::\n"
        "oldsvc:Ab3dEf7hI9KlM:19000:0:99999:7:::\n"
        "daemon:*:19000:0:99999:7:::\n").encode()
    ks = keys("firmware_password_shadow_crack", vuln)
    assert "fw_shadow_empty_password" in ks
    assert "fw_shadow_legacy_des" in ks
    assert "fw_shadow_weak_md5" in ks
    blob = json.dumps(analyze("firmware_password_shadow_crack", vuln),
                      default=str)
    assert "qJH7H.n4xBDSM8pAyz7wj." not in blob
    assert "Ab3dEf7hI9KlM" not in blob
    clean = ("svcbackup:$6$salt$abcdef0123456789:19000:0:99999:7:::\n"
             "daemon:!:19000:0:99999:7:::\n").encode()
    assert analyze("firmware_password_shadow_crack", clean) == []


def test_spi_flash_dump():
    blob = bytearray(131072)
    blob[0x1000:0x1004] = b"hsqs"
    blob[0x8000:0x800F] = b"bootcmd=bootm\x00\x00"
    blob[65536:131072] = bytes((i * 37 + 11) % 256
                               for i in range(65536))
    ks = keys("spi_flash_dump_analyzer", bytes(blob))
    assert "spi_partition_map" in ks
    assert "spi_env_region" in ks
    assert analyze("spi_flash_dump_analyzer",
                   b"\xff" * 8192) == []


# ---------------------------------------------------------------------------
# 219-226
# ---------------------------------------------------------------------------

def test_ble_gatt():
    vuln = (
        "GATT capture - operator-owned device\n"
        "Service 0000180a Device Information\n"
        "  Char 00002a29-0000 properties: read\n"
        "  Char 0000fff2-0000 properties: write, notify (UART bridge)\n"
    ).encode()
    assert "ble_sensitive_char_writable" in keys(
        "ble_gatt_char_explorer", vuln)
    clean = (
        "GATT capture\n"
        "  Char 00002a29-0000 properties: read\n"
        "  Char 00002a19-0000 properties: read\n").encode()
    assert analyze("ble_gatt_char_explorer", clean) == []


def test_zigbee_offline():
    tc_key = bytes([0x5A, 0x69, 0x67, 0x42, 0x65, 0x65, 0x41, 0x6C,
                    0x6C, 0x69, 0x61, 0x6E, 0x63, 0x65, 0x30, 0x39])
    frame = bytes([0x41, 0x88, 0x01]) + tc_key
    vuln = build_pcap([frame], linktype=195)
    ks = keys("zigbee_frame_decrypt_tool", vuln)
    assert "zigbee_default_tc_key" in ks
    assert "zigbee_unsecured_frames" in ks
    blob = json.dumps(analyze("zigbee_frame_decrypt_tool", vuln),
                      default=str)
    assert tc_key.hex() not in blob
    clean = build_pcap([bytes([0x49, 0x88, 0x01, 0x02])],
                       linktype=195)
    assert analyze("zigbee_frame_decrypt_tool", clean) == []


def test_mqtt_spy():
    pub_body = struct.pack(">H", 10) + b"home/alarm" + b"disarmed-1234"
    vuln = mqtt_connect() + mqtt_packet(2, b"\x00\x00")
    sub = struct.pack(">H", 1) + struct.pack(">H", 1) + b"#\x00"
    vuln += bytes([0x82, len(sub)]) + sub
    suback = struct.pack(">H", 1) + b"\x00"
    vuln += bytes([0x90, len(suback)]) + suback
    vuln += mqtt_packet(3, pub_body)
    ks = keys("mqtt_broker_payload_spy", vuln)
    assert "mqtt_anonymous_accepted" in ks
    assert "mqtt_wildcard_subscribe" in ks
    blob = json.dumps(analyze("mqtt_broker_payload_spy", vuln),
                      default=str)
    assert "disarmed-1234" not in blob
    clean = mqtt_connect("oper", "s3cret") + mqtt_packet(2, b"\x00\x05")
    assert analyze("mqtt_broker_payload_spy", clean) == []


def test_coap_discovery():
    payload = (b'</config>;rt="cfg",</ota/update>;rt="ota",'
               b'</status>;rt="status"')
    vuln = bytes([0x60, 0x45, 0x12, 0x34]) + b"\xff" + payload
    ks = keys("coap_request_fuzzer", vuln)
    assert "coap_sensitive_resource_unauth" in ks
    clean = bytes([0x60, 0x45, 0x12, 0x34]) + b"\xff" + \
        b'</status>;rt="status",</sensors/temp>;rt="temp"'
    assert analyze("coap_request_fuzzer", clean) == []


def test_can_mapper():
    vuln = (
        "can0  100   [8]  00 11 22 33 44 55 66 77\n"
        "can0  7DF   [8]  02 10 03 00 00 00 00 00\n"
        "can0  7E8   [8]  06 50 03 00 32 01 00 00\n"
        "can0  7DF   [8]  02 27 01 00 00 00 00 00\n"
        "can0  18DAF110   [8]  02 3E 00 00 00 00 00 00\n"
    ).encode()
    ks = keys("can_bus_id_mapper", vuln)
    assert "can_diagnostic_traffic" in ks
    assert "can_uds_security_access" in ks
    clean = ("can0  100   [8]  00 11 22 33 44 55 66 77\n"
             "can0  200   [8]  08 00 00 00 00 00 00 01\n").encode()
    assert analyze("can_bus_id_mapper", clean) == []


def test_modbus_scanner():
    fc43 = bytes([0x2B, 0x0E, 0x01, 0x00]) + \
        b"\x02\x00VendorX\x03\x00PLC-9000"
    fc3 = bytes([0x03, 16]) + struct.pack(">8H", *range(100, 108))
    vuln = modbus_adu(fc43) + modbus_adu(fc3, tid=2)
    ks = keys("modbus_register_scanner", vuln)
    assert "modbus_device_id_disclosed" in ks
    assert "modbus_registers_readable_noauth" in ks
    clean = modbus_adu(bytes([0x83, 0x02]))
    assert analyze("modbus_register_scanner", clean) == []


def test_sig_override():
    vuln = json.dumps({
        "name": "fw-update", "version": "2.0.0",
        "signature_required": False, "allow_downgrade": True,
        "url": "https://example.invalid/fw.bin"}).encode()
    ks = keys("firmware_sig_override_finder", vuln)
    assert "fw_update_signature_not_required" in ks
    assert "fw_update_downgrade_allowed" in ks
    clean = json.dumps({
        "version": "2.0.0", "signature_required": True,
        "signature": "abcdef0123456789abcdef0123456789",
        "min_version": "2.0.0"}).encode()
    assert analyze("firmware_sig_override_finder", clean) == []


def test_nvram_dumper():
    vuln = (b"board_id=XYZ123\nwl0_ssid=HomeNet\n"
            b"wl0_psk=SuperSecretWiFi99\nadmin_password=admin\n"
            b"region=US\n")
    ks = keys("nvram_parameter_dumper", vuln)
    assert "nvram_factory_credential" in ks
    assert "nvram_sensitive_parameter" in ks
    blob = json.dumps(analyze("nvram_parameter_dumper", vuln),
                      default=str)
    assert "SuperSecretWiFi99" not in blob
    clean = b"board_id=XYZ123\nregion=US\nserial=SN0001\n"
    assert analyze("nvram_parameter_dumper", clean) == []


# ---------------------------------------------------------------------------
# 227-240
# ---------------------------------------------------------------------------

def test_jffs2_extractor():
    vuln = jffs2_dirent("passwd") + jffs2_dirent("shadow") + \
        jffs2_dirent("index.html") + jffs2_dirent("rcS")
    ks = keys("jffs2_file_system_extractor", vuln)
    assert "jffs2_file_listing" in ks
    assert "jffs2_sensitive_files" in ks
    assert analyze("jffs2_file_system_extractor",
                   b"\x00" * 512) == []


def test_v850_pack():
    code = struct.pack("<H", 0x06E5) * 40 + struct.pack("<H", 0x006F)
    vuln = code + b"\x00" * 8 + \
        b"uart_debug_enable\x00password_check\x00main_loop\x00"
    ks = keys("ghidra_v850_architecture_pack", vuln)
    assert "v850_sensitive_strings" in ks
    assert "v850_code_map" in ks
    assert analyze("ghidra_v850_architecture_pack",
                   b"\x00" * 256) == []


def test_i2c_logger():
    read = ",".join(["0xAA"] * 20)
    vuln = (f"0.001,WRITE,0x50,0x00,0x10\n"
            f"0.002,READ,0x50,{read}\n"
            "0.003,READ,0x68,0x3B,0x12\n").encode()
    ks = keys("i2c_bus_traffic_logger", vuln)
    assert "i2c_eeprom_bulk_read" in ks
    assert "i2c_eeprom_write" in ks
    clean = b"0.001,READ,0x68,0x3B,0x12\n0.002,READ,0x68,0x3C,0x00\n"
    assert analyze("i2c_bus_traffic_logger", clean) == []


def test_upnp_miner():
    vuln = (
        "<root><device><modelName>Gateway9000</modelName>"
        "<modelDescription>Firmware 1.2 build 44</modelDescription>"
        "<URLBase>http://192.168.1.1:49152/</URLBase>"
        "<serviceList><service>"
        "<serviceType>urn:schemas-upnp-org:service:"
        "WANIPConnection:1</serviceType></service></serviceList>"
        "<actionList><action><name>AddPortMapping</name></action>"
        "</actionList></device></root>").encode()
    ks = keys("upnp_device_descriptor_miner", vuln)
    assert "upnp_wan_port_mapping" in ks
    assert "upnp_admin_actions" in ks
    clean = (
        "<root><device><modelName>Renderer</modelName>"
        "<serviceList><service><serviceType>urn:schemas-upnp-org:"
        "service:ContentDirectory:1</serviceType></service>"
        "</serviceList><actionList><action><name>Browse</name>"
        "</action></actionList></device></root>").encode()
    assert analyze("upnp_device_descriptor_miner", clean) == []


def test_hnap_detector():
    vuln = (
        "<html><body HNAP1><ActionList>"
        "<string>GetDeviceSettings</string>"
        "<string>SetAdminPassword</string>"
        "<string>SetDeviceSettings</string>"
        "</ActionList></body></html>").encode()
    ks = keys("hnap_protocol_exploiter", vuln)
    assert "hnap_enabled" in ks
    assert "hnap_write_actions_listed" in ks
    clean = b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic\r\n"
    assert analyze("hnap_protocol_exploiter", clean) == []


def test_vxworks_symbols():
    names = ["VxWorks 7 kernel", "symTbl", "usrAppInit", "sysHwInit",
             "netDevCreate", "ftpServerInit", "msgQCreate",
             "semBCreate", "taskSpawn", "usrShell", "dbgHelp",
             "shellIn", "wdCreate"]
    vuln = b"\x00" * 16 + b"\x00".join(
        n.encode() for n in names) + b"\x00"
    ks = keys("vxworks_symbol_table_restorer", vuln)
    assert "vxworks_symbol_table_present" in ks
    assert "vxworks_sensitive_symbol" in ks
    clean = b"hello world this is plain text with spaces only\x00"
    assert analyze("vxworks_symbol_table_restorer",
                   clean * 4) == []


def test_cisco_type7():
    from app.plugins.cisco_ios_config_decryptor import encode_type7
    enc = encode_type7("cisco123", salt=3)
    vuln = (f"hostname router1\n!\nusername admin password 7 {enc}\n"
            "enable secret 5 $1$mERr$abc123def456\n!\n").encode()
    ks = keys("cisco_ios_config_decryptor", vuln)
    assert "cisco_type7_reversible" in ks
    assert "cisco_type5_md5" in ks
    blob = json.dumps(analyze("cisco_ios_config_decryptor", vuln),
                      default=str)
    assert "cisco123" not in blob
    assert enc not in blob
    clean = ("hostname router1\n!\nusername svc secret 9 "
             "$9$abcdef0123456789\n!\n").encode()
    assert analyze("cisco_ios_config_decryptor", clean) == []


def _eth_udp(payload, dport=10001):
    eth = b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00"
    udp_len = 8 + len(payload)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + udp_len, 1, 0,
                     64, 17, 0, b"\xc0\xa8\x01\x01",
                     b"\xff\xff\xff\xff")
    udp = struct.pack(">HHHH", 10001, dport, udp_len, 0)
    return eth + ip + udp + payload


def test_ubiquiti_decoder():
    tlv = b""
    tlv += b"\x01" + struct.pack(">H", 6) + \
        bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    tlv += b"\x02" + struct.pack(">H", 6) + b"\x00\x00\xc0\xa8\x01\x01"
    tlv += b"\x0c" + struct.pack(">H", 6) + b"UAP-AC"
    tlv += b"\x14" + struct.pack(">H", 6) + b"4.3.20"
    payload = b"\x02\x06\x00\x00" + tlv
    vuln = build_pcap([_eth_udp(payload)])
    ks = keys("ubiquiti_mct_packet_decoder", vuln)
    assert "ubiquiti_discovery_disclosure" in ks
    assert "ubiquiti_legacy_firmware" in ks
    clean = build_pcap([_eth_udp(b"hello", dport=80)])
    assert analyze("ubiquiti_mct_packet_decoder", clean) == []


def test_watchdog_detector():
    vuln = build_dtb([{
        "name": "watchdog@0",
        "props": {"status": "disabled",
                  "timeout-sec": struct.pack(">I", 0)}}])
    ks = keys("hardware_watchdog_disabler", vuln)
    assert "watchdog_dt_disabled" in ks
    assert "watchdog_ineffective_timeout" in ks
    txt = b"bootargs: console=ttyS0 nowatchdog root=/dev/ram"
    assert "watchdog_disabled_bootargs" in keys(
        "hardware_watchdog_disabler", txt)
    clean = build_dtb([{
        "name": "watchdog@0",
        "props": {"status": "okay",
                  "timeout-sec": struct.pack(">I", 30)}}])
    assert analyze("hardware_watchdog_disabler", clean) == []


def test_intel_me_inventory():
    entries = b""
    for nm, off, size in (("FTPR", 0x1000, 0x8000),
                          ("NFTP", 0x9000, 0x4000),
                          ("XXXX", 0xD000, 0x1000)):
        entries += nm.encode() + b"\x00" * 4 + \
            struct.pack("<II", off, size) + b"\x00" * 16
    vuln = b"$FPT" + struct.pack("<I", 3) + b"\x00" * 24 + entries
    ks = keys("intel_me_firmware_cleaner", vuln)
    assert "intel_me_partition_inventory" in ks
    assert "intel_me_unknown_partition" in ks
    assert analyze("intel_me_firmware_cleaner",
                   b"\x5a" * 512) == []


def test_amlogic_offline():
    vuln = (b"; Amlogic image.cfg\n[LIST_NORMAL]\n"
            b"secure_boot=0\n"
            b"system=system.img\nboot=boot.img\n"
            b"u-boot.bin.usb.bl2=bl2.bin\n")
    ks = keys("amlogic_burning_tool_protocol", vuln)
    assert "aml_secure_boot_disabled" in ks
    assert "aml_unverified_package_list" in ks
    clean = b"[LIST_VERIFY]\nsecure_boot=1\naml signed package\n"
    assert analyze("amlogic_burning_tool_protocol", clean) == []


def test_tlv_parser():
    cred = b"api_token=TopSecretTokenValue"
    vuln = bytes([0x01, 0x03]) + b"cfg"
    vuln += bytes([0x10, len(cred)]) + cred
    entropy_block = bytes((i * 37 + 11) % 256 for i in range(255))
    vuln += bytes([0x20, 255]) + entropy_block
    ks = keys("tlv_packet_structure_parser", vuln)
    assert "tlv_credential_value" in ks
    assert "tlv_high_entropy_block" in ks
    blob = json.dumps(analyze("tlv_packet_structure_parser", vuln),
                      default=str)
    assert "TopSecretTokenValue" not in blob
    clean = bytes([0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x05])
    assert analyze("tlv_packet_structure_parser", clean) == []


def test_firmware_hardcoded_keys():
    aws = "AKIAQWERTYUIOPASDFGH"
    gh = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2"
    vuln = (f"#!/bin/sh\nexport AWS_ACCESS_KEY_ID={aws}\n"
            f"GH_TOKEN={gh}\n").encode()
    ks = keys("firmware_hardcoded_api_keys", vuln)
    assert "fw_hardcoded_api_key" in ks
    blob = json.dumps(analyze("firmware_hardcoded_api_keys", vuln),
                      default=str)
    assert aws not in blob and gh not in blob
    clean = b"#!/bin/sh\necho hello world\nmount -t proc proc /proc\n"
    assert analyze("firmware_hardcoded_api_keys", clean) == []


def test_secure_boot_status():
    vuln = build_dtb([
        {"name": "images", "props": {"key-name": "dev-key-2024"},
         "children": [{"name": "kernel", "props": {}}]},
        {"name": "configurations", "props": {}}])
    ks = keys("secure_boot_key_status_check", vuln)
    assert "fit_image_unsigned" in ks
    assert "secure_boot_test_key" in ks
    clean = build_dtb([
        {"name": "images", "props": {},
         "children": [{"name": "signature",
                       "props": {"required": "conf"}}]},
        {"name": "configurations", "props": {}}])
    assert analyze("secure_boot_key_status_check", clean) == []


# ---------------------------------------------------------------------------
# Cross-cutting: malformed input, run() plumbing, registry
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("pid", IDS)
def test_malformed_no_crash(pid):
    for blob in (b"", b"\x00", b"\xff" * 37, os.urandom(513),
                 b"hsqs", b"\xd0\x0d\xfe\xed" + b"\x00" * 8):
        hits = analyze(pid, blob)
        assert isinstance(hits, list)


def _ctx(artifacts=None):
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda r: httpx.Response(404, request=r)),
        follow_redirects=True, trust_env=False)
    ctx = Ctx(run_id="cat8-test", mode="passive", http=client,
              cache=Cache(), keys={}, limiter=RateLimiter(),
              evidence_dir="/tmp", source_type="website")
    if artifacts is not None:
        ctx.shared["firmware_artifacts"] = list(artifacts)
    return ctx


def run_plugin(pid, artifacts=None):
    from app.plugins.registry import discover
    cls = discover()[pid]
    ctx = _ctx(artifacts)
    tgt = Target(raw="supplied-firmware", type="binary",
                 normalized="supplied-firmware")

    async def _go():
        try:
            return await asyncio.wait_for(
                cls().run(tgt, ctx), timeout=30)
        finally:
            await ctx.http.aclose()
    return asyncio.run(_go())


def test_run_end_to_end_sample():
    res = run_plugin("uboot_env_block_parser",
                     [("fw.bin", uboot_env(
                         [("bootcmd", "tftp boot"),
                          ("serverip", "10.0.0.1")]))])
    assert res.status.value == "ok"
    assert {f.key for f in res.findings} >= {"uboot_network_boot"}
    res = run_plugin("nvram_parameter_dumper",
                     [("nvram.bin", b"admin_password=admin\n"
                      b"board_id=X1\n")])
    assert {f.key for f in res.findings} >= \
        {"nvram_factory_credential"}
    res = run_plugin("tlv_packet_structure_parser", [])
    assert res.status.value == "ok" and res.findings == []


def test_registry_count_and_ids():
    from app.plugins.registry import discover
    reg = discover()
    assert len(reg) == 1235
    for pid in IDS:
        assert pid in reg, pid
