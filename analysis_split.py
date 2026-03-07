import binascii, sys
sys.path.insert(0, "/home/administrator/home-assistant-jablotron100/custom_components/jablotron100")
from jablotron100.jablotron import Jablotron

def iter_packets_from_hex_lines(path):
    with open(path) as f:
        for line in f:
            raw = binascii.unhexlify(line.strip().replace(":", "").replace(" ", ""))
            for pkt in Jablotron.get_packets_from_packet(raw):
                yield pkt

def fmt(pkt): return binascii.hexlify(pkt).decode()

for direction, path in (("OUT","/tmp/jablotron_out.hex"), ("IN","/tmp/jablotron_in.hex")):
    for pkt in iter_packets_from_hex_lines(path):
        print(direction, fmt(pkt))

from jablotron import Jablotron
def label(pkt):
    t = []
    if Jablotron._is_sections_states_packet(pkt): t.append("SECTIONS_STATES")
    if Jablotron._is_pg_outputs_states_packet(pkt): t.append("PG_STATES")
    if Jablotron._is_device_state_packet(pkt): t.append(f"DEVICE_STATE dev={Jablotron._parse_device_number_from_device_state_packet(pkt)}")
    if Jablotron._is_device_info_packet(pkt): t.append(f"DEVICE_INFO dev={Jablotron._parse_device_number_from_device_info_packet(pkt)}")
    if Jablotron._is_device_status_packet(pkt): t.append(f"DEVICE_STATUS dev={Jablotron._parse_device_number_from_device_status_packet(pkt)}")
    if Jablotron._is_devices_sections_packet(pkt): t.append("DEVICES_SECTIONS")
    if Jablotron._is_devices_get_sections_packet(pkt): t.append("GET_DEVICES_SECTIONS")
    if Jablotron._is_login_error_packet(pkt): t.append("LOGIN_ERROR")
    return ",".join(t) or "UNKNOWN"
    