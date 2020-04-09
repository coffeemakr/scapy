import logging
logger = logging.getLogger("scapy")
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler())

from scapy.all import *
from scapy.contrib.stun import *

conf.debug_dissector = True


sport = 23322

p = IPv6(dst="stun.l.google.com")/UDP(sport=sport, dport=19302)/STUN(transaction_id=STUN.transaction_id.randval(),cookie=1234)

r = sr1(p)
r[UDP].decode_payload_as(STUN)
r.show()