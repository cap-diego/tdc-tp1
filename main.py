import json

from scapy.all import *

S1 = {}
frequency = {}
info = {}
entropy = None

# Source: IEEE 802
get_eth_desc = {
    "2048": "IPV4",
    "2054": "ARP",
    "34525": "IPV6"
}

def mostrar_fuente(s):
    N = sum(s.values())
    print(s)
    sym = sorted(s.items(), key=lambda x: -x[1])
    print("\n".join([" %s : %.5f" % (d, k / N) for d, k in sym]))


def calculate_freq():
    N = sum(S1.values())
    sym = sorted(S1.items(), key=lambda x: -x[1])
    for d, k in sym:
        frequency[d] = k / N

def calculate_info():
    sym = frequency.items()
    for k, v in sym:
        info[k] = -math.log(v, 2)

def calculate_entropy():
    global entropy
    entropy = sum(info.values())


def callback(pkt):

    if pkt.haslayer(Ether):
        addr = "BROADCAST" if pkt[Ether].dst == "ff:ff:ff:ff:ff:ff" else "UNICAST"
        prot = pkt[Ether].type
        prot_desc = get_eth_desc.get(str(prot), prot)
        s_i = (addr, prot_desc)

        if s_i not in S1:
            S1[s_i] = 0.0
        S1[s_i] += 1.0

    # mostrar_fuente(S1)


if __name__ == '__main__':
    sniff(prn=callback, offline="./output/ws_1.pcapng")

    calculate_freq()
    calculate_info()
    calculate_entropy()

    print(S1)
    print("Freq: {}\n".format(frequency))
    print("Info: {}\n".format(info))
    print("Entropy: ", entropy)

    results = {
        "entropy": entropy,
        "frequency": frequency,
        "information": info
    }

