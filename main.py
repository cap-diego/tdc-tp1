import argparse
import csv
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
        if d[1] in frequency:
            frequency[d[1]] += k / N
        else:
            frequency[d[1]] = k / N

def calculate_info():
    sym = frequency.items()
    for k, v in sym:
        info[k] = -math.log(v, 2)

def calculate_entropy():
    global entropy
    sym = frequency.items()
    r = []
    for k, v in sym:
        r.append(info[k] * v)
    entropy = sum(r)


def callback(pkt):
    if pkt.haslayer(Ether):
        addr = "BROADCAST" if pkt[Ether].dst == "ff:ff:ff:ff:ff:ff" else "UNICAST"
        prot = pkt[Ether].type
        prot_desc = get_eth_desc.get(str(prot), prot)
        s_i = (addr, prot_desc)

        if prot_desc not in ["IPV4", "ARP", "IPV6"]:
            print(prot_desc)

        if s_i not in S1:
            S1[s_i] = 0.0
        S1[s_i] += 1.0

    # mostrar_fuente(S1)


if __name__ == '__main__':
    print("Empezando analisis")
    parser = argparse.ArgumentParser(description='Network analyzer')
    parser.add_argument('--dataset', type=str, nargs='?',
                        help='dataset')

    args = parser.parse_args()
    if args.dataset:
        print("Offline")
        sniff(prn=callback, offline="./input/{}.pcap".format(args.dataset))
    else:
        print("Online")
        sniff(prn=callback)

    calculate_freq()
    calculate_info()
    calculate_entropy()

    print(S1)
    print("Freq: {}\n".format(frequency))
    print("Info: {}\n".format(info))
    print("Entropy: {}\n".format(entropy))

    print("Escribiendo resultados")

    with open('./results/{}_frequency.csv'.format(args.dataset), 'w') as f:
        writer = csv.writer(f)
        writer.writerow(["type", "value"])
        for k, v in frequency.items():
            writer.writerow([k, v])

    with open('./results/{}_information.csv'.format(args.dataset), 'w') as f:
        writer = csv.writer(f)
        writer.writerow(["type", "value"])
        for k, v in info.items():
            writer.writerow([k, v])

    with open('./results/{}_entropy.csv'.format(args.dataset), 'w') as f:
        writer = csv.writer(f)
        writer.writerow(["dataset", "value"])
        writer.writerow([args.dataset, entropy])