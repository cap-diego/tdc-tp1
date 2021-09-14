import argparse
import csv
from scapy.all import *

S1 = {}
frequency = {}
info = {}
entropy = None
broad_unicast = {
    "BROADCAST": 0,
    "UNICAST": 0
}

# Source: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
get_eth_desc = {
    "2048": "IPV4",
    "2054": "ARP",
    "34525": "IPV6"
}

# def mostrar_fuente(s):
#     N = sum(s.values())
#     print(s)
#     sym = sorted(s.items(), key=lambda x: -x[1])
#     print("\n".join([" %s : %.5f" % (d, k / N) for d, k in sym]))


def calculate_freq():
    Cantidad_total_simbolos = sum(S1.values())
    simbolos = sorted(S1.items(), key=lambda x: -x[1])
    for par_tipo_protocolo, cantidad_apariciones in simbolos:
        protocolo = par_tipo_protocolo[1]
        if protocolo in frequency:
            frequency[protocolo] += cantidad_apariciones / Cantidad_total_simbolos
        else:
            frequency[protocolo] = cantidad_apariciones / Cantidad_total_simbolos

def calculate_info():
    simbolos = frequency.items()
    for protocolo, frecuencia in simbolos:
        info[protocolo] = -math.log(frecuencia, 2)

def calculate_entropy():
    global entropy
    simbolos = frequency.items()
    entropy = 0.0
    for protocolo, frecuecia in simbolos:
        entropy += (info[protocolo] * frecuecia)
    


def callback(pkt):
    # https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    # Para IPv4 (RFC791) proto identifica el siguiente nivel de protocolo (pkt.payload.proto)
        # Para IPv6 (RFC8200) el campo es Next Header (pkt.payload.nh)

    if pkt.haslayer(Ether):
        addr = "BROADCAST" if pkt[Ether].dst == "ff:ff:ff:ff:ff:ff" else "UNICAST"
        prot = pkt[Ether].type
        prot_desc = get_eth_desc.get(str(prot), str(prot))
        s_i = (addr, prot_desc)

        broad_unicast[addr] += 1

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
    print("Broadcast/Unicast: {}\n".format(broad_unicast))
    print("Entropy: {}\n".format(entropy))

    if args.dataset is None:
        exit(0)

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

    with open('./results/{}_broadcast_unicast.csv'.format(args.dataset), 'w') as f:
        writer = csv.writer(f)
        writer.writerow(["type", "value"])
        for k, v in broad_unicast.items():
            writer.writerow([k, v])

