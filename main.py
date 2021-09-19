import argparse
import csv
from scapy.all import *

S1 = {}
S2 = {}

protocol_percentage = {}
symbol_frequency = {}
symbol_ip_frequency = {}
info = {}
entropy = None
entropy_ip = None

broad_unicast = {
    "BROADCAST": 0,
    "UNICAST": 0
}

# Source: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
get_eth_desc = {
    "2048": "IPV4",
    "2054": "ARP",
    "34525": "IPV6",
    "34958": "IEEE 802.1X"
}


def is_arp(proto):
    return proto == 2054


def map_op(op):
    # Defined at /scapy/layers/l2.py
    m = {"1": "who-has", "2": "is-at"}
    return m.get(str(op), str(op))

def calculate_protocol_percentage():
    cantidad_total_paquetes = sum(S1.values())
    simbolos = sorted(S1.items(), key=lambda x: -x[1])
    for par_tipo_protocolo, cantidad_apariciones in simbolos:
        protocolo = par_tipo_protocolo[1]
        if protocolo in protocol_percentage:
            protocol_percentage[protocolo] += (cantidad_apariciones / cantidad_total_paquetes) * 100
        else:
            protocol_percentage[protocolo] = cantidad_apariciones / cantidad_total_paquetes * 100


def calculate_ip_percentage():
    total_paquetes = sum(S2.values())
    simbolos = sorted(S2.items(), key=lambda x: -x[1])
    for ip, cantidad_apariciones in simbolos:
        if ip in protocol_percentage:
            protocol_percentage[ip] += (cantidad_apariciones / total_paquetes) * 100
        else:
            protocol_percentage[ip] = cantidad_apariciones / total_paquetes * 100


def calculate_symbol_freq():
    cantidad_total_paquetes = sum(S1.values())
    simbolos = sorted(S1.items(), key=lambda x: -x[1])
    for par_tipo_protocolo, cantidad_apariciones in simbolos:
        tipo =  "U" if par_tipo_protocolo[0] == "UNICAST" else "B" 
        protocolo = par_tipo_protocolo[1]
        symbol = "(" + tipo + " / " + protocolo +")"
        if symbol in symbol_frequency:
            symbol_frequency[symbol] += cantidad_apariciones / cantidad_total_paquetes
        else:
            symbol_frequency[symbol] = cantidad_apariciones / cantidad_total_paquetes

def calculate_ip_symbol_freq():
    cantidad_total_paquetes = sum(S2.values())
    simbolos = sorted(S2.items(), key=lambda x: -x[1])
    for ip, cantidad_apariciones in simbolos:
        if ip in symbol_frequency:
            symbol_ip_frequency[ip] += cantidad_apariciones / cantidad_total_paquetes
        else:
            symbol_ip_frequency[ip] = cantidad_apariciones / cantidad_total_paquetes

def calculate_info():
    simbolos = symbol_frequency.items()
    for simbolo, frecuencia in simbolos:
        info[simbolo] = -math.log(frecuencia, 2)

def calculate_ip_info():
    simbolos = symbol_ip_frequency.items()
    for simbolo, frecuencia in simbolos:
        info[simbolo] = -math.log(frecuencia, 2)


def calculate_entropy():
    global entropy
    simbolos = symbol_frequency.items()
    entropy = 0.0
    for simbolo, frecuencia in simbolos:
        entropy += (info[simbolo] * frecuencia)

def calculate_ip_entropy():
    global entropy_ip
    simbolos = symbol_ip_frequency.items()
    entropy_ip = 0.0
    for simbolo, frecuencia in simbolos:
        entropy_ip += (info[simbolo] * frecuencia)

def callback_analysis_1(pkt):
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


def callback_analysis_2(pkt):
    if pkt.haslayer(Ether):
        proto = pkt[Ether].type
        if not is_arp(proto):
           return

        #print("[ARP]    src: {}  --  dst: {}    Operation: {} ".format(pkt.psrc, pkt.pdst, map_op(pkt.op)))
        ip_src = pkt.psrc
        if ip_src not in S2:
            S2[ip_src] = 0.0
        S2[ip_src] += 1

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Network analyzer')
    parser.add_argument('--dataset', type=str, nargs='?',
                        help='dataset')
    parser.add_argument('--analysis', type=int,
                        help='type of analysis', choices=[1,2])

    args = parser.parse_args()
    type_analysis = 2 if args.analysis == 2 else 1
    callback = callback_analysis_2 if type_analysis == 2 else callback_analysis_1
    if args.dataset:
        print("Offline -- Running analysis {}".format(type_analysis))
        sniff(prn=callback, offline="./input/{}.pcap".format(args.dataset))
    else:
        print("Online -- Running analysis {}".format(type_analysis))
        sniff(prn=callback)

    if type_analysis == 1:
        calculate_protocol_percentage()
        calculate_symbol_freq()
        calculate_info()
        calculate_entropy()
    else:
        calculate_ip_percentage()
        calculate_ip_symbol_freq()
        calculate_ip_info()
        calculate_ip_entropy()
        symbol_frequency = symbol_ip_frequency
        entropy = entropy_ip

    print("Protocol Percentage: {}\n".format(protocol_percentage))
    print("Symbol Freq: {}\n".format(symbol_frequency))
    print("Info: {}\n".format(info))
    print("Broadcast/Unicast: {}\n".format(broad_unicast))
    print("Entropy: {}\n".format(entropy))

    if args.dataset is None:
        exit(0)

    print("Escribiendo resultados")
    os.makedirs(os.path.dirname('./results/analysis_1/'), exist_ok=True)
    os.makedirs(os.path.dirname('./results/analysis_2/'), exist_ok=True)

    with open('./results/analysis_{}/{}_protocol_percentage.csv'.format(type_analysis, args.dataset), 'w') as f:
        writer = csv.writer(f)
        writer.writerow(["type", "value"])
        for k, v in protocol_percentage.items():
            writer.writerow([k, v])

    
    with open('./results/analysis_{}/{}_symbol_frequency.csv'.format(type_analysis, args.dataset), 'w') as f:
        writer = csv.writer(f)
        writer.writerow(["type", "value"])
        for k, v in symbol_frequency.items():
            writer.writerow([k, v])

    with open('./results/analysis_{}/{}_information.csv'.format(type_analysis, args.dataset), 'w') as f:
        writer = csv.writer(f)
        writer.writerow(["type", "value"])
        for k, v in info.items():
            writer.writerow([k, v])

    with open('./results/analysis_{}/{}_entropy.csv'.format(type_analysis, args.dataset), 'w') as f:
        writer = csv.writer(f)
        writer.writerow(["dataset", "value"])
        writer.writerow([args.dataset, entropy])

    with open('./results/analysis_{}/{}_broadcast_unicast.csv'.format(type_analysis, args.dataset), 'w') as f:
        writer = csv.writer(f)
        writer.writerow(["type", "value"])
        for k, v in broad_unicast.items():
            writer.writerow([k, v])

