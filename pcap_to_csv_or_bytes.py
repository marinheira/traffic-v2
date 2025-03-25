#!/usr/bin/python2.7
# -*- coding: utf-8 -*-

from __future__ import division

import argparse, re, dpkt, sys
from subprocess import Popen, PIPE, call
import pandas as ps
import numpy as np
import socket

# Полный список характеристик потока:
FEATURES = [
    "proto", # протокол прикладного уровня
    "subproto", # дополнительный протокол, nDPI его даёт, но не всегда.
                # сейчас никак не используется
    "bulk0", # размер первой порции данных со стороны клиента
    "bulk1", # размер первой порции данных со стороны сервера
    "bulk2", # размер второй порции данных со стороны клиента
    "bulk3", # размер второй порции данных со стороны сервера
    "client_packet0", # размер первого сегмента со стороны клиента
    "client_packet1", # размер второго сегмента со стороны клиента
    "server_packet0", # размер первого сегмента со стороны сервера
    "server_packet1", # размер второго сегмента со стороны сервера
    "client_bulksize_avg", # средный размер порции данных со стороны клиента
    "client_bulksize_dev", # стандартное отклонение размера порции
                           # данных со стороны клиента
    "server_bulksize_avg", # средный размер порции данных со стороны сервера
    "server_bulksize_dev", # стандартное отклонение размера порции
                           # данных со стороны сервера
    "client_packetsize_avg", # средный размер сегмента со стороны клиента
    "client_packetsize_dev", # стандартное отклонение размера сегмента
                             # со стороны клиента
    "server_packetsize_avg", # средний размер сегмента со стороны сервера
    "server_packetsize_dev", # стандартное отклонение размера сегмента
                             # со стороны сервера
    "client_packets_per_bulk", # среднее количество сегментов на порцию
                               # данных со стороны клиента
    "server_packets_per_bulk", # среднее количество сегментов на порцию
                               # данных со стороны сервера
    "client_effeciency", # КПД клиента
    "server_efficiency", # КПД сервера
    "byte_ratio", # во сколько раз клиент передал больше байт, чем сервер
    "payload_ratio", # во сколько раз клиент передал больше полезной нагрузки, чем сервер
    "packet_ratio", # во сколько раз клиент передал больше сегментов, чем сервер
    "client_bytes", # сколько байт суммарно передано клиентом
    "client_payload", # сколько полезной нагрузки суммарно передано клиентом
    "client_packets", # сколько сегментов суммарно передано клиентом
    "client_bulks", # сколько порций данных суммарно передано клиентом
    "server_bytes", # сколько байт суммарно передано сервером
    "server_payload", # сколько полезной нагрузки суммарно передано сервером
    "server_packets", # сколько сегментов суммарно передано сервером
    "server_bulks", # сколько порций данных суммарно передано сервером
    "is_tcp", # используется ли TCP на транспортном уровне
             # (0 означает UDP, другие протоколы не рассматриваются)
    "IPsrc", "PORTsrc", #IP и порт клиента
    "IPdst", "PORTdst", # IP и порт сервера
    "SSL_name" # SSL-заголовок
]

# Полный список характеристик байтов:
BYTES_FEATURES = ["proto", "subproto", 
                  "IPsrc", "PORTsrc",
                  "IPdst", "PORTdst",
                  "SSL_name", 
                  "HSh_0", "HSh_1", "HSh_2", "HSh_3", # Порции хендшейка
                  "ClBt", # биты от клиента
                  "SBt" # биты от сервера
                  ]

def ip_from_string(ips):
    '''
        Преобразовать символьное представление IP-адреса
        в четырёхбайтную строку.
        Аргументы:
            ips - IP-адрес в виде строки (например: '10.0.0.1')
        Возвращает:
            строку из 4 байт
    '''
    return "".join(chr(int(n)) for n in ips.split("."))

def parse_flows(pcapfile):
    '''
        Прочитать данный файл PCAP, разделить его на потоки
        транспортного уровня и определить прикладной протокол
        каждого потока.
        Аргументы:
            pcapfile - путь к файлу PCAP (строка)
        Возвращает (генерирует):
            Список кортежей вида:
            (
                протокол прикладного уровня,
                дополнительный протокол,
                список Ethernet-фреймов
            )
    '''

    pipe = Popen(["/content/traffic-v2/ndpiReader", "-i", pcapfile, "-v2"], stdout=PIPE)
    raw = pipe.communicate()[0].decode("utf-8")
    #reg = re.compile(r'(UDP|TCP) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5}) <-> (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5}).*\[proto: [\d+\.]*\d+\/(\w+\.?\w+)*\]')
    # строка для парсинга и SSL-заголовка в том числе
    reg = re.compile(r'(UDP|TCP) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5}) <-> (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5}).*\[proto: [\d+\.]*\d+\/(\w+\.?\w+)*\](?:.*\[SSL client: ([^\]]*)\])?')
    
    # потоки
    flows = {}

    # протолол\субпротокол\ssl-заголовок потока
    apps = {}
    for captures in re.findall(reg, raw):
        transp_proto, ip_1, port1, ip_2, port2, app_proto, i_ssl = captures
        ip1 = ip_from_string(ip_1)
        ip2 = ip_from_string(ip_2)
        port1 = int(port1)
        port2 = int(port2)

        # ключ потока: транспортный протокол (tcp\udp), затем пара IP:порт источника и пункта назначения
        # к нему будут прицепляться порции потоков, выгружаемые dpkt-пакетом
        key = (transp_proto.lower(),
            frozenset(((ip1, port1), (ip2, port2))))
        flows[key] = [] # порции будут по одной цепляться сюда

        # Если протокол имеет вид proto.subproto, делим его. Если нет, представляем как proto, None
        apps[key] = app_proto.split(".")
        if len(apps[key]) == 1:
            apps[key].append(None)
        
        # добавляем SSL-заголовок
        apps[key].append(i_ssl)

    for ts, raw in dpkt.pcap.Reader(open(pcapfile, "rb")):
        try:
          eth = dpkt.ethernet.Ethernet(raw)
        except:
          print("Ошибка парсинга, пакет пропускается\n", 
          (transp_proto.lower(),
            frozenset(((ip_1, port1), (ip_2, port2)))))
          continue

        ip = eth.data
        if not isinstance(ip, dpkt.ip.IP):
            continue
        seg = ip.data
        if isinstance(seg, dpkt.tcp.TCP):
            transp_proto = "tcp"
        elif isinstance(seg, dpkt.udp.UDP):
            transp_proto = "udp"
        else:
            continue
        
        # ключ сессии: транспортный протокол (tcp\udp), затем пара IP:порт источника и пункта назначения
        key = (transp_proto, frozenset(((ip_from_string(socket.inet_ntoa(ip.src)), seg.sport),
            (ip_from_string(socket.inet_ntoa(ip.dst)), seg.dport))))

        # если ключа, который найден при чтении по порциям, нет в потоках от ndpi-reader, создаем его во flows
        try:
            assert key in flows
        except AssertionError:
            print("Не найдена пара IP в выгрузке ndpiReader, создан ключ во flows")
            print(transp_proto)
            print(repr(socket.inet_ntoa(ip.src)), seg.sport)
            print(repr(socket.inet_ntoa(ip.dst)), seg.dport)
            # raise
            flows[key] = []
        
        # если ключа, который найден при чтении по порциям, нет в потоках от ndpi-reader, создаем его
        # и заполняем ничем с указанием, что была ошибка чтения потока
        try:
            assert key in apps
        except AssertionError:
            apps[key] = ["Error_proto", None, None] # добавляем ошибку вместо транспортного протокола, 
            # НИЧЕГО на месте субпротокола и ssl-заголовка
        flows[key].append(eth)

    for key, flow in flows.items():
        ip_src = ".".join([str(ord(_)) for _ in list(key[1])[0][0]])
        port_src = list(key[1])[0][1]
        ip_dst = ".".join([str(ord(_)) for _ in list(key[1])[1][0]])
        port_dst = list(key[1])[1][1]
        yield apps[key][0], apps[key][1], apps[key][2], ip_src, port_src, ip_dst, port_dst, flow

def forge_flow_stats(flow, strip = 0):
    '''
        Рассчитать статистические метрики потока.
        Аргументы:
            flow - список Ethernet-фреймов
            strip - количество первых фреймов, по которым   
                строить таблицу признаков (если меньше 1,
                то фреймы не отбрасываются)
        Возвращает:
            Словарь, в котором ключи - названия метрик,
            значения - значения этих метрик.
            Если в потоке нет хотя бы двух порций данных,
            возвращает None.
    '''
    
    if len(flow) == 0:
        print("Пустой поток!", flow)
        return None

    ip = flow[0].data
    seg = ip.data
    if isinstance(seg, dpkt.tcp.TCP):
        # Смотрим, чтобы в первых двух пакетах был флаг SYN:
        try:
            seg2 = flow[1].data.data
        except IndexError:
            return None
        if not (seg.flags & dpkt.tcp.TH_SYN and seg2.flags & dpkt.tcp.TH_SYN):
            return None
        proto = "tcp"
        flow = flow[3:] # срезаем tcp handshake
    elif isinstance(seg, dpkt.udp.UDP):
        proto = "udp"
    else:
        raise ValueError("Unknown transport protocol: `{}`".format(
            seg.__class__.__name__))

    if strip > 0:
        flow = flow[:strip]

    client = (ip.src, seg.sport)
    server = (ip.dst, seg.dport)

    client_bulks = []
    server_bulks = []
    client_packets = []
    server_packets = []

    cur_bulk_size = 0
    cur_bulk_owner = "client"
    client_fin = False
    server_fin = False
    for eth in flow:
        ip = eth.data
        seg = ip.data
        if (ip.src, seg.sport) == client:
            if client_fin: continue
            if proto == "tcp":
                client_fin = bool(seg.flags & dpkt.tcp.TH_FIN)
            client_packets.append(len(seg))
            if cur_bulk_owner == "client":
                cur_bulk_size += len(seg.data)
            elif len(seg.data) > 0:
                server_bulks.append(cur_bulk_size)
                cur_bulk_owner = "client"
                cur_bulk_size = len(seg.data)
        elif (ip.src, seg.sport) == server:
            if server_fin: continue
            if proto == "tcp":
                server_fin = bool(seg.flags & dpkt.tcp.TH_FIN)
            server_packets.append(len(seg))
            if cur_bulk_owner == "server":
                cur_bulk_size += len(seg.data)
            elif len(seg.data) > 0:
                client_bulks.append(cur_bulk_size)
                cur_bulk_owner = "server"
                cur_bulk_size = len(seg.data)
        else:
            raise ValueError("There is more than one flow here!")

    if cur_bulk_owner == "client":
        client_bulks.append(cur_bulk_size)
    else:
        server_bulks.append(cur_bulk_size)

    stats = {
        "bulk0": client_bulks[0] if len(client_bulks) > 0 else 0,
        "bulk1": server_bulks[0] if len(server_bulks) > 0 else 0,
        "bulk2": client_bulks[1] if len(client_bulks) > 1 else 0,
        "bulk3": server_bulks[1] if len(server_bulks) > 1 else 0,
        "client_packet0": client_packets[0] if len(client_packets) > 0 else 0,
        "client_packet1": client_packets[1] if len(client_packets) > 1 else 0,
        "server_packet0": server_packets[0] if len(server_packets) > 0 else 0,
        "server_packet1": server_packets[1] if len(server_packets) > 1 else 0,
    }

    if client_bulks and client_bulks[0] == 0:
        client_bulks = client_bulks[1:]

    if not client_bulks or not server_bulks:
        return None

    stats.update({
        "client_bulksize_avg": np.mean(client_bulks),
        "client_bulksize_dev": np.std(client_bulks),
        "server_bulksize_avg": np.mean(server_bulks),
        "server_bulksize_dev": np.std(server_bulks),
        "client_packetsize_avg": np.mean(client_packets),
        "client_packetsize_dev": np.std(client_packets),
        "server_packetsize_avg": np.mean(server_packets),
        "server_packetsize_dev": np.std(server_packets),
        "client_packets_per_bulk": len(client_packets)/len(client_bulks),
        "server_packets_per_bulk": len(server_packets)/len(server_bulks),
        "client_effeciency": sum(client_bulks)/sum(client_packets),
        "server_efficiency": sum(server_bulks)/sum(server_packets),
        "byte_ratio": sum(client_packets)/sum(server_packets),
        "payload_ratio": sum(client_bulks)/sum(server_bulks),
        "packet_ratio": len(client_packets)/len(server_packets),
        "client_bytes": sum(client_packets),
        "client_payload": sum(client_bulks),
        "client_packets": len(client_packets),
        "client_bulks": len(client_bulks),
        "server_bytes": sum(server_packets),
        "server_payload": sum(server_bulks),
        "server_packets": len(server_packets),
        "server_bulks": len(server_bulks),
        "is_tcp": int(proto == "tcp")
    })

    return stats

def forge_flow_bytes(flow, strip = 0, strip_bytes = 4096):
    '''
        Достать n битов потока и все биты handshake, если таковой есть.
        Аргументы:
            flow - список Ethernet-фреймов
            strip - количество первых фреймов, по которым   
                строить таблицу признаков (если меньше 1,
                то фреймы не отбрасываются)
        Возвращает:
            Словарь, в котором ключи - названия метрик,
            значения - значения этих метрик.
            Если в потоке нет хотя бы двух порций данных,
            возвращает None.
    '''
    
    if len(flow) == 0:
        print("Пустой поток!", flow)
        return None

    ip = flow[0].data
    seg = ip.data
    if isinstance(seg, dpkt.tcp.TCP):
        # Смотрим, чтобы в первых двух пакетах был флаг SYN:
        try:
            seg2 = flow[1].data.data
        except IndexError:
            return None
        if not (seg.flags & dpkt.tcp.TH_SYN and seg2.flags & dpkt.tcp.TH_SYN):
            return None
        proto = "tcp"
        hand_shake = flow[:4]
        flow = flow[3:] # срезаем tcp handshake
    elif isinstance(seg, dpkt.udp.UDP):
        proto = "udp"
        hand_shake = "no_handshake"
    else:
        raise ValueError("Unknown transport protocol: `{}`".format(
            seg.__class__.__name__))

    if strip > 0:
        flow = flow[:strip]

    client = (ip.src, seg.sport)
    server = (ip.dst, seg.dport)

    client_bytes = []
    server_bytes = []

    cur_bulk_owner = "client"
    client_fin = False
    server_fin = False
    for eth in flow:
        ip = eth.data
        seg = ip.data
        if (ip.src, seg.sport) == client:
            if client_fin: continue
            if proto == "tcp":
                client_fin = bool(seg.flags & dpkt.tcp.TH_FIN)
            if cur_bulk_owner == "client":
                client_bytes.append(seg.data)
            elif len(seg.data) > 0:
                server_bytes.append(seg.data)
                cur_bulk_owner = "client"
        elif (ip.src, seg.sport) == server:
            if server_fin: continue
            if proto == "tcp":
                server_fin = bool(seg.flags & dpkt.tcp.TH_FIN)
            if cur_bulk_owner == "server":
                server_bytes.append(seg.data)
            elif len(seg.data) > 0:
                client_bytes.append(seg.data)
                cur_bulk_owner = "server"
        else:
            raise ValueError("There is more than one flow here!")

    if cur_bulk_owner == "client":
        client_bytes.append(seg.data)
    else:
        server_bytes.append(seg.data)

    if not client_bytes or not server_bytes:
      return None

    client_byte_str = b''.join(client_bytes)
    server_byte_str = b''.join(server_bytes)

    result_dict = {"HSh_0": hand_shake[0].data.data.data if isinstance(hand_shake, list) else np.nan,
                   "HSh_1": hand_shake[1].data.data.data if isinstance(hand_shake, list) else np.nan,
                   "HSh_2": hand_shake[2].data.data.data if isinstance(hand_shake, list) else np.nan,
                   "HSh_3": hand_shake[3].data.data.data if isinstance(hand_shake, list) else np.nan,
                   "ClBt": client_byte_str[:min(strip_bytes, len(client_byte_str))],
                   "SBt": server_byte_str[:min(strip_bytes, len(server_byte_str))]}
    
    return result_dict

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", nargs="+", help="pcap file")
    parser.add_argument("-o", "--output", help="output csv file", default="flows.csv")
    parser.add_argument("-reg", "--parse_regimen", help="stats or bytes?", default="stats")
    parser.add_argument("-s", "--strip", help="leave only first N datagramms", metavar = "N", default=0, type=int)
    parser.add_argument("-bt", "--nbytes", help="leave only first N bytes", metavar = "N", default=4096, type=int)
    args = parser.parse_args()

    if args.parse_regimen == "stats":
        flows = {feature: [] for feature in FEATURES}
        for pcapfile in args.file:
            if len(args.file) > 1:
                print(pcapfile)
            for proto, subproto, i_ssl, ip_src, port_src, ip_dst, port_dst, flow in parse_flows(pcapfile):
                stats = forge_flow_stats(flow, args.strip)
                if stats:
                    stats.update({"proto": proto, "subproto": subproto, 
                                  "IPsrc": ip_src, "PORTsrc": port_src,
                                  "IPdst": ip_dst, "PORTdst": port_dst,
                                  "SSL_name": i_ssl})
                    for feature in FEATURES:
                        flows[feature].append(stats[feature])
        data = ps.DataFrame(flows)
        data.to_csv(args.output, index=False)

    else:
        flow_bytes = {bytes_feature: [] for bytes_feature in BYTES_FEATURES}
        for pcapfile in args.file:
            if len(args.file) > 1:
                print(pcapfile)
        for proto, subproto, i_ssl, ip_src, port_src, ip_dst, port_dst, flow in parse_flows(pcapfile):
          i_bytes = forge_flow_bytes(flow, args.strip, args.nbytes)
          if i_bytes:
              i_bytes.update({"proto": proto, "subproto": subproto, 
                              "IPsrc": ip_src, "PORTsrc": port_src,
                              "IPdst": ip_dst, "PORTdst": port_dst,
                              "SSL_name": i_ssl})
              for bytes_feature in BYTES_FEATURES:
                  flow_bytes[bytes_feature].append(i_bytes[bytes_feature])
        data_bytes = ps.DataFrame(flow_bytes)
        data_bytes.to_csv(args.output, index=False)

if __name__ == "__main__":
    main()
