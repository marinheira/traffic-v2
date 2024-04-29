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
    "is_tcp" # используется ли TCP на транспортном уровне
             # (0 означает UDP, другие протоколы не рассматриваются)
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
    reg = re.compile(r'(UDP|TCP) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5}) <-> (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5}).*\[proto: [\d+\.]*\d+\/(\w+\.?\w+)*\]')
    flows = {}
    apps = {}
    for captures in re.findall(reg, raw):
        transp_proto, ip1, port1, ip2, port2, app_proto = captures
        ip1 = ip_from_string(ip1)
        ip2 = ip_from_string(ip2)
        port1 = int(port1)
        port2 = int(port2)
        key = (transp_proto.lower(),
            frozenset(((ip1, port1), (ip2, port2))))
        flows[key] = []
        apps[key] = app_proto.split(".")
        if len(apps[key]) == 1:
            apps[key].append(None)

    for ts, raw in dpkt.pcap.Reader(open(pcapfile, "rb")):
        eth = dpkt.ethernet.Ethernet(raw)
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
        key = (transp_proto, frozenset(((ip_from_string(socket.inet_ntoa(ip.src)), seg.sport),
            (ip_from_string(socket.inet_ntoa(ip.dst)), seg.dport))))
        try:
            assert key in flows
        except AssertionError:
            print("Не найдена пара IP в выгрузке ndpiReader, создан ключ во flows")
            print(transp_proto)
            print(repr(socket.inet_ntoa(ip.src)), seg.sport)
            print(repr(socket.inet_ntoa(ip.dst)), seg.dport)
            # raise
            flows[key] = []
            apps[key] = app_proto.split(".")
            if len(apps[key]) == 1:
                apps[key].append(None)
        flows[key].append(eth)

    for key, flow in flows.items():
        yield apps[key][0], apps[key][1], flow

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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", nargs="+", help="pcap file")
    parser.add_argument("-o", "--output", help="output csv file", default="flows.csv")
    parser.add_argument("-s", "--strip", help="leave only first N datagramms", metavar = "N", default=0, type=int)
    args = parser.parse_args()
    flows = {feature: [] for feature in FEATURES}
    for pcapfile in args.file:
        if len(args.file) > 1:
            print(pcapfile)
        for proto, subproto, flow in parse_flows(pcapfile):
            stats = forge_flow_stats(flow, args.strip)
            if stats:
                stats.update({"proto": proto, "subproto": subproto})
                for feature in FEATURES:
                    flows[feature].append(stats[feature])
    data = ps.DataFrame(flows)
    data.to_csv(args.output, index=False)

if __name__ == "__main__":
    main()
