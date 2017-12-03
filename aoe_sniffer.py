#!/usr/bin/env python3
import os
from threading import Thread, Lock
from time import sleep
import subprocess
import datetime
import pyshark


__author__ = "Iván de Paz Centeno"

def segments(l, count):
    blocks = len(l) // count
    for b in range(blocks):
        yield l[b*count:(b+1)*count]

    if len(l) % count > 0:
        yield l[(blocks)*count:]

def chrhex(hex_string):
    result = ""

    for segment in segments(hex_string, 2):
        result += chr(int(segment, 16))

    return result

def get_ip(iface):
    import os

    ipv4 = os.popen('ip addr show {}'.format(iface)).read().split("inet ")[1].split("/")[0]
    #ipv6 = os.popen('ip addr show {}'.format(iface)).read().split("inet6 ")[1].split("/")[0]
    return ipv4


SECONDS_TO_TRIGGER_BAN = 40
KICK_BAN_THRESHOLD = 1

class AoeSniffer(object):
    __players = {}
    __free_positions = [1,2,3,4,5,6,7,8]
    __potentially_banned_ips = {}
    __exit = False
    __lock = Lock()
    __last_check = datetime.datetime.now()
    __banned_ips = []

    @property
    def is_exit_requested(self):
        with self.__lock:
            return self.__exit

    def finish(self):
        with self.__lock:
            self.__exit = True

    def __init__(self, net_interface='eth0'):
        """

        :param net_interface: the network interface to sniff from. Examples "eth0", "wlan0", "tun0", ...
        """
        self.__interface = interface
        self.__private_ip = get_ip(interface)
        self.__capture_thread = Thread(target=self.__capture_func, daemon=True)
        self.__capture_thread.start()

    def __capture_func(self):
        capture = pyshark.LiveCapture(interface=self.__interface)
        for packet in capture.sniff_continuously():
            if (datetime.datetime.now() - self.__last_check).seconds > SECONDS_TO_TRIGGER_BAN:
                self.__last_check = datetime.datetime.now()
                self.__potentially_banned_ips = {}

            if 'ip' in packet and 'UDP' in packet:

                if packet.ip.dst == self.__private_ip:
                    remote_ip = packet.ip.src
                    remote_country = packet.ip.geosrc_country
                    packet_length = int(str(packet.length))

                    if "data" in packet:

                        if packet_length > 300:
                            # We pick a free position
                            position = self.__free_positions.pop(0)
                            #print("User connected from {} (Country: {}). Playing as position {}.".format(remote_ip,
                            #                                                                             remote_country,
                            #                                                                             position))
                            self.__players[remote_ip] = {'position': position, 'country': remote_country, 'quit_invoked': 0}
                        elif packet.data.data == "beefface":
                            self.__player_disconected__(remote_ip, remote_country)

                elif packet.ip.dst in self.__players:
                    remote_ip = packet.ip.dst
                    remote_country = packet.ip.geodst_country
                    if "data" in packet and packet.data.data == "beefface":
                        # Hey, I kicked someone. If I kick someone enough times in less than a certain time, I should
                        # ban him

                        if self.__player_disconected__(remote_ip, remote_country):
                            if remote_ip not in self.__potentially_banned_ips:
                                self.__potentially_banned_ips[remote_ip] = 0

                            self.__potentially_banned_ips[remote_ip] += 1

                            if self.__potentially_banned_ips[remote_ip] > KICK_BAN_THRESHOLD:
                                self.ban_ip(remote_ip)

    def __player_disconected__(self, player_ip, player_country):
        self.__players[player_ip]['quit_invoked'] += 1
        fully_disconnected = False

        if self.__players[player_ip]['quit_invoked'] == 3:
            free_position = self.__players[player_ip]['position']
            self.__free_positions.append(free_position)
            self.__free_positions = sorted(self.__free_positions)
            #print(
            #    "User disconected from {} (Country: {}). Position {} is now free".format(player_ip,
            #                                                                             player_country,
            #                                                                             free_position))
            fully_disconnected = True
            del self.__players[player_ip]

        return fully_disconnected

    def __str__(self):
        result = []
        users = {user_data['position']: {'ip': ip, 'country': user_data['country']} for ip, user_data in self.__players.items()}
        positions = [1,2,3,4,5,6,7,8]
        result.append("==========\n{} PLAYERS\n==========".format(len(users)))
        for user_position in positions:
            try:
                user_data = users[user_position]
                result.append("[{}] - IP: {}; Country: {}".format(user_position, user_data['ip'], user_data['country']))
            except KeyError:
                result.append("[{}] - EMPTY".format(user_position))

        result.append("\nBanned IPs: {}".format(self.__banned_ips))

        return "\n".join(result)

    def ban_ip(self, ip):
        p = subprocess.Popen(["iptables", "-A", "INPUT", "-p", "udp", "-s", ip, "-j", "DROP"],stdout=subprocess.PIPE)
        output, err = p.communicate()
        p = subprocess.Popen(["iptables", "-A", "OUTPUT", "-p", "udp", "-s", ip, "-j", "DROP"],stdout=subprocess.PIPE)
        output, err = p.communicate()
        self.__banned_ips.append(ip)


interface = 'wlxec086b17c65f'

sniffer = AoeSniffer(interface)
while True:
    os.system('clear')
    print(sniffer)
    sleep(0.5)