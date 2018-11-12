#!/usr/bin/env python3
#!coding:utf-8

import time
import struct
import socket
import select
import sys


def calc_chesksum(data):
    data_len = len(data)
    is_odd_number = data_len % 2
    sum = 0

    for i in range(0, data_len - is_odd_number, 2):
        # read 2 byte as a number once and add them up
        sum += (data[i]) + ((data[i+1]) << 8)

    if is_odd_number:
        # add last byte as a number if exist
        sum += (data[-1])

    # add high 16 digits and low 16 digits until sum shown in 16 digits
    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16)

    # take the inverse value
    checksum = ~sum & 0xffff

    # host byte sequence to network byte sequence
    checksum = checksum >> 8 | (checksum << 8 & 0xff00)

    return checksum


def request_ping(dst_addr, imcp_packet, rawsocket):
    # record request time
    request_ping_time = time.time()

    # send data to the socket
    rawsocket.sendto(imcp_packet, (dst_addr, 80))

    return request_ping_time


def pack_message(data_type, data_code, data_checksum, data_id, data_seq, payload_body):
    # pack string into binary format
    imcp_packet = struct.pack('>BBHHH32s', data_type, data_code,
                              data_checksum, data_id, data_seq, payload_body)

    # calc check sum
    icmp_chesksum = calc_chesksum(imcp_packet)

    # repack with calculated checksum
    imcp_packet = struct.pack('>BBHHH32s', data_type, data_code,
                              icmp_chesksum, data_id, data_seq, payload_body)

    return imcp_packet


def reply_ping(data_seq, rawsocket):
    time_left = 2  # total allowance time for this request(second)
    while True:
        # try get reply packet within timeout time(second)
        start_select_time = time.time()
        what_ready = select.select([rawsocket], [], [], time_left)
        wait_time = time.time() - start_select_time

        # timeout
        if what_ready[0] == []:  
            return -1, -1

        receive_time = time.time()

        # get reply packet
        received_packet = rawsocket.recvfrom(1024)[0]

        # get ttl from ip header
        ip_header = received_packet[0:20]
        ttl = struct.unpack(">BBHHHBBHLL", ip_header)[5]

        # get type and sequence from icmp header
        icmp_header = received_packet[20:28]
        reply_type = struct.unpack(">BBHHH", icmp_header)[0]
        reply_seq = struct.unpack(">BBHHH", icmp_header)[4]

        # get icmp echo reply with same sequence
        if reply_type == 0 and reply_seq == data_seq:
            return receive_time, ttl

        time_left -= wait_time

        # no time left
        if time_left <= 0:
            return -1, -1


def ping(target_name, count, size):
    data_type = 8  # icmp echo request
    data_code = 0  # must be 0
    data_checksum = 0  # initialize with 0
    data_id = 0  # identifier
    data_seq = 1  # sequence number

    # data
    payload_body = ''
    for i in range(0, size):
        payload_body = payload_body + chr(97 + (i % 26))
    payload_body = bytes(payload_body, encoding='utf-8')

    # get ipv4 address
    dst_addr = socket.gethostbyname(target_name)

    print("正在 Ping {0} [{1}] 具有 {2} 字节的数据:".format(
        target_name, dst_addr, size))

    # ceate socket
    rawsocket = socket.socket(
        socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))

    receive_num = 0  # num of reply get
    max_time = -1  # max time
    min_time = 2147483647  # min time
    time_sum = 0  # sum of time

    for i in range(0, count):
        # pack message
        icmp_packet = pack_message(
            data_type, data_code, data_checksum, data_id + i, data_seq + i, payload_body)

        # request ping
        request_ping_time = request_ping(dst_addr, icmp_packet, rawsocket)

        # reply ping
        reply_ping_time, ttl = reply_ping(data_seq + i, rawsocket)

        # calc times
        times = reply_ping_time - request_ping_time

        if times > 0:
            print("来自 {0} 的回复: 字节={1} 时间={2}ms TTL={3}".format(
                dst_addr, size, int(times * 1000), int(ttl)))
            if int(times * 1000) > max_time:
                max_time = int(times * 1000)
            if int(times * 1000) < min_time:
                min_time = int(times * 1000)
            receive_num += 1
            time_sum += int(times * 1000)
            time.sleep(0.7)
        else:
            print("请求超时。")

    # show summary
    print("\n{0}的Ping统计信息：".format(dst_addr))
    print("    数据包：已发送 = {0}，已接收 = {1}，丢失 = {2}（{3}% 丢失），".format(
        count, receive_num, count - receive_num, round((count - receive_num) / size * 100)))
    print("往返行程的估计时间（以毫秒为单位）：")
    print("    最短 = {0}ms，最长 = {1}ms，平均 = {2}ms\n".format(
        min_time, max_time, round(time_sum / count)))


if __name__ == "__main__":
    count = 4  # ping time count
    size = 32  # ping data size

    try:
        if len(sys.argv) < 2:
            raise RuntimeError()

        # pick paramaters
        for i in range(1, len(sys.argv)):
            if sys.argv[i] == '-n':
                count = int(sys.argv[i + 1])
            if sys.argv[i] == '-l':
                size = int(sys.argv[i + 1])
    except:
        sys.exit('用法: python3 ping.py [-n count] [-l size] target_name')

    ping(sys.argv[-1], count, size)

    # By.bunnyxt 2018-11-12
