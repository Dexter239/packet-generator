from django.shortcuts import render, HttpResponse, reverse, HttpResponseRedirect
from scapy.layers.inet import *
from scapy.all import *
from generator.models import Packet


def main(request):
    data = []
    packets = Packet.objects.all()
    for interface in get_windows_if_list():
        data.append(interface['name']+": "+interface['description'])
    return render(request, "index.html", context={'interfaces': data, 'packets': packets})


def refreshList(request):
    data = []
    for interface in get_windows_if_list():
        data.append("<option value=\""+interface['name']+": "+interface['description']+"\">"+interface['name']+": "+interface['description']+"</option>")
    return HttpResponse(data)


def safePacket(request):
    if request.method == "GET":
        random.seed(version=2)
        packet = Packet()
        version = request.GET.get('version_ip')
        if not version:
            version = 4
        packet.version = int(version)
        len_ip = request.GET.get('len_ip')
        if len_ip:
            packet.ip_len = int(len_ip)
        ip_tos = request.GET.get('type_service_ip')
        if ip_tos:
            packet.ip_type = int(ip_tos)
        all_len_ip = request.GET.get('all_len_ip')
        if all_len_ip:
            packet.ip_all_len = int(all_len_ip)
        ip_id = request.GET.get('id_ip')
        if ip_id:
            packet.ip_id = int(ip_id)
        ip_flags = request.GET.get('flags_ip')
        if ip_flags:
            packet.ip_flags = int(ip_flags)
        ip_offset = request.GET.get('offset_ip')
        if ip_offset:
            packet.ip_ofst = int(ip_offset)
        ip_ttl = request.GET.get('ttl_ip')
        if ip_ttl:
            packet.ip_ttl = int(ip_ttl)
        ip_num = request.GET.get('num_ip')
        if ip_num:
            packet.ip_num = int(ip_num)
        ip_crc = request.GET.get('crc_ip')
        if ip_crc:
            packet.ip_crc = int(ip_crc)
        ip_src = request.GET.get('src_ip')
        packet.ip_src = ip_src
        ip_dst = request.GET.get('dst_ip')
        packet.ip_dst = ip_dst
        prot = request.GET.get('type_of_protocol')
        packet.protocol = int(prot)
        if prot == '-1':
            return HttpResponse('Error')
        if prot == '0': #TCP
            scr_tcp = request.GET.get('src_port_tcp')
            packet.tcp_src = int(scr_tcp)
            dst_tcp = request.GET.get('dst_port_tcp')
            packet.tcp_dst = int(dst_tcp)
            tcp_seq = request.GET.get('num_seq_tcp')
            if tcp_seq:
                packet.tcp_num = int(tcp_seq)
            tcp_ack = request.GET.get('num_ack_tcp')
            if tcp_ack:
                packet.tcp_ack = int(tcp_ack)
            tcp_offset = request.GET.get('offset_tcp')
            if tcp_offset:
                packet.tcp_ofst = int(tcp_offset)
            tcp_res = request.GET.get('reserv_tcp')
            if tcp_res:
                packet.tcp_reserv = int(tcp_res)
            tcp_flags = request.GET.get('flags_tcp')
            if tcp_flags:
                packet.tcp_flag = int(tcp_flags)
            tcp_win = request.GET.get('size_win_tcp')
            if tcp_win:
                packet.tcp_win = int(tcp_win)
            tcp_crc = request.GET.get('crc_tcp')
            if tcp_crc:
                packet.tcp_crc = int(tcp_crc)
            tcp_ptr = request.GET.get('ptr_tcp')
            if tcp_ptr:
                packet.tcp_ptr = int(tcp_ptr)
            tcp_data = request.GET.get('data_tcp')
            packet.tcp_data = tcp_data
            packet.name = 'TCP' + str(random.randint(0, 100))
            packet.save()
            return HttpResponse(packet.name)
        if prot == '1': #UDP
            src_udp = request.GET.get('src_port_udp')
            packet.udp_src = int(src_udp)
            dst_udp = request.GET.get('dst_port_udp')
            packet.udp_dst = int(dst_udp)
            udp_len = request.GET.get('len_udp')
            if udp_len:
                packet.udp_len = int(udp_len)
            udp_crc = request.GET.get('crc_udp')
            if udp_crc:
                packet.udp_crc = int(udp_crc)
            udp_data = request.GET.get('data_udp')
            packet.udp_data = udp_data
            packet.name = 'UDP' + str(random.randint(0, 100))
            packet.save()
            return HttpResponse(packet.name)
        if prot == '2': #ICMP
            icmp_type = request.GET.get('type_icmp')
            if icmp_type:
                packet.icmp_type = int(icmp_type)
            icmp_code = request.GET.get('code_icmp')
            if icmp_code:
                packet.icmp_code = int(icmp_code)
            icmp_crc = request.GET.get('crc_icmp')
            if icmp_crc:
                packet.icmp_crc = int(icmp_crc)
            icmp_data = request.GET.get('data_icmp')
            packet.icmp_data = icmp_data
            packet.name = 'ICMP'+str(random.randint(0, 100))
            packet.save()
            return HttpResponse(packet.name)


def sendPacket(request):
    if request.method == "POST":
        ip_packet = IP()
        interface = request.POST.get('interfaces_list').split(':')[0]
        version = request.POST.get('version_ip')
        if not version:
            version = 4
        ip_packet.version = int(version)
        len_ip = request.POST.get('len_ip')
        if len_ip:
            ip_packet.ihl = int(len_ip)
        ip_tos = request.POST.get('type_service_ip')
        if ip_tos:
            ip_packet.tos = int(ip_tos)
        all_len_ip = request.POST.get('all_len_ip')
        if all_len_ip:
            ip_packet.len = int(all_len_ip)
        ip_id = request.POST.get('id_ip')
        if ip_id:
            ip_packet.id = int(ip_id)
        ip_flags = request.POST.get('flags_ip')
        if ip_flags:
            ip_packet.flags = int(ip_flags)
        ip_offset = request.POST.get('offset_ip')
        if ip_offset:
            ip_packet.frag = int(ip_offset)
        ip_ttl = request.POST.get('ttl_ip')
        if ip_ttl:
            ip_packet.ttl = int(ip_ttl)
        ip_num = request.POST.get('num_ip')
        if ip_num:
            ip_packet.proto = int(ip_num)
        ip_crc = request.POST.get('crc_ip')
        if ip_crc:
            ip_packet.chksum = int(ip_crc)
        ip_src = request.POST.get('src_ip')
        ip_packet.src = ip_src
        ip_dst = request.POST.get('dst_ip')
        ip_packet.dst = ip_dst
        prot = request.POST.get('type_of_protocol')
        if prot == '-1':
            return HttpResponse('Error')
        if prot == '0': #TCP
            tcp_packet = TCP()
            scr_tcp = request.POST.get('src_port_tcp')
            tcp_packet.sport = int(scr_tcp)
            dst_tcp = request.POST.get('dst_port_tcp')
            tcp_packet.dport = int(dst_tcp)
            tcp_seq = request.POST.get('num_seq_tcp')
            if tcp_seq:
                tcp_packet.seq = int(tcp_seq)
            tcp_ack = request.POST.get('num_ack_tcp')
            if tcp_ack:
                tcp_packet.ack = int(tcp_ack)
            tcp_offset = request.POST.get('offset_tcp')
            if tcp_offset:
                tcp_packet.dataofs = int(tcp_offset)
            tcp_res = request.POST.get('reserv_tcp')
            if tcp_res:
                tcp_packet.reserved = int(tcp_res)
            tcp_flags = request.POST.get('flags_tcp')
            if tcp_flags:
                tcp_packet.flags = int(tcp_flags)
            tcp_win = request.POST.get('size_win_tcp')
            if tcp_win:
                tcp_packet.window = int(tcp_win)
            tcp_crc = request.POST.get('crc_tcp')
            if tcp_crc:
                tcp_packet.chksum = int(tcp_crc)
            tcp_ptr = request.POST.get('ptr_tcp')
            if tcp_ptr:
                tcp_packet.urgptr = int(tcp_ptr)
            tcp_data = request.POST.get('data_tcp')
            send(ip_packet / tcp_packet / tcp_data, iface=interface)
        if prot == '1': #UDP
            udp_packet = UDP()
            src_udp = request.POST.get('src_port_udp')
            udp_packet.sport = int(src_udp)
            dst_udp = request.POST.get('dst_port_udp')
            udp_packet.dport = int(dst_udp)
            udp_len = request.POST.get('len_udp')
            if udp_len:
                udp_packet.len = int(udp_len)
            udp_crc = request.POST.get('crc_udp')
            if udp_crc:
                udp_packet.chksum = int(udp_crc)
            udp_data = request.POST.get('data_udp')
            send(ip_packet / udp_packet / udp_data, iface=interface)
        if prot == '2': #ICMP
            icmp_packet = ICMP()
            icmp_type = request.POST.get('type_icmp')
            if icmp_type:
                icmp_packet.type = int(icmp_type)
            icmp_code = request.POST.get('code_icmp')
            if icmp_code:
                icmp_packet.code = int(icmp_code)
            icmp_crc = request.POST.get('crc_icmp')
            if icmp_crc:
                icmp_packet.chksum = int(icmp_crc)
            icmp_data = request.POST.get('data_icmp')
            send(ip_packet / icmp_packet / icmp_data, iface=interface)
    return HttpResponse('ok')


def sendAll(request):
    if request.method == "POST":
        interface = request.POST.get('interfaces_list').split(':')[0]
        packets = Packet.objects.all()
        if packets:
            for packet in packets:
                ip_packet = IP()
                ip_packet.version = packet.version
                if packet.ip_len:
                    ip_packet.ihl = packet.ip_len
                if packet.ip_type:
                    ip_packet.tos = packet.ip_type
                if packet.ip_all_len:
                    ip_packet.len = packet.ip_all_len
                if packet.ip_id:
                    ip_packet.id = packet.ip_id
                if packet.ip_flags:
                    ip_packet.flags = packet.ip_flags
                if packet.ip_ofst:
                    ip_packet.frag = packet.ip_ofst
                if packet.ip_ttl:
                    ip_packet.ttl = packet.ip_ttl
                if packet.ip_num:
                    ip_packet.proto = packet.ip_num
                if packet.ip_crc:
                    ip_packet.chksum = packet.ip_crc
                ip_packet.src = packet.ip_src
                ip_packet.dst = packet.ip_dst
                if packet.protocol == -1:
                    return HttpResponse('Error')
                if packet.protocol == 0:  # TCP
                    tcp_packet = TCP()
                    tcp_packet.sport = packet.tcp_src
                    tcp_packet.dport = packet.tcp_dst
                    if packet.tcp_num:
                        tcp_packet.seq = packet.tcp_num
                    if packet.tcp_ack:
                        tcp_packet.ack = packet.tcp_ack
                    if packet.tcp_ofst:
                        tcp_packet.dataofs = packet.tcp_ofst
                    if packet.tcp_reserv:
                        tcp_packet.reserved = packet.tcp_reserv
                    if packet.tcp_flag:
                        tcp_packet.flags = packet.tcp_flag
                    if packet.tcp_win:
                        tcp_packet.window = packet.tcp_win
                    if packet.tcp_crc:
                        tcp_packet.chksum = packet.tcp_crc
                    if packet.tcp_ptr:
                        tcp_packet.urgptr = packet.tcp_ptr
                    send(ip_packet / tcp_packet / packet.tcp_data, iface=interface)
                if packet.protocol == 1:  # UDP
                    udp_packet = UDP()
                    udp_packet.sport = packet.udp_src
                    udp_packet.dport = packet.udp_dst
                    if packet.udp_len:
                        udp_packet.len = packet.udp_len
                    if packet.udp_crc:
                        udp_packet.chksum = packet.udp_crc
                    send(ip_packet / udp_packet / packet.udp_data, iface=interface)
                if packet.protocol == 2:  # ICMP
                    icmp_packet = ICMP()
                    if packet.icmp_type:
                        icmp_packet.type = packet.icmp_type
                    if packet.icmp_code:
                        icmp_packet.code = packet.icmp_code
                    if packet.icmp_crc:
                        icmp_packet.chksum = packet.icmp_crc
                    send(ip_packet / icmp_packet / packet.icmp_data, iface=interface)
            return HttpResponse('Ok')
        return HttpResponse('Error')
    return HttpResponse('Error')


def delPacket(request):
    if request.method == "GET":
        packet_name = request.GET.get('packet_name')
        packet = Packet.objects.get(name=packet_name)
        packet.delete()
        return HttpResponse('Ok')
    return HttpResponse('Error')