# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# To Do-

# DONE 1. Check logic of add and delete flows and verify working using ovs-ofctl dump-flows 
# DONE 2. Initiate all the TCP buffers as soon as TCP handshake is done. Buffer all the packets of TCP since the
#     beginning till TCP Termination. After reconnection send all the packets at once. And when get the ack
#     delete the packets.
# DONE 3. Create different buffer for non-TCP flows when the MN disconnects and buffer all the packets. During 
#     reconnection send all the packets at once and clear buffer.
# 4. Resend those packets for which we receive 3 duplicate ack. Create a logic for 3 duplicate acks
# 5. Implement ZWA at controller to freeze the Stationary host / Look for other alternatives as well                   


from ryu.topology import api
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto as ipp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.TCP_buffered_packets = {}
        self.buffered_packets = {}
        self.threedup = {}
        self.flag = 0
        self.group_id = 0
        self.tcp_flow_to_add = {"0000000000000001" : "00:00:00:00:00:04",
                                "1152921504606846977" : "00:00:00:00:00:07",
                                "1152921504606846978" : "00:00:00:00:00:07",
                                "1152921504606846979" : "00:00:00:00:00:07"}

    def print_dictionary_keys(self, dictionary, prefix=()):
        for key, value in dictionary.items():
            if isinstance(prefix, str):
                prefix = (prefix,)
            if isinstance(key, str) or isinstance(key, int):
                key = (key,)
            current_key = prefix + key
            print(current_key)
            if isinstance(value, dict):
                self.print_dictionary_keys(value, prefix=current_key)

    def get_nested_values(self, d):
        values = []
        for k, v in d.items():
            if isinstance(v, dict):
                values.extend(self.get_nested_values(v))
            else:
                values.append(v)
        return values

    def get_switches(self):
        switch_list = []
        for sw in api.get_all_switch(self):
            switch_list.append(sw.dp)
        return switch_list

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # dpid = format(datapath.id, "d").zfill(16)
        # if (dpid == '1152921504606846977' or dpid == '1152921504606846978' or dpid == '115292150460684697'):

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        #   ofproto.OFPCML_NO_BUFFER
                                        )]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_mobile_flow(self, datapath, dst_mac):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = format(datapath.id, "d").zfill(16)
        node_port = self.mac_to_port[dpid][dst_mac]

        match = parser.OFPMatch(eth_dst=dst_mac)
        actions = [parser.OFPActionOutput(node_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, match=match,
                                command=ofproto.OFPFC_ADD,
                                priority=1,
                                cookie=0,
                                instructions=inst)
        datapath.send_msg(mod)

        # Send all the Non TCP buffered packets to the mobile node at once
        if dst_mac in self.buffered_packets:
            for packet_data in self.buffered_packets[dst_mac]:
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=ofproto.OFPP_CONTROLLER, actions=actions,
                    data=packet_data)
                datapath.send_msg(out)
            # Clear the buffered packets for the mobile node 
            del self.buffered_packets[dst_mac]
        if dst_mac in self.TCP_buffered_packets:
            for packet_data in self.get_nested_values(self.TCP_buffered_packets[dst_mac]):
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=ofproto.OFPP_CONTROLLER, actions=actions,
                    data=packet_data)
                datapath.send_msg(out)
        return

    def del_mobile_flow(self, datapath, dst):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match1 = parser.OFPMatch(eth_dst=dst)
        mod = parser.OFPFlowMod(
            datapath=datapath, match=match1, cookie=0,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0,)
        datapath.send_msg(mod)

        match2 = parser.OFPMatch(eth_src=dst)
        mod = parser.OFPFlowMod(
            datapath=datapath, match=match2, cookie=0,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0,)
        datapath.send_msg(mod)

        self.buffered_packets.setdefault(dst, [])

    def handle_ack(self, pkt, dst_mac, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = format(datapath.id, "d").zfill(16)
        node_port = self.mac_to_port[dpid][dst_mac]
        # node_port = 1
        actions = [parser.OFPActionOutput(node_port)]

        tcp_ack_pkt = pkt.get_protocol(tcp.tcp)
        src_ip = pkt.get_protocol(ipv4.ipv4).src or pkt.get_protocol(ipv6.ipv6).src
        dst_ip = pkt.get_protocol(ipv4.ipv4).dst or pkt.get_protocol(ipv6.ipv6).dst
        src_port = tcp_ack_pkt.src_port
        dst_port = tcp_ack_pkt.dst_port
        ack=tcp_ack_pkt.ack

        key_ack = (dst_ip, dst_port, src_ip, src_port)
        key_3ack = (dst_ip, dst_port, src_ip, src_port, ack)
        
        if key_3ack in self.threedup:
            self.threedup[key_3ack]+=1
        else:
            self.threedup[key_3ack]=1

        if self.threedup[key_3ack] > 2:
            self.flag=1
            self.print_dictionary_keys(self.TCP_buffered_packets)
            if key_ack in self.TCP_buffered_packets[dst_mac]:
                packet_data = self.TCP_buffered_packets[dst_mac][key_ack][ack]
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=ofproto.OFPP_CONTROLLER, actions=actions,
                    data=packet_data)
                datapath.send_msg(out)
                self.threedup[key_3ack] = 0

        if key_ack in self.TCP_buffered_packets[dst_mac]:
            seq_to_delete = []
            for seq in self.TCP_buffered_packets[dst_mac][key_ack]:
                if seq < ack:
                    seq_to_delete.append(seq)

            # delete the keys from the dictionary outside of the for loop
            for seq in seq_to_delete:
                del self.TCP_buffered_packets[dst_mac][key_ack][seq]

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        self.flag=0
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst_mac = eth.dst
        src_mac = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src_mac] = in_port
        if "1152921504606846977" in self.mac_to_port:
            self.mac_to_port["1152921504606846977"]["00:00:00:00:00:07"] = 1
        if "1152921504606846978" in self.mac_to_port:
            self.mac_to_port["1152921504606846978"]["00:00:00:00:00:07"] = 1
        if "1152921504606846979" in self.mac_to_port:
            self.mac_to_port["1152921504606846979"]["00:00:00:00:00:07"] = 1



        if tcp_pkt:

            src_ip = pkt.get_protocol(ipv4.ipv4).src or pkt.get_protocol(ipv6.ipv6).src
            dst_ip = pkt.get_protocol(ipv4.ipv4).dst or pkt.get_protocol(ipv6.ipv6).dst
            src_port = tcp_pkt.src_port
            dst_port = tcp_pkt.dst_port
            key = (src_ip, src_port, dst_ip, dst_port)

            self.logger.info("""TCP packet in switch: %s, 
                             Src MAC: %s, Src IP: %s, Src Port: %s, 
                             Dst MAC: %s, Dst IP: %s, Dst Port: %s, 
                             Seq : %s, Ack : %s, Inport: %s""", dpid, src_mac, src_ip, src_port, dst_mac, dst_ip, dst_port, tcp_pkt.seq, tcp_pkt.ack, in_port)

            if (tcp_pkt.has_flags(tcp.TCP_SYN)):
                self.TCP_buffered_packets.setdefault(dst_mac,{}).setdefault(key,{})

            elif (tcp_pkt.has_flags(tcp.TCP_FIN, tcp.TCP_ACK) or tcp_pkt.has_flags(tcp.TCP_RST, tcp.TCP_ACK)):
                if dst_mac in self.TCP_buffered_packets:
                    if key in self.TCP_buffered_packets[dst_mac]:
                        del self.TCP_buffered_packets[dst_mac][key]

            else:
                # self.buffered_packets[dst_mac]["TCP"].append(msg.data)
                self.TCP_buffered_packets[dst_mac][key].setdefault(tcp_pkt.seq,msg.data)
                if (tcp_pkt.has_flags(tcp.TCP_ACK) or tcp_pkt.has_flags(tcp.TCP_ACK, tcp.TCP_PSH)): 
                    self.handle_ack(pkt, src_mac, datapath)
                if self.flag == 1:
                    return




        if udp_pkt and udp_pkt.src_port==8000:
            self.logger.info("Disconnect packet in %s %s %s %s", dpid, src_mac, dst_mac, in_port)
            for dp in self.get_switches():
                self.del_mobile_flow(dp, src_mac)
            return

        elif udp_pkt and udp_pkt.src_port==8001:
            self.logger.info("Connect packet in %s %s %s %s", dpid, src_mac, dst_mac, in_port)
            self.add_mobile_flow(datapath, src_mac)
            return

        if dst_mac in self.buffered_packets and not tcp_pkt:
            self.buffered_packets[dst_mac].append(msg.data)
            return

        else:
            if dst_mac in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst_mac]
            else:
                out_port = ofproto.OFPP_FLOOD

            if out_port != ofproto.OFPP_FLOOD and dpid in self.tcp_flow_to_add:
                actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
                match = parser.OFPMatch(eth_src=self.tcp_flow_to_add[dpid], ip_proto=ipp.IPPROTO_TCP, eth_type=ether_types.ETH_TYPE_IP)
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 2, match, actions, msg.buffer_id)
                else:
                    self.add_flow(datapath, 2, match, actions)
                del self.tcp_flow_to_add[dpid]

            actions = [parser.OFPActionOutput(out_port)]
            # install a flow to avoid packet_in next time for non TCP packets
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(eth_dst=dst_mac)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)