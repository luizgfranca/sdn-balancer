from ryu.app import simple_switch_13, simple_monitor_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.controller.controller import Datapath

from ryu.lib.packet import packet as pkt
from ryu.lib.packet import ethernet as eth
from ryu.lib.packet import tcp
from ryu.lib.packet import ipv4 as ip

from ryu.ofproto import ofproto_v1_3_parser

class Balancer(simple_monitor_13.SimpleMonitor13):

    to_balance_hosts = [('10.0.0.2', '00:00:00:00:00:02'), ('10.0.0.3', '00:00:00:00:00:03')]
    

    def __init__(self, *args, **kwargs):
        super(Balancer, self).__init__(*args, **kwargs)
        self.balance_alternator = 0

    def get_datapath(self, event):
        return event.msg.datapath

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        super(Balancer, self).switch_features_handler(ev)
        
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            eth_type=0x0800,
            ip_proto = 6
        )

        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        self.add_flow(datapath, 2, match, actions)


    def choose_host(self):
        self.logger.info('balance_alternator = ' + str(self.balance_alternator))
        next_host = self.to_balance_hosts[self.balance_alternator]
        self.logger.info('next_host: ' + str(next_host))
        
        if(self.balance_alternator == (len(self.to_balance_hosts) - 1)):
            self.balance_alternator = 0
        else:
            self.balance_alternator += 1

        return next_host

    def forward_to_host(self, ev, host_mac):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        
        packet = pkt.Packet(msg.data)
        eth_pkt = packet.get_protocol(eth.ethernet)
        dst = host_mac
        src = eth_pkt.src
        
        in_port = msg.match['in_port']
        self.logger.info("[log] packet in %s %s %s %s", dpid, src, dst, in_port)
        
        self.mac_to_port[dpid][src] = in_port
        
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        actions = [parser.OFPActionOutput(out_port)]
        
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port, 
            actions=actions,
            data=msg.data
        )

        datapath.send_msg(out)

    def balance(self, ev, parser, datapath, ethernet_packet, ip_packet, tcp_packet):
        new_host = self.choose_host()
        source = (ethernet_packet.src, ip_packet.src, tcp_packet.src_port)
        self.logger.info('***operation*** source: ' + str(source))
        old_destination = (ethernet_packet.dst, ip_packet.dst, tcp_packet.dst_port)
        self.logger.info('***operation*** old_destination: ' + str(old_destination))
        new_destination = (new_host[1], new_host[0], tcp_packet.dst_port)
        self.logger.info('***operation*** new_destination: ' + str(new_destination))

        self.mac_to_port.setdefault(ev.msg.datapath.id, {})
        
        in_physical_port = ev.msg.match['in_port']
        self.mac_to_port[ev.msg.datapath.id][ethernet_packet.src] = in_physical_port

        going_match = parser.OFPMatch(
            eth_type=0x0800,
            ip_proto = 6,
            ipv4_src = ip_packet.src,
            tcp_src = tcp_packet.src_port,
            ipv4_dst = ip_packet.dst,
            tcp_dst = tcp_packet.dst_port
        )

        going_actions = [
            parser.OFPActionSetField(ipv4_dst = new_host[0]),
            parser.OFPActionSetField(eth_dst = new_host[1]),
            parser.OFPActionOutput(
                self.mac_to_port[ev.msg.datapath.id][new_host[1]] 
                    if new_host[1] in self.mac_to_port 
                    else ev.msg.datapath.ofproto.OFPP_FLOOD
            )
        ]

        returning_match = parser.OFPMatch(
            eth_type=0x0800,
            ip_proto = 6,
            ipv4_src = new_host[0],
            tcp_src = tcp_packet.dst_port,
            ipv4_dst = ip_packet.src,
            tcp_dst = tcp_packet.src_port
        )

        returning_actions = [
            parser.OFPActionSetField(ipv4_src = ip_packet.dst),
            parser.OFPActionSetField(eth_src = ethernet_packet.dst),
            parser.OFPActionOutput(in_physical_port)
        ]            

        super(Balancer, self).add_flow(datapath, 3, going_match, going_actions)
        super(Balancer, self).add_flow(datapath, 3, returning_match, returning_actions)

        output = parser.OFPPacketOut(
            datapath=datapath, 
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=in_physical_port,
            actions=going_actions,
            data=ev.msg.data
        )

        datapath.send_msg(output)

        #return self.forward_to_host(ev, new_destination[0])

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        datapath = self.get_datapath(ev)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info('[log](datapath): ' + str(datapath))
        self.logger.info('[log](ofproto): ' + str(ofproto))
        self.logger.info('[log](parser): ' + str(parser))
    
        packet = pkt.Packet(ev.msg.data)
        self.logger.info('[log](packet): ' + str(packet))

        ethernet_packet = packet.get_protocol(eth.ethernet)
        self.logger.info('[log](ethernet_packet): ' + str(ethernet_packet))

        ip_packet = packet.get_protocol(ip.ipv4)
        self.logger.info('[log](ip_packet): ' + str(ip_packet))

        tcp_packet = packet.get_protocol(tcp.tcp)
        self.logger.info('[log](tcp_packet): ' + str(tcp_packet))

        if(not (tcp_packet is None) and ((ip_packet.dst, ethernet_packet.dst) in self.to_balance_hosts)):
            return self.balance(
                ev,
                parser, 
                datapath, 
                ethernet_packet, 
                ip_packet, 
                tcp_packet
            )

        return super(Balancer, self)._packet_in_handler(ev)