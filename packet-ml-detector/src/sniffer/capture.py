import threading
import time
from collections import deque
from scapy.all import sniff, IP, TCP, UDP, ICMP
import json

class PacketSniffer:
    def __init__(self, interface="eth0", packet_limit=1000):
        self.interface = interface
        self.packet_limit = packet_limit
        self.buffer = deque(maxlen=packet_limit)
        self.running = False
        self.callbacks = []
        
    def register_callback(self, func):
        self.callbacks.append(func)
    
    def packet_handler(self, packet):
        if not self.running:
            return
            
        features = self.extract_features(packet)
        if features:
            self.buffer.append(features)
            for cb in self.callbacks:
                cb(features)
    
    def extract_features(self, packet):
        features = {
            'timestamp': time.time(),
            'packet_len': len(packet),
            'ip_len': 0,
            'ttl': 0,
            'protocol': 0,
            'flags': 0,
            'tcp_win': 0,
            'tcp_flags': 0,
            'udp_len': 0,
            'icmp_type': -1,
            'payload_size': 0,
            'src_port': 0,
            'dst_port': 0,
            'ip_frag': 0,
            'ip_id': 0
        }
        
        if IP in packet:
            ip = packet[IP]
            features['ip_len'] = ip.len
            features['ttl'] = ip.ttl
            features['protocol'] = ip.proto
            features['ip_frag'] = ip.frag
            features['ip_id'] = ip.id
            
            if TCP in packet:
                tcp = packet[TCP]
                features['src_port'] = tcp.sport
                features['dst_port'] = tcp.dport
                features['tcp_win'] = tcp.window
                features['tcp_flags'] = tcp.flags
                features['payload_size'] = len(tcp.payload)
                
            elif UDP in packet:
                udp = packet[UDP]
                features['src_port'] = udp.sport
                features['dst_port'] = udp.dport
                features['udp_len'] = udp.len
                
            elif ICMP in packet:
                icmp = packet[ICMP]
                features['icmp_type'] = icmp.type
                
        return features
    
    def start(self):
        self.running = True
        self.thread = threading.Thread(
            target=sniff,
            kwargs={
                'iface': self.interface,
                'prn': self.packet_handler,
                'store': False,
                'timeout': None
            },
            daemon=True
        )
        self.thread.start()
        
    def stop(self):
        self.running = False
        
    def get_buffer(self):
        return list(self.buffer)