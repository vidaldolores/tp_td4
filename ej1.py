import argparse
from scapy.all import *
from scapy.all import DNSQR, DNS, IP, UDP, DNSRR
import socket

def handle_dns_packet(packet):
    if DNSQR in packet and packet[DNS].opcode == 0:
        client_ip = packet[IP].src
        client_port = packet[UDP].sport
        dns_query = packet[DNSQR].qname.decode('utf-8')

        # Enviar la consulta DNS al servidor DNS remoto
        remote_dns_ip = args.server
        response_packet = sr1(IP(dst=remote_dns_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=dns_query)), verbose=0)

        if response_packet:
            # Modificar la respuesta si es necesario
            if dns_query in args.mappings:
                response_packet[DNS].an = DNSRR(rrname=dns_query, rdata=args.mappings[dns_query])
                response_packet[DNS].ancount = 1
                del response_packet[DNS].ar

            # Enviar la respuesta modificada/sin modificar al cliente
            send(IP(dst=client_ip)/UDP(sport=53, dport=client_port)/response_packet[DNS], verbose=0)

parser = argparse.ArgumentParser(description='Servidor DNS proxy')
parser.add_argument('-s', '--server', help='Dirección IP del servidor DNS remoto', required=True)
parser.add_argument('-d', '--mappings', help='Mapeos de dominio a IP (ej.: example.com=1.2.3.4)', nargs='*', default={})
args = parser.parse_args()

if __name__ == '__main__':
    # Crear un socket para escuchar las consultas DNS
    dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_socket.bind(('0.0.0.0', 53))

    print('Servidor DNS proxy iniciado. Escuchando consultas DNS...')

    # Procesar continuamente las consultas DNS
    while True:
        data, addr = dns_socket.recvfrom(1024)
        packet = IP(data)
        handle_dns_packet(packet)
