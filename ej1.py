import argparse
# from scapy.all import *
from scapy.all import DNSQR, DNS, IP, UDP, DNSRR, sr1, send
import socket

# Esta función se encarga de manejar las consultas DNS interceptadas
def handle_dns_packet(packet):
    # chequeo si el campo DNSQR (query DNS) esta en el paquete y opcode == 0, lo cual indica una consulta estandar
    if DNSQR in packet and packet[DNS].opcode == 0:
        # obtnego direccion ip de origen 
        client_ip = packet[IP].src
        # obtengo direccion del puerto de origen
        client_port = packet[UDP].sport
        # obtengo la query DNS del paquete y la decodifico de bytes a una cadena de texto
        dns_query = packet[DNSQR].qname.decode('utf-8')

        # Enviar la consulta DNS al servidor DNS remoto
        args = parser.parse_args()
        # Obtiene la dirección IP del servidor DNS remoto a partir de los argumentos analizados
        remote_dns_ip = args.server
        # Envía una consulta DNS al servidor DNS remoto (sr1) 
        # Construye un paquete IP con destino a la dirección IP del servidor DNS remoto, con un paquete UDP en el puerto de destino 53 (DNS) y un paquete DNS con el indicador de recursión activado y la consulta DNS obtenida anteriormente
        response_packet = sr1(IP(dst=remote_dns_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=dns_query)), verbose=0)

        # Comprueba si se recibió una respuesta del servidor DNS remoto
        if response_packet:
            # Comprueba si la consulta DNS está presente en los mapeos definidos en los argumentos de línea de comandos
            if dns_query in args.mappings:
                # Modifica el campo de respuesta (an) del paquete DNS de respuesta. 
                # Reemplaza el RR (Resource Record) original con un nuevo RR que tiene el mismo nombre de consulta DNS pero con la dirección IP modificada según el mapeo definido en los argumentos de línea de comandos.
                response_packet[DNS].an = DNSRR(rrname=dns_query, rdata=args.mappings[dns_query])
                # Establece el contador de respuestas (ancount) en 1 para indicar que hay una respuesta modificada del response_packet
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

