'''
import argparse
#from scapy.all import *
from scapy.all import DNSQR, DNS, IP, UDP, DNSRR, sr1, send
import socket


# Esta función se encarga de manejar las consultas DNS interceptadas
def handle_dns_packet(packet):
 #chequeo si el campo DNSQR (query DNS) esta en el paquete y opcode == 0, lo cual indica una consulta estandar
    #la parte client port, client ip, UDP no sirve. Hay q usar qname 
    if DNSQR in packet and packet[DNS].opcode == 0:
        # obtnego direccion ip de origen 
        client_ip = packet[IP].src
        # obtengo direccion del puerto de origen
        client_port = packet[UDP].sport
        # obtengo la query DNS del paquete y la decodifico de bytes a una cadena de texto
        dns_query = packet[DNSQR].qname.decode('utf-8')

        print(f"[*] Query recibida: {dns_query} (de {client_ip}:{client_port})")

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
            #crear SOCKET sendto(packet, addr)
            # Enviar la respuesta modificada/sin modificar al cliente
            send(IP(dst=client_ip)/UDP(sport=53, dport=client_port)/response_packet[DNS], verbose=0)
            print(f"[*] Respondiendo {response_packet[DNSRR].rdata} (vía {args.server})")
        else:
            #Si no spoofeas fowardeas
            #socket2.sendto(data,(ip, nro de puerto))
            #socket2.recvfrom(1024)
            print("[*] No se recibió respuesta del servidor DNS remoto")
             #CREAR socket para el caso no respuesta: socket2.sendto(data,(ip, nro de puerto))
             #este mismo socket recibe la respuesta
            #socket2.recvfrom(1024)
            #cerramos socket
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
        print("Esperando consulta...")
        data, addr = dns_socket.recvfrom(1024)
        packet = IP(data)
        handle_dns_packet(packet)
        print(f"Respondiendo {addr}")
        # ERROR EN PONER IP
        
'''
#notas: hay q crear un socket de respuesta, usar qname. Todo lo que dice client ip 
# clien port y UDP no aporta nada, el handle no está bien implementado (no me dijieron que es lo que hay q cambiar igual)
#crear SOCKET sendto(packet, addr) 
#en que momento hay q predeterminar utdt= 1.1.1.1???? y donde?? 
#el codigo no llega al handle! 
#preguntar como codear bien los sockets que nos faltan

import argparse
from scapy.all import DNSQR, DNS, IP, UDP, DNSRR, sr1, send
import socket

# Función para enviar un paquete al cliente
def send_packet(packet, servidor, puerto):
    dns_query = str(packet[DNSQR].qname, 'utf-8')
    resolver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    resolver.connect((servidor, puerto))
    resolver.send(packet)
    response = resolver.recv(1024)
    return response

# Esta función se encarga de manejar las consultas DNS interceptadas
def handle_dns_packet(packet, servidor, puerto, dest_ips, dest):
    if DNSQR in packet and packet[DNS].opcode == 0:
        dns_query = str(packet[DNSQR].qname, 'utf-8')
        dominio = dns_query.split('.')[0]

        print(f"[*] Query recibida: {dns_query} con dominio {dominio} (de {servidor}:{puerto})")

        args = parser.parse_args()

        if response_packet:
            if dominio in dest:
                dest_ip = dest_ips[dest.index(dominio)]
                print(f'[*] Respondiendo {dest_ip} (predeterminado)')
            else:
                response_packet = send_packet(packet, servidor, puerto)
                response_packet = IP(response_packet)
                response_packet[DNS].an = DNSRR(rrname=dns_query, rdata=args.mappings[dns_query])
                response_packet[DNS].ancount = 1
                del response_packet[DNS].ar

                response_packet = bytes(response_packet)
                response_packet = response_packet[:2] + bytes([len(response_packet) - 2]) + response_packet[3:]

            print(f"[*] Respondiendo {response_packet[DNSRR].rdata} (vía {servidor}:{puerto})")
        else:
            print("[*] No se recibió respuesta del servidor DNS remoto")


parser = argparse.ArgumentParser(description='Servidor DNS proxy')
parser.add_argument('-s', '--server', help='Dirección IP del servidor DNS remoto', required=True)
parser.add_argument('-p', '--port', help='Puerto de destino del servidor DNS remoto', type=int, default=53)
parser.add_argument('-d', '--mappings', help='Mapeos de dominio a IP (ej.: example.com=1.2.3.4)', nargs='*', default={})
args = parser.parse_args()

servidor = args.server
puerto = args.port if args.port else 53

dest_ips = [item.split('=')[1] for sublist in args.mappings for item in sublist if '=' in item]
dest = [item.split('=')[0] for sublist in args.mappings for item in sublist if '=' in item]

dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dns_socket.bind(('0.0.0.0', puerto))

print(f'Servidor DNS proxy iniciado. Escuchando consultas DNS {servidor}:{puerto}...')

while True:
    print("Esperando consulta...")
    data, addr = dns_socket.recvfrom(1024)
    packet = IP(data)
    handle_dns_packet(packet, servidor, puerto, dest_ips, dest)
    print(f"Respondiendo {addr}")