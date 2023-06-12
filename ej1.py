import argparse
from scapy.all import DNSQR, DNS, IP, UDP, DNSRR, send, sr1
import socket

# Función para enviar un paquete al cliente

def send_packet(data, direc_servidor , puerto):
    sock =  socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(data, (direc_servidor, puerto))
    response, _ = sock.recvfrom(4096)
    return response


#cambiar esto 
def extract_ip_address(response_packet):
    dest_ip = None
    try:
        dest_ip = socket.inet_ntoa(response_packet[-4:])
    except:
        pass
    return dest_ip


def handle_dns_packet(packet, addr, servidor, puerto, dest_ips, dest):
    packet = DNS(data)
            
    if DNSQR in packet and packet[DNS].opcode == 0:
        dns_query = packet[DNSQR].qname.decode()
        dns_query = dns_query[:-1]
        dominio = dns_query.split()[0]

        print(f"[*] Query recibida: {dominio} (de {addr[0]}:{addr[1]})")

        if dominio not in dest:
            response_data = send_packet(data, servidor, puerto)
            ip_address = extract_ip_address(response_data)
    
            if ip_address:
                print(f'[*] Respondiendo {ip_address} (vía {servidor})')
                # Construir la respuesta DNS con la dirección IP real
                response_packet = f'{dominio} A {ip_address}'

            send(response_packet, verbose=0)

        else:
            index = dest.index(dominio)
            destination_ip = dest_ips[index]
            
            print(f'[*] Respondiendo {destination_ip} (predeterminado)')
            # Construir la respuesta DNS con la dirección IP predeterminada
            response_packet = f'{dominio} A {destination_ip}'

    else:
        print("[*] No se recibió respuesta del servidor DNS remoto")
    dns_socket.sendto(response_packet.encode(), addr)

parser = argparse.ArgumentParser(description='Servidor DNS proxy')
parser.add_argument('-s', '--server', help='Dirección IP del servidor DNS remoto', required=True)
parser.add_argument('-p', '--port', type=int, help='Puerto de esucha del servidor DNS proxy')
parser.add_argument('-d', '--mappings', help='Mapeos de dominio a IP (ej.: example.com=1.2.3.4)', nargs='+', default={})
args = parser.parse_args()

servidor = args.server
puerto = args.port if args.port else 53

dest_ips = [item.split(':')[1] for item in args.mappings]
dest = [item.split(':')[0] for item in args.mappings]

print(f'Servidor DNS proxy iniciado. Escuchando consultas DNS en {servidor}...')

# Configurar socket UDP para recibir consultas DNS
dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dns_socket.bind(('0.0.0.0', puerto))

while True:
    print("Esperando consulta...")
    data, addr = dns_socket.recvfrom(1024)
    #packet = IP(data)
    handle_dns_packet(data, addr, servidor, puerto, dest_ips, dest)
    print(f"Respondiendo {addr}")
