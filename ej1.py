import argparse  
from scapy.all import DNSQR, DNS, IP, UDP, DNSRR, send, sr1  
import socket  

# Creamos una función para enviar el paquete al servidor DNS remoto
def send_packet(data, direc_servidor, puerto):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(data, (direc_servidor, puerto))
    response, _ = sock.recvfrom(4096)
    return response

#Creamos una función que extrae la dirección IP de la respuesta,la usamos en el caso de que no se ecuentre en la lista "dest" creada mas adelante en el codigo
def extraer_direc_ip(response):
    direc_ip = None
    try:
        direc_ip = socket.inet_ntoa(response[-4:])
    except:
        pass
    return direc_ip

#Creamos la función para manejar el paquete DNS recibido
def handle_dns_packet(packet, addr, servidor, puerto, dest_ips, dest):
    packet = DNS(data)  #Convertimos los datos del paquete en un objeto DNS

    if DNSQR in packet and packet[DNS].opcode == 0:  #Verificamos si el paquete contiene una consulta DNS y  si el opcode es 0, lo cual sucede si es una consulta estandar
        dns_query = packet[DNSQR].qname.decode()  #Si el opcode es 0, obtenemos la consulta DNS como un string
        dns_query = dns_query[:-1]  #Eliminamos el punto final de la consulta DNS
        dominio = dns_query.split()[0]  #Obtenemos el nombre de dominio de la consulta

        print(f"[*] Query recibida: {dominio} (de {addr[0]}:{addr[1]})")

        if dominio not in dest:  #Verificamos si el dominio no está en la lista de destinos
            response_data = send_packet(data, servidor, puerto)  #Si no esta, enviamos la consulta al servidor DNS remoto
            direc_ip = extraer_direc_ip(response_data)  #Extraemos la dirección IP de la respuesta

            if direc_ip:
                print(f'[*] Respondiendo {direc_ip} (vía {servidor})')
                response_packet = f'{dominio} A {direc_ip}'  #Creamos el paquete de respuesta

            send(response_packet, verbose=0)  #Enviamos la respuesta al cliente

        else:  #Si el dominio está en la lista de destinos personalizados
            idx = dest.index(dominio)  #Obtenemos el índice del dominio en la lista de destinos
            destination_ip = dest_ips[idx]  #Obtenemos la dirección IP del destino

            print(f'[*] Respondiendo {destination_ip} (predeterminado)')
            response_packet = f'{dominio} A {destination_ip}'  #Creamos el paquete de respuesta

    else:
        print("[*] No se recibió respuesta del servidor DNS remoto")

    dns_socket.sendto(response_packet.encode(), addr)  #Enviamos la respuesta al cliente

#Configuramos los argumentos
parser = argparse.ArgumentParser(description='Servidor DNS proxy')
parser.add_argument('-s', '--server', help='Dirección IP del servidor DNS remoto', required=True)
parser.add_argument('-p', '--port', type=int, help='Puerto de escucha del servidor DNS proxy')
parser.add_argument('-d', '--mappings', help='Mapeos de dominio a IP (ej.: example.com=1.2.3.4)', nargs='+', default={})
args = parser.parse_args()

servidor = args.server  #Creamos variable con la dirección IP del servidor DNS remoto
puerto = args.port if args.port else 53  #Creamos variable con el puerto de escucha del servidor DNS proxy

dest_ips = [item.split(':')[1] for item in args.mappings]  #Creamos una lista con las direcciones IP de destino extraídas de los mapeos
dest = [item.split(':')[0] for item in args.mappings]  #Creamos una lista con los nombres de dominio de destino extraídos de los mapeos

print(f'Servidor DNS proxy iniciado. Escuchando consultas DNS en {servidor}...')

dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dns_socket.bind(('0.0.0.0', puerto))  #Enlazamos el socket a todas las interfaces de red en el puerto

while True:
    print("Esperando consulta...")
    data, addr = dns_socket.recvfrom(1024)  #Creamos variables para recibir los datos y dirección del cliente
    handle_dns_packet(data, addr, servidor, puerto, dest_ips, dest)  #LLamamos a la funcion handle para el paquete DNS recibido
    print(f"Respondiendo {addr}")  #Imprimimos la dirección del cliente al que le respondimos

