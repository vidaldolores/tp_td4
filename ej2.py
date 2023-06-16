import argparse
import socket
from scapy.all import Raw
from scapy.layers.http import *

def parse_arguments():
    parser = argparse.ArgumentParser(description='HTTP Redirector')
    parser.add_argument('-r', '--redirect', action='append', default=[], help='Define a redirect rule in the format "host:location"')
    parser.add_argument('-d', '--lista_archivo', action='append', default=[], help='')
    parser.add_argument('-c', '--archivo', help='')
   
    return parser.parse_args()

def create_redirects(rules):
    redirects = {}
    print(rules)
    if rules:
        for rule in rules:
            desde, hastaHTTPS, hasta = rule.split(":")
            host = desde
            location = hastaHTTPS + ':' + hasta
            redirects[host] = location
    return redirects

def handle_request(request_data, redirects, client_socket, recive_archivo):
    # Recibo lo que me envió el cliente y lo decodifico
   
    scapy_pkt = HTTP(request_data) #IGUAL
    raw = Raw(scapy_pkt) #IGUAL
    payload = (raw[Raw].load).decode() #IGUAL
   
    if 'GET' in payload:
        splits = payload.split(' ')
        for x in splits:
            if x.startswith('www.'):
                host = x
        host = host.strip()
    else: 
        return
        
    if host in redirects.keys():
        new_location = redirects[host]
        print(f'[*] Request GET recibido (Host: {host})')
        print(f'[*] Respondiendo redirección hacia {new_location}')
        response = (
            'HTTP/1.1 301 Moved Permanently\r\n'
            'Location: {}\r\n'
            'Connection: close\r\n\r\n'.format(new_location)
        )
        client_socket.sendall(bytes_encode(response))
    
    elif host in recive_archivo:
        with open(archivo, 'r') as file:
            html_content:str = file.read()
        print(f'[*] Request GET recibido (Host: {host})')
        print(f'[*] Respondiendo contenido del archivo {archivo}')
        response = (
            'HTTP/1.1 200\r\n'
            "Content-Type: text/html\r\n\r\n"
        )
        response += html_content
        client_socket.sendall(bytes_encode(response))
        
    else:
        print(f'[*] Request GET recibido (Host: {host})')
        print(f'[*] Respondiendo redirección hacia {host}')
        response = (
            'HTTP/1.1 301 Moved Permanently\r\n'
            'Location: {}\r\n'
            'Connection: close\r\n\r\n https://'.format(host)
           
        )
        client_socket.sendall(bytes_encode(response))


args = parse_arguments()
redirects = create_redirects(args.redirect)
recive_archivo = set(args.lista_archivo)
archivo = args.archivo
port = 80
# Creo un socket del servidor
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Lo enlazo a una dirección y un puerto
server_socket.bind(('0.0.0.0', port))
# Escucho en el socket del servidor para conexiones entrantes
server_socket.listen()

print(f'Servidor en ejecución en el puerto {port}...')
client_socket, client_address = server_socket.accept()

while True:
    # Acepto la conexión entrante
    request_data = client_socket.recv(1024)
    handle_request(request_data, redirects, client_socket, recive_archivo)