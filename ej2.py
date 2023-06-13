import argparse
import socket
from scapy.all import Raw
from scapy.layers.http import *

def parse_arguments():
    #La funcion crea un objeto ArgumentParser para manejar los argumentos de línea de comandos
    parser = argparse.ArgumentParser(description='HTTP Redirector')

    #Agregamos los argumentos esperados
    parser.add_argument('-r', '--redirect', action='append', default=[], help='Define a redirect rule in the format "host:location"')
    parser.add_argument('-d', '--lista_archivo', action='append', default=[], help='')
    parser.add_argument('-c', '--archivo', help='')

    #Devuelve un objeto que contiene los argumentos
    return parser.parse_args()

def create_redirects(rules):
    #La funcion crea un diccionario vacío para almacenar las reglas de redirección
    redirects = {}

    #Verificamos si hay reglas definidas
    if rules:
        #Si hay reglas definidas, iteramos sobre las reglas y las agregamos al diccionario de redirección
        for rule in rules:
            desde, hastaHTTPS, hasta = rule.split(":")
            host = desde
            location = hastaHTTPS + ':' + hasta
            redirects[host] = location

    #La funcion devuelve el diccionario de redirección creado
    return redirects

def handle_request(request_data, redirects, client_socket, recive_archivo):
    #La funcion convierte los datos de solicitud recibidos en un objeto HTTP de Scapy
    scapy_pkt = HTTP(request_data)

    #Extraemos los datos raw de la solicitud HTTP
    raw = Raw(scapy_pkt)

    #Decodificamos los datos raw en un string
    payload = (raw[Raw].load).decode()

    #Si la solicitud es de tipo GET
    if 'GET' in payload:
        splits = payload.split(' ')
        for x in splits:
            #Buscamos el host en la solicitud GET
            if x.startswith('www.'):
                host = x

    #Si el host está en las reglas de redirección
    if host in redirects:
        #Obtenemos la nueva ubicación para redirigir
        new_location = redirects[host]
        print(f'[*] Request GET recibido (Host: {host})')
        print(f'[*] Respondiendo redirección hacia {new_location}')

        #Construimos la respuesta HTTP de redirección
        response = (
            'HTTP/1.1 301 Moved Permanently\r\n'
            'Location: {}\r\n'
            'Connection: close\r\n\r\n'.format(new_location)
        )

        #Enviamos la respuesta al cliente a través del socket
        client_socket.sendall(bytes_encode(response))

    #Si el host está en la lista de archivos
    elif host in recive_archivo:
        #Pedimos que abra y lea el contenido del archivo
        with open(archivo, 'r') as file:
            html_content = file.read()
            
        print(f'[*] Request GET recibido (Host: {host})')
        print(f'[*] Respondiendo contenido del archivo {archivo}')

        #Respuesta HTTP
        response = (
            'HTTP/1.1 200\r\n'
            'Content-Type: text/html\r\n\r\n'
        )
        response += html_content

        #Enviamos la respuesta
        client_socket.sendall(bytes_encode(response))

    else:
        #Si no hay minguna regla de redirección para el host, lo redirigimos hacia el propio host
        print(f'[*] Request GET recibido (Host: {host})')
        print(f'[*] Respondiendo redirección hacia {host}')

        #Construimos la respuesta
        response = (
            'HTTP/1.1 301 Moved Permanently\r\n'
            'Location: {}\r\n'
            'Connection: close\r\n\r\n https://'.format(host)
        )

        #Enviamos la respuesta
        client_socket.sendall(bytes_encode(response))


args = parse_arguments()
redirects = create_redirects(args.redirect)
recive_archivo = set(args.lista_archivo)
archivo = args.archivo
port = 80

#Creamos un socket del servidor
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#Lo enlazamos a una dirección y un puerto
server_socket.bind(('0.0.0.0', port))

#Escuchamos al socket del servidor
server_socket.listen()
print(f'Servidor en ejecución en el puerto {port}...')

#Acepta una conexión
client_socket, client_address = server_socket.accept()

while True:
    #Recibimos los datos de la solicitud
    request_data = client_socket.recv(1024)

    #Llamamos a la funcion para poder "leer" la solicitud y enviar la respuesta al cliente
    handle_request(request_data, redirects, client_socket, recive_archivo)
