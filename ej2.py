import socket
import argparse
'''
def handle_request(request):
    if 'Host: www.uba.ar' in request:
        response = 'HTTP/1.1 301 Moved Permanently\r\n'
        response += 'Location: https://www.utdt.edu\r\n'
        response += '\r\n'
    else:
        response = 'HTTP/1.1 200 OK\r\n'
        response += 'Content-Type: text/html\r\n'
        response += '\r\n'
        response += 'Hello, World!'
    return response

def run_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8080))
    server_socket.listen(1)
    print('Servidor en ejecución en http://localhost:8080')

    while True:
        client_socket, address = server_socket.accept()
        request = client_socket.recv(1024).decode('utf-8')

        if request:
            response = handle_request(request)
            client_socket.sendall(response.encode('utf-8'))

        client_socket.close()

run_server()


def handle_request(client_socket):
    request = client_socket.recv(1024).decode('utf-8')
    request_lines = request.split('\r\n')
    
    # Obtiene la URL de la solicitud GET
    url = None
    for line in request_lines:
        if line.startswith('GET'):
            url = line.split(' ')[1]
            break
    
    parser = argparse.ArgumentParser(description='Servidor HTTP')
    parser.add_argument('-r', '--redirects', help='Dominios redirigidos en formato dominio:destino', nargs='+', required=True)
    args = parser.parse_args()

    redirects = args.redirects

    
    # Obtiene la URL de redirección correspondiente
    redirect_url = redirects.get(url)
    
    if redirect_url:
        # Envía una respuesta de redirección HTTP/1.1 302
        response = f'[*] Request GET recibido (Host: {redirect_url})\r\n\r\n'
    else:
        # Envía una respuesta de error HTTP/1.1 404
        response = 'HTTP/1.1 404 Not Found\r\n\r\n<h1>404 Not Found</h1>'
    
    # Envía la respuesta al cliente
    client_socket.sendall(response.encode('utf-8'))
    client_socket.close()

def run_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8080))
    server_socket.listen(1)
    
    print('[*] Request GET recibido (Host: {}) \n[*] Respondiendo redirección hacia {}')
    
    while True:
        client_socket, address = server_socket.accept()
        handle_request(client_socket)

run_server()



import argparse
import socket

def handle_request(client_socket, redirects):
    request = client_socket.recv(1024).decode('utf-8')
    request_lines = request.split('\r\n')

    # Obtiene el header "Host" de la solicitud GET
    host_header = None
    for line in request_lines:
        if line.startswith('GET'):
            host_header = line.split(' ')[1]
            break
    
    if host_header:
        # Imprime la solicitud GET recibida
        print(f'[*] Request GET recibido (Host: {host_header})')

        # Obtiene la URL de redirección correspondiente
        redirect_url = redirects.get(host_header)

        if redirect_url:
            # Imprime la respuesta de redirección
            print(f'[*] Respondiendo redirección hacia {redirect_url}')

            # Envía una respuesta de redirección HTTP/1.1 302
            response = f'HTTP/1.1 302 Found\r\nLocation: {redirect_url}\r\n\r\n'
        else:
            # Envía una respuesta de error HTTP/1.1 404
            response = 'HTTP/1.1 404 Not Found\r\n\r\n<h1>404 Not Found</h1>'
    else:
        # Envía una respuesta de error HTTP/1.1 400 si no se encuentra el header "Host"
        response = 'HTTP/1.1 400 Bad Request\r\n\r\n<h1>400 Bad Request</h1>'

    # Envía la respuesta al cliente
    client_socket.sendall(response.encode('utf-8'))
    client_socket.close()


def run_server(redirects):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8080))
    server_socket.listen(1)

    print('[*] Servidor HTTP en ejecución')

    while True:
        client_socket, address = server_socket.accept()
        handle_request(client_socket, redirects)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Servidor HTTP')
    parser.add_argument('-r', '--redirects', help='Dominios redirigidos en formato dominio:destino', nargs='+', required=True)
    args = parser.parse_args()

    redirects = {}
    for redirect in args.redirects:
        domain, destination = redirect.split(':')
        redirects[domain] = destination

    run_server(redirects)

'''

import argparse
import socket

def handle_request(client_socket, redirects):
    request = client_socket.recv(1024).decode('utf-8')
    request_lines = request.split('\r\n')

    # Obtiene el dominio de la solicitud GET
    domain = None
    for line in request_lines:
        if line.startswith('Host:'):
            domain = line.split(' ')[1]
            break

    # Obtiene la URL de redirección correspondiente
    redirect_url = redirects.get(domain)

    if redirect_url:
        # Envía una respuesta de redirección HTTP/1.1 301
        response = f'HTTP/1.1 301 Moved Permanently\r\nLocation: {redirect_url}\r\n\r\n'
        print(f'[*] Request GET recibido (Host: {domain})')
        print(f'[*] Respondiendo redirección hacia {redirect_url}')
    else:
        # Envía una respuesta de error HTTP/1.1 404
        response = 'HTTP/1.1 404 Not Found\r\n\r\n<h1>404 Not Found</h1>'
    
    # Envía la respuesta al cliente
    client_socket.sendall(response.encode('utf-8'))
    client_socket.close()

def run_server(redirects):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8080))
    server_socket.listen(1)
    
    print('[*] Servidor HTTP en ejecución')

    while True:
        client_socket, address = server_socket.accept()
        handle_request(client_socket, redirects)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Servidor HTTP')
    parser.add_argument('-r', '--redirects', help='Dominios redirigidos en formato dominio:destino', nargs='+', required=True)
    args = parser.parse_args()

    redirects = {}
    for redirect in args.redirects:
        domain, destination = redirect.split(':')
        redirects[domain] = destination

    run_server(redirects)


