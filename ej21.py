import argparse
import socket

def parse_arguments():
    parser = argparse.ArgumentParser(description='HTTP Redirector')
    parser.add_argument('-r', '--redirect', nargs='+', action='append', help='Define a redirect rule in the format "host:location"')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Port to run the server on (default: 8080)')
    return parser.parse_args()

def create_redirects(rules):
    redirects = {}
    if rules:
        for rule in rules:
            if len(rule) == 2:
                host, location = rule
                redirects[host] = location
    return redirects

def handle_request(client_socket, redirects):
    # Recibo lo que me envió el cliente y lo decodifico
    request_data = client_socket.recv(4096).decode('utf-8')

    # Extraigo el host de la solicitud
    host = None
    for line in request_data.split('\r\n'):
        if line.startswith('Host: '):
            host = line[6:]
            break

    if host in redirects:
        new_location = redirects[host]
        print(f'[*] Request GET recibido (Host: {host})')
        print(f'[*] Respondiendo redirección hacia {new_location}')
        response = (
            'HTTP/1.1 301 Moved Permanently\r\n'
            'Location: {}\r\n'
            'Connection: close\r\n\r\n'.format(new_location)
        )
        client_socket.sendall(response.encode('utf-8'))
    else:
        response = (
            'HTTP/1.1 404 Not Found\r\n'
            'Connection: close\r\n\r\n'
        )
        client_socket.sendall(response.encode('utf-8'))

    client_socket.close()

def run_server(port, redirects):
    # Creo un socket del servidor
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Lo enlazo a una dirección y un puerto
    server_socket.bind(('localhost', port))
    # Escucho en el socket del servidor para conexiones entrantes
    server_socket.listen(1)
    print(f'Servidor en ejecución en el puerto {port}...')

    while True:
        # Acepto la conexión entrante
        client_socket, client_address = server_socket.accept()
        handle_request(client_socket, redirects)

    server_socket.close()

def main():
    args = parse_arguments()
    redirects = create_redirects(args.redirect)
    run_server(args.port, redirects)

if __name__ == '__main__':
    main()
