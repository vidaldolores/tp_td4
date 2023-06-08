import socket
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
'''

def handle_request(client_socket):
    request = client_socket.recv(1024).decode('utf-8')
    request_lines = request.split('\r\n')
    
    # Obtiene la URL de la solicitud GET
    url = None
    for line in request_lines:
        if line.startswith('GET'):
            url = line.split(' ')[1]
            break
    
    # Define las redirecciones configurables
    redirects = {
        '/ruta1': 'http://nuevaurl1.com',
        '/ruta2': 'http://nuevaurl2.com',
        # Agrega más redirecciones aquí
    }
    
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
    
    print('[*] Request GET recibido (Host: {}) \n[*] Respondiendo redirección hacia https://www.google.com')
    
    while True:
        client_socket, address = server_socket.accept()
        handle_request(client_socket)

run_server()

