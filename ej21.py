import argparse
import socket

def create_response(status_code, status_text, headers, body=None):
    response = f"HTTP/1.1 {status_code} {status_text}\r\n"
    for key, value in headers.items():
        response += f"{key}: {value}\r\n"
    response += "\r\n"
    if body:
        response += body
    return response.encode("utf-8")

def handle_request(client_socket, redirects):
    request_data = client_socket.recv(1024).decode("utf-8")
    request_lines = request_data.split("\r\n")
    request_line = request_lines[0]
    request_method, request_path, request_protocol = request_line.split()

    headers = {}
    for line in request_lines[1:]:
        if line:
            key, value = line.split(": ", 1)
            headers[key] = value

    host_header = headers.get("Host", "")
    if request_method == "GET" and host_header:
        for redirect in redirects:
            domain, target = redirect.split(":")
            if host_header.strip() == domain.strip():
                response_headers = {
                    "Location": target.strip(),
                    "Connection": "close"
                }
                response = create_response(301, "Moved Permanently", response_headers)
                client_socket.sendall(response)
                print(f"[*] Request GET recibido (Host: {host_header})")
                print(f"[*] Respondiendo redirección hacia {target}")
                client_socket.close()
                return

    response_headers = {
        "Content-Type": "text/html",
        "Connection": "close"
    }
    response_body = "<h1>404 Not Found</h1>"
    response = create_response(404, "Not Found", response_headers, response_body)
    client_socket.sendall(response)
    print(f"[*] Request GET recibido (Host: {host_header})")
    print("[*] Respondiendo 404 Not Found")

    client_socket.close()

def start_server(host, port, redirects):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Server listening on {host}:{port}")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Received connection from {client_address[0]}:{client_address[1]}")
        handle_request(client_socket, redirects)

def main():
    parser = argparse.ArgumentParser(description='Servidor HTTP')
    parser.add_argument('-r', '--redirects', help='Dominios redirigidos en formato dominio:destino', nargs='+', required=True)
    args = parser.parse_args()

    redirects = args.redirects

    start_server("127.0.0.1", 8080, redirects)

if __name__ == "__main__":
    main()

