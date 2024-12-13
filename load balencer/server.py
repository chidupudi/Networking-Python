import socket
import gtts
# Backend Server code
def start_backend_server(host, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)

    print(f"Backend server started at {host}:{port}")
    while True:
        client_socket, _ = server.accept()
        print(f"Request received by backend server {host}:{port}")
        # Simulating request processing
        client_socket.sendall(b"HTTP/1.1 200 OK\r\n\r\nRequest Processed\n")
        client_socket.close()
# Run the backend server on a different thread for testing
if __name__ == "__main__":
    start_backend_server('localhost', 8081)  # Example backend server running on port 8081
