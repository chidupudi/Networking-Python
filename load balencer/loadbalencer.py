import socket
import time
# Load Balancer code
class LoadBalancer:
    def __init__(self, backend_servers):
        self.backend_servers = backend_servers
        self.index = 0  # Round-robin index

    def get_next_backend(self):
        backend = self.backend_servers[self.index]
        self.index = (self.index + 1) % len(self.backend_servers)
        return backend

    def forward_request(self, client_socket):
        # Get the next backend server using round-robin
        backend_host, backend_port = self.get_next_backend()

        # Forward the request to the backend server
        backend_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend_socket.connect((backend_host, backend_port))
        backend_socket.sendall(b"GET / HTTP/1.1\r\n")
        response = backend_socket.recv(1024)
        client_socket.sendall(response)
        
        backend_socket.close()

    def start(self, host, port):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((host, port))

        server.listen(5)

        print(f"Load balancer started at {host}:{port}")
        while True:
            client_socket, _ = server.accept()
            print("Request received by Load Balancer")
            self.forward_request(client_socket)
            client_socket.close()
# Run the Load Balancer
if __name__ == "__main__":
    backend_servers = [('localhost', 8081), ('localhost', 8082)]  # Add backend servers
    load_balancer = LoadBalancer(backend_servers)
    load_balancer.start('localhost', 8080)  # Load balancer running on port 8080
