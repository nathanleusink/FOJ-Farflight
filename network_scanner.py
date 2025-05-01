import socket
import random
import time
import ipaddress
from threading import Thread
from queue import Queue

# Configuration
TARGET_SUBNET = "192.168.1.0/24"  # Subnet to scan
COMMON_PORTS = [80, 443, 22, 3389]  # Common ports to probe
TIMEOUT = 2  # Socket timeout in seconds
MAX_THREADS = 10  # Number of concurrent threads
MIN_DELAY = 0.5  # Minimum delay between probes (seconds)
MAX_DELAY = 2.0  # Maximum delay between probes (seconds)

# Queue to hold IP addresses
ip_queue = Queue()
results = []

def probe_host(ip, port):
    """Attempt a TCP connection to the IP and port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        result = sock.connect_ex((str(ip), port))
        if result == 0:
            return True
    except socket.error:
        pass
    finally:
        sock.close()
    return False

def worker():
    """Worker thread to process IP addresses from the queue."""
    while not ip_queue.empty():
        ip = ip_queue.get()
        port = random.choice(COMMON_PORTS)  # Randomly select a port
        if probe_host(ip, port):
            results.append(f"{ip}:{port} is alive")
        # Random delay to avoid detection
        time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
        ip_queue.task_done()

def main():
    # Populate the queue with IP addresses from the subnet
    network = ipaddress.ip_network(TARGET_SUBNET)
    for ip in network.hosts():
        ip_queue.put(ip)

    print(f"Scanning {network} for live hosts...")
    start_time = time.time()

    # Start worker threads
    threads = []
    for _ in range(min(MAX_THREADS, ip_queue.qsize())):
        t = Thread(target=worker)
        t.start()
        threads.append(t)

    # Wait for all threads to complete
    for t in threads:
        t.join()

    # Print results
    if results:
        print("\nLive hosts found:")
        for result in results:
            print(result)
    else:
        print("\nNo live hosts found.")

    print(f"\nScan completed in {time.time() - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()
