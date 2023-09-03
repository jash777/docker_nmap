import docker
from flask import Flask, request, jsonify,render_template
import re

# Define the Docker API client
client = docker.from_env()

app = Flask(__name__)

def get_running_container_ips():
    container_ips = {}
    try:
        containers = client.containers.list()
        for container in containers:
            # Get container details
            container_info = container.attrs
            container_name = container_info['Name'].lstrip('/')
            # Get the container's IP address
            network_settings = container_info['NetworkSettings']
            container_ip = network_settings['IPAddress']
            container_ips[container_name] = container_ip
    except docker.errors.APIError as e:
        print(f"Error fetching container IPs: {e}")
    return container_ips

def run_nmap_scan(ip):
    # Define the Nmap command you want to run
    nmap_command = f"nmap -p- -sV {ip}"
    
    try:
        # Specify the container name or ID where you want to run Nmap
        container_name_or_id = "a8dec2806bf1"
        
        # Get the container object
        container = client.containers.get(container_name_or_id)

        # Execute the Nmap command inside the container
        exec_result = container.exec_run(nmap_command, stdout=True, stderr=True, tty=True)

        # Return the Nmap scan results as a dictionary
        return {
            'target_ip': ip,
            'nmap_output': exec_result.output.decode()
        }

    except docker.errors.NotFound:
        return {
            'error': f"Container '{container_name_or_id}' not found."
        }
    except docker.errors.APIError as e:
        return {
            'error': f"Error executing Nmap in container: {e}"
        }

def preprocess_nmap_output(nmap_output):
    # Regular expression pattern to extract service versions and open ports
    pattern = r'(\d+/\w+\s+[^\n]+)'

    # Find all matches in the Nmap output
    matches = re.findall(pattern, nmap_output)

    # Join the matches into a string
    sanitized_output = '\n'.join(matches)

    return sanitized_output

@app.route('/nmap-scan', methods=['POST','GET'])
def nmap_scan_api():
    container_ips = get_running_container_ips()
    results = {}

    for container_name, container_ip in container_ips.items():
        print(f"Running Nmap scan for container '{container_name}' with IP '{container_ip}':")
        scan_result = run_nmap_scan(container_ip)

        # Preprocess the Nmap output here
        scan_result['nmap_output'] = preprocess_nmap_output(scan_result['nmap_output'])
        
        results[container_name] = scan_result

    return render_template('nmap_results.html', results=results)



if __name__ == "__main__":
    app.run(debug=True)
