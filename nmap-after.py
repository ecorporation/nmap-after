import re
import argparse
import nmap

def parse_nmap_output(nmap_output):
    results = {}
    ip = None
    
    for line in nmap_output.splitlines():
        ip_match = re.match(r'Nmap scan report for (.*)', line)
        if ip_match:
            ip = ip_match.group(1)
            results[ip] = []
        elif ip:
            port_match = re.match(r'(\d+)/tcp\s+(\w+)\s+(\w+)\s+(\w+)', line)
            if port_match:
                port = port_match.group(1)
                state = port_match.group(2)
                service = port_match.group(3)
                results[ip].append({
                    'port': port,
                    'state': state,
                    'service': service
                })
    
    return results

def run_nmap_script_scan(ip, ports, arguments):
    nm = nmap.PortScanner()
    ports_str = ','.join(ports)
    scan_result = nm.scan(ip, ports_str, arguments=arguments)
    return scan_result

def main():
    parser = argparse.ArgumentParser(description='Parse Nmap output.')
    parser.add_argument('-f', '--file', required=True, help='Path to the Nmap output file')
    parser.add_argument('-o', '--output', required=False, help='Path to the output file')
    parser.add_argument('-arg', '--arguments', required=False, help='Additional arguments for Nmap scan')
    
    args = parser.parse_args()
    
    with open(args.file, 'r') as file:
        nmap_output = file.read()

    parsed_results = parse_nmap_output(nmap_output)

    output_lines = []
    script_scan_output = []

    for ip, ports in parsed_results.items():
        output_lines.append(f"IP: {ip}")
        for port_info in ports:
            output_lines.append(f"Port: {port_info['port']}\nState: {port_info['state']}\nService: {port_info['service']}")

    if args.arguments:
        for ip, ports in parsed_results.items():
            open_ports = [port_info['port'] for port_info in ports if port_info['state'] == 'open']
            if open_ports:
                nmap_scan_result = run_nmap_script_scan(ip, open_ports, args.arguments)
                script_scan_output.append(f"\nNmap scan results for {ip}:\n{nmap_scan_result}")

    if args.output:
        if args.arguments:
            with open(args.output, 'w') as outfile:
                outfile.write("\n".join(script_scan_output))
        else:
            with open(args.output, 'w') as outfile:
                outfile.write("\n".join(output_lines))
    else:
        for line in output_lines:
            print(line)
        if args.arguments:
            for line in script_scan_output:
                print(line)

if __name__ == "__main__":
    main()
