#!/usr/bin/env python3
import scapy.all as scapy
import argparse
import socket
import requests
import urllib3
import csv
import datetime
import concurrent.futures
from mac_vendor_lookup import MacLookup, VendorNotFoundError

# Nonaktifkan peringatan SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP address/IP range", required=True)
    parser.add_argument("-p", "--ports", dest="ports", help="Comma-separated ports (default: 22,53,80,443)", default="22,53,80,443")
    parser.add_argument("-u", "--update", dest="update", action="store_true", help="Update MAC vendor database")
    parser.add_argument("--netbox-url", dest="netbox_url", help="NetBox URL (e.g., http://127.0.0.1:8000)")
    parser.add_argument("--netbox-token", dest="netbox_token", help="NetBox API Token")
    # Argumen Telegram
    parser.add_argument("--telegram-token", dest="tele_token", help="Telegram Bot Token", default=None)
    parser.add_argument("--telegram-chat", dest="tele_chat", help="Telegram Chat ID", default=None)
    return parser.parse_args()

def send_telegram_alert(token, chat_id, message):
    if not token or not chat_id:
        return
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown"
    }
    try:
        requests.post(url, json=payload, timeout=5)
    except Exception as e:
        print(f"  [!] Failed to send Telegram alert: {e}")

def get_hostname(ip):
    try:
        host = socket.gethostbyaddr(ip)[0]
        if host and host != ip: return host
    except socket.herror: pass
        
    try:
        packet = scapy.IP(dst=ip)/scapy.UDP(sport=137, dport=137)/scapy.NBNSNodeStatusRequest(QUESTION_NAME="*")
        reply = scapy.sr1(packet, timeout=0.2, verbose=False)
        if reply and reply.haslayer(scapy.NBNSNodeStatusResponse):
            nb_name = reply[scapy.NBNSNodeStatusResponse].NODE_NAME.decode('utf-8', errors='ignore').strip()
            if nb_name: return nb_name
    except Exception: pass
    
    rev_ip = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    
    try:
        mdns_req = scapy.IP(dst=ip)/scapy.UDP(sport=5353, dport=5353)/scapy.DNS(rd=1, qd=scapy.DNSQR(qname=rev_ip, qtype="PTR"))
        reply = scapy.sr1(mdns_req, timeout=0.2, verbose=False)
        if reply and reply.haslayer(scapy.DNSRR):
            rdata = reply[scapy.DNSRR].rdata
            mdns_name = rdata.decode('utf-8', errors='ignore') if isinstance(rdata, bytes) else str(rdata)
            mdns_name = mdns_name.rstrip('.').replace('.local', '')
            if mdns_name: return mdns_name
    except Exception: pass

    try:
        llmnr_req = scapy.IP(dst=ip)/scapy.UDP(sport=5355, dport=5355)/scapy.LLMNRQuery(id=1, qd=scapy.DNSQR(qname=rev_ip, qtype="PTR"))
        reply = scapy.sr1(llmnr_req, timeout=0.2, verbose=False)
        if reply and reply.haslayer(scapy.DNSRR):
            rdata = reply[scapy.DNSRR].rdata
            llmnr_name = rdata.decode('utf-8', errors='ignore') if isinstance(rdata, bytes) else str(rdata)
            llmnr_name = llmnr_name.rstrip('.')
            if llmnr_name: return llmnr_name
    except Exception: pass
    
    return "Unknown"

def get_vendor(mac, mac_lookup):
    if int(mac.split(':')[0], 16) & 2: return "Randomized MAC (Android/iOS)"
    try: return mac_lookup.lookup(mac)
    except: return "Unknown Vendor"

def get_clean_hostname(vendor):
    v_low = vendor.lower()
    if "xiaomi" in v_low: return "Xiaomi"
    if "samsung" in v_low: return "Samsung"
    if "apple" in v_low or "mac" in v_low: return "Apple"
    if "epson" in v_low: return "Epson"
    if "ubiquiti" in v_low: return "Ubiquiti"
    if "routerboard" in v_low or "mikrotik" in v_low: return "MikroTik"
    if "proxmox" in v_low: return "Proxmox"
    if "vmware" in v_low: return "VMware"
    if "qemu" in v_low: return "QEMU"
    if "engenius" in v_low: return "EnGenius"
    if "tp-link" in v_low or "tplink" in v_low: return "TP-Link"
    if "intel" in v_low: return "Intel"
    if "randomized" in v_low: return "Mobile-Device"
    
    if vendor in ["Unknown Vendor", "Error"]: return "Unknown-Device"
    clean = ''.join(e for e in vendor.split()[0] if e.isalnum())
    return clean if clean else "Unknown-Device"

def get_os_by_ttl(ip):
    try:
        packet_icmp = scapy.IP(dst=ip)/scapy.ICMP()
        reply = scapy.sr1(packet_icmp, timeout=0.3, verbose=False)
        if not reply:
            for port in [135, 445, 80, 139]:
                packet_tcp = scapy.IP(dst=ip)/scapy.TCP(dport=port, flags="S")
                reply = scapy.sr1(packet_tcp, timeout=0.2, verbose=False)
                if reply: break
        
        if reply and reply.haslayer(scapy.IP):
            ttl = reply[scapy.IP].ttl
            if ttl <= 64: return f"Linux/macOS/Android ({ttl})"
            elif ttl <= 128: return f"Windows ({ttl})"
            else: return f"Network Device ({ttl})"
        return "Unknown (Firewall Drop)"
    except Exception: return "Unknown"

def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            if sock.connect_ex((ip, port)) == 0: open_ports.append(str(port))
            sock.close()
        except Exception: pass
    return open_ports

def guess_role_from_ports(open_ports_list):
    if not open_ports_list: return "endpoint"
    if "53" in open_ports_list: return "dns-server"
    elif "80" in open_ports_list or "443" in open_ports_list: return "web-server"
    elif "3389" in open_ports_list: return "windows-server"
    elif "22" in open_ports_list: return "linux-server"
    else: return "generic-node"

def scan(ip, ports_to_scan, update_db):
    mac_lookup = MacLookup()
    if update_db:
        try: mac_lookup.update_vendors()
        except Exception: pass

    print(f"[*] Scanning network {ip} for devices...\n")
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    answered = scapy.srp(broadcast / arp_request, timeout=2, verbose=False)[0]

    targets = [(ans[1].psrc, ans[1].hwsrc, get_vendor(ans[1].hwsrc, mac_lookup)) for ans in answered]
    clients_list = []
    
    def process_target(target):
        ip_addr, mac_addr, vendor = target
        hostname = get_hostname(ip_addr)
        if hostname == "Unknown": hostname = get_clean_hostname(vendor)
            
        open_ports_list = scan_ports(ip_addr, ports_to_scan)
        is_vm = any(v in vendor.lower() for v in ['proxmox', 'vmware', 'qemu', 'virtualbox'])
        
        return {
            "ip": ip_addr, "mac": mac_addr, "vendor": vendor,
            "hostname": hostname, "os": get_os_by_ttl(ip_addr),
            "open_ports": ", ".join(open_ports_list) if open_ports_list else "None",
            "role_tag": guess_role_from_ports(open_ports_list),
            "is_vm": is_vm
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        futures = [executor.submit(process_target, t) for t in targets]
        for future in concurrent.futures.as_completed(futures): clients_list.append(future.result())

    return sorted(clients_list, key=lambda i: tuple(map(int, i['ip'].split('.'))))

def print_results(results):
    print(f"{'IP Address':<16} {'MAC Address':<18} {'Role':<15} {'Type':<8} {'Hostname'}")
    print("-" * 80)
    for client in results:
        node_type = "VM" if client['is_vm'] else "Device"
        print(f"{client['ip']:<16} {client['mac']:<18} {client['role_tag']:<15} {node_type:<8} {client['hostname']}")

def export_to_csv(results):
    filename = f"scan_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    fieldnames = ['IP Address', 'MAC Address', 'Vendor', 'Hostname', 'OS', 'Open Ports', 'Role', 'Type']
    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            for client in results:
                writer.writerow({
                    'IP Address': client['ip'],
                    'MAC Address': client['mac'],
                    'Vendor': client['vendor'],
                    'Hostname': client['hostname'],
                    'OS': client['os'],
                    'Open Ports': client['open_ports'],
                    'Role': client['role_tag'],
                    'Type': 'VM' if client['is_vm'] else 'Device'
                })
        print(f"[*] Local report successfully exported to '{filename}'")
    except Exception as e:
        print(f"  [!] Failed to export CSV report: {e}")

def ensure_tag_exists(netbox_url, headers, tag_name):
    tag_endpoint = f"{netbox_url.rstrip('/')}/api/extras/tags/"
    try:
        check_resp = requests.get(f"{tag_endpoint}?name={tag_name}", headers=headers, verify=False)
        if check_resp.status_code == 200 and check_resp.json()['count'] == 0:
            requests.post(tag_endpoint, headers=headers, json={"name": tag_name, "slug": tag_name.lower().replace(" ", "-"), "color": "9e9e9e"}, verify=False)
    except Exception: pass

def register_vm_in_netbox(netbox_url, headers, vm_name):
    try:
        ct_id = requests.get(f"{netbox_url.rstrip('/')}/api/virtualization/cluster-types/?name=Proxmox", headers=headers, verify=False).json().get('results', [{}])[0].get('id') or requests.post(f"{netbox_url.rstrip('/')}/api/virtualization/cluster-types/", headers=headers, json={"name": "Proxmox", "slug": "proxmox"}, verify=False).json().get('id')
        c_id = requests.get(f"{netbox_url.rstrip('/')}/api/virtualization/clusters/?name=Proxmox-Cluster", headers=headers, verify=False).json().get('results', [{}])[0].get('id') or requests.post(f"{netbox_url.rstrip('/')}/api/virtualization/clusters/", headers=headers, json={"name": "Proxmox-Cluster", "type": ct_id}, verify=False).json().get('id')
        vm_id = requests.get(f"{netbox_url.rstrip('/')}/api/virtualization/virtual-machines/?name={vm_name}", headers=headers, verify=False).json().get('results', [{}])[0].get('id') or requests.post(f"{netbox_url.rstrip('/')}/api/virtualization/virtual-machines/", headers=headers, json={"name": vm_name, "cluster": c_id}, verify=False).json().get('id')
        
        requests.patch(f"{netbox_url.rstrip('/')}/api/virtualization/virtual-machines/{vm_id}/", headers=headers, json={"status": "active"}, verify=False)
        
        intf_id = requests.get(f"{netbox_url.rstrip('/')}/api/virtualization/interfaces/?virtual_machine_id={vm_id}&name=eth0", headers=headers, verify=False).json().get('results', [{}])[0].get('id') or requests.post(f"{netbox_url.rstrip('/')}/api/virtualization/interfaces/", headers=headers, json={"virtual_machine": vm_id, "name": "eth0"}, verify=False).json().get('id')
        return intf_id
    except Exception: return None

def cleanup_stale_records(live_results, target_network, netbox_url, headers, tele_token, tele_chat):
    print("\n[*] Reconciling: Clearing unused IP allocations in NetBox...")
    prefix = target_network.split('/')[1] if '/' in target_network else '24'
    api_ip_endpoint = f"{netbox_url.rstrip('/')}/api/ipam/ip-addresses/"

    live_ips = {f"{client['ip']}/{prefix}" for client in live_results}

    try:
        search_url = f"{api_ip_endpoint}?parent={target_network}"
        response = requests.get(search_url, headers=headers, verify=False)
        
        if response.status_code == 200:
            netbox_ips = response.json().get('results', [])
            for nb_ip in netbox_ips:
                address = nb_ip['address']
                ip_id = nb_ip['id']
                current_desc = nb_ip.get('description', '')
                dns_name = nb_ip.get('dns_name', 'Unknown')
                
                if address not in live_ips and current_desc != "Ready / Unused":
                    payload = {
                        "status": "active",
                        "description": "Ready / Unused",
                        "dns_name": "",
                        "assigned_object_type": None,
                        "assigned_object_id": None,
                        "tags": []
                    }
                    requests.patch(f"{api_ip_endpoint}{ip_id}/", headers=headers, json=payload, verify=False)
                    print(f"  [-] {address} is unreachable. Cleared allocation.")
                    
                    alert_msg = f"🔴 *PERANGKAT OFFLINE*\nIP `{address}` tidak lagi merespons. Alokasi NetBox dikosongkan.\nHostname Terakhir: `{dns_name}`"
                    send_telegram_alert(tele_token, tele_chat, alert_msg)
                    
    except Exception as e:
        print(f"  [!] Failed to reconcile records: {e}")

def push_to_netbox(results, target_network, netbox_url, token, tele_token, tele_chat):
    prefix = target_network.split('/')[1] if '/' in target_network else '24'
    api_endpoint = f"{netbox_url.rstrip('/')}/api/ipam/ip-addresses/"
    auth_header = token if token.lower().startswith(("bearer ", "token ")) else f"Token {token}"
    headers = {"Authorization": auth_header, "Content-Type": "application/json", "Accept": "application/json"}
    
    # Generate timestamp dengan format update: YYYY:MM:DD|HH:MM:SS
    scan_timestamp = datetime.datetime.now().strftime("%Y:%m:%d|%H:%M:%S")

    print(f"\n[*] Pushing {len(results)} active IP addresses to NetBox...")
    for client in results:
        ensure_tag_exists(netbox_url, headers, client['role_tag'])
        
        # Tentukan string scan port terbaru (apapun port yang terdeteksi)
        if client['open_ports'] != "None":
            scan_desc = f"Open Ports: {client['open_ports']}"
        else:
            scan_desc = "Standard Endpoint (No open ports)"
            
        # Periksa apakah deskripsi existing sudah ada di NetBox agar tidak tertimpa total
        final_desc = f"{scan_desc} | update: {scan_timestamp}"
        try:
            check_resp = requests.get(f"{api_endpoint}?address={client['ip']}", headers=headers, verify=False)
            if check_resp.status_code == 200 and check_resp.json()['count'] > 0:
                existing_ip_data = check_resp.json()['results'][0]
                existing_desc = existing_ip_data.get('description', '') or ''
                
                # Jika ada catatan penting user (misal: "GlobalActive ——— vmware-43Worker2 Kubernetes"), gabungkan dengan port terbaru dan timestamp
                if existing_desc and not existing_desc.startswith(("Open Ports:", "Standard Endpoint", "Ready / Unused")):
                    if " | Open Ports:" in existing_desc:
                        base_note = existing_desc.split(" | Open Ports:")[0]
                    elif " | Standard Endpoint" in existing_desc:
                        base_note = existing_desc.split(" | Standard Endpoint")[0]
                    else:
                        base_note = existing_desc.split(" | update:")[0].strip()
                    
                    final_desc = f"{base_note} | {scan_desc} | update: {scan_timestamp}"
        except Exception:
            pass

        payload = {
            "address": f"{client['ip']}/{prefix}",
            "status": "active",
            "description": final_desc,
            "tags": [{"name": client['role_tag']}] 
        }

        if client['is_vm']:
            vm_name = f"{client['hostname']}-{client['ip'].split('.')[-1]}" if client['hostname'] in ["Proxmox", "VMware", "QEMU"] else client['hostname']
            payload["dns_name"] = vm_name[:254]
            intf_id = register_vm_in_netbox(netbox_url, headers, vm_name)
            if intf_id:
                payload["assigned_object_type"] = "virtualization.vminterface"
                payload["assigned_object_id"] = intf_id
        else:
            payload["dns_name"] = client['hostname'][:254]
        
        try:
            check_resp = requests.get(f"{api_endpoint}?address={client['ip']}", headers=headers, verify=False)
            if check_resp.status_code == 200:
                data = check_resp.json()
                if data['count'] > 0:
                    requests.patch(f"{api_endpoint}{data['results'][0]['id']}/", headers=headers, json=payload, verify=False)
                    print(f"  [~] {client['ip']} updated (PATCH)")
                else:
                    post_resp = requests.post(api_endpoint, headers=headers, json=payload, verify=False)
                    if post_resp.status_code == 201:
                        print(f"  [+] {client['ip']} added (POST)")
                        alert_msg = f"🟢 *PERANGKAT BARU TERDETEKSI*\nIP: `{client['ip']}`\nHostname: `{payload['dns_name']}`\nVendor: `{client['vendor']}`\nRole: `{client['role_tag']}`"
                        send_telegram_alert(tele_token, tele_chat, alert_msg)
        except Exception: 
            pass
    
    cleanup_stale_records(results, target_network, netbox_url, headers, tele_token, tele_chat)

if __name__ == "__main__":
    options = get_arguments()
    ports_list = [int(p.strip()) for p in options.ports.split(",")]
    scan_results = scan(options.target, ports_list, options.update)
    print_results(scan_results)
    
    export_to_csv(scan_results)
    
    if options.netbox_url and options.netbox_token:
        push_to_netbox(scan_results, options.target, options.netbox_url, options.netbox_token, options.tele_token, options.tele_chat)