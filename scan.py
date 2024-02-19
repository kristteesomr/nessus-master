from get_token import disable_ssl_warnings, authenticate_session, get_access_keys
import requests
import csv
import time

sleep_period = 5

disable_ssl_warnings()
token = authenticate_session()
access_key, secret_key = get_access_keys(token)
IP = "https://172.24.120.204"
BASE_URL = f"{IP}:11127"
SCANS_URL = f"{BASE_URL}/scans"
FOLDERS_URL = f"{BASE_URL}/folders"

session = requests.Session()

headers = {
    "accept": "application/json",
    "content-type": "application/json",
    "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}"
}

proxies = {
    "https": "http://192.168.56.1:8080",
    "http": "http://192.168.56.1:8080" 
}

text_targets = ",".join([row[0] for row in csv.reader(open('IP.csv', 'r'))])

def check_dup_folder(folder_name):
    response = session.get(FOLDERS_URL, headers=headers, proxies=proxies, verify=False)
    folders = response.json().get('folders', [])
    
    for folder in folders:
        if folder.get('name') == folder_name:
            return folder.get('id')
    
    data_folder = {"name": folder_name}
    folder_id = session.post(FOLDERS_URL, headers=headers, json=data_folder, proxies=proxies, verify=False).json().get('id')
    return folder_id

#print(scan_id)
def check_status_of_scanning(scan_id, headers, proxies):
    response = session.get(f"{SCANS_URL}/{scan_id}", headers=headers, verify=False, proxies=proxies)
    status_id = response.json().get('info', {}).get('status')
    return status_id == "completed"

# Function to generate and download the report
def generate_and_download_report(scan_id, headers, proxies):
    # Set up payload for exporting the report
    payload = {
        "format": "pdf",
        "template_id": 16,
        "csvColumns": {},
        "formattingOptions": {"page_breaks": True},
        "extraFilters": {"host_ids": [], "plugin_ids": []}
    }

    # Export the report
    res2 = requests.post(url=f"{IP}:11127/scans/{scan_id}/export", json=payload, headers=headers, verify=False, proxies=proxies)
    jsonData = res2.json()

    scan_file = str(jsonData['file'])
    scan_token = str(jsonData['token'])

    status = "loading"

    while status != 'ready':
        url2 = f"{IP}:11127/scans/{scan_id}/export/{scan_file}/status"
        t = requests.get(url=url2, headers=headers, proxies=proxies, verify=False)
        data = t.json()

        if data['status'] == 'ready':
            status = 'ready'
        else:
            time.sleep(sleep_period)

    url3 = f"{IP}:11127/scans/{scan_id}/export/{scan_file}/download"
    d = requests.get(url=url3, headers=headers, verify=False, proxies=proxies)

    file_name = f"SCAN_{scan_id}_Report.pdf"
    with open(file_name, 'wb') as file:
        file.write(d.content)

    print(f"Report for SCAN_{scan_id} downloaded and saved successfully.")

def get_user_input(prompt):
    return input(prompt).strip()

#Using Burp Suite to get API
def create_payload(name, description, folder_id):
    return {
        "uuid":"731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65","credentials":{"add":{},"edit":{},"delete":[]},
        "settings":{
            "patch_audit_over_telnet":"no",
            "patch_audit_over_rsh":"no",
            "patch_audit_over_rexec":"no",
            "snmp_port":"161",
            "additional_snmp_port1":"161",
            "additional_snmp_port2":"161",
            "additional_snmp_port3":"161",
            "http_login_method":"POST",
            "http_reauth_delay":"",
            "http_login_max_redir":"0",
            "http_login_invert_auth_regex":"no",
            "http_login_auth_regex_on_headers":"no",
            "http_login_auth_regex_nocase":"no",
            "never_send_win_creds_in_the_clear":"yes",
            "dont_use_ntlmv1":"yes",
            "start_remote_registry":"no",
            "enable_admin_shares":"no",
            "start_server_service":"no",
            "ssh_known_hosts":"",
            "ssh_port":"22",
            "ssh_client_banner":"OpenSSH_5.0",
            "attempt_least_privilege":"no",
            "log_whole_attack":"no",
            "always_report_ssh_cmds":"no",
            "enable_plugin_debugging":"no",
            "debug_level":"1",
            "enable_plugin_list":"no",
            "audit_trail":"use_scanner_default",
            "include_kb":"use_scanner_default",
            "windows_search_filepath_exclusions":"",
            "windows_search_filepath_inclusions":"",
            "custom_find_filepath_exclusions":"",
            "custom_find_filesystem_exclusions":"",
            "custom_find_filepath_inclusions":"",
            "reduce_connections_on_congestion":"no",
            "network_receive_timeout":"5",
            "max_checks_per_host":"5","max_hosts_per_scan":"30","max_simult_tcp_sessions_per_host":"","max_simult_tcp_sessions_per_scan":"","safe_checks":"yes","stop_scan_on_disconnect":"no","slice_network_addresses":"no","auto_accept_disclaimer":"no","scan.allow_multi_target":"no","host_tagging":"yes","trusted_cas":"","advanced_mode":"Default","allow_post_scan_editing":"yes","reverse_lookup":"no","log_live_hosts":"no","display_unreachable_hosts":"no","display_unicode_characters":"no","report_verbosity":"Normal","report_superseded_patches":"yes","silent_dependencies":"yes","oracle_database_use_detected_sids":"no","samr_enumeration":"yes","adsi_query":"yes","wmi_query":"yes","rid_brute_forcing":"no","request_windows_domain_info":"no","scan_webapps":"no","user_agent_string":"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)","test_default_oracle_accounts":"no","provided_creds_only":"yes","report_paranoia":"Normal","thorough_tests":"no","assessment_mode":"default","collect_identity_data_from_ad":"","svc_detection_on_all_ports":"yes","detect_ssl":"yes","ssl_prob_ports":"All ports","dtls_prob_ports":"None","cert_expiry_warning_days":"60","enumerate_all_ciphers":"yes","check_crl":"no","tcp_scanner":"no","tcp_firewall_detection":"Automatic (normal)","syn_scanner":"yes","syn_firewall_detection":"Automatic (normal)","udp_scanner":"no","ssh_netstat_scanner":"yes","wmi_netstat_scanner":"yes","snmp_scanner":"yes","only_portscan_if_enum_failed":"yes","verify_open_ports":"no","unscanned_closed":"no","portscan_range":"default","wol_mac_addresses":"","wol_wait_time":"5","scan_network_printers":"no","scan_netware_hosts":"no","scan_ot_devices":"no","ping_the_remote_host":"yes","arp_ping":"yes","tcp_ping":"yes","tcp_ping_dest_ports":"built-in","icmp_ping":"yes","icmp_unreach_means_host_down":"no","icmp_ping_retries":"2","udp_ping":"no","test_local_nessus_host":"yes","fast_network_discovery":"no","discovery_mode":"Port scan (common ports)","acls":[{"object_type":"policy","permissions":0,"type":"default"}],
            "name":name,
            "enabled":True,
            "launch_now":True,
            "name":name,
            "description":description,
            "policy_id": 4,
            "folder_id":int(folder_id),
            "scanner_id":"1",
            "text_targets":text_targets,
                #"starttime":starttime,
            "rrules":"1"

        }
    }

def run_program():
    name = get_user_input("Enter name of this scan: ")
    description = get_user_input("Enter the description: ")
    folder_name = get_user_input("Enter folder name for scans: ")
    #starttime_input = get_user_input("Enter the starttime (format: yyyy-mm-dd HH:MM:SS): ")
    #starttime = datetime.strptime(starttime_input, "%Y-%m-%d %H:%M:%S").strftime("%Y%m%dT%H%M%S")

    folder_id = check_dup_folder(folder_name)
    payload = create_payload(name, description, folder_id)

    final_response = session.post(url=SCANS_URL, json=payload, headers=headers, verify=False, proxies=proxies)
    final_data = final_response.json()
    scan_id = final_data.get('scan', {}).get('id')

    if check_status_of_scanning(scan_id, headers, proxies):
        generate_and_download_report(scan_id, headers, proxies)
    else:
        print("Scanning is not yet completed. Waiting for the report to be generated.")
        while not check_status_of_scanning(scan_id, headers, proxies):
            time.sleep(sleep_period)

        generate_and_download_report(scan_id, headers, proxies)

def main():
    while True:
        run_program()
        user_input = get_user_input("Enter 'q' to quit or any other key to run the program again: ")
        if user_input.lower() == 'q':
            print("Exiting the program. Goodbye!")
            break

if __name__ == "__main__":
    main()



