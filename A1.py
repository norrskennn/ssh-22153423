from logging import FileHandler
from random import choice
from netmiko import ConnectHandler
import difflib
import logging

# Establish cisco_router information
router_info = {
    'device_type': 'cisco_ios',
    'host': '192.168.56.101',
    'username': 'prne',
    'password': 'cisco123!',
    'secret': 'class123!', 
}

# Hostname rename
hostname = 'R1'

# Cisco hardening advice
hardening_advice = """
! Cisco Hardening Advice

!General Recommendations

enable secret 5 $1$dYxA$WbhPASqVS56AAvopBYAbk1
service password-encryption
no ip http server
no ip http secure-server
ip domain name example.netacad.com
crypto key generate rsa modulus 2048
login block-for 120 attempts 3 within 60

! Management Access Control
line vty 0 15
    transport input ssh
    login local
    transport input telnet
    exec-timeout 5 0
    access-class 15
    password class123!

! Console Access Control
line con 0
    login local
    exec-timeout 5 0 
    access class 15 in
    password cisco123!

! SNMP Configuration
no snmp-server community
no snmp-server contact
no snmp-server location

! Logging configuration
logging buffered 4096
logging console critical
logging console warnings
logging trap notifications
no logging source-interface

! NTP Configuration
no ntp server
no ntp source

! Access control lists 
no ip access-list standards
    no permit
    no deny any log

! Interface Security
interface range 192.168.56.101/24
    no cdp enable
    switchport mode access
    switchport negotiate
    spanning-tree portfast
    ip verify source
"""

device_config = ""

acl_filename = 'acl_conf.txt'

# IPsec parameters
isakmp_policy = 10  # Lower number means higher priority
crypto_map = 'VPN_MAP'  # A crypto map defines IPsec policies that specify which traffic should be encrypted
shared_key = 'Th3cra!c$f@rfr0mm!ghty'  # This key must be configured identically on both ends for a VPN connection

def ssh(router_info):
    try:
        # Establish SSH connection
        with ConnectHandler(**router_info) as ssh_connection:
            # Enable mode
            ssh_connection.enable()
            print("SSH connection successful")

            # Log a syslog message
            ssh_connection.send_command("SSH Connection established.")

    except Exception as e:
        print(f"Error!: {str(e)}")

# Establish a Telnet connection
def telnet(router_info):
    try:
        with ConnectHandler(**router_info) as telnet_connection:
            # Send a syslog message to the file for telnet connection
            telnet_connection.send_command("Telnet connection established.")

    except Exception as e:
        print(f"Error: {str(e)}")

def hostname_change(router_info):
    new_hostname = input("Enter new hostname: ")
    while True:
        print("\n Change Hostname Menu: ")
        print("1. Change hostname with SSH ")
        print("2. Return to main menu")
        print("0. Exit")

        choice = input("Enter your choice: ")
        if choice == '1':
            try:
                with ConnectHandler(**router_info) as ssh_connection:
                    ssh_connection.enable()
                    ssh_connection.send_config_set([f"hostname {new_hostname}"])
                    print(f"Hostname changed to {new_hostname}")
            except Exception as e:
                print(f"Error changing hostname: {str(e)}")
        elif choice == '2':
            break
        elif choice == '0':
            print("Exiting hostname change.")
            exit()
        else:
            print("Invalid choice. Please choose again.")

def grab_router_config(router_info):
    try:
        with ConnectHandler(**router_info) as ssh_connection:
            ssh_connection.enable()
            output = ssh_connection.send_command("show running-config")
            return output

    except Exception as e:
        print(f"Error!: {str(e)}")
        return ""

def config_hardening_compare(device_config, hardening_advice):
    d = difflib.Differ()
    diff = list(d.compare(device_config.splitlines(), hardening_advice.splitlines()))
    print("\n".join(diff))

def syslog_config(router_info):
    try:
        syslog_file_handler = FileHandler('syslog_events_monitoring.txt')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        syslog_file_handler.setFormatter(formatter)

        logger = logging.getLogger()
        logger.addHandler(syslog_file_handler)
        logger.setLevel(logging.INFO)

        with ConnectHandler(**router_info) as ssh_connection:
            ssh_connection.enable()
            event_log_commands = [
                'logging buffered 4096',
                'logging console warning',
                'logging monitor warning',
                'logging trap notifications',
            ]
            ssh_connection.send_config_set(event_log_commands)
            ssh_connection.send_command("Logging syslog, event logging configured.")
    except Exception as e:
        print(f"Error!: {str(e)}")

def acl_config(router_info, acl_file):
    try:
        with ConnectHandler(**router_info) as ssh_connection:
            ssh_connection.enable()
            with open(acl_file, 'r') as file:
                acl_config = file.read().splitlines()
            output = ssh_connection.send_config_set(acl_config)
            print(output)
    except Exception as e:
        print(f"Error configuring ACL: {str(e)}")

def ipsec_config(router_info, isakmp_policy, crypto_map, shared_key):
    try:
        with ConnectHandler(**router_info) as ssh_connection:
            ssh_connection.enable()
            isakmp_config = f"crypto isakmp policy {isakmp_policy}\n" \
                            "encryption aes-256\n" \
                            "hash sha256\n" \
                            "authentication pre-share\n" \
                            "group 14\n" \
                            "lifetime 28800\n"

            shared_key_config = f"crypto isakmp key {shared_key} address 192.168.56.101\n"

            crypto_map_config = f"crypto map {crypto_map} 10 ipsec-isakmp\n" \
                                "set peer 0.0.0.0\n" \
                                "set transform-set myset\n" \
                                "match address 100\n"

            output = ssh_connection.send_config_set([isakmp_config, shared_key_config, crypto_map_config])
            print(output)
    except Exception as e:
        print(f"Error configuring IPsec: {str(e)}")

while True:
    print("\n Main Menu: ")
    print("1. Change_Hostname_now")
    print("2. Establish_SSH_Connection_")
    print("3. Establish_Telnet_Connection_")
    print("4. Retrieve_running_configuration")
    print("5. Compare_running_configuration_with_Cisco_Hardening_Advice")
    print("6. Configure_event_logging")
    print("7. Apply_Access_Control_from_list")
    print("8. Configure_IP_security")
    print("0. Exit")

    main_choice = input("Enter your choice: ")

    if main_choice == '1':
        hostname_change(router_info)
    elif main_choice == '2':
        ssh(router_info)
    elif main_choice == '3':
        telnet(router_info)
    elif main_choice == '4':
        device_config = grab_router_config(router_info)
        print("Running Configuration:\n", device_config)
    elif main_choice == '5':
        config_hardening_compare(device_config, hardening_advice)
    elif main_choice == '6':
        syslog_config(router_info)
    elif main_choice == '7':
        acl_config(router_info, acl_filename)
    elif main_choice == '8':
        ipsec_config(router_info, isakmp_policy, crypto_map, shared_key)
    elif main_choice == '0':
        print("Exiting router configuration.")
        exit()
    else:
        print("Invalid choice. Please try again.")
