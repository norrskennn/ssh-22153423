from logging import FileHandler
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

! General Recommendations

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
    exec-timeout 5 0
    password class123!

! Console Access Control
line con 0
    login local
    exec-timeout 5 0 
    password cisco123!
"""

device_config = ""

acl_list = 'acl_conf.txt'

# IPsec parameters
isakmp_policy = 10
crypto_map = 'VPN_MAP'
shared_key = 'Th3cra!c$f@rfr0mm!ghty'


def ssh(router_info):
    try:
        # Establish SSH connection
        with ConnectHandler(**router_info) as ssh_connection:
            # Enable mode
            ssh_connection.enable()
            print("SSH connection successful")

            # Log a syslog message
            ssh_connection.send_command("! SSH Connection established.")

    except Exception as e:
        print(f"Error!: {str(e)}")


def telnet(router_info):
    try:
        with ConnectHandler(**router_info) as telnet_connection:
            # Enter enable mode
            telnet_connection.enable()
            telnet_connection.send_command("! Telnet connection established.")
    except Exception as e:    
        print(f"Error: {str(e)}")


def hostname_change(router_info):
    new_hostname = input("Enter new hostname: ")
    try:
        with ConnectHandler(**router_info) as ssh_connection:
            ssh_connection.enable()
            ssh_connection.send_config_set([f"hostname {new_hostname}"])
            print(f"Hostname changed to {new_hostname}")
    except Exception as e:
        print(f"Error changing hostname: {str(e)}")


def grab_router_config(router_info):
    try:
        with ConnectHandler(**router_info) as ssh_connection:
            ssh_connection.enable()
            return ssh_connection.send_command("show running-config")
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
            print("Event logging configured.")
    except Exception as e:
        print(f"Error!: {str(e)}")


def acl_list(router_info, acl_file):
    try:
        with ConnectHandler(**router_info) as ssh_connection:
            ssh_connection.enable()
            with open(acl_file, 'r') as file:
                acl_config = file.read().splitlines()
            output = ssh_connection.send_config_set(acl_config)
            print(output)
    except FileNotFoundError:
        print(f"Error: File {acl_file} not found.")
    except Exception as e:
        print(f"Error: {str(e)}")


def ipsec_config(router_info, isakmp_policy, crypto_map, shared_key):
    try:
        with ConnectHandler(**router_info) as ssh_connection:
            ssh_connection.enable()
            isakmp_config = f"""crypto isakmp policy {isakmp_policy}
encryption aes-256
hash sha256
authentication pre-share
group 14
lifetime 28800"""

            shared_key_config = f"crypto isakmp key {shared_key} address 0.0.0.0"

            crypto_map_config = f"""crypto map {crypto_map} 10 ipsec-isakmp
set peer 0.0.0.0
set transform-set myset
match address 100"""

            output = ssh_connection.send_config_set([isakmp_config, shared_key_config, crypto_map_config])
            print(output)
    except Exception as e:
        print(f"Error configuring IPsec: {str(e)}")


while True:
    print("\n Main Menu: ")
    print("1. Change Hostname now")
    print("2. Establish SSH Connection")
    print("3. Establish Telnet Connection")
    print("4. Retrieve running configuration")
    print("5. Compare running configuration with Cisco Hardening Advice")
    print("6. Configure event logging")
    print("7. Apply Access Control from list")
    print("8. Configure IP security")
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
        print("Running Configuration now:\n", device_config)
    elif main_choice == '5':
        device_config = grab_router_config(router_info)
        config_hardening_compare(device_config, hardening_advice)
    elif main_choice == '6':
        syslog_config(router_info)
    elif main_choice == '7':
        acl_list(router_info, acl_list)
    elif main_choice == '8':
        ipsec_config(router_info, isakmp_policy, crypto_map, shared_key)
    elif main_choice == '0':
        print("Exiting router now.")
        break
    else:
        print("Invalid choice.")

