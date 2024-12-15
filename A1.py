from ast import main
from logging import FileHandler
from random import choice
from netmiko import ConnectHandler
import difflib
import logging

#Establish cisco_router information
router_info = {
    'device_type': 'cisco_ios',
    'host': '192.168.56.101',
    'username': 'prne',
    'password': 'cisco123!',
    'secret': 'class123!', 
}

#Hostnaem rename
hostname = 'R1'

#Cisco hardening advice
hardening_advice = """
! Cisco Hardening Advice

!General Recommendations

enable secret 5 $1$dYxA$WbhPASqVS56AAvopBYAbk1
service password-encrption
no ip http server
no ip http secure-sever
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

! Loggin configuration
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

! interface Security
interface range 192.168.56.101/24
    no cdp enable
    switchport mode access
    switchport negotiate
    spanning-trr portfast
    ip verify source
"""

device_config = ""

acl_list = 'acl_conf.txt'

#IPsec parameters
isakmp_policy = 10
crypto_map = 'VPN_MAP'
shared_key =  'Th3cra!c$f@rfr0mm!ghty'

def ssh(router_info):
    try:
        #Establish SSH connection
        with ConnectHandler(**router_info) as ssh_connection:
            #Enable mode
            ssh_connection.enable()
            print("SSH connection successful")

            #Log a syslog message
            ssh_connection.send_command("SSH Connection established.")

    #Print error message in string
    except Exception as e:
        print(f"Error!: {str(e)}")

#Establish a Telnet connection
def telnet(router_info):
    try:
        with ConnectHandler(**router_info)as telnet_connection:
            
            #Send a syslog message to the file for telnet connection
            telnet_connection.send_command("Telnet connection established.")
            #Syslog message is not being printed for security reasons
    
    #Prints an error message in string
    except Exception as e:    
        print(f"Error: {str(e)}")
            

def hostname_change(router_info):
    
    #New hostname from the user
    new_hostname = input("Enter new hostname: ")

    while True:
        print("\n Change Hostname Menu: ")
        print("1. Change hostname with SSH ")
        print("2. Return to main menu")
        print("0. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            ssh(new_hostname)
        elif  choice == '2':
            break
        elif choice == '0':
            print('Exiting {new_hostname}.')
            exit()
        else:
            print("Invalid. Choose again")

def grab_router_config(router_info):
    try:
        #Establish SSH connection for config files
        with ConnectHandler(**router_info) as ssh_connection:
            #Enter enable mode
            ssh_connection.enable()

            #Grab running config
            output = ssh_connection.send_command("show running-config")

            return output

    except Exception as e:
        print(f"Error!: {str(e)}")

#Compares the running config to cisco hardening advice
def config_hardening_compare(device_config, hardening_advice):
    #Difflib compares the config to hardening advice
    d = difflib.Differ()
    diff = list(d.compare(device_config.splitlines(), hardening_advice.splitlines()))

    #prints differences
    print("\n".join(diff))


def syslog_config(router_info):
    try:
        #Logging to a file
        syslog_file_handler = FileHandler('syslog_events_monitoring.txt')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(messages)s')
        syslog_file_handler.setFormatter(formatter)

        logger = logging.getLogger()
        logger.addHandler(syslog_file_handler)
        logger.setLevel(logging.INFO)

        #Establish SSH connection
        with ConnectHandler(**router_info) as ssh_connection:
            #Enter enable mode
            ssh_connection.enable()

            event_log_commands = [
                'logging buffered 4096', #Overwriting will occur after 50 messages logged
                'logging console warning', #Logs commands entered in console 
                'logging monitor warning', #Alerts if the systems performance or health is affected
                'logging trap notifcations', #Limits messages logged to file
            ]
            ssh_connection.send_config_set(event_log_commands)

            #Log syslog message for event log configuration
            ssh_connection.send_command("Logging syslog, event logging configured. ")
            # Syslog message not printed to console for security measures
    except Exception as e:
        print(f"Error!: {str(e)}")


def acl_list(router_info, acl_file):
    #connet to ssh
    with ConnectHandler(**router_info) as ssh_connection:
        #Enter enable mode
        ssh_connection.enable()


        #Read ACL config from file
        with open(acl_file, 'r') as file:
            acl_config = file.read().splitlines()

        #Send config command to the router
        output = ssh_connection.send_confifg_set(acl_config)

        #Show file configuration of who has access and thier privellage
        print(output)

def ipsec_config(router_info, isakmp_policy, crypto_map, shared_key):
    #connect to device
    with ConnectHandler(**router_info) as ssh_connection:
        #Enter enable mode
        ssh_connection.enable

        isakmp_config = f"crypto isakmp policy {isakmp_policy}\n" \
                        "encryption aes-256\n" \
                        "hash sha256\n" \
                        "authentication pre-share\n" \
                        f"group 14\n" \
                        f"lifetime 28800\n" \
        
        #Configure pre shared key
        shared_key_config =  f"crypto isakmp key {shared_key} address 192.168.56.101\n"

        #Config crypto mapping
        crypto_map_config = f"crypto map {crypto_map} 10 ipsec-isakmp" \
                            "set peer 0.0.0.0\n" \
                            f"set transform-set myset\n" \
                            "match address 100\n"
        
        #Send IPsec Config commands to device
        output = ssh_connection.send_config_set([isakmp_config, shared_key_config, crypto_map_config])

        print(output)

#Main menu
while True:
    print("\n Main Menu: ")
    print("1. Change Hostname")
    print("2. SSH Connection")
    print("3. Telnet Connection")
    print("4. Get running configuration")
    print("5. Compare running configuration with Cisco Hardening Advice")
    print("6. Configure event logging and redirect to a file")
    print("7. Set Access Control via list")
    print("8.IP security")
    print("0. Exit")

    main_choice = input("Enter choice: ")

    if main_choice == '1':
        hostname_change(router_info)
    elif main_choice == '2':
        ssh(router_info)
    elif main_choice == '3':
        telnet(router_info, "")
    elif main_choice == '4':
        device_config = grab_router_config(router_info)
        print("Current Running Configuration:\n", device_config)
    elif main_choice == '5':
        config_hardening_compare(device_config,hardening_advice)
    elif main_choice == '6':
        syslog_config(router_info)
    elif main_choice == '7':
       acl_list(router_info, acl_list) 
    elif main_choice == '8':
        ipsec_config(router_info,isakmp_policy,crypto_map,shared_key)
    elif main_choice == '0':
        print("Exiting router.")
        exit()
    else:
        print("Invalid option")
