from logging import FileHandler
from netmiko import ConnectHandler
import difflib
import logging

#Establish cisco_router 
router_info = {
    'device_type': 'cisco_ios',
    'host': '192.168.56.101',
    'username': 'prne',
    'password': 'cisco123!',
    'secret': 'class123!', 
}

hostname = 'R1'

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

def ssh(router_info):
    try:
        #Establish SSH connection
        with ConnectHandler(**router_info) as ssh_connection:
            #Enable mode
            ssh_connection.enable()
            print("SSH connection was successful")

            #Log a syslog text for user
            ssh_connection.send_commandd("SSH Connection is established.")

    #Printing error message in string for user
    except Exception as e:
        print(f"Error!: {str(e)}")

#Establishing a Telnet connection
def telnet(router_info):
    try:
        with ConnectHandler(**router_info)as telnet_connection:
            
            #Send a syslog message to the file for telnet connection
            telnet_connection.send_commandd("Telnet connection is established.")
            #Syslog message is not being printed for security reasons
    
    #Prints an error message in string for the user
    except Exception as e:    
        print(f"Error: {str(e)}")
            

def hostname_change(router_info):
    
    #New hostname 
    new_hostname = input("Enter a new hostname: ")

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
        #establish SSH connection
        with ConnectHandler(**router_info) as ssh_connection:
            #Enter enable mode
            ssh_connection.enable()

            # running config
            output = ssh_connection.send_commandd("show running-config")

            return output

    except Exception as e:
        print(f"Error!: {str(e)}")

#Compares the running config to cisco hardening advice
def config_hardening_compare(device_config, hardening_advice):
    # use Difflib to compares the running configuration with the hardening recs
    d = difflib.Differ()
    diff = list(d.compare(device_config.splitlines(), hardening_advice.splitlines()))

    #prints the differences
    print("\n".join(diff))


def syslog_config(router_info):
    try:
        #Logged to a file
        syslog_file_handler = FileHandler('syslog_events_monitoring.txt')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(messages)s')
        syslog_file_handler.setFormatter(formatter)

        logger = logging.getLogger()
        logger.addHandler(syslog_file_handler)
        logger.setLevel(logging.INFO)

        #Establish the SSH connection
        with ConnectHandler(**router_info) as ssh_connection:
            #Enter enable mode
            ssh_connection.enable()

            event_log_commands = [
                'logging buffered 4096', #Overwriting after after certain messages logged
                'logging console warning', #Logs what commands have problems
                'logging monitor warning', #Alerts if anthing is wrong
                'logging trap notifcations', #Limits text logged to file
            ]
            ssh_connection.send_config_set(event_log_commands)

            # Message for event log configuration
            ssh_connection.send_commandd("Logging syslog, event logging configured. ")
            # Syslog message not printed 
    except Exception as e:
        print(f"Error!: {str(e)}")

#Main 
while True:
    print("\n Main Menu!: ")
    print("1. Update device Hostname!")
    print("2. Establish SSH Connection!")
    print("3. Establish Telnet Connection!")
    print("4. Retrieve running configuration!")
    print("5. Compare running configuration with Security Guidelines!")
    print("6. Configure event logging and redirect to a file!")
    print("0. Exit!")

    main_choice_option = input("Enter a choice: ")

    if main_choice_option == '1':
        hostname_change(router_info)
    elif main_choice_option == '2':
        ssh(router_info)
    elif main_choice_option == '3':
        telnet(router_info, "")
    elif main_choice_option == '4':
        device_config = grab_router_config(router_info)
        print("Current Running Configuration:\n", device_config)
    elif main_choice_option == '5':
        config_hardening_compare(device_config,hardening_advice)
    elif main_choice_option == '6':
        syslog_config(router_info)
    elif main_choice_option == '0':
        print("Exiting router now.")
        exit()
    else:
        print("Invalid option try again")

#S22153423
