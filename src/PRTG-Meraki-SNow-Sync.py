from datetime import datetime, timezone
from enum import Enum
from logging.handlers import SysLogHandler
import os
import re
import sys
import time

from dotenv import load_dotenv
from loguru import logger
import meraki
import pysnow
from pysnow.exceptions import PysnowException
import requests


# ====================== Environment / Global Variables =======================
load_dotenv(override=True)

# Clover regex constant global variables.
CLOVER_ALL_BUT_WINDOW_NUMBER_REGEX = re.compile(r'\[.+\]|IBC|Window|Backup|([\da-fA-F]{2}:){5}[\da-fA-F]{2}')
CLOVER_WINDOW_NUMBER_REGEX = re.compile(r'[A-Z]{0,3}\d{1,2}(?:[A-Z])?')
CLOVER_SERIAL_NUMBER_LONG_REGEX = re.compile(r'Clover [A-Z]\d{3}[A-Z] [A-Z]\d{3}[A-Z]{2}\d{8}')
CLOVER_SERIAL_NUMBER_SHORT_REGEX = re.compile(r'[A-Z]\d{3}[A-Z]{2}\d{8}')
CLOVER_MAC_ADDRESS_REGEX = re.compile(r'd4:95:24(:[\da-f]{2}){3}')

# Logger constant global variables.
LOGGER_NAME = os.getenv('LOGGER_NAME')
LOGGER_FILE_NAME = os.getenv('LOGGER_FILE_NAME')

# Meraki constant global variables.
MERAKI_API_KEY = os.getenv('MERAKI_API_KEY')
MERAKI_ORGANIZATION_ID = os.getenv('MERAKI_ORGANIZATION_ID')
MERAKI_NETWORK_ID = os.getenv('MERAKI_NETWORK_ID')

# Meraki regex constant global variables.
MERAKI_CLOVER_NAME_REGEX = re.compile(r'^(?:IBC )?Window [A-Z]{0,3}\d{1,2}(?:[A-Z])? d4:95:24(?::[\da-f]{2}){3}$')
MERAKI_SITE_INFO_REGEX = re.compile(r'\(.+\)')

# PRTG constant global variables.
PRTG_TABLE_URL = os.getenv('PRTG_TABLE_URL')
PRTG_USERNAME = os.getenv('PRTG_USERNAME')
PRTG_PASSHASH = os.getenv('PRTG_PASSHASH')

# PRTG regex constant global variables.
PRTG_CLOVER_NAME_REGEX = re.compile(r'^\[[A-Za-z]+\d{3}(?:\([A-Za-z]+IBC\d{3}\))?\] (?:IBC )?Window [A-Z]{0,3}\d{1,2}(?:[A-Z])? d4:95:24(?::[\da-f]{2}){3}$')
PRTG_SITE_IN_CLOVER_NAME_REGEX = re.compile(r'\[.+\]')
PRTG_SITE_INFO_REGEX = re.compile(r' \(.+\)')

# ServiceNow constant global variables.
SERVICENOW_INSTANCE_NAME = os.getenv('SERVICENOW_INSTANCE_NAME')
SERVICENOW_INSTANCE_URL = f'https://{SERVICENOW_INSTANCE_NAME}.service-now.com'
SERVICENOW_USERNAME = os.getenv('SERVICENOW_USERNAME')
SERVICENOW_PASSWORD = os.getenv('SERVICENOW_PASSWORD')
SERVICENOW_CMDB_TABLET_TABLE_PATH = os.getenv('SERVICENOW_CMDB_TABLET_TABLE_PATH')
SERVICENOW_CLIENT = pysnow.Client(
    instance=SERVICENOW_INSTANCE_NAME,
    user=SERVICENOW_USERNAME,
    password=SERVICENOW_PASSWORD
)

# ServiceNow ticket constant global variables.
SERVICENOW_TICKET_CALLER_ID = os.getenv('SERVICENOW_TICKET_CALLER_ID')
SERVICENOW_TICKET_ASSIGNED_TO = os.getenv('SERVICENOW_TICKET_ASSIGNED_TO')
SERVICENOW_TICKET_COMPANY = os.getenv('SERVICENOW_TICKET_COMPANY')
SERVICENOW_TICKET_U_MILESTONE = os.getenv('SERVICENOW_TICKET_U_MILESTONE')

# Syslog constant global variables.
SYSLOG_ADDRESS = os.getenv('SYSLOG_ADDRESS')
SYSLOG_PORT = os.getenv('SYSLOG_PORT')

# Other constant global variables.
DC_TICKETING = False
DEBUG_MODE = True
LOG_LINE_BREAK = '--------------------------------------------------------------'
SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))


# ================================== Classes ==================================
class MerakiClover(object):
    """
    Represents a Clover payment device in Meraki.
    """

    # Constructor to initialize this object's fields.
    def __init__(self,
                 meraki_id: str = None,
                 name: str = None,
                 site: str = None,
                 window_number: str = None,
                 mac_address: str = None,
                 ip_address: str = None,
                 error: str = None):
        self.meraki_id = meraki_id
        self.name = name
        self.site = site
        self.is_ibc = False
        self.window_number = window_number
        self.mac_address = mac_address
        self.ip_address = ip_address
        self.error = error

    # Set IBC status of Clover.
    def __post_init__(self):
        self.is_ibc = True if "IBC" in self.name else False


class PRTGClover(object):
    """
    Represents a Clover payment device in PRTG.
    """

    # Constructor to initialize this object's fields.
    def __init__(self,
                 prtg_id: str = None,
                 name: str = None,
                 site: str = None,
                 window_number: str = None,
                 mac_address: str = None,
                 ip_address: str = None,
                 serial_number: str = None,
                 error: str = None):
        self.prtg_id = prtg_id
        self.name = name
        self.site = site
        self.is_ibc = False
        self.window_number = window_number
        self.mac_address = mac_address
        self.ip_address = ip_address
        self.serial_number = serial_number
        self.error = error
    
    # Set IBC status of Clover.
    def __post_init__(self):
        name_no_site = re.sub(PRTG_SITE_IN_CLOVER_NAME_REGEX, '', self.name)
        self.is_ibc = True if "IBC" in name_no_site else False


class CloverPair(object):
    """
    Represents a Meraki Clover and PRTG Clover that are paired up together.
    """

    # Constructor to initialize this object's fields.
    def __init__(self,
                 meraki_clover: MerakiClover,
                 prtg_clover: PRTGClover,
                 mismatch_error: str = None):
        self.meraki_clover = meraki_clover
        self.prtg_clover = prtg_clover
        self.mismatch_error = mismatch_error


class AffectedPlatform(Enum):
    """
    Represents which platform is affected from a Clover error.
    """

    MERAKI = 'Meraki'
    MERAKI_AND_PRTG = 'Meraki/PRTG'
    PRTG = 'PRTG'
    SNOW = 'ServiceNow'
    ALL = 'PRTG/Meraki/ServiceNow'
    NONE = 'No platform'


class CloverSyncStatus(object):
    """
    Represents the current status of the entire Clover sync operation.
    """

    # Data structures to keep track of the sync status across all systems.
    # Most keys to the dictionaries are the MAC address for the Clover.
    meraki_unknown_devices = list[dict]()
    meraki_offline_clovers = dict[str, MerakiClover]()
    meraki_backup_clovers = dict[str, MerakiClover]()
    meraki_invalid_clovers = dict[str, MerakiClover]()
    meraki_clovers = dict[str, MerakiClover]()
    prtg_id_to_mac = dict[str, str]()  # Keys are PRTG IDs
    prtg_id_to_sn = dict[str, str]()  # Keys are PRTG IDs
    prtg_unknown_clovers = list[dict]()
    prtg_offline_clovers = dict[str, PRTGClover]()
    prtg_invalid_clovers = dict[str, PRTGClover]()
    prtg_dc_macs = dict[str, PRTGClover]()
    prtg_unverified_macs = dict[str, PRTGClover]()
    prtg_mac_sensor_mismatch = dict[str, PRTGClover]()
    prtg_clovers = dict[str, PRTGClover]()
    clover_matches = dict[str, CloverPair]()
    clover_mismatches = dict[str, CloverPair]()
    unsyncable_clovers = dict[str, CloverPair]()
    servicenow_lost_clovers = list[dict]()
    servicenow_missing_clovers = set[str]()

    # Constructor to initialize this object's fields.
    def __init__(self):
        pass


# ================================= Functions =================================
def get_meraki_clovers(clover_sync_status: CloverSyncStatus) -> CloverSyncStatus:
    """
    Gets all Clover information from Meraki. Uses the given CloverSyncStatus
    object to save the status of all the Clovers in Meraki. Returns the updated
    CloverSyncStatus object with the gathered information.

    Args:
        clover_sync_status (CloverSyncStatus): The current status of the entire
            Clover sync operation.

    Returns:
        CloverSyncStatus: The updated status of the entire Clover sync
            operation.
    """

    logger.info('|')
    logger.info(log_title('Begin Meraki Report'))
    logger.info('Retrieving Clover information from Meraki...')

    # Use the Meraki API to get a list of all the Clover (client)
    # devices that have connected to the Meraki network from the past
    # 31 days.
    meraki_dash = meraki.DashboardAPI(
        MERAKI_API_KEY,
        output_log=False,
        print_console=False,
        suppress_logging=True
    )
    meraki_clovers = meraki_dash.networks.getNetworkClients(
        MERAKI_NETWORK_ID,
        total_pages='all',
        perPage=1000,
        timespan=2678400
    )

    # Iterate through each Clover device and update the status object
    # depending on the state of the Clover.
    for clover in meraki_clovers:
        # Check if this device is a Clover device or the probe is unknown.
        if clover['manufacturer'] is None or \
                'clover' not in clover['manufacturer'].lower() or \
                clover['recentDeviceName'] is None:
            # Add this device to the unknown devices list.
            clover_sync_status.meraki_unknown_devices.append(clover)
            continue

        # Clean the Clover's probe name by removing parentheses and its
        # contents.
        clean_probe = re.sub(MERAKI_SITE_INFO_REGEX, '',
                             clover['recentDeviceName']).strip()

        # Check if this Clover is connected to a Ready Meraki access point.
        if 'ready' in clean_probe.lower():
            continue

        # Check if this Clover is offline.
        if clover['status'] != 'Online':
            # Add this Clover to the offline Meraki Clovers dictionary.
            clover_name = (clover['description'] 
                           if clover['description'] is not None 
                           else clover['mac'])
            new_offline_clover = MerakiClover(
                meraki_id=clover['id'],
                name=clover_name,
                site=clean_probe,
                window_number=get_window_number(clover_name),
                mac_address=clover['mac'],
                ip_address=clover['ip'],
                error=None
            )
            clover_sync_status.meraki_offline_clovers[clover['mac']] = \
                new_offline_clover
            continue

        # Check if the Clover's name in Meraki is 'empty' (only MAC address).
        if clover['description'] is None:
            # Add this Clover to the invalid Meraki Clovers dictionary.
            missing_name_error = \
                f'Clover at site "{clean_probe}" with name "{clover['mac']}" ' \
                f'appears to have an invalid name ' \
                f'(the name is just the MAC address)'
            new_unnamed_clover = MerakiClover(
                meraki_id=clover['id'],
                name=clover['mac'],
                site=clean_probe,
                window_number=None,
                mac_address=clover['mac'],
                ip_address=clover['ip'],
                error=missing_name_error
            )
            clover_sync_status.meraki_invalid_clovers[clover['mac']] = \
                new_unnamed_clover
            continue

        # Check if this is a backup Clover.
        if 'backup' in clover['description'].lower():
            # Add this Clover to the backup Meraki Clovers dictionary.
            new_backup_clover = MerakiClover(
                meraki_id=clover['id'],
                name=clover['description'],
                site=clean_probe,
                window_number=get_window_number(clover['description']),
                mac_address=clover['mac'],
                ip_address=clover['ip'],
                error=None
            )
            clover_sync_status.meraki_backup_clovers[clover['mac']] = \
                new_backup_clover
            continue

        # Check if the Clover name is formatted incorrectly.
        if not MERAKI_CLOVER_NAME_REGEX.match(clover['description']):
            # Add this Clover to the invalid Meraki Clovers dictionary.
            invalid_name_error = \
                f'Clover at site "{clean_probe}" with name ' \
                f'"{clover['description']}" appears to have an invalid name ' \
                f'(the format is incorrect)'
            new_invalid_clover = MerakiClover(
                meraki_id=clover['id'],
                name=clover['description'],
                site=clean_probe,
                window_number=get_window_number(clover['description']),
                mac_address=clover['mac'],
                ip_address=clover['ip'],
                error=invalid_name_error
            )
            clover_sync_status.meraki_invalid_clovers[clover['mac']] = \
                new_invalid_clover
            continue

        # Since the name is formatted correctly, let's extract the window
        # number from the name.
        window_num = get_window_number(clover['description'])

        # Check if the MAC address is correct in the Clover's name.
        if clover['mac'] not in clover['description']:
            # Add this Clover to the invalid Meraki Clovers dictionary.
            invalid_mac_error = \
                f'Clover at site "{clean_probe}" with name ' \
                f'"{clover['description']}" appears to have an invalid name ' \
                f'(the MAC address in the name does not match the ' \
                f'Clover\'s true MAC address from the Meraki Dashboard)'
            new_invalid_clover = MerakiClover(
                meraki_id=clover['id'],
                name=clover['description'],
                site=clean_probe,
                window_number=window_num,
                mac_address=clover['mac'],
                ip_address=clover['ip'],
                error=invalid_mac_error
            )
            clover_sync_status.meraki_invalid_clovers[clover['mac']] = \
                new_invalid_clover
            continue

        # Make a new Meraki Clover object and add it to the Meraki Clovers
        # dictionary.
        new_meraki_clover = MerakiClover(
            meraki_id=clover['id'],
            name=clover['description'],
            site=clean_probe,
            window_number=window_num,
            mac_address=clover['mac'],
            ip_address=clover['ip'],
            error=None
        )
        clover_sync_status.meraki_clovers[clover['mac']] = new_meraki_clover

    logger.info('Clover information retrieved from Meraki!')
    logger.info(LOG_LINE_BREAK)

    # Begin the report for the Meraki Clover device retrieval.
    # Report unknown devices.
    unknown_devices_count = len(clover_sync_status.meraki_unknown_devices)
    logger.info('|')
    logger.info(
        log_title(f'Unknown devices found ({unknown_devices_count})'))
    for unknown_device in sorted(clover_sync_status.meraki_unknown_devices,
                                 key=lambda device:
                                 f'{device['recentDeviceName']} '
                                 f'{device['description']}'):
        logger.warning(f'    {unknown_device['recentDeviceName']} '
                       f'{(unknown_device['mac'] 
                         if unknown_device['description'] is None 
                         else unknown_device['description'])}')
    logger.info(LOG_LINE_BREAK)

    # Report offline devices.
    offline_devices_count = len(clover_sync_status.meraki_offline_clovers)
    logger.info('|')
    logger.info(
        log_title(f'Offline devices found ({offline_devices_count})'))
    for offline_device in sorted(clover_sync_status.
                                 meraki_offline_clovers.values(),
                                 key=lambda device: f'{device.site} '
                                                    f'{device.name}'):
        logger.info(f'    {offline_device.site} {offline_device.name}')
    logger.info(LOG_LINE_BREAK)

    # Report backup devices.
    backup_devices_count = len(clover_sync_status.meraki_backup_clovers)
    logger.info('|')
    logger.info(
        log_title(f'Backup devices found ({backup_devices_count})'))
    for backup_device in sorted(clover_sync_status.
                                meraki_backup_clovers.values(),
                                key=lambda device: f'{device.site} '
                                                   f'{device.name}'):
        logger.info(f'    {backup_device.site} {backup_device.name}')
    logger.info(LOG_LINE_BREAK)

    # Report invalid devices.
    invalid_device_count = len(clover_sync_status.meraki_invalid_clovers)
    logger.info('|')
    logger.info(
        log_title(f'Invalid devices found ({invalid_device_count})'))
    for invalid_device in sorted(clover_sync_status.
                                 meraki_invalid_clovers.values(),
                                 key=lambda device: f'{device.site} '
                                                    f'{device.name}'):
        logger.warning(f'    {invalid_device.site} {invalid_device.name}')
    logger.info(LOG_LINE_BREAK)

    # Report the total Clover device count from Meraki.
    logger.info('|')
    logger.info(log_title('End Meraki Report'))
    total_devices_count = invalid_device_count + \
        len(clover_sync_status.meraki_clovers)
    logger.info(f'Total Online Clovers in Meraki: {total_devices_count}')
    logger.info(LOG_LINE_BREAK)

    return clover_sync_status


def get_prtg_clovers(clover_sync_status: CloverSyncStatus) -> CloverSyncStatus:
    """
    Gets Clover information from PRTG. Uses the given CloverSyncStatus
    object to save the status of all the Clovers in PRTG. Returns the updated
    CloverSyncStatus object with the gathered information.

    Args:
        clover_sync_status (CloverSyncStatus): The current status of the entire
            Clover sync operation.

    Returns:
        CloverSyncStatus: The updated status of the entire Clover sync
            operation.
    """

    logger.info('|')
    logger.info(log_title('Begin PRTG Report'))
    logger.info('Retrieving Clover information from PRTG...')

    # Retrieve the MAC address sensor values and convert the response to JSON.
    prtg_macs_resp = requests.get(
        url=PRTG_TABLE_URL,
        params={
            'content': 'sensors',
            'columns': 'name,probe,device,message,status,parentid',
            'filter_name': '@sub(MAC)',
            'sortby': 'device',
            'output': 'json',
            'count': '50000',
            'username': PRTG_USERNAME,
            'passhash': PRTG_PASSHASH
        }
    )
    prtg_macs_json = prtg_macs_resp.json()

    # Fill the sensor values dictionary with MAC address sensor values.
    for mac_sensor in prtg_macs_json['sensors']:
        # Check if this Clover is connected to a Ready probe.
        if 'ready' in mac_sensor['probe'].lower():
            continue

        # Get the PRTG ID of the related device.
        prtg_id = f'{mac_sensor['parentid']}'

        # Check if the sensor is not online.
        if mac_sensor['status_raw'] != 3:
            clover_sync_status.prtg_id_to_mac[prtg_id] = 'Offline'
            continue

        # Check if the sensor is returning a 'dc' MAC address.
        if 'dc:95:24:' in mac_sensor['message_raw']:
            clover_sync_status.prtg_id_to_mac[prtg_id] = 'dc'
            continue

        # Check if the sensor has a valid value in it.
        if not CLOVER_MAC_ADDRESS_REGEX.match(mac_sensor['message_raw']):
            clover_sync_status.prtg_id_to_mac[prtg_id] = 'Invalid'
            continue

        # Add this MAC address to the PRTG ID to MAC address dictionary.
        clover_sync_status.prtg_id_to_mac[prtg_id] = mac_sensor['message_raw']

    # Retrieve the serial number sensor values and convert the response to
    # JSON.
    prtg_sns_resp = requests.get(
        url=PRTG_TABLE_URL,
        params={
            'content': 'sensors',
            'columns': 'name,probe,device,message,status,parentid',
            'filter_name': '@sub(Descr)',
            'sortby': 'device',
            'output': 'json',
            'count': '50000',
            'username': PRTG_USERNAME,
            'passhash': PRTG_PASSHASH
        }
    )
    prtg_sns_json = prtg_sns_resp.json()

    # Fill the PRTG ID to S/N dictionary with serial number sensor values.
    for sn_sensor in prtg_sns_json['sensors']:
        # Check if this Clover is connected to a Ready probe.
        if 'ready' in sn_sensor['probe'].lower():
            continue

        # Get the PRTG ID of the relevant device.
        prtg_id = f'{sn_sensor['parentid']}'

        # Check if the sensor is not online.
        if sn_sensor['status_raw'] != 3:
            clover_sync_status.prtg_id_to_sn[prtg_id] = 'Offline'
            continue

        # Check if the sensor has an invalid value in it.
        if not CLOVER_SERIAL_NUMBER_LONG_REGEX.match(sn_sensor['message_raw']):
            clover_sync_status.prtg_id_to_sn[prtg_id] = 'Invalid'
            continue

        # Add this S/N to the PRTG ID to S/N dictionary.
        clover_sync_status.prtg_id_to_sn[prtg_id] = sn_sensor['message_raw']

    # Prepare and send the PRTG API request to get Clover devices,
    # then convert the response to JSON.
    prtg_clovers_resp = requests.get(
        url=PRTG_TABLE_URL,
        params={
            'content': 'devices',
            'columns': 'probe,group,name,objid,host,status',
            'filter_group': '@sub(Clover)',
            'sortby': 'name',
            'output': 'json',
            'count': '50000',
            'username': PRTG_USERNAME,
            'passhash': PRTG_PASSHASH
        }
    )
    prtg_clovers_json = prtg_clovers_resp.json()

    # Update the PRTG Clover dictionary with initial Clover information.
    for clover in prtg_clovers_json['devices']:
        # Get the PRTG ID, clean up the probe name, and try to get a valid
        # Clover MAC address from the name of the device.
        prtg_id = f'{clover['objid']}'
        clean_probe = re.sub(PRTG_SITE_INFO_REGEX, '', clover['probe']).strip()
        name_mac_address = get_clover_mac(clover['name'])

        # Check if this Clover is connected to a Ready probe.
        if 'ready' in clean_probe.lower():
            continue

        # Check if this Clover's MAC address is not extractable.
        if name_mac_address == '':
            # Add this Clover to the unknown PRTG Clover dictionary.
            clover_sync_status.prtg_unknown_clovers.append(clover)
            continue

        # Check if this Clover is not online.
        if clover['status_raw'] != 3:
            # Add this Clover to the offline PRTG Clover dictionary. We will
            # use the MAC address from the name to identify this PRTG Clover.
            new_offline_clover = PRTGClover(
                prtg_id=prtg_id,
                name=clover['name'],
                site=clean_probe,
                mac_address=name_mac_address,
                ip_address=clover['host'],
                error=None
            )
            clover_sync_status.prtg_offline_clovers[name_mac_address] = \
                new_offline_clover
            continue

        # Get the values from the MAC sensor and S/N sensor.
        mac_address = clover_sync_status.prtg_id_to_mac[prtg_id]
        full_sn = clover_sync_status.prtg_id_to_sn[prtg_id]

        # Get the shortened S/N if there's a valid S/N.
        if full_sn == 'Offline' or full_sn == 'Invalid':
            short_sn = full_sn
        else:
            short_sn = full_sn.split(' ')[2]

        # Check if this Clover's MAC address sensor is returning a "dc" MAC
        # address value.
        if mac_address == 'dc':
            # Attempt to extract the window number from the Clover's name.
            window_num = get_window_number(clover['name'])

            # Add this Clover to the dc MACS PRTG Clover dictionary. We will
            # use the MAC address from the name to identify this PRTG Clover.
            dc_mac_error = f'Clover at site "{clean_probe}" with name ' \
                           f'"{clover['name']}" has its MAC ' \
                           f'sensor returning a "dc" MAC address'
            new_dc_mac_clover = PRTGClover(
                prtg_id=prtg_id,
                name=clover['name'],
                site=clean_probe,
                window_number=window_num,
                mac_address=name_mac_address,
                ip_address=clover['host'],
                serial_number=short_sn,
                error=dc_mac_error
            )
            clover_sync_status.prtg_dc_macs[name_mac_address] = \
                new_dc_mac_clover
            continue

        # Check if this Clover's MAC address sensor returned an invalid value.
        if not CLOVER_MAC_ADDRESS_REGEX.match(mac_address):
            # Add this Clover to the unverified PRTG Clover dictionary. We
            # will use the MAC address from the name to identify this PRTG
            # Clover.
            unverified_mac_error = f'Clover at site "{clean_probe}" with name ' \
                                   f'"{clover['name']}" has a MAC address that ' \
                                   f'could not be verified (the MAC sensor ' \
                                   f'returned an invalid value)'
            new_unverified_clover = PRTGClover(
                prtg_id=prtg_id,
                name=clover['name'],
                site=clean_probe,
                mac_address=name_mac_address,
                ip_address=clover['host'],
                serial_number=short_sn,
                error=unverified_mac_error
            )
            clover_sync_status.prtg_unverified_macs[name_mac_address] = \
                new_unverified_clover
            continue

        # Check if the name is formatted incorrectly.
        if not PRTG_CLOVER_NAME_REGEX.match(clover['name']):
            # Add this Clover to the invalid PRTG Clovers dictionary.
            invalid_name_error = \
                f'Clover at site "{clean_probe}" with name "{clover['name']}" ' \
                f'appears to have an invalid name (the format is incorrect)'
            new_invalid_clover = PRTGClover(
                prtg_id=prtg_id,
                name=clover['name'],
                site=clean_probe,
                window_number=get_window_number(clover['name']),
                mac_address=mac_address,
                ip_address=clover['host'],
                serial_number=short_sn,
                error=invalid_name_error
            )
            clover_sync_status.prtg_invalid_clovers[mac_address] = \
                new_invalid_clover
            continue

        # Since the name is formatted correctly, let's extract the window
        # number from the name.
        window_num = get_window_number(clover['name'])

        # Check if the MAC address is incorrect in the name.
        if mac_address not in clover['name']:
            # Add this Clover to the mac sensor mismatch PRTG Clovers 
            # dictionary.
            invalid_mac_error = \
                f'Clover at site "{clean_probe}" with name "{clover['name']}" ' \
                f'appears to have an invalid name ' \
                f'(the MAC address in the name does not match the ' \
                f'Clover\'s true MAC address from the MAC sensor)'
            new_invalid_clover = PRTGClover(
                prtg_id=prtg_id,
                name=clover['name'],
                site=clean_probe,
                window_number=window_num,
                mac_address=mac_address,
                ip_address=clover['host'],
                serial_number=short_sn,
                error=invalid_mac_error
            )
            clover_sync_status.prtg_mac_sensor_mismatch[mac_address] = \
                new_invalid_clover
            continue

        # Check if the site is correct in the name.
        if clean_probe not in clover['name']:
            # Add this Clover to the invalid PRTG Clovers dictionary.
            invalid_site_error = \
                f'Clover at site "{clean_probe}" with name ' \
                f'"{clover['name']}" appears to have an invalid name (the ' \
                f'site in the name does not match the Clover\'s probe name)'
            new_invalid_clover = PRTGClover(
                prtg_id=prtg_id,
                name=clover['name'],
                site=clean_probe,
                window_number=window_num,
                mac_address=mac_address,
                ip_address=clover['host'],
                serial_number=short_sn,
                error=invalid_site_error
            )
            clover_sync_status.prtg_invalid_clovers[mac_address] = \
                new_invalid_clover
            continue

        # Make a new PRTG Clover object and add it to the PRTG Clovers
        # dictionary.
        new_prtg_clover = PRTGClover(
            prtg_id=prtg_id,
            name=clover['name'],
            site=clean_probe,
            window_number=window_num,
            mac_address=mac_address,
            ip_address=clover['host'],
            serial_number=short_sn,
            error=None
        )
        clover_sync_status.prtg_clovers[mac_address] = new_prtg_clover

    logger.info('Clover information retrieved from PRTG!')
    logger.info(LOG_LINE_BREAK)

    # Begin the report for the PRTG Clover device retrieval.
    # Report unknown devices.
    unknown_devices_count = len(clover_sync_status.prtg_unknown_clovers)
    logger.info('|')
    logger.info(
        log_title(f'Unknown devices found ({unknown_devices_count})'))
    for unknown_device in sorted(clover_sync_status.prtg_unknown_clovers,
                                 key=lambda device: f'{device['name']}'):
        logger.warning(f'    {unknown_device['name']}')
    logger.info(LOG_LINE_BREAK)

    # Report offline devices.
    offline_devices_count = len(clover_sync_status.prtg_offline_clovers)
    logger.info('|')
    logger.info(
        log_title(f'Offline devices found ({offline_devices_count})'))
    for offline_device in sorted(clover_sync_status.
                                 prtg_offline_clovers.values(),
                                 key=lambda device: f'{device.name}'):
        logger.info(f'    {offline_device.name}')
    logger.info(LOG_LINE_BREAK)

    # Report 'dc' MAC address sensor devices.
    dc_mac_devices_count = len(clover_sync_status.prtg_dc_macs)
    logger.info('|')
    logger.info(
        log_title(f'"dc" MAC addresses found ({dc_mac_devices_count})'))
    for dc_mac_device in sorted(clover_sync_status.prtg_dc_macs.values(),
                                key=lambda device: f'{device.name}'):
        logger.warning(f'    {dc_mac_device.name}')
    logger.info(LOG_LINE_BREAK)

    # Report unverified PRTG Clover device MAC addresses.
    unverified_devices_count = len(clover_sync_status.prtg_unverified_macs)
    logger.info('|')
    logger.info(
        log_title(f'Unverified devices found ({unverified_devices_count})'))
    for unverified_device in sorted(clover_sync_status.
                                    prtg_unverified_macs.values(),
                                    key=lambda device: f'{device.name}'):
        logger.warning(f'    {unverified_device.name}')
    logger.info(LOG_LINE_BREAK)
    
    # Report PRTG Clover MAC sensor mismatches.
    mac_sensor_mismatch_devices_count = len(clover_sync_status.prtg_mac_sensor_mismatch)
    logger.info('|')
    logger.info(
        log_title(f'MAC sensor mismatch devices found ({mac_sensor_mismatch_devices_count})'))
    for mac_sensor_mismatch_device in sorted(clover_sync_status.
                                    prtg_mac_sensor_mismatch.values(),
                                    key=lambda device: f'{device.name}'):
        logger.warning(f'    {mac_sensor_mismatch_device.name}')
    logger.info(LOG_LINE_BREAK)

    # Report invalid devices.
    invalid_device_count = len(clover_sync_status.prtg_invalid_clovers)
    logger.info('|')
    logger.info(
        log_title(f'Invalid devices found ({invalid_device_count})'))
    for invalid_device in sorted(clover_sync_status.
                                 prtg_invalid_clovers.values(),
                                 key=lambda device: f'{device.name}'):
        logger.warning(f'    {invalid_device.name}')
    logger.info(LOG_LINE_BREAK)

    # Report the total Clover device count from PRTG.
    logger.info('|')
    logger.info(log_title('End PRTG Report'))
    total_devices_count = invalid_device_count + \
        len(clover_sync_status.prtg_clovers) + \
        len(clover_sync_status.prtg_unverified_macs) + \
        len(clover_sync_status.prtg_dc_macs) + \
        len(clover_sync_status.prtg_mac_sensor_mismatch)
    logger.info(f'Total Online Clovers in PRTG: {total_devices_count}')
    logger.info(LOG_LINE_BREAK)

    return clover_sync_status


def analyze_clovers(clover_sync_status: CloverSyncStatus) -> CloverSyncStatus:
    """
    Compares Clovers from Meraki and PRTG to gather a list of matching,
    mismatched, and unsyncable Clovers. Updates and returns the given
    CloverSyncStatus object with the analysis.

    Args:
        clover_sync_status (CloverSyncStatus): The current status of the entire
            Clover sync operation.

    Returns:
        CloverSyncStatus: The updated status of the entire Clover sync
            operation.
    """

    # Print the beginning of the Clover analysis.
    logger.info('|')
    logger.info(log_title('Begin Clover Analysis'))
    logger.info('Analyzing valid Clovers between Meraki and PRTG...')
    logger.info(LOG_LINE_BREAK)

    # Make references to the valid Meraki / PRTG Clover dictionaries.
    all_meraki_clovers = clover_sync_status.meraki_clovers
    all_prtg_clovers = clover_sync_status.prtg_clovers

    # Go through each valid Meraki Clover and try to find the matching
    # Clover in the PRTG Clovers dictionary.
    for meraki_clover in sorted(all_meraki_clovers.values(),
                                key=lambda device: f'{device.site} '
                                                   f'{device.name}'):
        clover_mac = meraki_clover.mac_address

        # Check if the MAC address is not found in the PRTG Clovers dictionary.
        if clover_mac not in all_prtg_clovers.keys():
            # Check this Meraki Clover against the offline PRTG Clovers.
            if clover_mac in clover_sync_status.prtg_offline_clovers.keys():
                # Make a reference to the offline PRTG Clover.
                offline_prtg_clover = \
                    clover_sync_status.prtg_offline_clovers[clover_mac]

                # Meraki Clover has a matching PRTG Clover, but the PRTG Clover
                # is offline. Make a new Clover pair and add it to the
                # unsyncable Clover dictionary.
                prtg_clover_offline_error = f'Clover at site "{meraki_clover.site}" ' \
                    f'with name "{meraki_clover.name}" has a corresponding Clover in ' \
                    f'PRTG that is offline'
                new_unsyncable_pair = CloverPair(
                    meraki_clover=all_meraki_clovers[clover_mac],
                    prtg_clover=offline_prtg_clover,
                    mismatch_error=prtg_clover_offline_error
                )
                clover_sync_status.unsyncable_clovers[clover_mac] = \
                    new_unsyncable_pair
                continue
            # Check this Meraki Clover against the "dc" MAC address PRTG
            # Clovers.
            elif clover_mac in clover_sync_status.prtg_dc_macs.keys():
                # Make a reference to the "dc" MAC address PRTG Clover.
                dc_mac_prtg_clover = \
                    clover_sync_status.prtg_dc_macs[clover_mac]

                # Meraki Clover has a matching PRTG Clover, but the PRTG Clover
                # has a MAC address sensor returning a "dc" MAC address.
                # Make a new Clover pair and add it to the unsyncable Clover
                # dictionary.
                prtg_dc_mac_error = f'Clover at site "{meraki_clover.site}" with name ' \
                    f'"{meraki_clover.name}" has a corresponding Clover in PRTG that is ' \
                    f'returning a "dc" MAC address'
                new_unsyncable_pair = CloverPair(
                    meraki_clover=all_meraki_clovers[clover_mac],
                    prtg_clover=dc_mac_prtg_clover,
                    mismatch_error=prtg_dc_mac_error
                )
                clover_sync_status.unsyncable_clovers[clover_mac] = \
                    new_unsyncable_pair
                continue
            # Check this Meraki Clover against the unverified PRTG Clovers.
            elif clover_mac in clover_sync_status.prtg_unverified_macs.keys():
                # Make a reference to the unverified PRTG Clover.
                unverified_prtg_clover = \
                    clover_sync_status.prtg_unverified_macs[clover_mac]

                # Meraki Clover has a matching PRTG Clover, but the PRTG Clover
                # is unverified. Make a new Clover pair and add it to the
                # unsyncable Clover dictionary.
                prtg_unverified_error = f'Clover at site "{meraki_clover.site}" with name ' \
                    f'"{meraki_clover.name}" has a corresponding Clover in PRTG that is unverified'
                new_unsyncable_pair = CloverPair(
                    meraki_clover=all_meraki_clovers[clover_mac],
                    prtg_clover=unverified_prtg_clover,
                    mismatch_error=prtg_unverified_error
                )
                clover_sync_status.unsyncable_clovers[clover_mac] = \
                    new_unsyncable_pair
                continue
            # Check this Meraki Clover against the invalid PRTG Clovers.
            elif clover_mac in clover_sync_status.prtg_invalid_clovers.keys():
                # Make a reference to the invalid PRTG Clover.
                invalid_prtg_clover = \
                    clover_sync_status.prtg_invalid_clovers[clover_mac]

                # Meraki Clover has a matching PRTG Clover, but the PRTG Clover
                # is invalid. Make a new Clover pair and add it to the
                # unsyncable Clover dictionary.
                prtg_invalid_error = f'Clover at site "{meraki_clover.site}" with name ' \
                    f'"{meraki_clover.name}" has a corresponding Clvoer in PRTG that is invalid'
                new_unsyncable_pair = CloverPair(
                    meraki_clover=all_meraki_clovers[clover_mac],
                    prtg_clover=invalid_prtg_clover,
                    mismatch_error=prtg_invalid_error
                )
                clover_sync_status.unsyncable_clovers[clover_mac] = \
                    new_unsyncable_pair
                continue
            # Check this Meraki Clover against the MAC sensor mismatched PRTG
            # Clovers.
            elif clover_mac in clover_sync_status.prtg_mac_sensor_mismatch.keys():
                # Make a reference to the MAC sensor mismatched PRTG Clover.
                mac_sensor_mismatch_prtg_clover = \
                    clover_sync_status.prtg_mac_sensor_mismatch[clover_mac]
                
                # Meraki Clover has a matching PRTG Clover, but the PRTG
                # Clover's MAC address sensor is different than the MAC address
                # in the PRTG Clover's name. Make a new Clover pair and add it
                # to the unsyncable Clover dictionary.
                prtg_mac_mismatch_error = f'Clover at site "{meraki_clover.site}" with name ' \
                    f'"{meraki_clover.name}" has a corresponding Clover in PRTG that has a ' \
                    f'MAC address mismatch'
                new_unsyncable_pair = CloverPair(
                    meraki_clover=all_meraki_clovers[clover_mac],
                    prtg_clover=mac_sensor_mismatch_prtg_clover,
                    mismatch_error=prtg_mac_mismatch_error
                )
                clover_sync_status.unsyncable_clovers[clover_mac] = \
                    new_unsyncable_pair
                continue

            # This Clover is exclusive to Meraki and not in PRTG.
            continue

        prtg_clover = all_prtg_clovers[clover_mac]
        prtg_site_no_ibc = re.sub(r'\(.+\)', '', prtg_clover.site).strip()

        # Check if these Clovers do not have the same site.
        if meraki_clover.site != prtg_site_no_ibc:
            # Add these Clovers to the mismatch dictionary.
            logger.warning(f'    Site mismatch detected for Clover at site '\
                           f'"{prtg_site_no_ibc}" with name '
                           f'{prtg_clover.name} | '
                           f'Meraki: {meraki_clover.site} | '
                           f'PRTG: {prtg_site_no_ibc}')
            site_error = f'Clover at site "{prtg_site_no_ibc}" with name '\
                         f'"{prtg_clover.name}" has sites ' \
                         f'that do not match | Meraki: {meraki_clover.site}' \
                         f' | PRTG: {prtg_site_no_ibc}'
            new_mismatched_pair = \
                CloverPair(
                    meraki_clover=meraki_clover,
                    prtg_clover=prtg_clover,
                    mismatch_error=site_error
                )
            clover_sync_status.clover_mismatches[clover_mac] = \
                new_mismatched_pair
            continue

        # Check if these Clovers do not have the same window number.
        if meraki_clover.window_number != prtg_clover.window_number:
            # Add these Clovers to the mismatch dictionary while removing
            # them from their respective Clover dictionaries.
            logger.warning(f'    Window # mismatch detected for Clover at site '\
                           f'"{prtg_site_no_ibc}" with name ' +
                           f'{prtg_clover.name} | '
                           f'Meraki: {meraki_clover.window_number} | '
                           f'PRTG: {prtg_clover.window_number}')
            window_error = f'Clover at site "{prtg_site_no_ibc}" with name '\
                           f'"{prtg_clover.name}" ' \
                           f'has window numbers that do not match | ' \
                           f'Meraki: {meraki_clover.window_number} | ' \
                           f'PRTG: {prtg_clover.window_number}'
            new_mismatched_pair = \
                CloverPair(
                    meraki_clover=meraki_clover,
                    prtg_clover=prtg_clover,
                    mismatch_error=window_error
                )
            clover_sync_status.clover_mismatches[clover_mac] = \
                new_mismatched_pair
            continue

        # Check if these Clovers do not have the same IPv4 address.
        if meraki_clover.ip_address != prtg_clover.ip_address:
            # Add these Clovers to the mismatch dictionary while removing
            # them from their respective Clover dictionaries.
            logger.warning(f'    IPv4 address mismatch detected for Clover at site '\
                           f'"{prtg_site_no_ibc}" with name '
                           f'{prtg_clover.name} | '
                           f'Meraki: {meraki_clover.ip_address} | '
                           f'PRTG: {prtg_clover.ip_address}')
            ip_error = f'Clover at site "{prtg_site_no_ibc}" with name '\
                       f'"{prtg_clover.name}" has IPv4 ' \
                       f'addresses that do not match | ' \
                       f'Meraki: {meraki_clover.ip_address} | ' \
                       f'PRTG: {prtg_clover.ip_address}'
            new_mismatched_pair = \
                CloverPair(
                    meraki_clover=meraki_clover,
                    prtg_clover=prtg_clover,
                    mismatch_error=ip_error
                )
            clover_sync_status.clover_mismatches[clover_mac] = \
                new_mismatched_pair
            continue

        # This Meraki Clover matches a Clover in PRTG! Add it to the
        # matching Clovers dictionary.
        new_matching_pair = \
            CloverPair(
                meraki_clover=meraki_clover,
                prtg_clover=prtg_clover,
                mismatch_error=None
            )
        clover_sync_status.clover_matches[clover_mac] = new_matching_pair

    logger.info(LOG_LINE_BREAK)

    # Remove matched Clovers from the valid Meraki / PRTG dictionaries.
    for clover_mac in clover_sync_status.clover_matches.keys():
        all_meraki_clovers.pop(clover_mac)
        all_prtg_clovers.pop(clover_mac)

    # Remove mismatched Clovers from the valid Meraki / PRTG dictionaries.
    for clover_mac in clover_sync_status.clover_mismatches.keys():
        all_meraki_clovers.pop(clover_mac)
        all_prtg_clovers.pop(clover_mac)

    # Remove unsyncable Clovers from the valid Meraki Clover dictionary.
    for clover_mac in clover_sync_status.unsyncable_clovers.keys():
        all_meraki_clovers.pop(clover_mac)

    # Remove Clovers that are involved with a MAC sensor mismatch from the
    # remaining valid Meraki Clover dictionary.
    remaining_meraki_clover_macs = list(all_meraki_clovers.keys())
    for clover_mac in remaining_meraki_clover_macs:
        # Go through each MAC sensor mismatch PRTG Clover.
        for mac_sensor_mismatch_clover in clover_sync_status.prtg_mac_sensor_mismatch.values():
            # If a remaining Meraki Clover MAC address is found in the name of
            # a MAC sensor mismatched PRTG Clover name, remove it from the list
            # of remaining Meraki Clovers.
            if clover_mac in mac_sensor_mismatch_clover.name:
                all_meraki_clovers.pop(clover_mac)
                break
        
    # Check remaining valid PRTG Clovers against non-valid Meraki Clovers.
    for clover_mac,prtg_clover in all_prtg_clovers.items():
        # Check this PRTG Clover against the offline Meraki Clovers.
        if clover_mac in clover_sync_status.meraki_offline_clovers.keys():
            # Make a reference to the offline Meraki Clover.
            offline_meraki_clover = clover_sync_status.meraki_offline_clovers[
                clover_mac]

            # PRTG Clover has a matching Meraki Clover, but the Meraki
            # Clover is offline. Make a new Clover pair and add it to
            # the unsyncable Clover dictionary.
            meraki_offline_error = f'Clover at site "{prtg_clover.site}" with name ' \
                f'"{prtg_clover.name}" has a corresponding Clover in Meraki that is offline'
            new_unsyncable_pair = CloverPair(
                meraki_clover=offline_meraki_clover,
                prtg_clover=all_prtg_clovers[clover_mac],
                mismatch_error=meraki_offline_error
            )
            clover_sync_status.unsyncable_clovers[clover_mac] = \
                new_unsyncable_pair
            continue
        # Check this PRTG Clover against the invalid Meraki Clovers.
        elif clover_mac in clover_sync_status.meraki_invalid_clovers.keys():
            # Make a reference to the invalid Meraki Clover.
            invalid_meraki_clover = \
                clover_sync_status.meraki_invalid_clovers[clover_mac]

            # PRTG Clover has a matching Meraki Clover, but the Meraki
            # Clover is invalid. Make a new Clover pair and add it to
            # the unsyncable Clover dictionary.
            meraki_invalid_error = f'Clover at site "{prtg_clover.site}" with name ' \
                f'"{prtg_clover.name}" has a corresponding Clover in Meraki that is invalid'
            new_unsyncable_pair = CloverPair(
                meraki_clover=invalid_meraki_clover,
                prtg_clover=all_prtg_clovers[clover_mac],
                mismatch_error=meraki_invalid_error
            )
            clover_sync_status.unsyncable_clovers[clover_mac] = \
                new_unsyncable_pair
            continue
        # Check this PRTG Clover against the backup Meraki Clovers.
        elif clover_mac in clover_sync_status.meraki_backup_clovers.keys():
            # Make a reference to the backup Meraki Clover.
            backup_meraki_clover = \
                clover_sync_status.meraki_backup_clovers[clover_mac]

            logger.warning(f'    Backup mismatch detected for Clover at site '
                           f'"{all_prtg_clovers.get(clover_mac).site}" with name '
                           f'"{all_prtg_clovers.get(clover_mac).name}" | '
                           f'Meraki: {backup_meraki_clover.name} | '
                           f'PRTG: {all_prtg_clovers.get(clover_mac).name}')
            backup_mismatch_error = f'Clover at site "{all_prtg_clovers.get(clover_mac).site}" with name ' \
                                    f'"{all_prtg_clovers.get(clover_mac).name}" has a ' \
                                    f'corresponding Clover in Meraki that is ' \
                                    f'labeled as a backup | ' \
                                    f'Meraki: {backup_meraki_clover.name} | ' \
                                    f'PRTG: {all_prtg_clovers.get(clover_mac).name}'
            
            # PRTG Clover has a matching Meraki Clover, but the Meraki
            # Clover is a backup Clover. Make a new Clover pair and add
            # it to the unsyncable Clover dictionary.
            new_unsyncable_pair = CloverPair(
                meraki_clover=backup_meraki_clover,
                prtg_clover=all_prtg_clovers[clover_mac],
                mismatch_error=backup_mismatch_error
            )
            clover_sync_status.unsyncable_clovers[clover_mac] = \
                new_unsyncable_pair
            continue

        # This is exclusive to PRTG and not in Meraki.
        continue

    # Remove unsyncable Clovers from the valid PRTG Clover dictionary.
    for clover_mac in clover_sync_status.unsyncable_clovers.keys():
        all_prtg_clovers.pop(clover_mac, None)

    # Add an exclusive error to the remaining valid Meraki Clovers.
    for excl_meraki in clover_sync_status.meraki_clovers.values():
        excl_meraki.error = f'Clover at site "{excl_meraki.site}" with name ' \
                            f'"{excl_meraki.name}" is exclusively in Meraki ' \
                            f'and NOT in PRTG'

    # Add an exclusive error to the remaining valid PRTG Clovers.
    for excl_prtg in clover_sync_status.prtg_clovers.values():
        excl_prtg.error = f'Clover at site "{excl_prtg.site}" with name ' \
                          f'"{excl_prtg.name}" is exclusively in PRTG and ' \
                          f'NOT in Meraki'

    # Print all the Clovers exclusively in Meraki.
    exclusive_meraki_count = len(all_meraki_clovers)
    logger.info('|')
    logger.info(
        log_title(f'Exclusive Meraki Clovers ({exclusive_meraki_count})'))
    for clover in sorted(all_meraki_clovers.values(),
                         key=lambda device: f'{device.site} {device.name}'):
        logger.warning(f'    {clover.site} {clover.name}')
    logger.info(LOG_LINE_BREAK)

    # Print all the Clovers exclusively in PRTG.
    exclusive_prtg_count = len(all_prtg_clovers)
    logger.info('|')
    logger.info(
        log_title(f'Exclusive PRTG Clovers ({exclusive_prtg_count})'))
    for clover in sorted(all_prtg_clovers.values(),
                         key=lambda device: f'{device.name}'):
        logger.warning(f'    {clover.name}')
    logger.info(LOG_LINE_BREAK)

    # Print that we've ended the Clover analysis.
    logger.info('|')
    logger.info(log_title('End Clover Analysis'))
    logger.info('Valid Clovers analyzed!')
    logger.info(LOG_LINE_BREAK)

    return clover_sync_status


def sync_to_snow(clover_sync_status: CloverSyncStatus) -> CloverSyncStatus:
    """
    Synchronize the matching Clover information we gathered from Meraki and
    PRTG to ServiceNow. Updates the CloverSyncStatus object with lost Clovers
    inside ServiceNow.

    Args:
        clover_sync_status (CloverSyncStatus): The current status of the entire
            Clover sync operation.

    Returns:
        CloverSyncStatus: The updated status of the entire Clover sync
            operation.
    """

    # Print that we are beginning the ServiceNow sync for valid Clovers.
    logger.info('|')
    logger.info(log_title('Begin ServiceNow Sync'))
    logger.info('Synchronizing valid Clovers to ServiceNow...')
    logger.info(LOG_LINE_BREAK)

    # Get all Clovers in ServiceNow from the tablet table.
    servicenow_clover_table = SERVICENOW_CLIENT.resource(api_path=SERVICENOW_CMDB_TABLET_TABLE_PATH)
    servicenow_clover_query = (pysnow.QueryBuilder().
                         field('name').order_ascending().
                         AND().
                         field('company.name').equals('Vitu')
                         )
    servicenow_clover_resp = servicenow_clover_table.get(
        query=servicenow_clover_query,
        fields=['sys_id', 'u_active_contract', 'install_status', 'name', 'location',
                'location.name', 'serial_number', 'ip_address', 'mac_address',
                'u_prtg_id', 'u_meraki_id'])
    raw_servicenow_clovers = servicenow_clover_resp.all()

    # Convert the ServiceNow response to a dictionary where the keys are the
    # Clover's MAC addresses for easy references.
    servicenow_clovers = dict[str, dict]()
    for raw_servicenow_clover in raw_servicenow_clovers:
        servicenow_clovers[raw_servicenow_clover['mac_address']] = raw_servicenow_clover

    # Iterate through each Clover in ServiceNow and synchronize the
    # information gathered from the given Clover dictionary.
    update_count = 0
    for servicenow_clover in servicenow_clovers.values():
        # Check if this Clover is out of contract or retired. If it is, skip it.
        if servicenow_clover['u_active_contract'] == 'false' or \
           servicenow_clover['install_status'] == '7':  # 7 = Retired
            continue
        
        # Make quick references.
        matching_clover_pairs = clover_sync_status.clover_matches
        servicenow_clover_mac = servicenow_clover['mac_address']

        # Check to make sure this ServiceNow Clover has been seen before.
        if servicenow_clover_mac in matching_clover_pairs.keys():
            # Clover is valid and matching in both Meraki and PRTG.
            pass
        elif servicenow_clover_mac in clover_sync_status.clover_mismatches.keys():
            # Clover is valid, but not matching in Meraki / PRTG.
            continue
        elif servicenow_clover_mac in clover_sync_status.unsyncable_clovers.keys():
            # Clover is unsyncable.
            continue
        elif servicenow_clover_mac in clover_sync_status.meraki_clovers.keys():
            # Clover is exclusively in Meraki.
            continue
        elif servicenow_clover_mac in \
                clover_sync_status.meraki_offline_clovers.keys():
            # Clover is offline in Meraki.
            continue
        elif servicenow_clover_mac in \
                clover_sync_status.meraki_invalid_clovers.keys():
            # Clover is invalid in Meraki.
            continue
        elif servicenow_clover_mac in clover_sync_status.prtg_clovers.keys():
            # Clover is exclusively in PRTG.
            continue
        elif servicenow_clover_mac in clover_sync_status.prtg_offline_clovers.keys():
            # Clover is offline in PRTG.
            continue
        elif servicenow_clover_mac in clover_sync_status.prtg_dc_macs.keys():
            # Clover MAC address sensor is returning a "dc" MAC address.
            continue
        elif servicenow_clover_mac in clover_sync_status.prtg_unverified_macs.keys():
            # Clover is unverified from PRTG.
            continue
        elif servicenow_clover_mac in clover_sync_status.prtg_invalid_clovers.keys():
            # Clover is invalid in PRTG.
            continue
        elif servicenow_clover_mac in clover_sync_status.prtg_mac_sensor_mismatch.keys():
            # Clover MAC address is different between the MAC sensor and the 
            # MAC address in its name.
            continue
        # We found a lost Clover in ServiceNow.
        else:
            # Try to find this ServiceNow Clover's MAC address in the names of
            # the PRTG MAC sensor mismatch Clovers.
            lost_clover = True
            for prtg_mac_mismatch_clover in clover_sync_status.prtg_mac_sensor_mismatch.values():
                if servicenow_clover_mac in prtg_mac_mismatch_clover.name:
                    # This ServiceNow Clover is not lost. It is involved in a
                    # PRTG MAC sensor mismatch.
                    lost_clover = False
                    break
            
            # Check if the ServiceNow Clover is lost.
            if lost_clover:
                # This Clover was not found anywhere. It could mean this SNow
                # Clover is supposed to be retired or removed from ServiceNow.
                clover_sync_status.servicenow_lost_clovers.append(servicenow_clover)
            
            continue

        # Make quick references.
        mac_address = servicenow_clover['mac_address']
        clover_pair = matching_clover_pairs[mac_address]
        meraki_clover = clover_pair.meraki_clover
        prtg_clover = clover_pair.prtg_clover
        servicenow_update = dict()

        # Check if the site does not match in SNow.
        if servicenow_clover['location.name'] != meraki_clover.site:
            servicenow_update['location'] = meraki_clover.site

        # Check if the name is incorrect in Snow.
        if meraki_clover.is_ibc:
            correct_name = meraki_clover.site + ' Clover IBC Window' + \
            meraki_clover.window_number
        else:
            correct_name = meraki_clover.site + ' Clover Window' + \
            meraki_clover.window_number
        if servicenow_clover['name'] != correct_name:
            servicenow_update['name'] = correct_name

        # Check if the IPv4 address is incorrect in SNow.
        if servicenow_clover['ip_address'] != prtg_clover.ip_address:
            servicenow_update['ip_address'] = prtg_clover.ip_address

        # Check if the serial number is incorrect in SNow.
        if CLOVER_SERIAL_NUMBER_SHORT_REGEX.match(f'{prtg_clover.serial_number}') and \
                servicenow_clover['serial_number'] != prtg_clover.serial_number:
            servicenow_update['serial_number'] = prtg_clover.serial_number

        # Check if the PRTG ID is incorrect in SNow.
        if servicenow_clover['u_prtg_id'] != prtg_clover.prtg_id:
            servicenow_update['u_prtg_id'] = prtg_clover.prtg_id

        # Check if the Meraki ID is incorrect in SNow.
        if servicenow_clover['u_meraki_id'] != meraki_clover.meraki_id:
            servicenow_update['u_meraki_id'] = meraki_clover.meraki_id

        # Check if we need to update SNow.
        if servicenow_update:
            try:
                logger.info(f'Syncing {servicenow_clover['name']} to '
                            f'ServiceNow...')
                # Only sync to ServiceNow if we are not debugging.
                if not DEBUG_MODE:
                    servicenow_clover_table.update(
                        query={
                            'sys_id': servicenow_clover['sys_id']
                        },
                        payload=servicenow_update
                    )
                    time.sleep(1)
                logger.info('Clover successfully synced!')
                update_count += 1
            except PysnowException as e:
                logger.error(f'An error occurred when trying to sync '
                                    f'Clover to ServiceNow: '
                                    f'{servicenow_clover['name']}')
                logger.error(f'Error output: {str(e)}')
    
    # Check if there are missing Clovers in ServiceNow from Clover matches.
    for clover_pair in clover_sync_status.clover_matches.values():
        if clover_pair.meraki_clover.mac_address not in servicenow_clovers.keys() and 'backup' not in clover_pair.meraki_clover.name:
            # Make an INC saying that there is a missing Clover in the CMDB.
            clover_sync_status.servicenow_missing_clovers.add(clover_pair.meraki_clover.mac_address)
    
    # Check if there are missing Clovers in ServiceNow from Clover mismatches.
    for clover_pair in clover_sync_status.clover_mismatches.values():
        if clover_pair.meraki_clover.mac_address not in servicenow_clovers.keys() and 'backup' not in clover_pair.meraki_clover.name:
            # Make an INC saying that there is a missing Clover in the CMDB.
            clover_sync_status.servicenow_missing_clovers.add(clover_pair.meraki_clover.mac_address)
    
    # Check if there are missing Clovers in ServiceNow from unsyncable Clovers.
    for clover_pair in clover_sync_status.unsyncable_clovers.values():
        if clover_pair.meraki_clover.mac_address not in servicenow_clovers.keys() and 'backup' not in clover_pair.meraki_clover.name:
            # Make an INC saying that there is a missing Clover in the CMDB.
            clover_sync_status.servicenow_missing_clovers.add(clover_pair.meraki_clover.mac_address)
            
    # Check if there are missing Clovers in ServiceNow from Meraki invalid Clovers.
    for clover in clover_sync_status.meraki_invalid_clovers.values():
        if clover.mac_address not in servicenow_clovers.keys() and 'backup' not in clover.name.lower():
            clover_sync_status.servicenow_missing_clovers.add(clover.mac_address)
            
    # Check if there are missing Clovers in ServiceNow from Meraki offline Clovers.
    for clover in clover_sync_status.meraki_offline_clovers.values():
        if clover.mac_address not in servicenow_clovers.keys() and 'backup' not in clover.name.lower():
            clover_sync_status.servicenow_missing_clovers.add(clover.mac_address)
            
    # Check if there are missing Clovers in ServiceNow from PRTG "dc" MAC Clovers.
    for clover_mac in clover_sync_status.prtg_dc_macs.keys():
        if clover_mac not in servicenow_clovers.keys():
            clover_sync_status.servicenow_missing_clovers.add(clover_mac)
            
    # Check if there are missing Clovers in ServiceNow from PRTG invalid Clovers.
    for clover_mac in clover_sync_status.prtg_invalid_clovers.keys():
        if clover_mac not in servicenow_clovers.keys():
            clover_sync_status.servicenow_missing_clovers.add(clover_mac)
            
    # Check if there are missing Clovers in ServiceNow from PRTG Clovers that 
    # have a MAC sensor mismatch.
    for clover_mac in clover_sync_status.prtg_mac_sensor_mismatch.keys():
        if clover_mac not in servicenow_clovers.keys():
            clover_sync_status.servicenow_missing_clovers.add(clover_mac)
            
    # Check if there are missing Clovers in ServiceNow from PRTG offline Clovers.
    for clover_mac in clover_sync_status.prtg_offline_clovers.keys():
        if clover_mac not in servicenow_clovers.keys():
            clover_sync_status.servicenow_missing_clovers.add(clover_mac)
            
    # Check if there are missing Clovers in ServiceNow from PRTG unverified Clovers.
    for clover_mac in clover_sync_status.prtg_unverified_macs.keys():
        if clover_mac not in servicenow_clovers.keys():
            clover_sync_status.servicenow_missing_clovers.add(clover_mac)

    logger.info(LOG_LINE_BREAK)
    logger.info('Valid Clovers synchronized to ServiceNow!')
    logger.info(LOG_LINE_BREAK)

    # Print all the lost ServiceNow Clovers.
    lost_clover_count = len(clover_sync_status.servicenow_lost_clovers)
    logger.info('|')
    logger.info(
        log_title(f'Lost ServiceNow Clovers ({lost_clover_count})'))
    for clover in sorted(clover_sync_status.servicenow_lost_clovers,
                         key=lambda device: f'{device['name']}'):
        logger.warning(f'    {clover['name']}')
    logger.info(LOG_LINE_BREAK)
    
    # Print all the missing ServiceNow Clovers.
    missing_clover_count = len(clover_sync_status.servicenow_missing_clovers)
    logger.info('|')
    logger.info(
        log_title(f'Missing ServiceNow Clovers ({missing_clover_count})'))
    for clover_mac in sorted(clover_sync_status.servicenow_missing_clovers):
        logger.warning(f'    {clover_mac}')
    logger.info(LOG_LINE_BREAK)

    # Print how many Clovers were synced in ServiceNow.
    logger.info('|')
    logger.info(log_title('End ServiceNow Sync'))
    logger.info('Valid Clovers have been synchronized to ServiceNow!')
    logger.info(f'{update_count} / {len(servicenow_clovers)} '
                       f'Clovers updated in ServiceNow')
    logger.info(LOG_LINE_BREAK)

    return clover_sync_status


def make_servicenow_incident_tickets(clover_sync_status: CloverSyncStatus) -> None:
    """
    Given a CloverSyncStatus object, make ServiceNow tickets for Clovers that
    need to be fixed in Meraki, PRTG, or ServiceNow. Checks for existing
    tickets to avoid duplicate ticket creation.

    Args:
        clover_sync_status (CloverSyncStatus): The object that keeps track of
            the entire sync operation.
    """

    # Prepare the creation of tickets in ServiceNow.
    servicenow_incident_table = SERVICENOW_CLIENT.resource(api_path='/table/incident')
    existing_sync_incidents = dict()
    created_sync_incidents = dict()

    logger.info('|')
    logger.info(log_title('Begin ServiceNow Ticket Creation'))
    logger.info('Creating ServiceNow tickets...')
    logger.info(LOG_LINE_BREAK)

    # Get all Clover sync incident tickets from ServiceNow.
    servicenow_incidents_resp = servicenow_incident_table.get(
        query='short_descriptionLIKEVitu Clover Sync^stateNOT IN6,7,8,10',
        fields=['name', 'short_description']
    )
    sync_incidents = servicenow_incidents_resp.all()

    # Make a dictionary of all existing sync incident tickets. The keys are
    # the MAC address of the Clover and the value is the incident.
    for sync_incident in sync_incidents:
        mac_address = sync_incident['short_description'][-17:]
        existing_sync_incidents[mac_address] = sync_incident

    # Check if "dc" MAC ticketing is enabled.
    if DC_TICKETING:
        # Make a ticket for each PRTG Clover with a "dc" MAC address sensor
        # value.
        for dc_mac_clover in clover_sync_status.prtg_dc_macs.values():
            # Check if a ticket for this Clover already exists.
            if dc_mac_clover.mac_address in existing_sync_incidents.keys():
                continue

            # Create the payload to make a new INC ticket in ServiceNow.
            logger.warning(f'Opening INC for Clover at site "{dc_mac_clover.site}" '
                           f'with name {dc_mac_clover.name} because this '
                           f'Clover\'s MAC address sensor in PRTG is '
                           f'returning a "dc" MAC address')
            ticket_payload = \
                make_incident_payload(dc_mac_clover, AffectedPlatform.PRTG)

            # Check if the payload creation was unsuccessful.
            if not ticket_payload:
                logger.error(f'An error occurred when trying to make '
                                    f'a new INC in ServiceNow for Clover '
                                    f'{dc_mac_clover.name}')
                continue

            # Try to make a new incident for this exclusive Meraki Clover.
            try:
                # Only create the ticket in ServiceNow if we are not debugging.
                if not DEBUG_MODE:
                    created_sync_incidents[dc_mac_clover.mac_address] = \
                        servicenow_incident_table.create(payload=ticket_payload)
                    time.sleep(1)
                logger.info(f'Successfully created the INC for Clover '
                                   f'{dc_mac_clover.name}!')
            except PysnowException as e:
                logger.error(f'An error occurred when trying to make '
                                    f'a new INC in ServiceNow for Clover '
                                    f'{dc_mac_clover.name}')
                logger.error(f'Error output: {str(e)}')

    # Make a ticket for each exclusive Meraki Clover.
    for excl_clover in clover_sync_status.meraki_clovers.values():
        # Check if a ticket for this Clover already exists.
        if excl_clover.mac_address in existing_sync_incidents.keys():
            continue

        # Create the payload to make a new INC in ServiceNow.
        logger.warning(f'Opening INC for Clover at site "{excl_clover.site}" with name '
                              f'"{excl_clover.name}" because this '
                              f'Clover is exclusively in Meraki and NOT in PRTG')
        ticket_payload = \
            make_incident_payload(excl_clover, AffectedPlatform.MERAKI)

        # Check if the payload creation was unsuccessful.
        if not ticket_payload:
            logger.error(f'An error occurred when trying to make a new '
                                f'INC in ServiceNow for Clover '
                                f'{excl_clover.site} {excl_clover.name}')
            continue

        # Try to make a new incident for this exclusive Meraki Clover.
        try:
            # Only create the ticket in ServiceNow if we are not debugging.
            if not DEBUG_MODE:
                created_sync_incidents[excl_clover.mac_address] = \
                    servicenow_incident_table.create(payload=ticket_payload)
                time.sleep(1)
            logger.info(f'Successfully created the INC for Clover ' +
                               f'{excl_clover.site} {excl_clover.name}!')
        except PysnowException as e:
            logger.error(f'An error occurred when trying to make a new '
                                f'INC in ServiceNow for Clover '
                                f'{excl_clover.site} {excl_clover.name}')
            logger.error(f'Error output: {str(e)}')

    # Make a ticket for each exclusive PRTG Clover.
    for excl_clover in clover_sync_status.prtg_clovers.values():
        # Check if a ticket for this Clover already exists.
        if excl_clover.mac_address in existing_sync_incidents.keys():
            continue

        # Create the payload to make a new INC in ServiceNow.
        logger.warning(f'Opening INC for Clover at site "{excl_clover.site}" '\
                       f'with name "{excl_clover.name}" '
                       f'because this Clover is exclusively in PRTG and '
                       f'NOT in Meraki')
        ticket_payload = \
            make_incident_payload(excl_clover, AffectedPlatform.PRTG)

        # Check if the payload creation was unsuccessful.
        if not ticket_payload:
            logger.error(f'An error occurred when trying to make a new '
                                f'INC in ServiceNow for Clover '
                                f'{excl_clover.name}')
            continue

        # Try to make a new incident for this exclusive PRTG Clover.
        try:
            # Only create the ticket in ServiceNow if we are not debugging.
            if not DEBUG_MODE:
                created_sync_incidents[excl_clover.mac_address] = \
                    servicenow_incident_table.create(payload=ticket_payload)
                time.sleep(1)
            logger.info(f'Successfully created the INC for Clover ' +
                               f'{excl_clover.name}!')
        except PysnowException as e:
            logger.error(f'An error occurred when trying to make a new '
                                f'INC in ServiceNow for Clover ' +
                                f'{excl_clover.name}')
            logger.error(f'Error output: {str(e)}')

    # Make a ticket for each mismatched Clover.
    for mm_clover_pair in clover_sync_status.clover_mismatches.values():
        # Check if a ticket for this Clover already exists.
        if mm_clover_pair.meraki_clover.mac_address in \
          existing_sync_incidents.keys():
            continue

        # Create the payload to make a new INC in ServiceNow.
        logger.warning(f'Opening INC for Clover at site '\
                       f'"{mm_clover_pair.prtg_clover.site}" with name ' +
                       f'"{mm_clover_pair.prtg_clover.name}" because ' +
                       f'{mm_clover_pair.mismatch_error}')
        ticket_payload = \
            make_incident_payload(mm_clover_pair, AffectedPlatform.ALL)

        # Check if the payload creation was unsuccessful.
        if not ticket_payload:
            logger.error(f'An error occurred when trying to make a new '
                                f'INC in ServiceNow for Clover ' +
                                f'{mm_clover_pair.prtg_clover.name}')
            continue

        # Try to make a new incident for this mismatched Clover.
        try:
            # Only create the ticket in ServiceNow if we are not debugging.
            if not DEBUG_MODE:
                created_sync_incidents[mm_clover_pair.meraki_clover.mac_address] = \
                    servicenow_incident_table.create(payload=ticket_payload)
                time.sleep(1)
            logger.info(f'Successfully created the INC for Clover ' +
                               f'{mm_clover_pair.prtg_clover.name}!')
        except PysnowException as e:
            logger.error(f'An error occurred when trying to make a new '
                                f'INC in ServiceNow for Clover ' +
                                f'{mm_clover_pair.prtg_clover.name}')
            logger.error(f'Error output: {str(e)}')

    # Make a ticket for each lost Clover found in ServiceNow.
    for lost_clover in clover_sync_status.servicenow_lost_clovers:
        # Check if a ticket for this Clover already exists.
        if lost_clover['mac_address'] in existing_sync_incidents.keys():
            continue

        # Create the payload to make a new INC in ServiceNow.
        logger.warning(f'Opening INC for Clover at site '
                       f'"{lost_clover['location.name']}" with name '
                       f'"{lost_clover['name']}" because '
                       f'I could not find it in Meraki nor PRTG')
        ticket_payload = {
            'short_description':
                f'[ServiceNow] Vitu Clover Sync issue for {lost_clover['name']} '
                f'{lost_clover['mac_address']}',
            'description':
                f'Lost Clover found in ServiceNow - {lost_clover['name']} '
                f'could not be found in Meraki nor PRTG',
            'caller_id': SERVICENOW_TICKET_CALLER_ID,
            'assignment_group': 'Expert Services Level One Team',
            'company': SERVICENOW_TICKET_COMPANY,
            'location': lost_clover['location.name'],
            'configuration_item': lost_clover['name'],
            'u_milestone': SERVICENOW_TICKET_U_MILESTONE,
            'category': 'Inquiry',
            'subcategory': 'internal application',
            'severity': '2 - Medium'
        }

        # Try to make a new incident for this lost Clover.
        try:
            # Only create the ticket in ServiceNow if we are not debugging.
            if not DEBUG_MODE:
                created_sync_incidents[lost_clover['mac_address']] = \
                    servicenow_incident_table.create(payload=ticket_payload)
                time.sleep(1)
            logger.info(f'Successfully created the INC for '
                               f'{lost_clover['name']}!')
        except PysnowException as e:
            logger.error(f'An error occurred when trying to make a new '
                                f'INC in ServiceNow for {lost_clover['name']}')
            logger.error(f'Error output: {str(e)}')

    # Make a ticket for each missed device swap via an erroneous backup.
    for unsyncable_pair in clover_sync_status.unsyncable_clovers.values():
        # Check if the Clover is not a backup in Meraki.
        if 'backup' not in unsyncable_pair.meraki_clover.name.lower():
            continue

        # Make references to each Clover.
        meraki_clover = unsyncable_pair.meraki_clover
        prtg_clover = unsyncable_pair.prtg_clover

        # Check if a ticket for this Clover pair already exists.
        if meraki_clover.mac_address in existing_sync_incidents.keys():
            continue

        # Create the payload to make a new INC in ServiceNow.
        logger.warning(f'Opening INC for Clover at site "{prtg_clover.site}" '\
                       f'with name "{prtg_clover.name}" because '
                       f'the corresponding Clover in Meraki is labeled'
                       f'as a backup Clover')
        
        # Make the ServiceNow configuration item name for the ticket.
        if meraki_clover.is_ibc or prtg_clover.is_ibc:
            config_item_name = f'{meraki_clover.site} Clover IBC Window{meraki_clover.window_number}'
        else:
            config_item_name = f'{meraki_clover.site} Clover Window{meraki_clover.window_number}'
        ticket_payload = {
            'short_description':
                f'[Meraki] Vitu Clover Sync issue for {prtg_clover.name} '
                f'{meraki_clover.mac_address}',
            'description':
                f'Clover mismatch detected - {prtg_clover.name} '
                f'has a corresponding Clover in Meraki that is labeled as a '
                f'backup Clover',
            'caller_id': SERVICENOW_TICKET_CALLER_ID,
            'assignment_group': 'Expert Services Level One Team',
            'company': SERVICENOW_TICKET_COMPANY,
            'location': meraki_clover.site,
            'configuration_item': config_item_name,
            'u_milestone': SERVICENOW_TICKET_U_MILESTONE,
            'category': 'Inquiry',
            'subcategory': 'internal application',
            'severity': '2 - Medium'
        }

        # Try to make a new incident for this mismatched Clovers.
        try:
            # Only create the ticket in ServiceNow if we are not debugging.
            if not DEBUG_MODE:
                created_sync_incidents[meraki_clover.mac_address] = \
                    servicenow_incident_table.create(payload=ticket_payload)
                time.sleep(1)
            logger.info(f'Successfully created the INC for '
                               f'{prtg_clover.name}!')
        except PysnowException as e:
            logger.error(f'An error occurred when trying to make a new '
                                f'INC in ServiceNow for {prtg_clover.name}')
            logger.error(f'Error output: {str(e)}')
    
    # Make a ticket for each MAC address affected by a MAC sensor mismatch.
    for affected_mac,mac_mismatched_clover in clover_sync_status.prtg_mac_sensor_mismatch.items():
        # Check if a ticket for this Clover already exists.
        if affected_mac in existing_sync_incidents.keys():
            continue

        # Create the payload to make a new INC in ServiceNow.
        logger.warning(f'Opening INC for Clover '
                              f'{mac_mismatched_clover.name} because '
                              f'{mac_mismatched_clover.error}')
        ticket_payload = \
            make_incident_payload(mac_mismatched_clover, AffectedPlatform.PRTG)

        # Check if the payload creation was unsuccessful.
        if not ticket_payload:
            logger.error(f'An error occurred when trying to make a new '
                                f'INC in ServiceNow for Clover '
                                f'{mac_mismatched_clover.name}')
            continue

        # Try to make a new incident for this MAC mismatched Clover.
        try:
            # Only create the ticket in ServiceNow if we are not debugging.
            if not DEBUG_MODE:
                created_sync_incidents[affected_mac] = \
                    servicenow_incident_table.create(payload=ticket_payload)
                time.sleep(1)
            logger.info(f'Successfully created the INC for Clover '
                               f'{mac_mismatched_clover.name}!')
        except PysnowException as e:
            logger.error(f'An error occurred when trying to make a new '
                                f'INC in ServiceNow for Clover '
                                f'{mac_mismatched_clover.name}')
            logger.error(f'Error output: {str(e)}')

    # Make a ticket for each invalid Meraki Clover.
    for invalid_meraki in clover_sync_status.meraki_invalid_clovers.values():
        # Check if a ticket for this Clover already exists.
        if invalid_meraki.mac_address in existing_sync_incidents.keys():
            continue

        # Create the payload to make a new INC in ServiceNow.
        logger.warning(f'Opening an INC because {invalid_meraki.error}')
        ticket_payload = {
            'short_description':
                f'[Meraki] Vitu Clover Sync issue at {invalid_meraki.site} '
                f'for Clover {invalid_meraki.mac_address}',
            'description':
                f'The Clover at site "{invalid_meraki.site}" with name '
                f'"{invalid_meraki.name}" has an invalid name, so the '
                f'Clover name must be fixed manually',
            'caller_id': SERVICENOW_TICKET_CALLER_ID,
            'assignment_group': 'Expert Services Level One Team',
            'company': SERVICENOW_TICKET_COMPANY,
            'location': invalid_meraki.site,
            'configuration_item': 'AG-LAB-FULLSET',
            'u_milestone': SERVICENOW_TICKET_U_MILESTONE,
            'category': 'Inquiry',
            'subcategory': 'internal application',
            'severity': '2 - Medium'
        }

        # Try to make a new incident for this invalid Clover.
        try:
            # Only create the ticket in ServiceNow if we are not debugging.
            if not DEBUG_MODE:
                created_sync_incidents[invalid_meraki.mac_address] = \
                    servicenow_incident_table.create(payload=ticket_payload)
                time.sleep(1)
            logger.info(f'Successfully created the INC for Clover '
                                f'{invalid_meraki.site} '
                                f'{invalid_meraki.name}!')
        except PysnowException as e:
            logger.error(f'An error occurred when trying to make a '
                                f'new INC in ServiceNow for Clover '
                                f'{invalid_meraki.site} '
                                f'{invalid_meraki.name}')
            logger.error(f'Error output: {str(e)}')

    # Make a ticket for each invalid PRTG Clover.
    for invalid_prtg in clover_sync_status.prtg_invalid_clovers.values():
        # Check if a ticket for this Clover already exists.
        if invalid_prtg.mac_address in existing_sync_incidents.keys():
            continue

        # Create the payload to make a new INC in ServiceNow.
        logger.warning(f'Opening an INC for Clover {invalid_prtg.name} '
                     f'because {invalid_prtg.error}')
        ticket_payload = {
            'short_description':
                f'[PRTG] Vitu Clover Sync issue at {invalid_prtg.site} '
                f'for Clover {invalid_prtg.mac_address}',
            'description':
                f'The Clover at site "{invalid_prtg.site}" with name '
                f'"{invalid_prtg.name}" has an invalid name, so the '
                f'Clover name must be fixed manually',
            'caller_id': SERVICENOW_TICKET_CALLER_ID,
            'assignment_group': 'Expert Services Level One Team',
            'company': SERVICENOW_TICKET_COMPANY,
            'location': invalid_prtg.site,
            'configuration_item': 'AG-LAB-FULLSET',
            'u_milestone': SERVICENOW_TICKET_U_MILESTONE,
            'category': 'Inquiry',
            'subcategory': 'internal application',
            'severity': '2 - Medium'
        }

        # Try to make a new incident for this invalid Clover.
        try:
            # Only create the ticket in ServiceNow if we are not debugging.
            if not DEBUG_MODE:
                created_sync_incidents[invalid_prtg.mac_address] = \
                    servicenow_incident_table.create(payload=ticket_payload)
                time.sleep(1)
            logger.info(f'Successfully created the INC for Clover '
                                f'{invalid_prtg.site} '
                                f'{invalid_prtg.name}!')
        except PysnowException as e:
            logger.error(f'An error occurred when trying to make a '
                                f'new INC in ServiceNow for Clover '
                                f'{invalid_prtg.site} '
                                f'{invalid_prtg.name}')
            logger.error(f'Error output: {str(e)}')
            
    # Make a ticket for each missing Clover in ServiceNow.
    current_created_sync_incidents = list(created_sync_incidents.keys())
    for missing_clover_mac in clover_sync_status.servicenow_missing_clovers:
        # Check if a ticket for this Clover already exists or this Clover is 
        # a Clover that is specified as a Clover that does not need to be in
        # our ServiceNow CMDB.
        if missing_clover_mac in existing_sync_incidents.keys() or \
            missing_clover_mac in current_created_sync_incidents or \
            missing_clover_mac in clover_sync_status.meraki_offline_clovers.keys() or \
            missing_clover_mac in clover_sync_status.meraki_backup_clovers.keys() or \
            missing_clover_mac in clover_sync_status.prtg_offline_clovers.keys():
            continue

        # Create the payload to make a new INC in ServiceNow.
        logger.warning(f'Opening an INC for Clover {missing_clover_mac} '
                       f'because it is missing from ServiceNow')
        ticket_payload = {
            'short_description':
                f'[ServiceNow] Vitu Clover Sync issue for '
                f'{missing_clover_mac}',
            'description':
                f'Clover with MAC address "{missing_clover_mac}" is missing from ' \
                f'ServiceNow - it must be added manually',
            'caller_id': SERVICENOW_TICKET_CALLER_ID,
            'assignment_group': 'Expert Services Level One Team',
            'company': SERVICENOW_TICKET_COMPANY,
            'configuration_item': 'AG-LAB-FULLSET',
            'u_milestone': SERVICENOW_TICKET_U_MILESTONE,
            'category': 'Inquiry',
            'subcategory': 'internal application',
            'severity': '2 - Medium'
        }

        # Try to make a new incident for this missing Clover.
        try:
            # Only create the ticket in ServiceNow if we are not debugging.
            if not DEBUG_MODE:
                created_sync_incidents[missing_clover_mac] = \
                    servicenow_incident_table.create(payload=ticket_payload)
                time.sleep(1)
            logger.info(f'Successfully created the INC for Clover '
                        f'{missing_clover_mac}!')
        except PysnowException as e:
            logger.error(f'An error occurred when trying to make a '
                         f'new INC in ServiceNow for Clover '
                         f'{missing_clover_mac}')
            logger.error(f'Error output: {str(e)}')

    # Print how many tickets were created in ServiceNow.
    logger.info(LOG_LINE_BREAK)
    logger.info('|')
    logger.info(log_title('End ServiceNow Ticket Creation'))
    logger.info(f'Total ServiceNow tickets created: {len(created_sync_incidents)}')
    logger.info(LOG_LINE_BREAK)


def get_clover_mac(name: str) -> str:
    """
    Extracts the final 6 hex characters (including the 2 ':' separators) from a
    given Clover name string and returns a lowercase colon-separated valid
    Clover MAC address. If a MAC address cannot be extracted the empty string 
    ('') is returned.

    Args:
        name (str): The Clover name.
    
    Returns:
        str: If successful, the full valid Clover MAC address. Otherwise the
            empty string ('').
    """

    mac = 'd4:95:24:' + name.strip().lower().replace('-', ':').replace('::', ':')[-8:]
    return mac if CLOVER_MAC_ADDRESS_REGEX.match(mac) else ''


def make_incident_payload(clover_obj: object, platform: AffectedPlatform) -> dict:
    """
    Given a Clover object or CloverPair object and the affected platform
    relating to the object, this function returns a dictionary that represents
    the payload for ServiceNow to create a new incident ticket.

    Args:
        clover_obj (object): The Clover object (PRTGClover / MerakiClover) or 
            CloverPair object to create the ServiceNow incident ticket for.
        platform (AffecctedPlatform): The platform(s) that the Clover error
            affects.
    
    Returns:
        dict: A dictionary formatted to match the ServiceNow incident payload.
    """

    # Check if the Clover object is a CloverPair.
    if isinstance(clover_obj, CloverPair):
        meraki_clover = clover_obj.meraki_clover
        prtg_clover = clover_obj.prtg_clover

        # Make the ServiceNow configuration item name for the INC.
        if meraki_clover.is_ibc or prtg_clover.is_ibc:
            config_item_name = f'{prtg_clover.site} Clover IBC Window{prtg_clover.window_number}'
        else:
            config_item_name = f'{prtg_clover.site} Clover Window{prtg_clover.window_number}'

        ticket_payload = {
            'short_description':
                f'[PRTG] [Meraki] Vitu Clover Sync issue at {prtg_clover.site} '
                f'for Clover {meraki_clover.mac_address}',
            'description': clover_obj.mismatch_error,
            'caller_id': SERVICENOW_TICKET_CALLER_ID,
            'assignment_group': 'Expert Services Level One Team',
            'company': SERVICENOW_TICKET_COMPANY,
            'location': prtg_clover.site,
            'configuration_item': config_item_name,
            'u_milestone': SERVICENOW_TICKET_U_MILESTONE,
            'category': 'Inquiry',
            'subcategory': 'internal application',
            'severity': '2 - Medium'
        }
    # Check if the Clover object is a Meraki / PRTG Clover object.
    elif isinstance(clover_obj, MerakiClover) or \
            isinstance(clover_obj, PRTGClover):
        # Make the ServiceNow configuration item name for the ticket.
        if clover_obj.is_ibc:
            config_item_name = f'{clover_obj.site} Clover IBC Window{clover_obj.window_number}'
        else:
            config_item_name = f'{clover_obj.site} Clover Window{clover_obj.window_number}'

        ticket_payload = {
            'short_description':
                f'[{platform.value}] Vitu Clover Sync issue at '
                f'{clover_obj.site} for Clover {clover_obj.mac_address}',
            'description': clover_obj.error,
            'caller_id': SERVICENOW_TICKET_CALLER_ID,
            'assignment_group': 'Expert Services Level One Team',
            'company': SERVICENOW_TICKET_COMPANY,
            'location': clover_obj.site,
            'configuration_item': config_item_name,
            'u_milestone': SERVICENOW_TICKET_U_MILESTONE,
            'category': 'Inquiry',
            'subcategory': 'internal application',
            'severity': '2 - Medium'
        }
    # We were given invalid input.
    else:
        ticket_payload = {}

    return ticket_payload


def get_window_number(clover_name: str) -> str | None:
    """
    Returns the Clover's window number as a string if it was found in the
    provided name. Otherwise, returns None.

    Args:
        clover_name (str): The Clover name to search.
    
    Returns:
        str | None: The window number as a string if it was found in the
            name, otherwise return None.
    """

    # Remove the site from the Clover name in case this is a PRTG Clover name.
    clover_name_no_site = re.sub(PRTG_SITE_IN_CLOVER_NAME_REGEX, '', clover_name)

    # Extract the window number from the Clover name and return it if it's valid,
    # otherwise return None.
    window_number = re.findall(CLOVER_WINDOW_NUMBER_REGEX, clover_name_no_site)[0]
    return None if window_number == '' else window_number


def initialize_logger() -> None:
    """
    Initializes the global logger for this script. Logs will be forwarded to 
    the console, a local log file, and a remote syslog server.
    """

    # Check if the "logs" folder exists. If not, create it.
    if not os.path.isdir(f'{SCRIPT_PATH}/../logs'):
        os.mkdir(f'{SCRIPT_PATH}/../logs')

    # Customize the logger's appearance.
    logger.remove()
    logger_format = (
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{function: <32}</cyan>:<cyan>{line: <4}</cyan> - "
        "<level>{message}</level>"
    )
    
    # Add the console to the logger.
    logger.add(sys.stdout, format=logger_format)

    # Add the local log file to the logger.
    now_utc = datetime.now(timezone.utc)
    logger.add(f'{SCRIPT_PATH}/../logs/{LOGGER_FILE_NAME}_log_{now_utc.strftime("%Y-%m-%d_%H-%M-%S-%Z")}.log',
               format=logger_format)

    # We only want to add the Syslog handle to the logger if we are in production.
    if not DEBUG_MODE:
        # Add the remote syslog server to the logger.
        syslog_handle = SysLogHandler(address=(SYSLOG_ADDRESS, int(SYSLOG_PORT)), facility=14)
        logger.add(syslog_handle, format=logger_format)


def log_title(title: str) -> str:
    """
    Formats the provided string as a title line for the logger. The format 
    will place the string in the center of a left and right padding of 
    dashes (-).

    Args:
        title (str): The title for the line in the logger.

    Returns:
        str: The provided string with a left and right dash padding (-).
    """

    return '{:-^62}'.format(f' {title} ')


def sync() -> None:
    """
    Runs the sync operation amongst PRTG, Meraki, and ServiceNow.
    """

    # Initialize the global logger for this script.
    initialize_logger()
    
    # Check if we are running in debug mode.
    logger.info('|')
    if DEBUG_MODE:
        logger.debug(log_title('RUNNING IN DEBUG MODE!'))
        logger.info('|')
        
    # Begin the sync script.
    logger.info(log_title('Beginning the sync operation'))

    # Make the status object to keep track of relevant sync information.
    curr_clover_sync_status = CloverSyncStatus()

    # Perform the sync operation.
    curr_clover_sync_status = get_meraki_clovers(curr_clover_sync_status)
    curr_clover_sync_status = get_prtg_clovers(curr_clover_sync_status)
    curr_clover_sync_status = analyze_clovers(curr_clover_sync_status)
    curr_clover_sync_status = sync_to_snow(curr_clover_sync_status)
    make_servicenow_incident_tickets(curr_clover_sync_status)

    # End the sync operation.
    logger.info('|')
    logger.info(log_title('Finished the sync operation'))
    logger.info('|')


if __name__ == '__main__':
    sync()
