from datetime import datetime
from enum import Enum
import json
import logging
from logging.handlers import SysLogHandler
import os
import re
import sys
import time

import configparser
import meraki
import pysnow
import pysnow.exceptions
import pytz
import requests


# Module information.
__author__ = 'Anthony Farina'
__copyright__ = 'Copyright (C) 2022 Anthony Farina'
__credits__ = ['Anthony Farina']
__maintainer__ = 'Anthony Farina'
__email__ = 'farinaanthony96@gmail.com'
__license__ = 'MIT'
__version__ = '2.0.4'
__status__ = 'Released'


# Configuration file constant global variables.
CONFIG = configparser.ConfigParser()
CONFIG_PATH = '/../configs/PRTG-Meraki-SNow-Sync-config.ini'
SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))
CONFIG.read(SCRIPT_PATH + CONFIG_PATH)

# PRTG constant global variables.
PRTG_SERVER_URL = CONFIG['PRTG Info']['server-url']
PRTG_TABLE_URL = PRTG_SERVER_URL + CONFIG['PRTG Info']['table']
PRTG_USERNAME = CONFIG['PRTG Info']['username']
PRTG_PASSWORD = CONFIG['PRTG Info']['password']

# Meraki constant global variables.
MERAKI_API_KEY = CONFIG['Meraki Info']['api-key']
MERAKI_ORG_ID = CONFIG['Meraki Info']['org-id']
MERAKI_NET_ID = CONFIG['Meraki Info']['net-id']

# ServiceNow constant global variables.
SNOW_INSTANCE = CONFIG['ServiceNow Info']['instance']
SNOW_INST_URL = 'https://' + SNOW_INSTANCE + '.service-now.com'
SNOW_USERNAME = CONFIG['ServiceNow Info']['username']
SNOW_PASSWORD = CONFIG['ServiceNow Info']['password']
SNOW_CMDB_PATH = CONFIG['ServiceNow Info']['cmdb-table']
SYNC_REQUEST_SYS_ID = CONFIG['ServiceNow Info']['sync-req-sys-id']
SNOW_ORDER_NOW_PATH = f'/api/sn_sc/servicecatalog/items/' \
                      f'{SYNC_REQUEST_SYS_ID}/order_now'
SNOW_CLIENT = pysnow.Client(
    instance=SNOW_INSTANCE,
    user=SNOW_USERNAME,
    password=SNOW_PASSWORD
)

# Regex (regular expression) constant global variables.
PRTG_NAME_REGEX = re.compile(r'\[[A-Za-z]+\d{3}] Window '
                             r'[A-Z]{0,3}\d{1,2}[A-Z]? '
                             r'd4:95:24(:[\da-f]{2}){3}')
MERAKI_NAME_REGEX = re.compile(r'Window [A-Z]{0,3}\d{1,2}[A-Z]? '
                               r'd4:95:24(:[\da-f]{2}){3}')
SITE_INFO_REGEX = re.compile(r' \(.+\)')
EVERYTHING_BUT_WIND_NUM_REGEX = re.compile(r'\[.+]|Window|([\da-f]{2}:){5}'
                                           r'[\da-f]{2}')
CLOVER_SN_REGEX = re.compile(r'Clover [A-Z]\d{3}[A-Z] '
                             r'[A-Z]\d{3}[A-Z]{2}\d{8}')
CLOVER_MAC_REGEX = re.compile(r'd4:95:24(:[\da-f]{2}){3}')

# Logger constant global variables.
LOGGER_NAME = CONFIG['Logger Info']['name']

# Other constant global variables.
DC_TICKETING = False


# Represents a Clover payment device in Meraki.
class MerakiClover(object):
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
        self.window_number = window_number
        self.mac_address = mac_address
        self.ip_address = ip_address
        self.error = error


# Represents a Clover payment device in PRTG.
class PRTGClover(object):
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
        self.window_number = window_number
        self.mac_address = mac_address
        self.ip_address = ip_address
        self.serial_number = serial_number
        self.error = error


# Represents a Meraki Clover and PRTG Clover that are paired up together.
class CloverPair(object):
    # Constructor to initialize this object's fields.
    def __init__(self,
                 meraki_clover: MerakiClover,
                 prtg_clover: PRTGClover,
                 mismatch_error: str = None):
        self.meraki_clover = meraki_clover
        self.prtg_clover = prtg_clover
        self.mismatch_error = mismatch_error


# Enumeration that represents which platform should be represented as being
# affected.
class AffectedPlatform(Enum):
    MERAKI = 'Meraki'
    PRTG = 'PRTG'
    SNOW = 'ServiceNow'
    ALL = 'PRTG/Meraki/ServiceNow'
    NONE = 'No platform'


# Represents the current status of the Clover collection thus far in the
# sync process.
class CloverSyncStatus(object):
    # Data structures to keep track of the sync status across all systems.
    # Most keys to the dictionaries are the MAC address for the Clover.
    meraki_unknown_devices = list[dict]()
    meraki_offline_clovers = dict[str, MerakiClover]()
    meraki_invalid_clovers = dict[str, MerakiClover]()
    meraki_clovers = dict[str, MerakiClover]()
    prtg_id_to_mac = dict[str, str]()  # Keys are PRTG IDs
    prtg_id_to_sn = dict[str, str]()  # Keys are PRTG IDs
    prtg_unknown_clovers = list[dict]()
    prtg_offline_clovers = dict[str, PRTGClover]()
    prtg_invalid_clovers = dict[str, PRTGClover]()
    prtg_dc_macs = dict[str, PRTGClover]()
    prtg_unverified_macs = dict[str, PRTGClover]()
    prtg_clovers = dict[str, PRTGClover]()
    clover_matches = dict[str, CloverPair]()
    clover_mismatches = dict[str, CloverPair]()
    unsyncable_clovers = dict[str, CloverPair]()
    snow_lost_clovers = list[dict]()

    # Constructor to initialize this object's fields.
    def __init__(self):
        pass


# Get Clover information from Meraki. Use the given Clover sync status
# object to record the status of the Clovers in Meraki. Return the updated
# Clover sync status object.
def get_meraki_clovers(clover_sync_status: CloverSyncStatus) -> \
        CloverSyncStatus:
    global_logger.info(
        '----------------------- Begin Meraki Report ----------------------')
    global_logger.info('Retrieving Clover information from Meraki...')

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
        MERAKI_NET_ID,
        total_pages='all',
        perPage=1000,
        timespan=2678400
    )

    # Iterate through each Clover device and update the status object
    # depending on the state of the Clover.
    for clover in meraki_clovers:
        # Check if this device is a Clover device.
        if clover['manufacturer'] is None or \
                'Clover' not in clover['manufacturer']:
            # Add this device to the unknown devices list.
            clover_sync_status.meraki_unknown_devices.append(clover)
            continue

        # Clean the Clover's probe name by removing parentheses and its
        # contents.
        clean_probe = re.sub(SITE_INFO_REGEX, '', clover['recentDeviceName'])

        # Check if this Clover is connected to a Ready Meraki access point.
        if 'ready' in clean_probe.lower():
            continue

        # Check if this Clover is offline.
        if clover['status'] != 'Online':
            # Add this Clover to the offline Meraki Clovers dictionary.
            new_offline_clover = MerakiClover(
                meraki_id=clover['id'],
                name=(clover['description']
                      if clover['description'] is not None
                      else clover['mac']),
                site=clean_probe,
                mac_address=clover['mac'],
                ip_address=clover['ip']
            )
            clover_sync_status.meraki_offline_clovers[clover['mac']] = \
                new_offline_clover
            continue

        # Check if the Clover's name in Meraki is 'empty' (only MAC address).
        if clover['description'] is None:
            # Add this Clover to the invalid Meraki Clovers dictionary.
            missing_name_error = \
                'Clover at site "' + clean_probe + '" with name "' + \
                clover['mac'] + '" appears to have an invalid name ' \
                '(the name is just the MAC address)'
            new_unnamed_clover = MerakiClover(
                meraki_id=clover['id'],
                name=clover['mac'],
                site=clean_probe,
                mac_address=clover['mac'],
                ip_address=clover['ip'],
                error=missing_name_error
            )
            clover_sync_status.meraki_invalid_clovers[clover['mac']] = \
                new_unnamed_clover
            continue

        # Check if the Clover name is formatted incorrectly.
        if not MERAKI_NAME_REGEX.match(clover['description']):
            # Add this Clover to the invalid Meraki Clovers dictionary.
            invalid_name_error = \
                'Clover at site "' + clean_probe + '" with name "' + \
                clover['description'] + '" appears to have an invalid name ' \
                '(the name format is invalid)'
            new_invalid_clover = MerakiClover(
                meraki_id=clover['id'],
                name=clover['description'],
                site=clean_probe,
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
        if clover['description'][-17:] != clover['mac']:
            # Add this Clover to the invalid Meraki Clovers dictionary.
            invalid_mac_error = \
                'Clover at site "' + clean_probe + '" with name "' + \
                clover['description'] + '" appears to have an invalid name ' \
                '(the MAC address in the name does not match the ' \
                'Clover''s true MAC address)'
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
            ip_address=clover['ip']
        )
        clover_sync_status.meraki_clovers[clover['mac']] = new_meraki_clover

    global_logger.info('Clover information retrieved from Meraki!')
    global_logger.info(
        '------------------------------------------------------------------')

    # Begin the report for the Meraki Clover device retrieval.
    # Report unknown devices.
    unknown_devices_count = len(clover_sync_status.meraki_unknown_devices)
    global_logger.info(' ')
    global_logger.info('-------------------- Unknown devices found (' +
                       str(unknown_devices_count) + ') -------------------')
    for unknown_device in sorted(clover_sync_status.meraki_unknown_devices,
                                 key=lambda device:
                                 str(device['recentDeviceName']) + ' ' +
                                 str(device['description'])):
        global_logger.warning('    ' +
                              str(unknown_device['recentDeviceName']) +
                              ' ' + str(unknown_device['description']))
    global_logger.info(
        '------------------------------------------------------------------')

    # Report offline devices.
    offline_devices_count = len(clover_sync_status.meraki_offline_clovers)
    global_logger.info(' ')
    global_logger.info('-------------------- Offline devices found (' +
                       str(offline_devices_count) + ') -------------------')
    for offline_device in sorted(clover_sync_status.
                                 meraki_offline_clovers.values(),
                                 key=lambda device: str(device.site) + ' ' +
                                 str(device.name)):
        global_logger.info('    ' + str(offline_device.site) + ' ' +
                           str(offline_device.name))
    global_logger.info(
        '------------------------------------------------------------------')

    # Report invalid devices.
    invalid_device_count = len(clover_sync_status.meraki_invalid_clovers)
    global_logger.info(' ')
    global_logger.info('-------------------- Invalid devices found (' +
                       str(invalid_device_count) + ') -------------------')
    for invalid_device in sorted(clover_sync_status.
                                 meraki_invalid_clovers.values(),
                                 key=lambda device: str(device.site) + ' ' +
                                 str(device.name)):
        global_logger.warning('    ' + str(invalid_device.site) + ' ' +
                              str(invalid_device.name))
    global_logger.info(
        '------------------------------------------------------------------')

    # Report the total Clover device count from Meraki.
    global_logger.info(' ')
    global_logger.info(
        '------------------------ End Meraki Report -----------------------')
    total_devices_count = invalid_device_count + \
        len(clover_sync_status.meraki_clovers)
    global_logger.info('Total Online Clovers in Meraki: ' +
                       str(total_devices_count))
    global_logger.info(
        '------------------------------------------------------------------')
    global_logger.info(' ')

    return clover_sync_status


# Get Clover information from PRTG. Use the given Clover sync status
# object to record the status of the Clovers in PRTG. Return the updated
# Clover sync status object.
def get_prtg_clovers(clover_sync_status: CloverSyncStatus) -> CloverSyncStatus:
    global_logger.info(
        '------------------------ Begin PRTG Report -----------------------')
    global_logger.info('Retrieving Clover information from PRTG...')

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
            'password': PRTG_PASSWORD
        }
    )
    prtg_macs_json = prtg_macs_resp.json()

    # Fill the sensor values dictionary with MAC address sensor values.
    for mac_sensor in prtg_macs_json['sensors']:
        # Check if this Clover is connected to a Ready probe.
        if 'ready' in mac_sensor['probe'].lower():
            continue

        # Get the PRTG ID of the related device
        prtg_id = str(mac_sensor['parentid'])

        # Check if the sensor is not online.
        if mac_sensor['status_raw'] != 3:
            clover_sync_status.prtg_id_to_mac[prtg_id] = 'Offline'
            continue

        # Check if the sensor is returning a 'dc' MAC address.
        if 'dc:95:24:' in mac_sensor['message_raw']:
            clover_sync_status.prtg_id_to_mac[prtg_id] = 'dc'
            continue

        # Check the sensor has a valid value in it.
        if not CLOVER_MAC_REGEX.match(mac_sensor['message_raw']):
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
            'password': PRTG_PASSWORD
        }
    )
    prtg_sns_json = prtg_sns_resp.json()

    # Fill the PRTG ID to S/N dictionary with serial number sensor values.
    for sn_sensor in prtg_sns_json['sensors']:
        # Check if this Clover is connected to a Ready probe.
        if 'ready' in sn_sensor['probe'].lower():
            continue

        # Get the PRTG ID of the relevant device.
        prtg_id = str(sn_sensor['parentid'])

        # Check if the sensor is not online.
        if sn_sensor['status_raw'] != 3:
            clover_sync_status.prtg_id_to_sn[prtg_id] = 'Offline'
            continue

        # Check if the sensor has an invalid value in it.
        if not CLOVER_SN_REGEX.match(sn_sensor['message_raw']):
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
            'password': PRTG_PASSWORD
        }
    )
    prtg_clovers_json = prtg_clovers_resp.json()

    # Update the PRTG Clover dictionary with initial Clover information.
    for clover in prtg_clovers_json['devices']:
        # Get the PRTG ID, clean up the probe name, and try to get a valid
        # Clover MAC address from the name of the device.
        prtg_id = str(clover['objid'])
        clean_probe = re.sub(SITE_INFO_REGEX, '', clover['probe'])
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
                ip_address=clover['host']
            )
            clover_sync_status.prtg_offline_clovers[name_mac_address] = \
                new_offline_clover
            continue

        # Get the values from the MAC sensor and S/N sensor.
        mac_address = clover_sync_status.prtg_id_to_mac[prtg_id]
        full_sn = clover_sync_status.prtg_id_to_sn[prtg_id]
        short_sn = full_sn.split(' ')[2]

        # Check if this Clover's MAC address sensor is returning a "dc" MAC
        # address value.
        if mac_address == 'dc':
            # Attempt to extract the window number from the Clover's name.
            window_num = get_window_number(clover['name'])

            # Add this Clover to the dc MACS PRTG Clover dictionary. We will
            # use the MAC address from the name to identify this PRTG Clover.
            dc_mac_error = \
                'Clover with name "' + clover['name'] + '" has its MAC ' \
                'sensor returning a "dc" MAC address'
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
        if not CLOVER_MAC_REGEX.match(mac_address):
            # Add this Clover to the unverified PRTG Clover dictionary. We
            # will use the MAC address from the name to identify this PRTG
            # Clover.
            unverified_mac_error = \
                'Clover MAC address with name "' + clover['name'] + \
                '" could not be verified'
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
        if not PRTG_NAME_REGEX.match(clover['name']):
            # Add this Clover to the invalid PRTG Clovers dictionary.
            invalid_name_error = \
                'Clover with name "' + clover['name'] + '" appears to ' \
                'have an invalid name (the name format is invalid)'
            new_invalid_clover = PRTGClover(
                prtg_id=prtg_id,
                name=clover['name'],
                site=clean_probe,
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
            # Add this Clover to the invalid PRTG Clovers dictionary.
            invalid_mac_error = \
                'Clover with name "' + clover['name'] + '" appears to ' \
                'have an invalid name (the MAC address in the name does not ' \
                'match the Clover''s true MAC address)'
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
            clover_sync_status.prtg_invalid_clovers[mac_address] = \
                new_invalid_clover
            continue

        # Check if the site is correct in the name.
        if clean_probe not in clover['name']:
            # Add this Clover to the invalid PRTG Clovers dictionary.
            invalid_site_error = \
                'Clover at site "' + clean_probe + '" with name "' + \
                clover['name'] + '" appears to have an invalid name ' \
                '(the site in the name does not match the Clover''s ' \
                'probe name)'
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
            serial_number=short_sn
        )
        clover_sync_status.prtg_clovers[mac_address] = new_prtg_clover

    global_logger.info('Clover information retrieved from PRTG!')
    global_logger.info(
        '------------------------------------------------------------------')

    # Begin the report for the PRTG Clover device retrieval.
    # Report unknown devices.
    unknown_devices_count = len(clover_sync_status.prtg_unknown_clovers)
    global_logger.info(' ')
    global_logger.info('-------------------- Unknown devices found (' +
                       str(unknown_devices_count) + ') -------------------')
    for unknown_device in sorted(clover_sync_status.prtg_unknown_clovers,
                                 key=lambda device: str(device['name'])):
        global_logger.warning('    ' + str(unknown_device['name']))
    global_logger.info(
        '------------------------------------------------------------------')

    # Report offline devices.
    offline_devices_count = len(clover_sync_status.prtg_offline_clovers)
    global_logger.info(' ')
    global_logger.info('-------------------- Offline devices found (' +
                       str(offline_devices_count) + ') -------------------')
    for offline_device in sorted(clover_sync_status.
                                 prtg_offline_clovers.values(),
                                 key=lambda device: str(device.name)):
        global_logger.info('    ' + str(offline_device.name))
    global_logger.info(
        '------------------------------------------------------------------')

    # Report 'dc' MAC address sensor devices.
    dc_mac_devices_count = len(clover_sync_status.prtg_dc_macs)
    global_logger.info(' ')
    global_logger.info('--------------- "dc" MAC addresses found (' +
                       str(dc_mac_devices_count) + ') ---------------')
    for dc_mac_device in sorted(clover_sync_status.prtg_dc_macs.values(),
                                key=lambda device: str(device.name)):
        global_logger.warning('    ' + str(dc_mac_device.name))
    global_logger.info(
        '------------------------------------------------------------------')

    # Report unverified PRTG Clover device MAC addresses.
    unverified_devices_count = len(clover_sync_status.prtg_unverified_macs)
    global_logger.info(' ')
    global_logger.info('------------------ Unverified devices found (' +
                       str(unverified_devices_count) + ') ------------------')
    for unverified_device in sorted(clover_sync_status.
                                    prtg_unverified_macs.values(),
                                    key=lambda device: str(device.name)):
        global_logger.warning('    ' + str(unverified_device.name))
    global_logger.info(
        '------------------------------------------------------------------')

    # Report invalid devices.
    invalid_device_count = len(clover_sync_status.prtg_invalid_clovers)
    global_logger.info(' ')
    global_logger.info('-------------------- Invalid devices found (' +
                       str(invalid_device_count) + ') -------------------')
    for invalid_device in sorted(clover_sync_status.
                                 prtg_invalid_clovers.values(),
                                 key=lambda device: str(device.name)):
        global_logger.warning('    ' + str(invalid_device.name))
    global_logger.info(
        '------------------------------------------------------------------')

    # Report the total Clover device count from PRTG.
    global_logger.info(' ')
    global_logger.info(
        '------------------------- End PRTG Report ------------------------')
    total_devices_count = invalid_device_count + \
        len(clover_sync_status.prtg_clovers) + \
        len(clover_sync_status.prtg_unverified_macs)
    global_logger.info('Total Online Clovers in PRTG: ' +
                       str(total_devices_count))
    global_logger.info(
        '------------------------------------------------------------------')
    global_logger.info(' ')

    return clover_sync_status


# Compares Clovers from Meraki and PRTG to gather a list of matching,
# mismatched, and unsyncable Clovers. Updates and returns the given Clover
# sync status object with the analysis.
def analyze_clovers(clover_sync_status: CloverSyncStatus) -> CloverSyncStatus:
    # Print the beginning of the Clover analysis.
    global_logger.info(
        '---------------------- Begin Clover Analysis ---------------------')
    global_logger.info('Analyzing valid Clovers between Meraki and PRTG...')
    global_logger.info(
        '------------------------------------------------------------------')

    # Make references to the valid Meraki / PRTG Clover dictionaries.
    all_meraki_clovers = clover_sync_status.meraki_clovers
    all_prtg_clovers = clover_sync_status.prtg_clovers

    # Go through each valid Meraki Clover and try to find the matching
    # Clover in the PRTG Clovers dictionary.
    for meraki_clover in sorted(all_meraki_clovers.values(),
                                key=lambda device: str(device.site) + ' ' +
                                str(device.name)):
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
                new_unsyncable_pair = CloverPair(
                    meraki_clover=all_meraki_clovers[clover_mac],
                    prtg_clover=offline_prtg_clover
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
                new_unsyncable_pair = CloverPair(
                    meraki_clover=all_meraki_clovers[clover_mac],
                    prtg_clover=dc_mac_prtg_clover
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
                new_unsyncable_pair = CloverPair(
                    meraki_clover=all_meraki_clovers[clover_mac],
                    prtg_clover=unverified_prtg_clover
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
                new_unsyncable_pair = CloverPair(
                    meraki_clover=all_meraki_clovers[clover_mac],
                    prtg_clover=invalid_prtg_clover
                )
                clover_sync_status.unsyncable_clovers[clover_mac] = \
                    new_unsyncable_pair
                continue

            # This Clover is exclusive to Meraki and not in PRTG.
            continue

        prtg_clover = all_prtg_clovers[clover_mac]

        # Check if these Clovers do not have the same site.
        if meraki_clover.site != prtg_clover.site:
            # Add these Clovers to the mismatch dictionary.
            global_logger.warning('    Site mismatch detected for ' +
                                  prtg_clover.name + ' | Meraki: ' +
                                  meraki_clover.site + ' | PRTG: ' +
                                  prtg_clover.site)
            site_error = \
                'Clover with name "' + prtg_clover.name + \
                '" has sites that do not match | Meraki: ' + \
                meraki_clover.site + ' | PRTG: ' + prtg_clover.site
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
            global_logger.warning('    Window # mismatch detected for ' +
                                  prtg_clover.name + ' | Meraki: ' +
                                  meraki_clover.window_number + ' | PRTG: ' +
                                  prtg_clover.window_number)
            window_error = \
                'Clover with name "' + prtg_clover.name + \
                '" has window numbers that do not match | Meraki: ' + \
                meraki_clover.window_number + ' | PRTG: ' + \
                prtg_clover.window_number
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
            global_logger.warning('    IPv4 address mismatch detected for ' +
                                  prtg_clover.name + ' | Meraki: ' +
                                  meraki_clover.ip_address + ' | PRTG: ' +
                                  prtg_clover.ip_address)
            ip_error = \
                'Clover with name "' + prtg_clover.name + \
                '" has IPv4 addresses that do not match | Meraki: ' + \
                meraki_clover.ip_address + ' | PRTG: ' + prtg_clover.ip_address
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
                prtg_clover=prtg_clover
            )
        clover_sync_status.clover_matches[clover_mac] = new_matching_pair

    global_logger.info(
        '------------------------------------------------------------------')

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

    # Check remaining valid PRTG Clovers against non-valid Meraki Clovers.
    for clover_mac in all_prtg_clovers.keys():
        # Check this PRTG Clover against the offline Meraki Clovers.
        if clover_mac in clover_sync_status.meraki_offline_clovers.keys():
            # Make a reference to the offline Meraki Clover.
            offline_meraki_clover = clover_sync_status.meraki_offline_clovers[
                clover_mac]

            # PRTG Clover has a matching Meraki Clover, but the Meraki
            # Clover is offline. Make a new Clover pair and add it to
            # the unsyncable Clover dictionary.
            new_unsyncable_pair = CloverPair(
                meraki_clover=offline_meraki_clover,
                prtg_clover=all_prtg_clovers[clover_mac]
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
            new_unsyncable_pair = CloverPair(
                meraki_clover=invalid_meraki_clover,
                prtg_clover=all_prtg_clovers[clover_mac]
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
        excl_meraki.error = \
            'Clover at site "' + excl_meraki.site + '" with name "' + \
            excl_meraki.name + '" is exclusively in Meraki and NOT in PRTG'

    # Add an exclusive error to the remaining valid PRTG Clovers.
    for excl_prtg in clover_sync_status.prtg_clovers.values():
        excl_prtg.error = \
            'Clover at site "' + excl_prtg.site + '" with name "' + \
            excl_prtg.name + '" is exclusively in PRTG and NOT in Meraki'

    # Print all the Clovers exclusively in Meraki.
    exclusive_meraki_count = len(all_meraki_clovers)
    global_logger.info(' ')
    global_logger.info('----------------- Exclusive Meraki Clovers (' +
                       str(exclusive_meraki_count) + ') ------------------')
    for clover in sorted(all_meraki_clovers.values(),
                         key=lambda device: str(device.site) + ' ' +
                         str(device.name)):
        global_logger.warning('    ' + str(clover.site) + ' ' +
                              str(clover.name))
    global_logger.info(
        '------------------------------------------------------------------')

    # Print all the Clovers exclusively in PRTG.
    exclusive_prtg_count = len(all_prtg_clovers)
    global_logger.info(' ')
    global_logger.info('------------------- Exclusive PRTG Clovers (' +
                       str(exclusive_prtg_count) + ') ------------------')
    for clover in sorted(all_prtg_clovers.values(),
                         key=lambda device: str(device.name)):
        global_logger.warning('    ' + str(clover.name))
    global_logger.info(
        '------------------------------------------------------------------')

    # Print that we've ended the Clover analysis.
    global_logger.info(' ')
    global_logger.info(
        '----------------------- End Clover Analysis ----------------------')
    global_logger.info('Valid Clovers analyzed!')
    global_logger.info(
        '------------------------------------------------------------------')
    global_logger.info(' ')

    return clover_sync_status


# Synchronize the matching Clover information we gathered from Meraki and
# PRTG to ServiceNow.
def sync_to_snow(clover_sync_status: CloverSyncStatus) -> CloverSyncStatus:
    # Print that we are beginning the ServiceNow sync for valid Clovers.
    global_logger.info(
        '---------------------- Begin ServiceNow Sync ---------------------')
    global_logger.info('Synchronizing valid Clovers to ServiceNow...')
    global_logger.info(
        '------------------------------------------------------------------')

    # Get all Clovers in ServiceNow from the tablet table.
    snow_clover_table = SNOW_CLIENT.resource(api_path=SNOW_CMDB_PATH)
    snow_clover_query = (pysnow.QueryBuilder().
                         field('name').order_ascending().
                         AND().
                         field('company.name').equals('Vitu').
                         AND().
                         field('u_active_contract').equals('true')
                         )
    snow_clover_resp = snow_clover_table.get(
        query=snow_clover_query,
        fields=['sys_id', 'name', 'location', 'location.name', 'serial_number',
                'ip_address', 'mac_address', 'u_prtg_id', 'u_meraki_id'])
    snow_clovers = snow_clover_resp.all()
    update_count = 0

    # Iterate through each Clover in ServiceNow and synchronize the
    # information gathered from the given Clover dictionary.
    for snow_clover in snow_clovers:
        matching_clover_pairs = clover_sync_status.clover_matches
        snow_clover_mac = snow_clover['mac_address']

        # Check to make sure this ServiceNow Clover has been seen before.
        if snow_clover_mac in matching_clover_pairs.keys():
            # Clover is valid and matching in both Meraki and PRTG.
            pass
        elif snow_clover_mac in clover_sync_status.clover_mismatches.keys():
            # Clover is valid, but not matching in Meraki / PRTG.
            continue
        elif snow_clover_mac in clover_sync_status.unsyncable_clovers.keys():
            # Clover is unsyncable.
            continue
        elif snow_clover_mac in clover_sync_status.meraki_clovers.keys():
            # Clover is exclusively in Meraki.
            continue
        elif snow_clover_mac in \
                clover_sync_status.meraki_offline_clovers.keys():
            # Clover is offline in Meraki.
            continue
        elif snow_clover_mac in \
                clover_sync_status.meraki_invalid_clovers.keys():
            # Clover is invalid in Meraki.
            continue
        elif snow_clover_mac in clover_sync_status.prtg_clovers.keys():
            # Clover is exclusively in PRTG.
            continue
        elif snow_clover_mac in clover_sync_status.prtg_offline_clovers.keys():
            # Clover is offline in PRTG.
            continue
        elif snow_clover_mac in clover_sync_status.prtg_dc_macs.keys():
            # Clover MAC address sensor is returning a "dc" MAC address.
            continue
        elif snow_clover_mac in clover_sync_status.prtg_unverified_macs.keys():
            # Clover is unverified from PRTG.
            continue
        elif snow_clover_mac in clover_sync_status.prtg_invalid_clovers.keys():
            # Clover is invalid in PRTG.
            continue
        # We found a lost Clover in ServiceNow.
        else:
            # This Clover was not found anywhere. The MAC address may be in
            # the name of a device in PRTG, or it could mean this SNow
            # Clover is supposed to be retired.
            clover_sync_status.snow_lost_clovers.append(snow_clover)
            continue

        # Make quick references.
        mac_address = snow_clover['mac_address']
        clover_pair = matching_clover_pairs[mac_address]
        meraki_clover = clover_pair.meraki_clover
        prtg_clover = clover_pair.prtg_clover
        snow_update = dict()

        # Check if the site does not match in SNow.
        if snow_clover['location.name'] != prtg_clover.site:
            snow_update['location'] = prtg_clover.site

        # Check if the name is incorrect in Snow.
        correct_name = prtg_clover.site + ' Clover Window' + \
            prtg_clover.window_number
        if snow_clover['name'] != correct_name:
            snow_update['name'] = correct_name

        # Check if the IPv4 address is incorrect in SNow.
        if snow_clover['ip_address'] != prtg_clover.ip_address:
            snow_update['ip_address'] = prtg_clover.ip_address

        # Check if the serial number is incorrect in SNow.
        if CLOVER_SN_REGEX.match(str(prtg_clover.serial_number)) and \
                snow_clover['serial_number'] != prtg_clover.serial_number:
            snow_update['serial_number'] = prtg_clover.serial_number

        # Check if the PRTG ID is incorrect in SNow.
        if snow_clover['u_prtg_id'] != prtg_clover.prtg_id:
            snow_update['u_prtg_id'] = prtg_clover.prtg_id

        # Check if the Meraki ID is incorrect in SNow.
        if snow_clover['u_meraki_id'] != meraki_clover.meraki_id:
            snow_update['u_meraki_id'] = meraki_clover.meraki_id

        # Check if we need to update SNow.
        if snow_update:
            try:
                global_logger.info('Syncing ' + snow_clover['name'] +
                                   ' to ServiceNow...')
                snow_clover_table.update(
                    query={
                        'sys_id': snow_clover['sys_id']
                    },
                    payload=snow_update
                )
                global_logger.info('Clover successfully synced!')
                time.sleep(1)
                update_count += 1
            except pysnow.exceptions as e:
                global_logger.error('An error occurred when trying to sync '
                                    'Clover to ServiceNow: ' +
                                    snow_clover['name'])
                global_logger.error('    ' + str(e))

    global_logger.info(
        '------------------------------------------------------------------')
    global_logger.info('Valid Clovers synchronized to ServiceNow!')
    global_logger.info(
        '------------------------------------------------------------------')

    # Print all the lost ServiceNow Clovers.
    lost_clover_count = len(curr_clover_sync_status.snow_lost_clovers)
    global_logger.info(' ')
    global_logger.info('------------------ Lost ServiceNow Clovers (' +
                       str(lost_clover_count) + ') ------------------')
    for clover in sorted(curr_clover_sync_status.snow_lost_clovers,
                         key=lambda device: str(device['name'])):
        global_logger.warning('    ' + str(clover['name']))
    global_logger.info(
        '------------------------------------------------------------------')

    # Print how many Clovers were synced in ServiceNow.
    global_logger.info(' ')
    global_logger.info(
        '----------------------- End ServiceNow Sync ----------------------')
    global_logger.info('Valid Clovers have been synchronized to ServiceNow!')
    global_logger.info(str(update_count) + ' / ' + str(len(snow_clovers)) +
                       ' Clovers updated in ServiceNow')
    global_logger.info(
        '------------------------------------------------------------------')
    global_logger.info(' ')

    return clover_sync_status


# Given a Clover Sync Status object, make SNow tickets for Clovers that need
# to be fixed in either Meraki or PRTG. Checks for existing tickets to avoid
# duplicate ticket creation. Will create autonomous tickets if possible,
# otherwise it will create an incident for an engineer to manually engage with.
def make_snow_tickets(clover_sync_status: CloverSyncStatus):
    # Prepare the creation of tickets in ServiceNow.
    snow_incident_table = SNOW_CLIENT.resource(api_path='/table/incident')
    existing_sync_incidents = dict()
    snow_ritm_table = SNOW_CLIENT.resource(api_path='/table/sc_req_item')
    existing_sync_ritms = dict()
    total_tickets = 0

    global_logger.info(
        '---------------- Begin ServiceNow Ticket Creation ----------------')
    global_logger.info('Creating ServiceNow tickets...')
    global_logger.info(
        '------------------------------------------------------------------')

    # Get all Clover sync incident tickets from ServiceNow.
    snow_incidents_resp = snow_incident_table.get(
        query='short_descriptionLIKEVitu Clover Sync^stateNOT IN6,7,8,10',
        fields=['name', 'short_description']
    )
    sync_incidents = snow_incidents_resp.all()

    # Make a dictionary of all existing sync incident tickets. The keys are
    # the MAC address of the Clover and the value is the incident.
    for sync_incident in sync_incidents:
        mac_address = sync_incident['short_description'][-17:]
        existing_sync_incidents[mac_address] = sync_incident

    # Get all Clover sync request item tickets from ServiceNow.
    snow_ritms_resp = snow_ritm_table.get(
        query='short_descriptionLIKEVitu Clover Sync^stateNOT IN8,3,4,7',
        fields=['name', 'short_description']
    )
    sync_ritms = snow_ritms_resp.all()

    # Make a dictionary of all existing sync incident tickets. The keys are
    # the MAC address of the Clover and the value is the incident.
    for sync_ritm in sync_ritms:
        mac_address = sync_ritm['short_description'][-17:]
        existing_sync_ritms[mac_address] = sync_ritm

    # Check if "dc" MAC ticketing is enabled.
    if DC_TICKETING:
        # Make a ticket for each PRTG Clover with a "dc" MAC address sensor
        # value.
        for dc_mac_clover in clover_sync_status.prtg_dc_macs.values():
            # Check if a ticket for this Clover already exists.
            if dc_mac_clover.mac_address in existing_sync_incidents.keys() or \
               dc_mac_clover.mac_address in existing_sync_ritms.keys():
                continue

            # Create the payload to make a new INC ticket in ServiceNow.
            global_logger.warning(
                'Opening INC for Clover ' + dc_mac_clover.name + ' because '
                'this Clover''s MAC address sensor is returning a "dc" MAC '
                'address')
            ticket_payload = \
                make_incident_payload(dc_mac_clover, AffectedPlatform.PRTG)

            # Check if the payload creation was unsuccessful.
            if not ticket_payload:
                global_logger.error(
                    'An error occurred when trying to make a new INC in '
                    'ServiceNow for Clover ' + dc_mac_clover.name)
                continue

            # Try to make a new incident for this exclusive Meraki Clover.
            try:
                snow_incident_table.create(payload=ticket_payload)
                global_logger.info('Successfully created the INC for Clover ' +
                                   dc_mac_clover.name + '!')
                time.sleep(1)
                total_tickets += 1
            except pysnow.exceptions as e:
                global_logger.error(
                    'An error occurred when trying to make a new INC in '
                    'ServiceNow for Clover ' + dc_mac_clover.name)
                global_logger.error('Error: ' + str(e))

    # Make a ticket for each exclusive Meraki Clover.
    for excl_clover in clover_sync_status.meraki_clovers.values():
        # Check if a ticket for this Clover already exists.
        if excl_clover.mac_address in existing_sync_incidents.keys() or \
           excl_clover.mac_address in existing_sync_ritms.keys():
            continue

        # Create the payload to make a new INC in ServiceNow.
        global_logger.warning('Opening INC at site ' + excl_clover.site +
                              ' for Clover ' + excl_clover.name +
                              ' because this Clover is exclusively in Meraki' +
                              ' and NOT in PRTG')
        ticket_payload = \
            make_incident_payload(excl_clover, AffectedPlatform.MERAKI)

        # Check if the payload creation was unsuccessful.
        if not ticket_payload:
            global_logger.error('An error occurred when trying to make a new '
                                'INC in ServiceNow for Clover ' +
                                excl_clover.site + ' ' + excl_clover.name)
            continue

        # Try to make a new incident for this exclusive Meraki Clover.
        try:
            snow_incident_table.create(payload=ticket_payload)
            global_logger.info('Successfully created the INC for Clover ' +
                               excl_clover.site + ' ' + excl_clover.name + '!')
            time.sleep(1)
            total_tickets += 1
        except pysnow.exceptions as e:
            global_logger.error('An error occurred when trying to make a new '
                                'INC in ServiceNow for Clover ' +
                                excl_clover.site + ' ' + excl_clover.name)
            global_logger.error('Error: ' + str(e))

    # Make a ticket for each exclusive PRTG Clover.
    for excl_clover in clover_sync_status.prtg_clovers.values():
        # Check if a ticket for this Clover already exists.
        if excl_clover.mac_address in existing_sync_incidents.keys() or \
           excl_clover.mac_address in existing_sync_ritms.keys():
            continue

        # Create the payload to make a new INC in ServiceNow.
        global_logger.warning('Opening INC for Clover ' + excl_clover.name +
                              ' because this Clover is exclusively in PRTG '
                              'and NOT in Meraki')
        ticket_payload = \
            make_incident_payload(excl_clover, AffectedPlatform.PRTG)

        # Check if the payload creation was unsuccessful.
        if not ticket_payload:
            global_logger.error('An error occurred when trying to make a new '
                                'INC in ServiceNow for Clover ' +
                                excl_clover.name)
            continue

        # Try to make a new incident for this exclusive PRTG Clover.
        try:
            snow_incident_table.create(payload=ticket_payload)
            global_logger.info('Successfully created the INC for Clover ' +
                               excl_clover.name + '!')
            time.sleep(1)
            total_tickets += 1
        except pysnow.exceptions as e:
            global_logger.error('An error occurred when trying to make a new '
                                'INC in ServiceNow for Clover ' +
                                excl_clover.name)
            global_logger.error('Error: ' + str(e))

    # Make a ticket for each mismatched Clover.
    for mm_clover_pair in clover_sync_status.clover_mismatches.values():
        # Check if a ticket for this Clover already exists.
        if mm_clover_pair.meraki_clover.mac_address in \
          existing_sync_incidents.keys() or \
          mm_clover_pair.meraki_clover.mac_address in \
          existing_sync_ritms.keys():
            continue

        # Create the payload to make a new INC in ServiceNow.
        global_logger.warning('Opening INC for Clover ' +
                              mm_clover_pair.prtg_clover.name + ' because ' +
                              mm_clover_pair.mismatch_error)
        ticket_payload = \
            make_incident_payload(mm_clover_pair, AffectedPlatform.ALL)

        # Check if the payload creation was unsuccessful.
        if not ticket_payload:
            global_logger.error('An error occurred when trying to make a new '
                                'INC in ServiceNow for Clover ' +
                                mm_clover_pair.prtg_clover.name)
            continue

        # Try to make a new incident for this mismatched Clover.
        try:
            snow_incident_table.create(payload=ticket_payload)
            global_logger.info('Successfully created the INC for Clover ' +
                               mm_clover_pair.prtg_clover.name + '!')
            time.sleep(1)
            total_tickets += 1
        except pysnow.exceptions as e:
            global_logger.error('An error occurred when trying to make a new '
                                'INC in ServiceNow for Clover ' +
                                mm_clover_pair.prtg_clover.name)
            global_logger.error('Error: ' + str(e))

    # Make a ticket for each lost Clover found in ServiceNow.
    for lost_clover in clover_sync_status.snow_lost_clovers:
        # Check if a ticket for this Clover already exists.
        if lost_clover['mac_address'] in existing_sync_incidents.keys() or \
           lost_clover['mac_address'] in existing_sync_ritms.keys():
            continue

        # Create the payload to make a new INC in ServiceNow.
        global_logger.warning('Opening INC for ' + lost_clover['name'] + ' ' +
                              'because I could not find it in Meraki nor PRTG')
        ticket_payload = {
            'short_description':
                '[SNow] Vitu Clover Sync issue for ' + lost_clover['name'] +
                ' ' + lost_clover['mac_address'],
            'description':
                'Lost Clover found in ServiceNow - ' + lost_clover['name'] +
                ' could not be found in Meraki nor PRTG',
            'caller_id': 'Cody Harper',
            'assignment_group': 'Expert Services Level One Team',
            'company': 'Vitu',
            'location': lost_clover['location.name'],
            'configuration_item': lost_clover['name'],
            'u_milestone': 'Vitu Oct 2020 - Sept 2021',
            'category': 'Inquiry',
            'severity': '2 - Medium'
        }

        # Try to make a new incident for this lost Clover.
        try:
            snow_incident_table.create(payload=ticket_payload)
            global_logger.info('Successfully created the INC for ' +
                               lost_clover['name'] + '!')
            time.sleep(1)
            total_tickets += 1
        except pysnow.exceptions as e:
            global_logger.error('An error occurred when trying to make a new '
                                'INC in ServiceNow for ' + lost_clover['name'])
            global_logger.error('Error: ' + str(e))

    # Make an automated ticket for each invalid Meraki Clover.
    for invalid_meraki in clover_sync_status.meraki_invalid_clovers.values():
        # Check if a ticket for this Clover already exists.
        if invalid_meraki.mac_address in existing_sync_incidents.keys() or \
           invalid_meraki.mac_address in existing_sync_ritms.keys():
            continue

        # Attempt to fix the name.
        if invalid_meraki.window_number is not None:
            # Initialize quick reference to the new name.
            new_name = 'Window ' + invalid_meraki.window_number + ' ' + \
                       invalid_meraki.mac_address

            # Make a new automated RITM ticket in ServiceNow.
            global_logger.warning('Opening automated RITM at site ' +
                                  invalid_meraki.site + ' for Clover ' +
                                  invalid_meraki.name + ' to change the name '
                                  'to ' + new_name)
            automation_successful = make_automated_ticket(
                AffectedPlatform.MERAKI, new_name, invalid_meraki)

            # Check if the ticket was successfully made.
            if automation_successful:
                time.sleep(1)
                total_tickets += 1
        elif invalid_meraki.mac_address in \
                clover_sync_status.unsyncable_clovers.keys():
            # Initialize quick references to the Clover and new name.
            prtg_clover = clover_sync_status.unsyncable_clovers[
                invalid_meraki.mac_address].prtg_clover
            new_name = 'Window ' + prtg_clover.window_number + ' ' + \
                       invalid_meraki.mac_address

            # Make sure the invalid Meraki object has the 'None' window number
            # updated from its corresponding PRTG Clover.
            invalid_meraki.window_number = prtg_clover.window_number

            # Make a new automated RITM ticket in ServiceNow.
            global_logger.warning('Opening automated RITM at site ' +
                                  invalid_meraki.site + ' for Clover ' +
                                  invalid_meraki.name + ' to change the name '
                                  'to ' + new_name)
            automation_successful = make_automated_ticket(
                AffectedPlatform.MERAKI, new_name, invalid_meraki)

            # Check if the ticket was successfully made.
            if automation_successful:
                time.sleep(1)
                total_tickets += 1
        else:
            # We don't have the window number for this Clover, so we cannot
            # automate a RITM.
            global_logger.error('Error opening an automated RITM at site ' +
                                invalid_meraki.site + ' for Clover ' +
                                invalid_meraki.name +
                                ' because I do not have the window number')
            ticket_payload = {
                'short_description':
                    '[Meraki] Vitu Clover Sync issue at ' +
                    invalid_meraki.site + ' for Clover ' +
                    invalid_meraki.mac_address,
                'description':
                    'The Clover at site ' + invalid_meraki.site +
                    ' with name ' + invalid_meraki.name + ' cannot be '
                    'autonomously fixed because a window number was unable to'
                    ' be determined - the Clover name must be fixed manually',
                'caller_id': 'Cody Harper',
                'assignment_group': 'Expert Services Level One Team',
                'company': 'Vitu',
                'location': invalid_meraki.site,
                'configuration_item': 'AG-LAB-FULLSET',
                'u_milestone': 'Vitu Oct 2020 - Sept 2021',
                'category': 'Inquiry',
                'severity': '2 - Medium'
            }

            # Try to make a new incident for this invalid Clover.
            try:
                snow_incident_table.create(payload=ticket_payload)
                global_logger.info('Successfully created the INC for Clover '
                                   + invalid_meraki.site + ' ' +
                                   invalid_meraki.name + '!')
                time.sleep(1)
                total_tickets += 1
            except pysnow.exceptions as e:
                global_logger.error('An error occurred when trying to make a '
                                    'new INC in ServiceNow for Clover ' +
                                    invalid_meraki.site + ' ' +
                                    invalid_meraki.name)
                global_logger.error('Error: ' + str(e))

    # Make an automated ticket for each invalid PRTG Clover.
    for invalid_prtg in clover_sync_status.prtg_invalid_clovers.values():
        # Check if a ticket for this Clover already exists.
        if invalid_prtg.mac_address in existing_sync_incidents.keys() or \
           invalid_prtg.mac_address in existing_sync_ritms.keys():
            continue

        # Attempt to fix the name.
        if invalid_prtg.window_number is not None:
            new_name = '[' + invalid_prtg.site + '] Window ' + \
                       invalid_prtg.window_number + ' ' + \
                       invalid_prtg.mac_address

            global_logger.warning('Opening automated RITM for ' +
                                  invalid_prtg.name + ' to change the name '
                                  'to ' + new_name)
            automation_successful = make_automated_ticket(
                AffectedPlatform.PRTG, new_name, invalid_prtg)

            # Check if the ticket was successfully made.
            if automation_successful:
                time.sleep(1)
                total_tickets += 1
        elif invalid_prtg.mac_address in \
                clover_sync_status.unsyncable_clovers.keys():
            # Initialize quick references to the Clover and new name.
            meraki_clover = clover_sync_status.unsyncable_clovers[
                invalid_prtg.mac_address].meraki_clover
            new_name = '[' + meraki_clover.site + '] Window ' + \
                       meraki_clover.window_number + ' ' + \
                       invalid_prtg.mac_address

            # Make sure the invalid PRTG object has the 'None' window number
            # updated from its corresponding Meraki Clover.
            invalid_prtg.window_number = meraki_clover.window_number

            global_logger.warning('Opening automated RITM for ' +
                                  invalid_prtg.name + ' to change the name '
                                  'to ' + new_name)
            automation_successful = make_automated_ticket(
                AffectedPlatform.PRTG, new_name, invalid_prtg)

            # Check if the ticket was successfully made.
            if automation_successful:
                time.sleep(1)
                total_tickets += 1
        else:
            global_logger.error('Error opening automated RITM for Clover ' +
                                invalid_prtg.name +
                                ' because I do not have the window number')
            ticket_payload = {
                'short_description':
                    '[PRTG] Vitu Clover Sync issue at ' +
                    invalid_prtg.site + ' for Clover ' +
                    invalid_prtg.mac_address,
                'description':
                    'The Clover with name ' + invalid_prtg.name + ' cannot be '
                    'autonomously fixed because a window number was unable to'
                    ' be determined - the Clover name must be fixed manually',
                'caller_id': 'Cody Harper',
                'assignment_group': 'Expert Services Level One Team',
                'company': 'Vitu',
                'location': invalid_prtg.site,
                'configuration_item': 'AG-LAB-FULLSET',
                'u_milestone': 'Vitu Oct 2020 - Sept 2021',
                'category': 'Inquiry',
                'severity': '2 - Medium'
            }

            # Try to make a new incident for this invalid Clover.
            try:
                snow_incident_table.create(payload=ticket_payload)
                global_logger.info('Successfully created the INC for Clover '
                                   + invalid_prtg.name + '!')
                time.sleep(1)
                total_tickets += 1
            except pysnow.exceptions as e:
                global_logger.error('An error occurred when trying to make a '
                                    'new INC in ServiceNow for Clover ' +
                                    invalid_prtg.name)
                global_logger.error('Error: ' + str(e))

    # Print how many tickets were created in ServiceNow.
    global_logger.info(
        '------------------------------------------------------------------')
    global_logger.info(' ')
    global_logger.info(
        '----------------- End ServiceNow Ticket Creation -----------------')
    global_logger.info(
        'Total ServiceNow tickets created: ' + str(total_tickets))
    global_logger.info(
        '------------------------------------------------------------------')


# Extracts the final 6 hex characters (including the 2 ':' separators) from a
# given Clover name and returns a lowercase colon-separated valid Clover MAC
# address. If a MAC address cannot be extracted '' is returned.
def get_clover_mac(name: str) -> str:
    mac = 'd4:95:24:' + \
          name.strip().lower().replace('-', ':').replace('::', ':')[-8:]
    return mac if CLOVER_MAC_REGEX.match(mac) else ''


# Given a Clover object or CloverPair object and the affected platform
# relating to the object, this function returns a dictionary that represents
# the payload for ServiceNow to create a new incident ticket.
def make_incident_payload(clover_obj: object, platform: AffectedPlatform) -> \
        dict:
    # Check if the Clover object is a CloverPair.
    if isinstance(clover_obj, CloverPair):
        meraki_clover = clover_obj.meraki_clover
        prtg_clover = clover_obj.prtg_clover

        ticket_payload = {
            'short_description':
                '[PRTG] [Meraki] Vitu Clover Sync issue at ' +
                prtg_clover.site + ' for Clover ' +
                meraki_clover.mac_address,
            'description': clover_obj.mismatch_error,
            'caller_id': 'Cody Harper',
            'assignment_group': 'Expert Services Level One Team',
            'company': 'Vitu',
            'location': prtg_clover.site,
            'configuration_item':
                prtg_clover.site + ' Clover Window' +
                prtg_clover.window_number,
            'u_milestone': 'Vitu Oct 2020 - Sept 2021',
            'category': 'Inquiry',
            'severity': '2 - Medium'
        }
    # Check if the Clover object is a Meraki / PRTG Clover object.
    elif isinstance(clover_obj, MerakiClover) or \
            isinstance(clover_obj, PRTGClover):
        ticket_payload = {
            'short_description':
                '[' + str(platform.value) + '] Vitu Clover Sync issue at ' +
                clover_obj.site + ' for Clover ' +
                clover_obj.mac_address,
            'description': clover_obj.error,
            'caller_id': 'Cody Harper',
            'assignment_group': 'Expert Services Level One Team',
            'company': 'Vitu',
            'location': clover_obj.site,
            'configuration_item':
                clover_obj.site + ' Clover Window' +
                clover_obj.window_number,
            'u_milestone': 'Vitu Oct 2020 - Sept 2021',
            'category': 'Inquiry',
            'severity': '2 - Medium'
        }
    # We were given invalid input.
    else:
        ticket_payload = {}

    return ticket_payload


# Given a Clover object and the corrected name, make an automated ticket in
# ServiceNow to be approved / denied.
def make_automated_ticket(platform: AffectedPlatform, new_name: str,
                          clover: object) -> bool:
    # Identify the type of Clover and extract the relevant information.
    if isinstance(clover, MerakiClover):
        clover_id = clover.meraki_id
        clover_name = clover.name
    elif isinstance(clover, PRTGClover):
        clover_id = clover.prtg_id
        clover_name = clover.name
    else:
        global_logger.error('Cannot make an automated ticket with this '
                            'object: ' + str(clover))
        time.sleep(1)
        return False

    # Make the ticket.
    snow_req_resp = \
        requests.post(
            url=SNOW_INST_URL + SNOW_ORDER_NOW_PATH,
            auth=(SNOW_USERNAME, SNOW_PASSWORD),
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            data=json.dumps(
                {
                    'sysparm_quantity': '1',
                    'variables':
                        {
                            'affected_platform': str(platform.value),
                            'id': clover_id,
                            'Incorrect_Name': clover_name,
                            'corrected_name': new_name
                        }
                }
            )
        )

    # Check if the ticket creation was unsuccessful.
    if not 200 <= snow_req_resp.status_code <= 299:
        global_logger.error('An error occurred when trying to make an '
                            'automated RITM for Clover ' + clover_name +
                            ' to change the name to ' + new_name)
        global_logger.error('Reason: ' + snow_req_resp.reason)
        time.sleep(1)
        return False

    # Make a new short description for the request item ticket.
    short_desc = '[' + str(platform.value) + '] Automated Vitu Clover Sync ' \
                 'Request at ' + clover.site + ' for Clover ' + \
                 clover.mac_address

    # Extract the sys ID of the request from the response.
    snow_req_resp_json = snow_req_resp.json()
    ritm_sys_id = snow_req_resp_json['result']['sys_id']

    # Get the relevant request item.
    ritm_table_path = f'/table/sc_req_item'
    snow_ritm_table = SNOW_CLIENT.resource(api_path=ritm_table_path)

    # Edit the short description of the relevant request item.
    updated_ritm = snow_ritm_table.update(
        query={'request': ritm_sys_id},
        payload={
            'short_description': short_desc,
            'description': clover.error,
            'caller_id': 'Cody Harper',
            'assigned_to': 'Christopher Villasenor',
            'company': 'Vitu',
            'location': clover.site,
            'configuration_item':
                clover.site + ' Clover Window' + clover.window_number,
            'u_milestone': 'Vitu Oct 2020 - Sept 2021',
            'category': 'Inquiry',
            'severity': '2 - Medium'
        }
    )

    # Check if the edit was unsuccessful.
    if not updated_ritm:
        global_logger.error('Error editing the short description for the '
                            'automated RITM ' + ritm_sys_id + ' relating to '
                            'Clover at site ' + clover.site + ' with name '
                            + clover_name)
        time.sleep(1)
        return False

    global_logger.info('Automated RITM created successfully at site ' +
                       clover.site + ' for Clover ' + clover_name)
    return True


# Returns the Clover's window number as a string if it was found in the
# name. Otherwise, returns 'None'.
def get_window_number(clover_name: str) -> str | None:
    # Extract the window number from the Clover name.
    window_number = re.sub(EVERYTHING_BUT_WIND_NUM_REGEX, '',
                           clover_name).strip()
    return None if window_number == '' else window_number


# Returns the global logger for this script. Logs will be generated for the
# console, a log file, and Paper Trail.
def make_logger() -> logging.Logger:
    # Make the logger's timestamps in UTC.
    logging.Formatter.converter = time.gmtime

    # Initialize a format for the log file and standard out handlers.
    stdout_file_format = logging.Formatter(
        '%(asctime)s [%(name)s] [%(levelname)s] %(message)s',
        datefmt='%b %d %Y %H:%M:%S UTC')

    # Initialize and configure the standard out handler for logging to the
    # console.
    stdout_handle = logging.StreamHandler(sys.stdout)
    stdout_handle.setLevel(logging.INFO)
    stdout_handle.setFormatter(stdout_file_format)

    # Initialize and configure the log file handler for logging to a file.
    now_utc = datetime.utcnow().replace(tzinfo=pytz.UTC)

    # Check if the "logs" folder exists. If not, create it.
    if not os.path.isdir(SCRIPT_PATH + '/../logs'):
        os.mkdir(SCRIPT_PATH + '/../logs')

    log_file_handle = logging.FileHandler(
        SCRIPT_PATH + '/../logs/prtg_meraki_snow_sync_log_' +
        now_utc.strftime('%Y-%m-%d_%H-%M-%S-%Z') + '.log')
    log_file_handle.setLevel(logging.INFO)
    log_file_handle.setFormatter(stdout_file_format)

    # Initialize and configure the remote system handler for logging to
    # Paper Trail.
    paper_trail_handle = SysLogHandler(address=('logs.papertrailapp.com',
                                                49638))
    paper_trail_handle.setLevel(logging.INFO)
    paper_trail_handle.setFormatter(
        logging.Formatter(LOGGER_NAME + ': %(message)s'))

    # Initialize the global logger and add the standard out, file, and remote
    # handlers to it.
    logger = logging.getLogger(name=LOGGER_NAME)
    logger.addHandler(stdout_handle)
    logger.addHandler(log_file_handle)
    logger.addHandler(paper_trail_handle)
    logger.setLevel(logging.INFO)

    return logger


# Main method that runs the script. It has no input parameters.
if __name__ == '__main__':
    # Make the global logger for this script.
    global_logger = make_logger()

    # Make the status object to keep track of relevant sync information.
    curr_clover_sync_status = CloverSyncStatus()

    # Perform the entire sync operation.
    curr_clover_sync_status = get_meraki_clovers(curr_clover_sync_status)
    curr_clover_sync_status = get_prtg_clovers(curr_clover_sync_status)
    curr_clover_sync_status = analyze_clovers(curr_clover_sync_status)
    curr_clover_sync_status = sync_to_snow(curr_clover_sync_status)
    make_snow_tickets(curr_clover_sync_status)

    # End the sync operation.
    global_logger.info(' ')
    global_logger.info('Finished the sync')
