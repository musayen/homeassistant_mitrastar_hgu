"""

Support for MitraStar GPT-2541GNAC Router (Movistar Spain).
For more details about this platform, please refer to the documentation at 

"""
import base64
from datetime import datetime
import hashlib
import logging
import re
import requests
import voluptuous as vol

from homeassistant.components.device_tracker import (DOMAIN, PLATFORM_SCHEMA, DeviceScanner)
from homeassistant.const import (CONF_HOST, CONF_PASSWORD, CONF_USERNAME, HTTP_HEADER_X_REQUESTED_WITH)
import homeassistant.helpers.config_validation as cv

_LOGGER = logging.getLogger(__name__)

# Custom element for configuration.yaml
# number_of_guest_ap: number of guest wireless networks enabled on the router
CONF_NUMBER_GUEST_AP = 'number_of_guest_ap'
DEFAULT_NUMBER_GUEST_AP = 0

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_HOST): cv.string,
    vol.Required(CONF_PASSWORD): cv.string,
    vol.Required(CONF_USERNAME): cv.string,
    vol.Optional(CONF_NUMBER_GUEST_AP, default=DEFAULT_NUMBER_GUEST_AP): cv.positive_int
})

def get_scanner(hass, config):
    """Validate the configuration and return a Mitrastar scanner."""

    scanner = MitraStarDeviceScanner(config[DOMAIN])
    return scanner if scanner.success_init else None


class MitraStarDeviceScanner(DeviceScanner):
    """This class queries a MitraStar GPT-2541GNAC wireless Router (Movistar Spain)."""

    def __init__(self, config):
        """Initialize the scanner."""
        host = config[CONF_HOST]
        username = config[CONF_USERNAME]
        password = config[CONF_PASSWORD]
        n_guest_ap = config[CONF_NUMBER_GUEST_AP]
        
        # The maximum number of guest wireless APs for this router is 3
        if (n_guest_ap > 3):
            n_guest_ap = 3

        self.parse_macs = re.compile(r'([0-9a-fA-F]{2}:' + '[0-9a-fA-F]{2}:' + '[0-9a-fA-F]{2}:' + '[0-9a-fA-F]{2}:' + '[0-9a-fA-F]{2}:' + '[0-9a-fA-F]{2})')
        self.parse_dhcp = re.compile(r'<td>([0-9a-zA-Z\-._]+)<\/td><td>([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})<\/td><td>([0-9]+.[0-9]+.[0-9]+.[0-9]+.[0-9]+)')

        self.host = host
        self.username = username
        self.password = password
        self.n_guest_ap = n_guest_ap

        self.LOGIN_URL = 'http://{ip}/login-login.cgi'.format(**{'ip': self.host})
        self.headers1 = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36'}

        self.last_results = {}
        self.dhcp_data = {}
        self.success_init = self._update_info()

    def scan_devices(self):
        """Scan for new devices and return a list with found device IDs."""
        self._update_info()
        return self.last_results

    def get_device_name(self, device):
        """Get the device name from the router DHCP table."""
        match = [element[0] for element in self.dhcp_data if element[1].lower()==device]
        if len(match) > 0:
            device_name = match[0]
        else:
            device_name =  None
        return device_name

    def get_extra_attributes(self, device):
        """Get the device ip from the router DHCP table."""
        match = [element for element in self.dhcp_data if element[1].lower()==device]
        extra_attributes = {
          "ip": "unknown",
          "mac": "unknown"
        }
        if len(match) > 0:
            # match[0] is an array of [0]name, [1]mac, [2]ip
            extra_attributes["mac"] = match[0][1]
            extra_attributes["ip"] = match[0][2]
        
        return extra_attributes

    def _update_info(self):
        """Ensure the information from the MitraStar router is up to date.
        Return boolean if scanning successful.
        """
        _LOGGER.info('Checking MitraStar GPT-2541GNAC Router')

        data, dhcp_data = self.get_MitraStar_info()
        if not data:
            return False

        self.last_results = data
        self.dhcp_data = dhcp_data
        return True

    def _read_table(self, session, url):
        response = session.get(url, headers=self.headers1)
        if response.status_code == 200:
            response_string = str(response.content, "utf-8")
            return response_string
        else:
            _LOGGER.error('Unable to contact router at: {}'.format(url))

    def get_MitraStar_info(self):
        """Retrieve data from MitraStar GPT-2541GNAC Router."""
        
        username1 = str(self.username)
        password1 = str(self.password)

        sessionKey = base64.b64encode(
            '{user}:{pass}'.format(**{
                'user': username1,
                'pass': password1
            }).encode()
        )
        data1 = {
            'sessionKey': sessionKey,
            'pass': ''
        }

        # Session creation and login
        session1 = requests.Session()
        login_response = session1.post(self.LOGIN_URL, data=data1, headers=self.headers1)
       
        # Check HTTP result code after login (200 = login successful)
        if login_response.status_code == 200:

            # Router tables URLs
            urls = ['http://{}/arpview.cmd'.format(self.host), \
            'http://{}/wlstationlist.cmd'.format(self.host), \
            'http://{}/wlextstationlist.cmd?action=view&wlSsidIdx=1'.format(self.host) ]
            
            # Add URLs for guest APs depending on the number_of_guest_ap defined at configuration.yaml
            for guest_ap_id in range (2, 2+self.n_guest_ap):
                urls.append('http://{}/wlextstationlist.cmd?action=view&wlSsidIdx={}'.format(self.host, guest_ap_id))
            
            mac_array = []
            
            # Read urls one by one and append unique elements to mac_array
            for url_address in urls:
                url_result = self._read_table(session1, url_address).lower()
                mac_array_new = self.parse_macs.findall(url_result)
                mac_array.extend([element for element in mac_array_new if element not in mac_array])

            # Read DHCP table to store hostnames and IP addresses of hosts
            dhcp_url = 'http://{}/dhcpinfo.html'.format(self.host)
            url_result = self._read_table(session1, dhcp_url).replace('\n ','').replace(' ','').replace('_','-')
            dhcp_data = self.parse_dhcp.findall(url_result)

            _LOGGER.debug('MitraStar GPT-2541GNAC found %d devices' %len(mac_array))

        else:
            mac_array = None
            _LOGGER.error('Error connecting to the router...')

        return mac_array, dhcp_data

