# PRTG-Meraki-SNow-Sync

## Summary
Synchronizes existing devices seen in PRTG, Meraki, and ServiceNow together. The data synced includes device names, MAC addresses, IPv4 addresses, and serial numbers.

_Note: If you have any questions or comments you can always use GitHub
discussions, or email me at farinaanthony96@gmail.com._

#### Why
Keeps our ServiceNow CMDB updated with the latest devices in our network system infrastructure
and notifies engineers of discrepancies amongst these systems.

## Requirements
- Python 3.11.1
- configparser
- meraki
- pysnow
- pytz
- requests

## Usage
- Edit the config file with relevant PRTG, Meraki, and ServiceNow access 
  information as well as the name of the logger.

- Simply run the script using Python:
  `python PRTG-Meraki-SNow-Sync.py`

## Compatibility
Should be able to run on any machine with a Python interpreter. This script
was only tested on a Windows machine running Python 3.11.1.

## Disclaimer
The code provided in this project is an open source example and should not
be treated as an officially supported product. Use at your own risk. If you
encounter any problems, please log an
[issue](https://github.com/CC-Digital-Innovation/PRTG-Meraki-SNow-Sync/issues).

## Contributing
1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request ツ

## History
-  version 2.1.0 - 2023/03/20
    - Fixed crash when a device in Meraki would have its "recentDeviceName" 
      be None
    - Implemented f-strings to replace str() to increase readability / 
      efficiency
    - Added fastvue as a remote logger for debugging / redundancy purposes
    - Added private logging method to simplify title creation in the logs
    - Updated license


-  version 2.0.6 - 2022/12/14
    - Fixed bug that wouldn't sync the shortened serial number to ServiceNow


-  version 2.0.5 - 2022/12/13
    - Fixed bug that caused the script to crash when trying to split an
      invalid S/N string


-  version 2.0.4 - 2022/12/11
    - Fixed bug that synced full Clover serial number instead of the
      desired shortened version


-  version 2.0.3 - 2022/12/09
    - Fixed bug that prevented S/N syncing
    - Updated README.md to be more robust
    - Updated Python version in the Dockerfile


-  version 2.0.2 - 2022/11/11
    - Add extra str()'s to logger strings to prevent "None" names from crashing the script
    - Adjust cronjob for daylight savings


-  version 2.0.1 - 2022/10/27
    - Corrected various files for our CI/CD pipeline
    - Made error strings, logging output, and ticket descriptions more robust
    - Added enumeration to represent affected platform for a particular Clover issue
    - Made short_desc's shorter because we hit a char limit in SNow
    - Add a global constant to quickly enable / disable "dc" ticketing


-  version 2.0.0 - 2022/10/25
    - Complete overhaul of the original sync script: Automated approval system for renaming devices
    - Creates INC tickets in SNow for discrepancies found across PRTG, Meraki, and SNow
    - Paper Trail logging


-  version 1.0.0 - 2022/02/24
    - (initial release)

## Credits
Anthony Farina <<farinaanthony96@gmail.com>>
