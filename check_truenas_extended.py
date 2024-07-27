#!/usr/bin/env python3

# The MIT License (MIT)
# Copyright (c) 2015 Goran Tornqvist
# Extended by Stewart Loving-Gibbard 2020, 2021, 2022, 2023
# Additional help from Folke Ashberg 2021
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys

# Attempt to require minimum version of Python
#
# NOTE: This will NOT work much of the time, and instead you'll get a cryptic 
# error because this script won't compile at all in earlier versions of Python.
#
# For example, several users are seeing this and not understanding it:
#
# curie# ./check_truenas_extended_play.py
#  File "./check_truenas_extended_play.py", line 48
#    ZpoolName: str
#
# This is dying because of the user of Dataclass in earlier versions of Python that
# don't recognize it. Dataclass was introduced in Python 3.7.
# 
# So, this is both the least and most we can do without having wrappers or shell scripts
# or batch files, none of which is going to make this script any easier to use.
#
# Sorry I can't do more without deliberately avoding language features!
#
# -- SLG 3/1/2022
MIN_PYTHON = (3, 7)
if sys.version_info < MIN_PYTHON:
    sys.exit("Python %s.%s or later is required.\n" % MIN_PYTHON)

import argparse
import json
import string
import urllib3
import requests
import logging
from dataclasses import dataclass
from enum import Enum
import argparse
import logging
import sys

class RequestTypeEnum(Enum):
    GET_REQUEST = 1
    POST_REQUEST = 2

@dataclass
class ZpoolCapacity:
    ZpoolName: str
    ZpoolAvailableBytes: int
    TotalUsedBytesForAllDatasets: int
  

class Startup(object):
    def __init__(self, hostname, user, passwd, use_ssl, verify_ssl_cert, ignore_dismissed_alerts, debug, zpool_name, zpool_warn, zpool_critical, show_zpool_perfdata):
        self._hostname = hostname
        self._user = user
        self._passwd = passwd
        self._use_ssl = use_ssl
        self._verify_ssl_cert = verify_ssl_cert
        self._ignore_dismissed_alerts = ignore_dismissed_alerts
        self._debug_logging = debug
        self._zpool_name = zpool_name
        self._wfree = zpool_warn
        self._cfree = zpool_critical
        self._show_zpool_perfdata = show_zpool_perfdata

    def check_alerts(self):r, secret, use_ssl, verify_cert, ignore_dismissed_alerts, debug_logging, zpool_name, zpool_warn, zpool_critical, show_zpool_perfdata):
        # TODO: Implement check_alerts method
        pass

    def check_zpool(self):
        # TODO: Implement check_zpool method
        pass

    def check_zpool_capacity(self):
        # TODO: Implement check_zpool_capacity method
        pass

    def handle_requested_alert_type(self, alert_type):
        if alert_type == 'alerts':
            self.check_alerts()
        elif alert_type == 'repl':
            self.check_repl()
        elif alert_type == 'update':
            self.check_update()
        elif alert_type == 'zpool':
            self.check_zpool()
        elif alert_type == 'zpool_capacity':
            self.check_zpool_capacity()
        else:
            print("Unknown type: " + alert_type)
            sys.exit(3)

    def setup_logging(self):
        logger = logging.getLogger()

        if self._debug_logging:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.CRITICAL)

def main():
    # Build parser for arguments
    parser = argparse.ArgumentParser(description='Checks a TrueNAS/FreeNAS server using the 2.0 API. Version ' + check_truenas_script_version)
    parser.add_argument('-H', '--hostname', required=True, type=str, help='Hostname or IP address')
    parser.add_argument('-u', '--user', required=False, type=str, help='Username, only root works, if not specified: use API Key')
    parser.add_argument('-p', '--passwd', required=True, type=str, help='Password or API Key')
    parser.add_argument('-t', '--type', required=True, type=str, help='Type of check, either alerts, zpool, zpool_capacity, repl, or update')
    parser.add_argument('-pn', '--zpoolname', required=False, type=str, default='all', help='For check type zpool, the name of zpool to check. Optional; defaults to all zpools.')
    parser.add_argument('-ns', '--no-ssl', required=False, action='store_true', help='Disable SSL (use HTTP); default is to use SSL (use HTTPS)')
    parser.add_argument('-nv', '--no-verify-cert', required=False, action='store_true', help='Do not verify the server SSL cert; default is to verify the SSL cert')
    parser.add_argument('-ig', '--ignore-dismissed-alerts', required=False, action='store_true', help='Ignore alerts that have already been dismissed in FreeNas/TrueNAS; default is to treat them as relevant')
    parser.add_argument('-d', '--debug', required=False, action='store_true', help='Display debugging information; run script this way and record result when asking for help.')
    parser.add_argument('-zw', '--zpool-warn', required=False, type=int, default=default_zpool_warning_percent, help='ZPool warning storage capacity free threshold. Give a percent value in the range 1-100, defaults to ' + str(default_zpool_warning_percent) + '%%. Used with zpool_capacity check.')
    parser.add_argument('-zc', '--zpool-critical', required=False, type=int, default=default_zool_critical_percent, help='ZPool critical storage capacity free threshold. Give a percent value in the range 1-100, defaults to ' + str(default_zool_critical_percent) +'%%. Used with zpool_capacity check.')
    parser.add_argument('-zp', '--zpool-perfdata', required=False, action='store_true', help='Add Zpool capacity perf data to output. Used with zpool_capacity check.')

    # if no arguments, print out help
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    # Parse the arguments
    args = parser.parse_args(sys.argv[1:])

    use_ssl = not args.no_ssl
    verify_ssl_cert = not args.no_verify_cert

    startup = Startup(args.hostname, args.user, args.passwd, use_ssl, verify_ssl_cert, args.ignore_dismissed_alerts, args.debug, args.zpoolname, args.zpool_warn, args.zpool_critical, args.zpool_perfdata)

    startup.handle_requested_alert_type(args.type)

if __name__ == '__main__':
    main()
ly way with the current
        # API. If you know better, please let me know!
        #
        # -- SLG 12/04/2021


        BYTES_IN_MEGABYTE = 1024 * 1024;

        logging.debug('check_zpool_capacity')

        warnZpoolCapacityPercent = self._wfree
        critZpoolCapacityPercent = self._cfree

        datasetPayload = {
            'query-options': {
                'extra': {
                    'flat': False
                }
            },
             'query-filters': []   
        }     
        dataset_results = self.get_request_with_payload('pool/dataset', datasetPayload)

        warn=0
        crit=0
        critical_messages = ''
        warning_messages = ''
        zpools_examined_with_no_issues = ''
        root_level_datasets_examined = ''
        root_level_dataset_count = 0
        all_root_level_dataset_names = ''
        perfdata = ''
        if (self._show_zpool_perfdata):
            perfdata= ';|'
        
        # We allow filtering on pool name here
        looking_for_all_pools = self._zpool_name.lower() == 'all'

        # Build a dict / array thingy and add to it as we proceed...
        zpoolNameToCapacityDict = {}
        
        try:
            # Go through all the datasets, and sum up values for the zpools we are interested in
            for dataset in dataset_results:
                root_level_dataset_count += 1
                dataset_name = dataset['name']
                dataset_pool_name = dataset['pool']
                
                all_root_level_dataset_names += dataset_name + ' '
                
                logging.debug('Checking root-level dataset for relevancy: dataset %s from pool %s', dataset_name, dataset_pool_name)
                
                # Either match all datasets, from any pool, or only datasets from the requested pool
                if (looking_for_all_pools or self._zpool_name == dataset_pool_name):
                    logging.debug('Relevant root-level dataset found: dataset %s from pool %s', dataset_name, dataset_pool_name)
                    root_level_datasets_examined = root_level_datasets_examined + ' ' + dataset_name
                    logging.debug('root_level_datasets_examined: %s', root_level_datasets_examined)

                    dataset_used_bytes = dataset['used']['parsed']
                    dataset_available_bytes = dataset['available']['parsed']

                    logging.debug('dataset_used_bytes: %d', dataset_used_bytes)
                    logging.debug('dataset_available_bytes: %d', dataset_available_bytes)

                    # We haven't seen this Zpool before, starting new summary record about it
                    if (not dataset_pool_name in zpoolNameToCapacityDict):
                        # dataset_available_bytes is the same for any dataset in a zpool, so we can just use the first
                        # one encountered. It will be the same value for all the relevant data sets, since they are all
                        # in the same Zpool with the same amount of available space
                        newZpoolCapacity = ZpoolCapacity(dataset_pool_name, dataset_available_bytes, dataset_used_bytes)
                        zpoolNameToCapacityDict[dataset_pool_name] = newZpoolCapacity
                    # Otherwise we've seen it before, update our count of used bytes
                    else:
                        zpoolNameToCapacityDict[dataset_pool_name].TotalUsedBytesForAllDatasets += dataset_used_bytes
                    logging.debug('currentZpoolCapacity: ' + str(zpoolNameToCapacityDict[dataset_pool_name]))


            # So now we have summary data on all the Zpools we care about. Go through each of them 
            # and see if any are above warning/critical percentages.
            for currentZpoolCapacity in zpoolNameToCapacityDict.values():
                zpoolTotalBytes = currentZpoolCapacity.ZpoolAvailableBytes + currentZpoolCapacity.TotalUsedBytesForAllDatasets
                usedPercentage = (currentZpoolCapacity.TotalUsedBytesForAllDatasets / zpoolTotalBytes ) * 100;
                usagePercentDisplayString = f'{usedPercentage:3.1f}'
                
                logging.debug('Warning capacity: ' + str(warnZpoolCapacityPercent) + '%' + ' Critical capacity: ' + str(critZpoolCapacityPercent) + '%')                 
                logging.debug('ZPool ' + str(currentZpoolCapacity.ZpoolName) + ' usedPercentage: ' + usagePercentDisplayString + '%')  
                
                # Add warning/critical errors for the current ZPool summary being checked, if needed
                if (usedPercentage >= critZpoolCapacityPercent):
                    crit += 1
                    critical_messages += " - Pool " + currentZpoolCapacity.ZpoolName + " usage " + usagePercentDisplayString + "% exceeds critical value of " + str(critZpoolCapacityPercent) + "%"                        
                elif (usedPercentage >= warnZpoolCapacityPercent):
                    warn += 1
                    warning_messages += " - Pool " + currentZpoolCapacity.ZpoolName + " usage " + usagePercentDisplayString + "% exceeds warning value of " + str(warnZpoolCapacityPercent) + "%"
                else:
                    # Don't add dashes to start, only to additions
                    if (len(zpools_examined_with_no_issues) > 0):
                        zpools_examined_with_no_issues += ' - '
                    zpools_examined_with_no_issues += currentZpoolCapacity.ZpoolName + ' (' + usagePercentDisplayString + '% used)'                    

                # Add perfdata if user requested it
                if (self._show_zpool_perfdata):
                    usedMegaBytes = currentZpoolCapacity.TotalUsedBytesForAllDatasets / BYTES_IN_MEGABYTE
                    usedMegabytesString = f'{usedMegaBytes:3.2f}'                    

                    warningBytes = zpoolTotalBytes * (warnZpoolCapacityPercent / 100)
                    warningMegabytes = warningBytes / BYTES_IN_MEGABYTE
                    warningMegabytesString = f'{warningMegabytes:3.2f}'

                    criticalBytes = zpoolTotalBytes * (critZpoolCapacityPercent / 100)
                    criticalMegabytes = criticalBytes / BYTES_IN_MEGABYTE
                    criticalMegabytesString = f'{criticalMegabytes:3.2f}'

                    totalMegabytes = zpoolTotalBytes / BYTES_IN_MEGABYTE
                    totalMegabytesString = f'{totalMegabytes:3.2f}' 

                    logging.debug('usedMegabytesString: ' + usedMegabytesString)  
                    logging.debug('warningMegabytesString: ' + warningMegabytesString)  
                    logging.debug('criticalMegabytesString: ' + criticalMegabytesString)                      
                    logging.debug('totalMegabytesString: ' + totalMegabytesString)  

                    perfdata += " " + currentZpoolCapacity.ZpoolName + "=" + usedMegabytesString + "MB;" + warningMegabytesString + ";" + criticalMegabytesString + ";0;" + totalMegabytesString                                

        except:
            print ('UNKNOWN - check_zpool() - Error when contacting TrueNAS server: ' + str(sys.exc_info()))
            sys.exit(3)
        
        # There were no datasets on the system, and we were looking for datasets from any pool
        if (root_level_datasets_examined == '' and root_level_dataset_count == 0 and looking_for_all_pools):
            root_level_datasets_examined = '(No Datasets found)'
            
        # There were no datasets matching the requested specific pool name on the system
        if (root_level_datasets_examined == '' and root_level_dataset_count > 0 and not looking_for_all_pools and crit == 0):
            crit = crit + 1
            critical_messages = '- No datasets found matching ZPool {} out of {} root level datasets ({})'.format(self._zpool_name, root_level_dataset_count, all_root_level_dataset_names)

        # If we have zpools with no issues to show in a warning/error, we want a leading dash in front of it.
        # Otherwise, no dash.
        error_or_warning_dividing_dash = ''
        if (len(zpools_examined_with_no_issues) > 0):
            error_or_warning_dividing_dash = ' - '
            logging.debug('Yes there is a dividing dash:' + error_or_warning_dividing_dash)

        if crit > 0:
            # Show critical errors before any warnings
            print ('CRITICAL' + critical_messages + warning_messages + error_or_warning_dividing_dash + zpools_examined_with_no_issues + perfdata)
            sys.exit(2)
        elif warn > 0:
            print ('WARNING' + warning_messages + error_or_warning_dividing_dash + zpools_examined_with_no_issues + perfdata)
            sys.exit(1)
        else:
            print ('OK - No Zpool capacity issues. ZPools examined: ' + zpools_examined_with_no_issues + ' - Root level datasets examined:' + root_level_datasets_examined + perfdata)
            sys.exit(0)



    def handle_requested_alert_type(self, alert_type):
        if alert_type == 'alerts':
            self.check_alerts()
        elif alert_type == 'repl':
            self.check_repl()
        elif alert_type == 'update':
            self.check_update()
        elif alert_type == 'zpool':
            self.check_zpool()
        elif alert_type == 'zpool_capacity':
            self.check_zpool_capacity()
        else:
            print ("Unknown type: " + alert_type)
            sys.exit(3)

    def setup_logging(self):
        logger = logging.getLogger()
        
        if (self._debug_logging):
            #print('Trying to set logging level debug')
            logger.setLevel(logging.DEBUG)
        else:
            #print('Should be setting no logging level at all')
            logger.setLevel(logging.CRITICAL)

check_truenas_script_version = '1.42'

default_zpool_warning_percent = 80
default_zool_critical_percent = 90

def main():
    # Build parser for arguments
    parser = argparse.ArgumentParser(description='Checks a TrueNAS/FreeNAS server using the 2.0 API. Version ' + check_truenas_script_version)
    parser.add_argument('-H', '--hostname', required=True, type=str, help='Hostname or IP address')
    parser.add_argument('-u', '--user', required=False, type=str, help='Username, only root works, if not specified: use API Key')
    parser.add_argument('-p', '--passwd', required=True, type=str, help='Password or API Key')
    parser.add_argument('-t', '--type', required=True, type=str, help='Type of check, either alerts, zpool, zpool_capacity, repl, or update')
    parser.add_argument('-pn', '--zpoolname', required=False, type=str, default='all', help='For check type zpool, the name of zpool to check. Optional; defaults to all zpools.')
    parser.add_argument('-ns', '--no-ssl', required=False, action='store_true', help='Disable SSL (use HTTP); default is to use SSL (use HTTPS)')
    parser.add_argument('-nv', '--no-verify-cert', required=False, action='store_true', help='Do not verify the server SSL cert; default is to verify the SSL cert')
    parser.add_argument('-ig', '--ignore-dismissed-alerts', required=False, action='store_true', help='Ignore alerts that have already been dismissed in FreeNas/TrueNAS; default is to treat them as relevant')
    parser.add_argument('-d', '--debug', required=False, action='store_true', help='Display debugging information; run script this way and record result when asking for help.')
    parser.add_argument('-zw', '--zpool-warn', required=False, type=int, default=default_zpool_warning_percent, help='ZPool warning storage capacity free threshold. Give a percent value in the range 1-100, defaults to ' + str(default_zpool_warning_percent) + '%%. Used with zpool_capacity check.')    
    parser.add_argument('-zc', '--zpool-critical', required=False, type=int, default=default_zool_critical_percent, help='ZPool critical storage capacity free threshold. Give a percent value in the range 1-100, defaults to ' + str(default_zool_critical_percent) +'%%. Used with zpool_capacity check.')
    parser.add_argument('-zp', '--zpool-perfdata', required=False, action='store_true', help='Add Zpool capacity perf data to output. Used with zpool_capacity check.')    
    
    # if no arguments, print out help
    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)
 
    # Parse the arguments
    args = parser.parse_args(sys.argv[1:])

    use_ssl = not args.no_ssl
    verify_ssl_cert = not args.no_verify_cert
 
    startup = Startup(args.hostname, args.user, args.passwd, use_ssl, verify_ssl_cert, args.ignore_dismissed_alerts, args.debug, args.zpoolname, args.zpool_warn, args.zpool_critical, args.zpool_perfdata)
 
    startup.handle_requested_alert_type(args.type)
 
if __name__ == '__main__':
    main()
    
