#!/usr/bin/env python3

import sys,os,getopt
import traceback
import os
import fcntl
import json
import requests
import time
from datetime import datetime
import pytz

from six import PY2

if PY2:
    get_unicode_string = unicode
else:
    get_unicode_string = str

sys.path.insert(0, './ds-integration')
from DefenseStorm import DefenseStorm

from html.parser import HTMLParser

class integration(object):

    system_JSON_field_mappings = {
        'description' : 'message',
        'date' : 'timestamp'
    }

    JSON_field_mappings = {
        'eventId' : 'event_id',
        'processPath' : 'process_path',
        'destinations' : 'ip_dest',
        'loggedUsers' : 'username',
        'macAddresses' : 'mac_address',
        'collectorGroup' : 'group',
        'rules' : 'rule_name',
        'ip' : 'client_ip',
        'id' : 'client_info',
        'device' : 'client_hostname',
        'operatingSystem' : 'os_type',
    }

    def ensilo_basicAuth(self):
        url = self.url + '/management-rest/events/list-events'
        url = self.url + '/management-rest/system-events/list-system-events'
        self.ds.log('INFO', "Attempting basic auth to  url: " + url)
        response = self.ensilo_request('/management-rest/system-events/list-system-events')
        if response == None and response.headers == None:
            return response
        headers = response.headers
        if 'X-Auth-Token' in headers.keys():
            token = headers['X-Auth-Token']
        else:
            self.ds.log('WARNING', 
                "Response missing X-Auth-Token in response from enSilo Server {0}.".format(url))
            return None
        return token

    def ensilo_getEvents(self):
        params = {'lastSeenFrom':self.last_run, 'lastSeenTo':self.current_run}
        #params = None
        response = self.ensilo_request('/management-rest/events/list-events', params = params)
        events = response.json()
        extra_events = []
        for event in events:
            event['message'] = "Event ID: " + str(event['eventId']) + " Process: " + event['process'] + " Action: " + event['action']
            event['category'] = "events"
            try:
                dt_timestamp = datetime.strptime(event['lastSeen'], self.time_format)
                dt_timestamp = self.pytz_timezone.localize(dt_timestamp)
                event['timestamp'] = dt_timestamp.isoformat()
            except Exception as E:
                self.ds.log('ERROR', "converting timestamp in event")
            if 'collectors' in event.keys() and event['collectors'] != None:
                c_events = event['collectors']
                for c_event in c_events:
                    c_event['category'] = "events"
                    c_event['message'] = "Event ID: " + str(event['eventId']) + " collectors event"
                    c_event['eventId'] = event['eventId']
                    c_event['timestamp'] = event['timestamp']
                    extra_events.append(c_event)
                del event['collectors']

        total_events = events + extra_events
        return total_events

    def ensilo_getSystemEvents(self):
        params = {'fromDate':self.last_run, 'toDate':self.current_run}
        response = self.ensilo_request('/management-rest/system-events/list-system-events', params = params)
        return response.json()


    def ensilo_request(self, path, params = None, verify=False, proxies=None):
        url = self.url + path
        self.ds.log('INFO', "Attempting to connect to url: " + url + " with params: " + json.dumps(params))
        self.ds.log('INFO', "Attempting to connect to url: " + url)
        try:
            if self.token == None:
                self.ds.log('INFO', "No token.  Performing basic auth")
                if params == None:
                    response = requests.get(url, auth=(self.username, self.password), verify=verify, proxies=proxies)
                else:
                    response = requests.get(url, auth=(self.username, self.password), params = params, verify=verify, proxies=proxies)
            else:
                headers = {'X-Auth-Token': self.token}
                response = requests.get(url, headers=headers, params = params, timeout=15,
                                    verify=verify, proxies=proxies)
        except Exception as e:
            self.ds.log('ERROR', "Exception in ensilo_request: {0}".format(str(e)))
            return None
        if not response or response.status_code != 200:
            self.ds.log('ERROR', "Received unexpected " + str(response) + " response from enSilo Server {0}.".format(url))
            self.ds.log('ERROR', "Exiting due to unexpected response.")
            sys.exit(0)
        return response



    def ensilo_main(self): 

        self.url = self.ds.config_get('ensilo', 'server_url')
        self.auth_method = self.ds.config_get('ensilo', 'auth_method')
        self.state_dir = self.ds.config_get('ensilo', 'state_dir')
        self.last_run = self.ds.get_state(self.state_dir)
        self.time_offset = int(self.ds.config_get('ensilo', 'time_offset'))
        self.timezone = self.ds.config_get('ensilo', 'timezone')
        self.pytz_timezone = pytz.timezone(self.timezone)
        self.time_format = "%Y-%m-%d %H:%M:%S"
        current_time = time.time()
        utc_tz = pytz.timezone("UTC")
        self.tz_offset = self.pytz_timezone.localize(datetime.utcfromtimestamp(current_time)).strftime("%z")
        if self.last_run == None:
            dt_last_run = datetime.utcfromtimestamp(60 * ((current_time - ((self.time_offset + 900) * 60)) // 60))
            dt_last_run = utc_tz.localize(dt_last_run)
            dt_last_run = dt_last_run.astimezone(self.pytz_timezone)
            self.last_run = dt_last_run.strftime(self.time_format)
        dt_current_run = utc_tz.localize(datetime.utcfromtimestamp(current_time - (self.time_offset * 60)))
        dt_current_run = dt_current_run.astimezone(self.pytz_timezone)
        self.current_run = dt_current_run.strftime(self.time_format)

        if self.auth_method == 'basic':
            self.token = None
            self.username = self.ds.config_get('ensilo', 'username')
            self.password = self.ds.config_get('ensilo', 'password')
            self.token = self.ensilo_basicAuth()
            if self.token != None and self.get_token == True:
                print("Token - " + self.token)
                return None
        elif self.auth_method == 'token':
            self.token = self.ds.config_get('ensilo', 'token')
        else:
            self.ds.log('ERROR', "Invalid Configuration - 'auth_method'")
            return None

        if self.token == None or self.token == '':
            self.ds.log('ERROR', "Invalid Configuration or auth failed.  No token available")
            return None


        events = self.ensilo_getEvents()

        system_events = self.ensilo_getSystemEvents()

        if events == None:
            self.ds.log('INFO', "There are no event logs to send")
        else:
            self.ds.log('INFO', "Sending {0} event logs".format(len(events)))
            for log in events:
                self.ds.writeJSONEvent(log, JSON_field_mappings = self.JSON_field_mappings, flatten = False)

        if system_events == None:
            self.ds.log('INFO', "There are no system event logs to send")
        else:
            self.ds.log('INFO', "Sending {0} system event logs".format(len(system_events)))
            for log in system_events:
                log['category'] = "system-events"
                self.ds.writeJSONEvent(log, JSON_field_mappings = self.system_JSON_field_mappings)


        self.ds.set_state(self.state_dir, self.current_run)
        self.ds.log('INFO', "Done Sending Notifications")


    def run(self):
        try:
            pid_file = self.ds.config_get('ensilo', 'pid_file')
            fp = open(pid_file, 'w')
            try:
                fcntl.lockf(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except IOError:
                self.ds.log('ERROR', "An instance of cb defense syslog connector is already running")
                # another instance is running
                sys.exit(0)
            self.ensilo_main()
        except Exception as e:
            traceback.print_exc()
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return
    
    def usage(self):
        print
        print(os.path.basename(__file__))
        print
        print('  No Options: Run a normal cycle')
        print
        print('  -t    Testing mode.  Do all the work but do not send events to GRID via ')
        print('        syslog Local7.  Instead write the events to file \'output.TIMESTAMP\'')
        print('        in the current directory')
        print
        print('  -l    Log to stdout instead of syslog Local6')
        print
        print('  -g    Authenticate to Get Token then exit')
        print
    
        print
    
    def __init__(self, argv):

        self.testing = False
        self.send_syslog = True
        self.ds = None
        self.get_token = None
    
        try:
            opts, args = getopt.getopt(argv,"htlg")
        except getopt.GetoptError:
            self.usage()
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                self.usage()
                sys.exit()
            elif opt in ("-t"):
                self.testing = True
            elif opt in ("-l"):
                self.send_syslog = False
            elif opt in ("-g"):
                self.get_token = True
    
        try:
            self.ds = DefenseStorm('ensiloEventLogs', testing=self.testing, send_syslog = self.send_syslog)
        except Exception as e:
            traceback.print_exc()
            try:
                self.ds.log('ERROR', 'ERROR: ' + str(e))
            except:
                pass


if __name__ == "__main__":
    i = integration(sys.argv[1:]) 
    i.run()
