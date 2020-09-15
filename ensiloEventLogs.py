#!/usr/bin/env python3

import sys,os,getopt
import traceback
import os
import fcntl
import json
import requests
import time
from datetime import datetime

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
        'date' : 'timestamp',
        'eventId' : 'event_id',
        'processPath' : 'process_path'
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
        response = self.ensilo_request('/management-rest/events/list-events', params = params)
        events = response.json()
        for event in events:
            if 'collectors' in event.keys():
                if len(event['collectors']) == 1:
                    event['collector_lastSeen'] = event['collectors'][0]['lastSeen']
                    event['collector_id'] = event['collectors'][0]['id']
                    event['device'] = event['collectors'][0]['device']
                    event['operatingSystem'] = event['collectors'][0]['operatingSystem']
                    event['macAddresses'] = event['collectors'][0]['macAddresses']
                    event['ip'] = event['collectors'][0]['ip']
                    event['collectorGroup'] = event['collectors'][0]['collectorGroup']
                    del event['collectors']
            if 'loggedUsers' in event.keys() and event['loggedUsers'] != None:
                if len(event['loggedUsers']) == 1:
                    event['user_name'] = event['loggedUsers'][0]
                    del event['loggedUsers']
        return events

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
            self.ds.log('WARNING', 
                    "Received unexpected " + str(response) + " response from enSilo Server {0}.".format(url))
            return None
        return response



    def ensilo_main(self): 

        self.url = self.ds.config_get('ensilo', 'server_url')
        self.auth_method = self.ds.config_get('ensilo', 'auth_method')
        self.state_dir = self.ds.config_get('ensilo', 'state_dir')
        self.last_run = self.ds.get_state(self.state_dir)
        self.time_offset = int(self.ds.config_get('ensilo', 'time_offset'))
        self.time_format = "%Y-%m-%d %H:%M:%S"
        current_time = time.time()
        if self.last_run == None:
            self.last_run = (datetime.utcfromtimestamp(60 * ((current_time - (self.time_offset * 10000)) // 60))).strftime(self.time_format)
        self.current_run = (datetime.utcfromtimestamp(current_time - self.time_offset)).strftime(self.time_format)

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
                log['message'] = "Event ID: " + str(log['eventId']) + " Process: " + log['process'] + " Action: " + log['action']
                log['category'] = "events"
                log['timestamp'] = log['lastSeen']
                self.ds.writeJSONEvent(log, JSON_field_mappings = self.JSON_field_mappings)

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
