#!/usr/bin/env python
# coding: utf-8

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
    callback: logstash
    type: notification
    author: Thomas Dupouy <moz@free.fr>
    short_description: Sends events to Logstash (ansible v2)
    description:
      - This callback will report facts and task events to Logstash https://www.elastic.co/products/logstash
    version_added: "1.0"
    requirements:
      - whitelisting in configuration
      - a running logstash instance without authentication
    options:
      server:
        description: Address of the Logstash server
        ini:
          - section: callback_logstash
            key: server
        env:
          - name: LOGSTASH_SERVER
        default: localhost
      port:
        description: Port on which logstash is listening
        ini:
          - section: callback_logstash
            key: port
        env:
          - name: LOGSTASH_PORT
        default: 5000
'''

EXAMPLES = '''
examples: >
    1. Enable callback plugin
    ansible.cfg:
        [defaults]
            callback_whitelist = logstash

    2. Setup logstash connection via environment variables or ansible.cfg
    environment variables:
        export LOGSTASH_SERVER=logstash.example.com
        export LOGSTASH_PORT=5000

    or same in ansible.cfg:
        [callback_logstash]
        server = logstash.example.com
        port = 5000

    3. Use the following logstash configuration
        input {
          tcp {
            port => 5000
            codec => json_lines
          }
        }
        
        filter {
          ruby { code => "event['log'] =  event['log'][0...100000] if event.get('log').to_s.length > 100000" }
        }
        
        output {
          elasticsearch {
            hosts => ["localhost:9200"]
            index => "ansible.%{+YYYY.MM.dd}"
            }
        }

'''

import os
import re
import json
import socket
import uuid
import pickle
from datetime import date, datetime
from ansible.plugins.callback import CallbackBase
from ansible.parsing.ajson import AnsibleJSONEncoder
from ansible.utils.display import Display
from ansible import constants as C

display = Display()

class CallbackModule(CallbackBase):

    CALLBACK_VERSION = 1.0
    CALLBACK_TYPE = 'aggregate'
    CALLBACK_NAME = 'logstash'
    CALLBACK_NEEDS_WHITELIST = True

    def __init__(self):
        super(CallbackModule, self).__init__()
        self.field = re.compile('^_[^_]')

    def set_options(self, task_keys=None, var_options=None, direct=None):
        super(CallbackModule, self).set_options(task_keys=task_keys, var_options=var_options, direct=direct)

        self.data = {
            'session': str(uuid.uuid4()),
            'user': os.getlogin()
        }

        try:
            server = self.get_option('server')
            port = int(self.get_option('port'))
        except KeyError as e:
            display.error(e)
            return
        
        try:
            # Open socket to logstash server
            # The connection will be closed by remote side after sending newline
            self.sock = socket.socket()
            self.sock.connect((server, port))
            self.connected = True
            display.banner("Logging to %s:%s" % (server, port))
        except ConnectionRefusedError:
            display.error("Cannot connect to %s:%s for logging" % (server, port))
            self.connected = False

    def collect_output(self, result):
        self._clean_results(result._result, result._task.action)
        self._handle_warnings(result._result)
        data = self.data.copy()
        data['task'] = result._task.get_name()
        data['host'] = result._host.get_name()

        failed_modules = result._result.get('failed_modules', None)
        if failed_modules:
            log = failed_modules['setup']
        else:
            log = result._result

        data['rc'] = log.get('rc', 0)
        stdout = log.get('stdout', '')
        stderr = log.get('stderr', '')
        module_stdout = log.get('module_stdout', '')
        module_stderr = log.get('module_stderr', '')
        msg = log.get('msg', '')
        data['log'] = ('\n'.join([repr(msg), stdout, stderr, module_stdout, module_stderr]).strip())
        _ = data.pop('stdout', None)
        _ = data.pop('stderr', None)
        _ = data.pop('module_stdout', None)
        _ = data.pop('module_stderr', None)
        _ = data.pop('msg', None)
        return data

    def send_output(self, msg):
        # Send json data through connected socket
        if self.connected:
            msg = json.dumps(msg, cls=AnsibleJSONEncoder)
            msg = msg.replace('\n', ' ')
            self.sock.sendall(msg.encode('utf-8'))
            self.sock.send('\n'.encode())

    def v2_playbook_on_start(self, playbook):
        self.data['playbook'] = os.path.basename(playbook._file_name)
        data = self.data.copy()
        data['task'] = 'Playbook start'
        self.send_output(data)

    def v2_playbook_on_stats(self, stats):
        """Display info about playbook statistics"""
        data = self.data.copy()
        data['task'] = 'Playbook end'
        summary = {}
        for h in sorted(stats.processed.keys()):
            summary[h] = stats.summarize(h)
        data['stdout'] = summary
        self.send_output(data)
        display.display("Session: %s" % (self.data['session']))

    def v2_runner_on_failed(self, result, ignore_errors=False):
        data = self.collect_output(result)
        data['status'] = 'failed'
        self.send_output(data)

    def v2_runner_on_ok(self, result):
        data = self.collect_output(result)
        data['status'] = 'success'
        self.send_output(data)

    def v2_runner_on_unreachable(self, result):
        data = self.collect_output(result)
        data['status'] = 'unreachable'
        data['rc'] = -1
        self.send_output(data)

