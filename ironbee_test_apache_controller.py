# -*- coding: utf-8 -*-
#############################################################################
##                                                                         ##
## Licensed to Qualys, Inc. (QUALYS) under one or more                     ##
## contributor license agreements.  See the NOTICE file distributed with   ##
## this work for additional information regarding copyright ownership.     ##
## QUALYS licenses this file to You under the Apache License, Version 2.0  ##
## (the "License"); you may not use this file except in compliance with    ##
## the License.  You may obtain a copy of the License at                   ##
##                                                                         ##
##     http://www.apache.org/licenses/LICENSE-2.0                          ##  
##                                                                         ##
## Unless required by applicable law or agreed to in writing, software     ##
## distributed under the License is distributed on an "AS IS" BASIS,       ##
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.##
## See the License for the specific language governing permissions and     ##
## limitations under the License.                                          ##
#############################################################################
 
from ironbee_test_utils import *
import time
import signal
import shutil
import glob

def parse_apache_base_config(options,file):
    new_lines = []
    
    try:
        lines = open(file, "r").readlines()
    except:
        options.log.error("failed to parse file %s" % (file))
        sys.exit(-1)
    for line in lines:
        for key in options.apache_vars:
            if key in line:
                line = line.replace(key, options.apache_vars[key])
                options.log.debug("replacing %s with %s" % (key,options.apache_vars[key]))
        new_lines.append(line)

    try:
        options.apache_vars['@APACHE_HTTPD_CONF@'] = file.replace('.in','')
        fh = open(options.apache_vars['@APACHE_HTTPD_CONF@'], "w").writelines(new_lines)
    except:
        options.log.error("could not open http.conf output file %s" % (options.apache_vars['@APACHE_CONF@']))
        sys.exit(-1)

def parse_ironbee_base_config(options,file):
    new_lines = []

    try:
        lines = open(file, "r").readlines()
    except:
        options.log.error("failed to parse file %s" % (file))
        sys.exit(-1)
    for line in lines:
        for key in options.apache_vars:
            if key in line:
                line = line.replace(key, options.apache_vars[key])
                options.log.debug("replacing %s with %s" % (key,options.apache_vars[key]))
        new_lines.append(line)

    try:
        options.apache_vars['@IRONBEE_CONF@'] = file.replace('.in','')
        fh = open(options.apache_vars['@IRONBEE_CONF@'], "w").writelines(new_lines)
    except:
        options.log.error("could not open ironbee.conf output file %s" % (options.apache_vars['@IRONBEE_CONF@']))
        sys.exit(-1)

def parse_apache_vars(options):
    options.log.debug('parsing apache var string %s' % (options.apache_var_string))
    options.apache_vars = {}
    tmp_apache_list = options.apache_var_string.split(",")
    
    tmp_apache_dict = {}

    for var_entry in tmp_apache_list:
        #var_entry = var_entry.replace(' ','')
        tmp_apache_list2 = var_entry.split(":")
        tmp_apache_dict[tmp_apache_list2[0].replace(' ','')] = tmp_apache_list2[1]

    #Current Working Dir
    if tmp_apache_dict.has_key('@CWD@'):
        options.apache_vars['@CWD@'] =  tmp_apache_dict['@CWD@']
    else:    
        options.apache_vars['@CWD@'] = "%s" % (os.getcwd())
           
    #Apache Server Root
    if tmp_apache_dict.has_key('@IRONBEE_SERVERROOT_DIR@'):
        options.apache_vars['@IRONBEE_SERVERROOT_DIR@'] =  tmp_apache_dict['@IRONBEE_SERVERROOT_DIR@']
    else:    
        options.apache_vars['@IRONBEE_SERVERROOT_DIR@'] = "%s/server_root" % (os.getcwd())

    #Apache Log Directory
    if tmp_apache_dict.has_key('@IRONBEE_LOGS_DIR@'):
        options.apache_vars['@IRONBEE_LOGS_DIR@'] =  tmp_apache_dict['@IRONBEE_LOGS_DIR@']
    else:
        options.apache_vars['@IRONBEE_LOGS_DIR@'] = options.apache_vars['@IRONBEE_SERVERROOT_DIR@'] + "/logs"

    #Apache Libexec Directory
    if tmp_apache_dict.has_key('@APXS_LIBEXECDIR@'):
        options.apache_vars['@APXS_LIBEXECDIR@'] =  tmp_apache_dict['@APXS_LIBEXECDIR@']
    else:
        options.apache_vars['@APXS_LIBEXECDIR@'] = "/usr/lib/apache2/modules"

    #Apache Document Root
    if tmp_apache_dict.has_key('@IRONBEE_DOCROOT_DIR@'):
        options.apache_vars['@IRONBEE_DOCROOT_DIR@'] =  tmp_apache_dict['@IRONBEE_DOCROOT_DIR@']
    else:
        options.apache_vars['@IRONBEE_DOCROOT_DIR@'] = options.apache_vars['@IRONBEE_SERVERROOT_DIR@'] + "/htdocs"

    #Ironbee coredump directory
    if tmp_apache_dict.has_key('@IRONBEE_COREDUMP_DIR@'):
        options.apache_vars['@IRONBEE_COREDUMP_DIR@'] =  tmp_apache_dict['@IRONBEE_COREDUMP_DIR@']
    else:
        options.apache_vars['@IRONBEE_COREDUMP_DIR@'] = options.apache_vars['@IRONBEE_SERVERROOT_DIR@'] + "/tmp"     
        
    #Ironbee test directory
    if tmp_apache_dict.has_key('@IRONBEE_TESTS_DIR@'):
        options.apache_vars['@IRONBEE_TESTS_DIR@'] =  tmp_apache_dict['@IRONBEE_TESTS_DIR@']
    else:
        options.apache_vars['@IRONBEE_TESTS_DIR@'] = options.apache_vars['@CWD@'] + "/tests"      

    #Ironbee DebugLogLevel 
    if tmp_apache_dict.has_key('@IRONBEE_DEBUG_LOG_LEVEL@'):
        options.apache_vars['@IRONBEE_DEBUG_LOG_LEVEL@'] =  tmp_apache_dict['@IRONBEE_DEBUG_LOG_LEVEL@']
    else:
        options.apache_vars['@IRONBEE_DEBUG_LOG_LEVEL@'] = "4"

    #Ironbee SensorId 
    if tmp_apache_dict.has_key('@IRONBEE_SENSOR_ID@'):
        options.apache_vars['@IRONBEE_SENSOR_ID@'] =  tmp_apache_dict['@IRONBEE_SENSOR_ID@']
    else:
        options.apache_vars['@IRONBEE_SENSOR_ID@'] = "AAAABBBB-1111-2222-3333-FFFF00000023"

    #Ironbee SensorName 
    if tmp_apache_dict.has_key('@IRONBEE_SENSOR_NAME@'):
        options.apache_vars['@IRONBEE_SENSOR_NAME@'] =  tmp_apache_dict['@IRONBEE_SENSOR_NAME@']
    else:
        options.apache_vars['@IRONBEE_SENSOR_NAME@'] = "ExampleSensorName"

    #Ironbee LuaLoadModule
    if tmp_apache_dict.has_key('@IRONBEE_LUA_LOAD_MODULE@'):
        options.apache_vars['@IRONBEE_LUA_LOAD_MODULE@'] = tmp_apache_dict['@IRONBEE_LUA_LOAD_MODULE@']
    else:
        options.apache_vars['@IRONBEE_LUA_LOAD_MODULE@'] = "\"example.lua\"" 

    #Ironbee SensorName 
    if tmp_apache_dict.has_key('@IRONBEE_SENSOR_HOSTNAME@'):
        options.apache_vars['@IRONBEE_SENSOR_HOSTNAME@'] =  tmp_apache_dict['@IRONBEE_SENSOR_HOSTNAME@']
    else:
        options.apache_vars['@IRONBEE_SENSOR_HOSTNAME@'] = "example.sensor.tld"

    #Ironbee AuditEngine 
    if tmp_apache_dict.has_key('@IRONBEE_AUDIT_ENGINE@'):
        options.apache_vars['@IRONBEE_AUDIT_ENGINE@'] =  tmp_apache_dict['@IRONBEE_AUDIT_ENGINE@']
    else:
        options.apache_vars['@IRONBEE_AUDIT_ENGINE@'] = "On"

    #Ironbee AuditLogIndex
    if tmp_apache_dict.has_key('@IRONBEE_AUDIT_LOG_INDEX@'):
        options.apache_vars['@IRONBEE_AUDIT_LOG_INDEX@'] =  tmp_apache_dict['@IRONBEE_AUDIT_LOG_INDEX@']
    else:
        options.apache_vars['@IRONBEE_AUDIT_LOG_INDEX@'] = "auditlog.log"

    #Ironbee AuditLogBaseDir
    if tmp_apache_dict.has_key('@IRONBEE_AUDIT_LOG_BASE_DIR@'):
        options.apache_vars['@IRONBEE_AUDIT_LOG_BASE_DIR@'] =  tmp_apache_dict['@IRONBEE_AUDIT_LOG_BASE_DIR@']
    else:
        options.apache_vars['@IRONBEE_AUDIT_LOG_BASE_DIR@'] = options.apache_vars['@IRONBEE_LOGS_DIR@'] + "/audit"

    #IronBee AuditLogSubDirFormat
    if tmp_apache_dict.has_key('@IRONBEE_AUDIT_LOG_SUB_DIR_FORMAT@'):
        options.apache_vars['@IRONBEE_AUDIT_LOG_SUB_DIR_FORMAT@'] =  tmp_apache_dict['@IRONBEE_AUDIT_LOG_SUB_DIR_FORMAT@']
    else:
        options.apache_vars['@IRONBEE_AUDIT_LOG_SUB_DIR_FORMAT@'] = "\"%Y%m%d-%H%M\""

    #IronBee AuditLogDirMode 
    if tmp_apache_dict.has_key('@IRONBEE_AUDIT_LOG_DIR_MODE@'):
        options.apache_vars['@IRONBEE_AUDIT_LOG_DIR_MODE@'] =  tmp_apache_dict['@IRONBEE_AUDIT_LOG_DIR_MODE@']
    else:
        options.apache_vars['@IRONBEE_AUDIT_LOG_DIR_MODE@'] = "0755"

    #IronBee AuditLogParts 
    if tmp_apache_dict.has_key('@IRONBEE_AUDIT_LOG_PARTS@'):
        options.apache_vars['@IRONBEE_AUDIT_LOG_PARTS@'] =  tmp_apache_dict['@IRONBEE_AUDIT_LOG_PARTS@']
    else:
        options.apache_vars['@IRONBEE_AUDIT_LOG_PARTS@'] = "minimal request -requestBody response -responseBody"

    #IronBee RequestBuffering
    if tmp_apache_dict.has_key('@IRONBEE_REQUEST_BUFFERING@'):
        options.apache_vars['@IRONBEE_REQUEST_BUFFERING@'] =  tmp_apache_dict['@IRONBEE_REQUEST_BUFFERING@']
    else:
        options.apache_vars['@IRONBEE_REQUEST_BUFFERING@'] = "On"

    #IronBee PoCSigTrace
    if tmp_apache_dict.has_key('@IRONBEE_POC_SIG_TRACE@'):
        options.apache_vars['@IRONBEE_POC_SIG_TRACE@'] =  tmp_apache_dict['@IRONBEE_POC_SIG_TRACE@']
    else:
        options.apache_vars['@IRONBEE_POC_SIG_TRACE@'] = "On"

    #IronBee Any Extra Config Directives
    if tmp_apache_dict.has_key('@IRONBEE_EXTRA@'):
        options.apache_vars['@IRONBEE_EXTRA@'] =  tmp_apache_dict['@IRONBEE_EXTRA@']
    else:
        options.apache_vars['@IRONBEE_EXTRA@'] = ""

    ############# Support Variable replacement for these two vars only#################
    #Apache config template
    if tmp_apache_dict.has_key('@APACHE_HTTPD_CONF_TEMPLATE@'):
        for key in options.apache_vars:
            if key in tmp_apache_dict['@APACHE_HTTPD_CONF_TEMPLATE@']:
                tmp_apache_dict['@APACHE_HTTPD_CONF_TEMPLATE@'] = tmp_apache_dict['@APACHE_HTTPD_CONF_TEMPLATE@'].replace(key,options.apache_vars[key])

        options.apache_vars['@APACHE_HTTPD_CONF_TEMPLATE@'] =  tmp_apache_dict['@APACHE_HTTPD_CONF_TEMPLATE@']
    else:
        options.apache_vars['@APACHE_HTTPD_CONF_TEMPLATE@'] = options.apache_vars['@IRONBEE_SERVERROOT_DIR@'] + "/conf/httpd.conf.in"

    #Ironbee config template
    if tmp_apache_dict.has_key('@IRONBEE_CONF_TEMPLATE@'):
        for key in options.apache_vars:
            if key in tmp_apache_dict['@IRONBEE_CONF_TEMPLATE@']:
                tmp_apache_dict['@IRONBEE_CONF_TEMPLATE@'] = tmp_apache_dict['@IRONBEE_CONF_TEMPLATE@'].replace(key,options.apache_vars[key])

        options.apache_vars['@IRONBEE_CONF_TEMPLATE@'] =  tmp_apache_dict['@IRONBEE_CONF_TEMPLATE@']
    else:
        options.apache_vars['@IRONBEE_CONF_TEMPLATE@'] = options.apache_vars['@IRONBEE_SERVERROOT_DIR@'] + "/conf/ironbee.conf.in"
           
def apache_start(options):
    options.log.debug("starting apache")
    parse_apache_vars(options)
    parse_ironbee_base_config(options,'%s' % options.apache_vars['@IRONBEE_CONF_TEMPLATE@'])
    parse_apache_base_config(options,'%s' % options.apache_vars['@APACHE_HTTPD_CONF_TEMPLATE@'])
    cmd = "ulimit -c unlimited; apache2 -d %s -f %s -c \"Listen %s:%s\" -k start" % (options.apache_vars['@IRONBEE_SERVERROOT_DIR@'],options.apache_vars['@APACHE_HTTPD_CONF@'],options.host,options.port)
    (returncode, stdout, stderr) = cmd_wrapper(options,cmd,False)
    time.sleep(2)
    if returncode != 0:
        options.log.error("failed to start apache exit code:%i stdout:%s stderr:%s" % (returncode,stdout,stderr))
        sys.exit(-1)
    else:
        options.apache_pid_file = options.apache_vars['@IRONBEE_LOGS_DIR@'] + "/httpd.pid"
        options.apache_pid = open(options.apache_pid_file).read()
        #just to be safe
        options.apache_pid = options.apache_pid.replace('\n','')
        options.log.debug("apache started with pid %s" % (options.apache_pid))

          
def apache_stop(options):
    if options.apache_pid:
        
        try:
            os.kill(int(options.apache_pid), 0)
        except OSError:
            options.log.error("apache process with pid of %s no longer running" % (options.apache_pid))
            return
            
        try:
            options.log.debug("stopping apache with pid %s" % (options.apache_pid))
            os.kill(int(options.apache_pid), signal.SIGTERM)
            time.sleep(2)
        except:
            options.log.error("could not stop apache process with pid of %s" % (options.apache_pid))  
    else:
        options.log.error("Could not find apache pid %s to stop it." % (options.apache_pid))
                          
def apache_restart(options):
    options.log.debug("restarting apache")
    apache_stop(options)
    apache_start(options)

def apache_reset_and_restart(options,apache_var_string):
    apache_stop(options)
    if options.local_apache:
       if apache_var_string != "":
           options.apache_var_string = apache_var_string
       apache_start(options)
       
def apache_check_for_core(options):
    if options.apache_vars.has_key('@IRONBEE_COREDUMP_DIR@'):
        core_file_list = glob.glob('%s/core*' % (options.apache_vars['@IRONBEE_COREDUMP_DIR@']))
        if len(core_file_list) == 1:
            core_file = core_file_list[0]
            f=open('gdb_commands.txt','w')
            f.write('set height 0\nset logging file %s.core.gdb.txt\nset logging on\nbt full\ninfo threads\nquit' % (options.current_req_id))
            f.close()
        
            cmd = "gdb -x gdb_commands.txt apache2 %s" % (core_file)   
            (returncode, stdout, stderr) = cmd_wrapper(options,cmd,False)
            time.sleep(2)
            if returncode != 0:
                options.log.error("failed to process coredump exit code:%i stdout:%s stderr:%s" % (returncode,stdout,stderr))
                return
            else:
                options.log.debug("moving core dump file %s to %s/%s.core" % (core_file,options.apache_vars['@CWD@'],options.current_req_id))
                shutil.move(core_file,"%s/%s.core" % (options.apache_vars['@CWD@'],options.current_req_id))
                return
        elif len(core_file_list) == 0:
            options.log.debug('checked for core dump in %s but none found' % (options.apache_vars['@IRONBEE_COREDUMP_DIR@']))
            return
        elif len(core_file_list) > 1:
            options.log.debug('more than one core dump found in %s, please remove old core dumps %s' % (options.apache_vars['@IRONBEE_COREDUMP_DIR@'],core_file_list))
            return
        
