#!/usr/bin/python
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

import sys
from ironbee_test_utils import *
import re
from urlparse import *
from optparse import OptionParser
from ironbee_test_file_parser import *
from ironbee_test_logging import *
from ironbee_test_apache_controller import *
import shutil

sub_n_rn=True
send_header=True
send_user_agent=True
send_connection_header=True

if __name__ == "__main__":
    parser = OptionParser()
    #host we will be testing
    parser.add_option("--host", dest="host", default="127.0.0.1",type="string", help="host we will be testing defaults to 127.0.0.1")
    #port on host to connect to
    parser.add_option("--port", dest="port", default=9931, type="int", help="port on the host we will be testing defaults to 9931")
    #Start Apache
    parser.add_option("--local-apache", dest="local_apache",action="store_true", default=False, help="If this option is specified it will start a local apache server using the ip address and port specified with --host --port options defaults to 127.0.0.1:9931")
    parser.add_option("--apache-vars", dest="apache_var_string",default="@CWD@:%s,@IRONBEE_TESTS_DIR@:%s/tests,@IRONBEE_CONF_TEMPLATE@:%s/apache_httpd_server_root/conf/ironbee.conf.in,@APACHE_HTTPD_CONF_TEMPLATE@:%s/apache_httpd_server_root/conf/httpd.conf.in,@IRONBEE_SERVERROOT_DIR@:%s/apache_httpd_server_root,@IRONBEE_LOGS_DIR@:%s/apache_httpd_server_root/logs,@IRONBEE_DOCROOT_DIR@:%s/apache_httpd_server_root/htdocs,@IRONBEE_COREDUMP_DIR@:%s/apache_httpd_server_root/tmp" % (os.getcwd(),os.getcwd(),os.getcwd(),os.getcwd(),os.getcwd(),os.getcwd(),os.getcwd(),os.getcwd()), type="string", help="List of variable replacements for use in conjunction with --local-apache. Defautls are @CWD@:%s,@IRONBEE_TESTS_DIR@:%s/tests,@IRONBEE_CONF_TEMPLATE@:%s/apache_httpd_server_root/conf/ironbee.conf.in,@APACHE_HTTPD_CONF_TEMPLATE@:%s/apache_httpd_server_root/conf/httpd.conf.in,@IRONBEE_SERVERROOT_DIR@:%s/apache_httpd_server_root,@IRONBEE_LOGS_DIR@:%s/apache_httpd_server_root/logs,@APXS_LIBEXECDIR@:/usr/lib/apache2/modules,@IRONBEE_DOCROOT_DIR@:%s/apache_httpd_server_root/htdocs,@IRONBEE_COREDUMP_DIR@:%s/apache_httpd_server_root/tmp" % (os.getcwd(),os.getcwd(),os.getcwd(),os.getcwd(),os.getcwd(),os.getcwd(),os.getcwd(),os.getcwd()))
    #The way in which we will send the request defaults to raw socket
    parser.add_option("--send-mode", dest="send_mode", default="raw_socket",type="string", help="how we send the request urllib, raw_socket,jnovak_send_rst_bad_chksum,jnovak_send_overlap_bad_chksum,jnovak_send_bogus_ecn_flags,jnovak_sequence_wrap,jnovak_multiple_syns,jnovak_rst_syn_again,jnovak_syn_pushflag,jnovak_syn_urgflag")
    #By default we normalize all payloads. This will send the raw payload without attempting to parse it.
    parser.add_option("--no-normalize", action="store_true", dest="normalize", default=False, help="we normalize all payloads. This will send the raw payload without attempting to parse it.")
    #Parse a buffer from cli and send this. you cannot use this and file mode at the same time.
    parser.add_option("--one-shot", dest="one_shot", type="string", help="send user specified request cannot use with file-glob and file-format options [\\r\\n\\t] are replaced with actual [\\r\\n\\t]")
    #Save all requests to a file
    parser.add_option("--save-requests", dest="save_requests", action="store_true", default=False, help="Save all request/responses to files default is False in format that can be read by raw")
    #Save all requests that we have send/recv failures for
    parser.add_option("--save-requests-on-fail", dest="save_requests_on_fail", action="store_false", default=True, help="Save all request/responses to files in format that can be read by raw on send/recv failues default is true")
    #Glob of test files
    parser.add_option("--file-glob", dest="file_glob", type="string", help="glob of files we will use as input")
    #Format of files we will be testing
    parser.add_option("--file-format", dest="file_format", type="string", help="type of file we will be processing mod_security_r,iristic_evasion,raw,pcap,ironbee_audit_log,ironbee_audit_log_index,ironbee_test_file,pcap2raw,tshark2raw")
    #File matching
    #parser.add_option("--output-re-match", dest="output_re_match", type="string", help="seperator is +=+= (<path>)+=+=(<format>)+=+=(<regex>)#=#=(<optional_regex>):+:+(<path2>)+=+=(<format>)+=+=(<regex>)#=#=(<optional_regex>) ex: apache_httpd_server_root/logs/error.log+=+=text+=+=example\.onEventConnDataIn\: GET \/index\.html HTTP\/1\.1\\\r\\\n")
    #File matching
    #parser.add_option("--output-in-match", dest="output_in_match", type="string", help="seperator is +=+= (<path>)+=+=(<format>)+=+=(<match>)#=#=(<optional_match_1>)#=#=(optional_match_2>) ex: apache_httpd_server_root/logs/error.log+=+=text+=+=example.onEventConnDataIn: GET /index.html HTTP/1.1")
    #Encodings to apply to the request specified as a list?
    #parser.add_option("--encode-request", dest="encode_request", type="string", help="type of encoding to use sha_encode,md5_encode,b64_encode,urlencode,html_escape,double_urlencode,hex_encoding,zero_x_encoding,double_percent_hex_encoding,double_nibble_hex_encoding,first_nibble_hex_encoding,second_nibble_hex_encoding,utf8_barebyte_encoding,utf8_encoding,msu_encoding,random_upper,random_lower,mysql_encode,mssql_encode")
    #Apply buffer overflow tests to parsed portions of the test file
    #parser.add_option("--botest", dest="botest", action="store_true", default=False, help="perform buffer overflow tests on parsed http requests")
    #Fuzz the selected requests
    #parser.add_option("--fuzz-eratio", dest="fuzz_eratio", type="string", help="error ratio to introduce into fuzz testing logic similar to editcap -E flag will be applied")
    #Select which portions of the request to fuzz
    #parser.add_option("--fuzz-portions", dest="fuzz_portions", type="string", help="portions of the parsed http request to fuzz options are method, uri, proto, proto version, request_line (made up of method,uri,proto,proto_version), header_(name), headers(a collection of all headers, http_data, http_parameter, all, random")
    #file logging level
    parser.add_option("--file-log-level", dest="file_log_level", default="debug", type="string", help="specify the level of messages you want see debug,warning,error,critical default is debug")
    #console logging level
    parser.add_option("--console-log-level", dest="console_log_level", default="debug", type="string", help="specify the level of messages you want see debug,warning,error,critical default is debug")
    parser.add_option("--no-host-header-replace", dest="replace_host_header", default=True, action="store_false", help="By default we replace the host header with what is provided via the --host option.  This option will use the host header from the original request")
    #Optional BPF to apply when parsing pcaps
    parser.add_option("--pcap-bpf", dest="pcap_bpf", help="If parsing a pcap file, optionally apply user supplied bpf")

    #Exit if we encounter a parsing error. Other wise default is to attempt to send request we could not parse.
    parser.add_option("--exit-on-parse-error", default=False, action="store_true",dest="exit_on_parse_error", help="By default we will send the request and show response even if we have parsing problems. This will force an exit on a HTTP parsing error.")
    #If using the nikto2 db we need the vars file as well
    parser.add_option("--nikto2-vars-file", dest="nikto2_vars_file", type="string", help="you must specify the path to the nikto2 variable file usually called db_variables")
    #If using ironbee_test_format this will limit the tests we run to the user specified regex
    parser.add_option("--ironbee-test-regex",dest="ironbee_test_regex", default=None, help="regex of test id's you want to include otherwise all tests are run")

    #Optional BPF to apply when parsing pcaps
    parser.add_option("--convert-2-raw-parts", dest="convert_2_raw_parts", help="optional list of parts you want to print when converting from some other format to raw. avaliable options are request,response, request_line, request_method,")

    #Path to IronBee cli tool
    parser.add_option("--ibcli-bin", dest="ibcli_bin", type="string", help="path the the ironbee cli tool")

    #IronBee cli config
    parser.add_option("--ibcli-conf", dest="ibcli_conf", type="string", help="path to the ironbee config file to use with the IronBee cli tool")
 
    #parse the opts
    (options, args) = parser.parse_args()
    
    options.log = setup_logger(options.file_log_level,options.console_log_level)
    
    #Global options for matching
    options.match_types = ['simple','simple_negated','re','re_negated']
    options.response_match_types = ['status','proto','version','http_stat_code','http_stat_msg','headers','body','raw_response','status_line']    
    options.file_match_types = ['text','ironbee_audit_log_index']
    
    if options.local_apache:
        apache_start(options)
        
    #Do optional output matching
    #if options.output_re_match or options.output_in_match:
    #    parse_output_match_string(options)
    #else:
    #     options.file_matcher_dict = None
    #     options.match_list = None

    master_results_list = []
    #ironbee_test_results = deepdict()
    ironbee_test_results = {} 
    ivanr_test_results = deepdict()
 
    #support user specified request via cli.. "I said across her nose not up it..."
    if options.one_shot:
        payload = options.one_shot.replace('\\n', '\n')
        payload = payload.replace('\\r', '\r')
        payload = payload.replace('\\t', '\t')
        payload = payload.replace('\\f', '\f')
        payload = payload.replace('\\v', '\v')
        
        request = parse_payload(options,options.host,options.port,payload,options.normalize)
        parsed_response = send_request(options,request)

    #    if options.file_matcher_dict:
    #        do_file_matching(options)
        for response_part in parsed_response:
            options.log.debug("%s:\n\t%s" % (response_part,parsed_response[response_part]))
            
            if options.local_apache:
                apache_check_for_core(options) 
        
    elif options.file_glob:
        glob_list = glob_2_file_list(options.file_glob)
        if len(glob_list) > 0:
            for test in glob_list:
                options.log.debug("working with file %s" % (test))
                rules=deepdict()
                fp = FileParser()
              
                #support Ivans Evasion tests
                if options.file_format == "iristic_evasion":
                    (payload,rules) = fp.ivan_evasion_test(test)
                    request = parse_payload(options,options.host,options.port,payload,options.normalize)
                    parsed_response = send_request(options,request)
    
                    #Do we have any file matches to perform?  If so pull the buffer and incriment the position.
                    #if options.file_matcher_dict:
                    #     do_file_matching(options)
      
                    for response_part in parsed_response:
                        options.log.debug("%s:\n\t%s" % (response_part,parsed_response[response_part]))
                                       
                    for rule in rules:
                        if rule['location'] != None:
                            if rule.has_key('regex_obj'):
                                if rule.has_key('location') and rule['location'] == 'RESPONSE_STATUS':
                                    if rule['regex_obj'].search(parsed_response['status']) != None:
                                        ivanr_test_results[test]['result'] = rule['result']
                                        options.log.debug("file:%s result:%s pattern:%s match:%s" % (test,rule['result'],rule['regex'],parsed_response['status']))
                                        break
                                elif rule.has_key('location') and rule['location'] == 'RESPONSE_BODY':
                                    if rule['regex_obj'].search(parsed_response['body']) != None:
                                        ivanr_test_results[test]['result'] = rule['result']
                                        options.log.debug("file:%s result:%s pattern:%s match:%s" % (test,rule['result'],rule['regex'],parsed_response['body']))
                                        break 
                                else:
                                    options.log.error('Unknown location %s' % (rule['location']))
                                    break
                            else:
                                options.log.error('had a rule but no regex skipping rule')
                                break
                        else:
                            ivanr_test_results[test]['result'] = rule['result']
                            log.options.debug("file:%s result:%s pattern:none match:none" % (test,rule['result']))
                            break        
                    if options.local_apache:
                        apache_check_for_core(options)
                        
                elif options.file_format == "ironbee_audit_log":
                    audit_log_dict = fp.parse_ironbee_multi_part_mime(options,test)
                    request = parse_payload(options,options.host,options.port,audit_log_dict['http-request-headers']['body_buffer'],options.normalize)
                    parsed_response = send_request(options,request)
    
                    for response_part in parsed_response:
                       options.log.debug("%s:\n\t%s" % (response_part,parsed_response[response_part]))
                       
                    if options.local_apache:
                        apache_check_for_core(options)
                        
                elif options.file_format == "ironbee_audit_log_index":
                    audit_log_index = fp.parse_ironbee_audit_log_index(options,test)
                    for audit_log_file in audit_log_index:
                        audit_log_dict = fp.parse_ironbee_multi_part_mime(options,audit_log_file)
                        request = parse_payload(options,options.host,options.port,audit_log_dict['http-request-headers']['body_buffer'],options.normalize)
                        parsed_response = send_request(options,request)

                        for response_part in parsed_response:
                           options.log.debug("%s:\n\t%s" % (response_part,parsed_response[response_part]))
                           
                        if options.local_apache:
                            apache_check_for_core(options)
                            
                elif options.file_format == "pcap":
                    stream_dict = fp.parse_pcap(options,test)
                    #try to deal with pipelined requests
                    i = 0
                    for stream in stream_dict:
                        for request in stream_dict[i]['request_list']:
                            if request != None:
                                parsed_request = parse_payload(options,options.host,options.port,request,options.normalize)
                                parsed_response = send_request(options,parsed_request)
                        
                                for response_part in parsed_response:
                                    options.log.debug("%s:\n\t%s" % (response_part,parsed_response[response_part]))
                            
                                if options.local_apache:
                                    apache_check_for_core(options)
                        i = i + 1

                elif options.file_format == "pcap2raw":
                    stream_list = fp.parse_pcap(options,test)
                    for stream in stream_list:
                         request_list_len = len(stream['request_list'])
                         response_list_len = len(stream['response_list'])

                         if(request_list_len == response_list_len):
                             merged = open('%s.merged.raw' % (stream['file_format']) , 'w')

                             i = 0
                             while i < request_list_len:
                                 request = open('%s.request.%s.raw' % (stream['file_format'], i) , 'w')
                                 request.write(stream['request_list'][i])
                                 merged.write(stream['request_list'][i])
                                 request.close()

                                 response = open('%s.response.%s.raw' % (stream['file_format'], i) , 'w')
                                 response.write(stream['response_list'][i])
                                 merged.write(stream['response_list'][i])
                                 response.close()
                                 i = i + 1

                             merged.close()

                         else:
                             print "WARNING!!! there is a mis-match between requests and responses in stream %s\n" % (stream['num'])
                             #requests
                             i = 0
                             while i < request_list_len:
                                 f = open('%s.request.%s.raw' % (stream['file_format'], i) , 'w')
                                 f.write(stream['request_list'][i])
                                 f.close()
                                 i = i + 1

                             #responses                             
                             i = 0
                             while i < response_list_len:
                                 f = open('%s.response.%s.raw' % (stream['file_format'], i) , 'w')
                                 f.write(stream['response_list'][i])
                                 f.close()
                                 i = i + 1

                elif options.file_format == "pcap2ibcli":
                    if options.ibcli_bin == None:
                        options.log.error("You must specify a path to the IronBee cli tool via --ibcli-bin") 
                        sys.exit(-1)

                    if options.ibcli_conf == None:
                        options.log.error("You must specify a path to the IronBee cli tool via --ibcli-conf") 
                        sys.exit(-1)
 
                    stream_list = fp.parse_pcap(options,test)
                    for stream in stream_list:
                         request_list_len = len(stream['request_list'])
                         response_list_len = len(stream['response_list'])

                         if(request_list_len == response_list_len):
                             i = 0
                             while i < request_list_len:
                                 #request
                                 f = open('tmp.request.raw', 'w')
                                 f.write(stream['request_list'][i])
                                 f.close()
                                 #response
                                 f = open('tmp.response.raw', 'w')
                                 f.write(stream['response_list'][i])
                                 f.close()

                                 (returncode, stdout, stderr) = cmd_wrapper(options, "ulimit -c unlimited; %s --conf %s --request=tmp.request.raw --response=tmp.response.raw" % (options.ibcli_bin, options.ibcli_conf), False)
                                 options.log.debug(stderr)
                                 core_dump = check_for_core_dumps(options,'%s/core*' % (os.getcwd()))
                                 if core_dump != None:
                                     process_core_dump(options, core_dump, options.ibcli_bin, stream['file_format'])
                                     shutil.move("tmp.request.raw","%s.coredump.request.raw" % (stream['file_format']))
                                     shutil.move("tmp.response.raw","%s.coredump.response.raw" % (stream['file_format']))
                                 i = i + 1


                elif options.file_format == "tshark":
                    stream_list = fp.tshark_parse_pcap(options,test)
                    for stream in stream_list:
                        for request in stream['request_list']:
                            if request != None:
                                parsed_request = parse_payload(options,options.host,options.port,request,options.normalize)
                                parsed_response = send_request(options,parsed_request)

                                for response_part in parsed_response:
                                    options.log.debug("%s:\n\t%s" % (response_part,parsed_response[response_part]))

                                if options.local_apache:
                                    apache_check_for_core(options)

                elif options.file_format == "tshark2raw":
                    stream_list = fp.tshark_parse_pcap(options,test)
                    for stream in stream_list:
                         request_list_len = len(stream['request_list'])
                         response_list_len = len(stream['response_list'])

                         if(request_list_len == response_list_len):
                             #merged request/response raw
                             merged = open('%s.merged.raw' % (stream['file_format']) , 'w')

                             i = 0
                             while i < request_list_len:
                                 request = open('%s.request.%s.raw' % (stream['file_format'], i) , 'w')
                                 request.write(stream['request_list'][i])
                                 merged.write(stream['request_list'][i])
                                 request.close()
                                 
                                 response = open('%s.response.%s.raw' % (stream['file_format'], i) , 'w')
                                 response.write(stream['response_list'][i])
                                 merged.write(stream['response_list'][i])
                                 response.close()
                                 i = i + 1 
                                  
                             merged.close()

                         else:
                             options.log.error("WARNING!!! there is a mis-match between requests and responses in stream %s\n" % (stream['num']))                      
                             #requests
                             i = 0
                             while i < request_list_len:
                                 f = open('%s.request.%s.raw' % (stream['file_format'], i) , 'w')
                                 f.write(stream['request_list'][i])
                                 f.close()
                                 i = i + 1

                             #responses                             
                             i = 0
                             while i < response_list_len:
                                 f = open('%s.response.%s.raw' % (stream['file_format'], i) , 'w')
                                 f.write(stream['response_list'][i])
                                 f.close()
                                 i = i + 1
                         
                elif options.file_format == "raw":
                        request = fp.parse_raw_request_from_file(options,test)
                           
                        parsed_request = parse_payload(options,options.host,options.port,request,options.normalize)
                        parsed_response = send_request(options,parsed_request)
                        
                        for response_part in parsed_response:
                            options.log.debug("%s:\n\t%s" % (response_part,parsed_response[response_part])) 
                        
                        if options.local_apache:
                            apache_check_for_core(options) 
                             
                elif options.file_format == "modsec_audit_log":
                        modsec_req_dict = fp.modsec_audit_log(test)
                        for txid in modsec_req_dict:
                            parsed_request = parse_payload(options,options.host,options.port,modsec_req_dict[txid],options.normalize)
                            parsed_response = send_request(options,parsed_request)
                        
                            for response_part in parsed_response:
                                options.log.debug("%s:\n\t%s" % (response_part,parsed_response[response_part]))
                                
                            if options.local_apache:
                                apache_check_for_core(options) 
                                
                elif options.file_format == "ironbee_test_file":
                    ironbee_test_dict = fp.ironbee_test_file(options,test)
                    for test_entry in ironbee_test_dict:
                        save_apache_var_string = "" 
                         
                        #Read the request       
                        if ironbee_test_dict[test_entry].has_key('raw_request_from_file'):
                            ironbee_test_dict[test_entry]['raw_request'] = fp.parse_raw_request_from_file(options,ironbee_test_dict[test_entry]['raw_request_from_file'])
                        elif ironbee_test_dict[test_entry].has_key('raw_request'):
                            ironbee_test_dict[test_entry]['raw_request'] = ''.join(ironbee_test_dict[test_entry]['raw_request'])
                        else:
                            options.log.error('currently we only support two request types raw_request and raw_request_from_file you provided neither')
                            sys.exit(-1)
                        
                        #Get our current file position from stuff we match on later    
                        parsed_request = parse_payload(options,options.host,options.port,ironbee_test_dict[test_entry]['raw_request'],ironbee_test_dict[test_entry]['normalize'])
                        if ironbee_test_dict[test_entry]['matches'].has_key('file_matches'):
                            for file_match in ironbee_test_dict[test_entry]['matches']['file_matches']:
                                if os.path.exists(file_match):
                                    ironbee_test_dict[test_entry]['matches']['file_matches'][file_match]['position'] = get_file_size(file_match)
                                else:
                                    ironbee_test_dict[test_entry]['matches']['file_matches'][file_match]['position'] = 0

                        #Deal with local Apache stuff
                        if ironbee_test_dict[test_entry].has_key('local_apache'):
                            if options.local_apache:
                                apache_stop(options)
                            if ironbee_test_dict[test_entry]['local_apache'].has_key('apache_vars'):
                                save_apache_var_string = options.apache_var_string
                                options.apache_var_string = ironbee_test_dict[test_entry]['local_apache']['apache_vars']
                            apache_start(options)                        
                        
                        #Send that badboy        
                        parsed_response = send_request(options,parsed_request)
                       
                        #Do some matching
                        ironbee_test_results[test_entry] = {}
                        ironbee_test_results[test_entry]['result'] = True
                        ironbee_test_results[test_entry]['description'] = ironbee_test_dict[test_entry]['description']
                        ironbee_test_results[test_entry]['id'] = test_entry 
                        if ironbee_test_dict[test_entry]['matches'].has_key('file_matches'):
                            for file_match in ironbee_test_dict[test_entry]['matches']['file_matches']:
                                if os.path.exists(file_match):
                                    (ironbee_test_dict[test_entry]['matches']['file_matches'][file_match]['file_contents'],ironbee_test_dict[test_entry]['matches']['file_matches'][file_match]['position']) = read_file_from_offset_and_update(options,file_match,ironbee_test_dict[test_entry]['matches']['file_matches'][file_match]['position'])
                                    if ironbee_test_dict[test_entry]['matches']['file_matches'][file_match]['format'] == "ironbee_audit_log_index":
                                        tmp_file = fp.file_from_audit_log_index_line(options,file_match,ironbee_test_dict[test_entry]['matches']['file_matches'][file_match]['file_contents'])
                                        ironbee_test_dict[test_entry]['matches']['file_matches'][file_match]['ironbee_audit_log_real'] = tmp_file
                                        try:
                                            ironbee_test_dict[test_entry]['matches']['file_matches'][file_match]['file_contents'] = open(tmp_file).read()
                                        except:
                                            #if we fail to read file maybe we should just set to nothing
                                            
                                            #ironbee_test_results[test_entry]['result'] = False
                                            #ironbee_test_results[test_entry]['failure_reason'] = "failed to read audit_log from file %s using index of %s" % (tmp_file,file_match)
                                                                                        #Restart Apache
                                            #if ironbee_test_dict[test_entry].has_key('local_apache'):
                                            #    apache_reset_and_restart(options,save_apache_var_string)
                                            #break
                                            options.log.error("failed to read from audit_log file %s" % (tmp_file))
                                            ironbee_test_dict[test_entry]['matches']['file_matches'][file_match]['file_contents'] = ""
                                                                                         
                                    for type in options.match_types:
                                       if ironbee_test_dict[test_entry]['matches']['file_matches'][file_match].has_key(type):
                                           for match in ironbee_test_dict[test_entry]['matches']['file_matches'][file_match][type]:
                                               
                                               options.log.debug("%s %s %s" % (ironbee_test_dict[test_entry]['matches']['file_matches'][file_match]['file_contents'],match,type))
                                               if do_buff_match(options,ironbee_test_dict[test_entry]['matches']['file_matches'][file_match]['file_contents'],match,type) == True:
                                                   options.log.debug("match of %s found in %s" % (match,file_match))
                                               else:
                                                   ironbee_test_results[test_entry]['result'] = False
                                                   if ironbee_test_dict[test_entry]['matches']['file_matches'][file_match].has_key('ironbee_audit_log_real'):
                                                       
                                                       ironbee_test_results[test_entry]['failure_reason'] = "failed to match %s:%s needed by test %s in file %s" % (match,type,file_match,ironbee_test_dict[test_entry]['matches']['file_matches'][file_match]['ironbee_audit_log_real'])
                                                   else:
                                                       ironbee_test_results[test_entry]['failure_reason'] = "failed to match %s:%s needed by test %s in file %s" % (match,type,file_match,test_entry)
                                                   
                                                   #Restart Apache
                                                   if ironbee_test_dict[test_entry].has_key('local_apache'):
                                                       apache_reset_and_restart(options,save_apache_var_string)
                                                   break                                                         
                                else:
                                    ironbee_test_results[test_entry]['result'] = False
                                    ironbee_test_results[test_entry]['failure_reason'] = "failed to find file %s needed by test %s" % (file_match,test_entry)
                                    
                                    #Restart Apache
                                    if ironbee_test_dict[test_entry].has_key('local_apache'):
                                        apache_reset_and_restart(options,save_apache_var_string)
                                    break
                                
                        if ironbee_test_dict[test_entry]['matches'].has_key('response_matches'):
                            for response_part in ironbee_test_dict[test_entry]['matches']['response_matches']:
                                if parsed_response.has_key(response_part):
                                    for type in options.match_types:
                                        if ironbee_test_dict[test_entry]['matches']['response_matches'][response_part].has_key(type):
                                            for match in ironbee_test_dict[test_entry]['matches']['response_matches'][response_part][type]:
                                                    if do_buff_match(options,parsed_response[response_part],match,type) == True:
                                                         options.log.debug("match of %s found in %s" % (match,response_part))
                                                    else:
                                                         ironbee_test_results[test_entry]['result'] = False
                                                         ironbee_test_results[test_entry]['failure_reason'] = "failed to match %s:%s needed by test %s in response_part %s" % (match,type,response_part,test_entry)
                                                        
                                                         #Restart Apache
                                                         if ironbee_test_dict[test_entry].has_key('local_apache'):
                                                             apache_reset_and_restart(options,save_apache_var_string)
                                                         break                                                                                                
                                else:
                                    ironbee_test_results[test_entry]['result'] = False
                                    ironbee_test_results[test_entry]['failure_reason'] = "failed to find response_part %s needed by test %s" % (response_part,test_entry)
                                   
                                    #Restart Apache
                                    if ironbee_test_dict[test_entry].has_key('local_apache'):
                                        apache_reset_and_restart(options,save_apache_var_string)
                                    break
                        #Restart Apache
                        if ironbee_test_dict[test_entry].has_key('local_apache'):
                            apache_reset_and_restart(options,save_apache_var_string)
                                                              
                        for response_part in parsed_response:
                            options.log.debug("%s:\n\t%s" % (response_part,parsed_response[response_part]))   
                                          
                elif options.file_format == "nikto2_db":
                    if options.nikto2_vars_file == None:
                        options.log.error("you must specify the path to the nikto2 variable file usually called db_variables")
                        sys.exit(-1)
                    else:
                        options.nikto_vars_parsed = fp.nikto2_vars(options.nikto2_vars_file)
                         
                    nikto_db = fp.nikto2_db(options,test)
                    for nikto_req in nikto_db:
                        request = "%s %s HTTP/1.0\r\n" % (nikto_req['http_method'],nikto_req['http_uri'])
                        
                        if nikto_req['http_headers'] != None:
                            request = request + nikto_req['http_headers'] + '\r\n'
                        
                        if nikto_req['http_data'] != None:
                            request = request + nikto_req['http_data']
                            
                        parsed_request = parse_payload(options,options.host,options.port,request,True)
                        parsed_response = send_request(options,parsed_request)

                        if options.local_apache:
                           apache_check_for_core(options)
 
                        #for response_part in parsed_response:
                            #options.log.debug("%s:\n\t%s" % (response_part,parsed_response[response_part]))
                        if nikto_req['match'] in parsed_response['raw_response']:
                            options.log.debug("match:%s summary:%s" % (nikto_req['match'],nikto_req['summary']))
                else:
                    options.log.error("unsupported test type exiting")
                    sys.exit(-1)
        else:
            options.log.error("The --file-glob option %s did not match any files" % (options.file_glob))
            sys.exit(-1)               
    else:
        options.log.error("You must specify a set of test files via the --file-glob option")
        sys.exit(-1)

    #If we have ironbee_test_results print them        
    if len(ironbee_test_results) > 0:    
        ironbee_test_cntr = {}
        print "\n"
        print "IronBee Test Results".center(60, '=')
        for test_entry in ironbee_test_results:
            if not  ironbee_test_cntr.has_key('pass_cnt'):
                ironbee_test_cntr['pass_cnt'] = 0
                ironbee_test_cntr['fail_cnt'] = 0
            if ironbee_test_results[test_entry]['result'] == True:
                print ("%s:%s" % (test_entry,ironbee_test_results[test_entry]['description'])).ljust(40, ' '),"[ pass ]"
                ironbee_test_cntr['pass_cnt'] =  ironbee_test_cntr['pass_cnt'] + 1 
                
            elif ironbee_test_results[test_entry]['result'] == False:
                print ("%s:%s" % (test_entry,ironbee_test_results[test_entry]['description'])).ljust(40, ' '),"[ fail ]:%s" % ironbee_test_results[test_entry]['failure_reason']
                ironbee_test_cntr['fail_cnt'] =  ironbee_test_cntr['fail_cnt'] + 1
    
        if ironbee_test_cntr.has_key('pass_cnt'):
            print "Summary".center(60, '=') 
            print "Pass".ljust(40, ' '),ironbee_test_cntr['pass_cnt']
            print "Fail".ljust(40, ' '),ironbee_test_cntr['fail_cnt']       
    
    #If we have ivanr_test_results print them
    if len(ivanr_test_results) > 0:    
        print "IvanR Test Results".center(60, '=')
        for test_entry in ivanr_test_results:
            print ("%s" % (test_entry)).ljust(40, ' '),"[ %s ]" % (ivanr_test_results[test_entry]['result'])
        print "IvanR Test Results".center(60, '=')                       
    #if options.match_list:
    #    options.log.debug("match results\n")
    #    for line in options.match_list:
    #        options.log.debug(line)

    if options.local_apache:
        apache_stop(options)
        
    options.log.debug("done")
