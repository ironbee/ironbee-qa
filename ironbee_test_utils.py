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

import socket
import sys
import urllib2
import urllib
from collections import defaultdict
from urlparse import *
from scapy.all import *
from Judy_Novak_Evasions import *
import random, time
import subprocess
import re
import StringIO
import gzip

def glob_2_file_list(glob_list):
    import glob
    glob_converted_to_list=[]
    tmp_list=glob_list.split(",")
    for glob_pre_expansion in tmp_list:
        tmp_glob = glob.glob(glob_pre_expansion)
        for file in tmp_glob:
            if file not in glob_converted_to_list:
                glob_converted_to_list.append(file)
    return glob_converted_to_list

def deepdict():
    return defaultdict(deepdict)

#encode using python quote encoding
def encode_quote(options,string):
    try:
        newstring = urllib.quote(string)
        return newstring
    except:
        return string
    
def encode_find_and_replace(options,payload):
    import AntiIDS
    antiids = AntiIDS.AntiIDS()
    import IronBeeEvasions 
    ib_evasions = IronBeeEvasions.IronBeeEvasions() 
    #AntiIDS stuff from WsFuzzer
    # mode 0 - Null method processing - Windows targets only 
    # mode 1 - random URI (non-UTF8) encoding
    # mode 2 - directory self-reference (/./)
    # mode 3 - premature URL ending
    # mode 4 - prepend long random string
    # mode 5 - fake parameter
    # mode 6 - TAB as request spacer
    # mode 7  - random case sensitivity - Windows targets only
    # mode 8 - directory separator (\) - Windows targets only
    # mode 9 - None 
    # mode 10 - URI (non-UTF8) encoding
    # mode 11 - Double Percent Hex Encoding - Windows targets only
    # mode 12 - Double Nibble Hex Encoding - Windows targets only
    # mode 13 - First Nibble Hex Encoding - Windows targets only
    # mode 14 - Second Nibble Hex Encoding - Windows targets only

    newpayload = payload
    
    for encode in re.finditer('\<ibt_encode\:(?P<encode_opt_string>[^\>]+)>(?P<encode_string>.+)\<\/ibt\_encode\>',newpayload,re.DOTALL):
        encode_opt_string = encode.group('encode_opt_string')
        encode_target_match = encode.group(0)
        encode_string = encode.group('encode_string')
        encode_options = encode_opt_string.split(',')     
        
        for option in encode_options:
            #Python Quote encoding
            if option == "quote":
                encode_string = urllib.quote(encode_string)
            elif option == "quote_plus":
                encode_string = urllib.quote_plus(encode_string)
            elif option == "rand_uri":
                encode_string = antiids.encode_anti_ids("1",encode_string)
            elif option == "dir_self_ref":
                encode_string = antiids.encode_anti_ids("2",encode_string)
            elif option == "premature_url_end":
                encode_string = antiids.encode_anti_ids("3",encode_string)
            elif option == "prepend_rand":
                encode_string = antiids.encode_anti_ids("4",encode_string)
            elif option == "fake_param":
                encode_string = antiids.encode_anti_ids("5",encode_string)
            elif option == "tab_as_space":
                encode_string = antiids.encode_anti_ids("6",encode_string)
            elif option == "dir_forward_space":
                encode_string = antiids.encode_anti_ids("5",encode_string)
            elif option == "uri":
                encode_string = antiids.encode_anti_ids("10",encode_string)
            elif option == "double_percent_hex":
                encode_string = antiids.encode_anti_ids("11",encode_string)                                                                      
            elif option == "double_nibble_hex":
                encode_string = antiids.encode_anti_ids("12",encode_string)
            elif option == "first_nibble_hex":
                encode_string = antiids.encode_anti_ids("13",encode_string)
            elif option == "second_nibble_hex":
                encode_string = antiids.encode_anti_ids("14",encode_string)
            elif option == "nfkc_sub":
                encode_string = ib_evasions.nfkc_sub(encode_string).encode('utf-8')
            elif option == "nfkd_sub":
                encode_string = ib_evasions.nfkd_sub(encode_string).encode('utf-8')
            else:
                options.log.error('Unknown encoding %s' % (option))
                                             
        newpayload = newpayload.replace(encode_target_match,encode_string,1)
        
    
    options.log.debug("old payload %s new payload %s" % (payload,newpayload))    
    return newpayload

def cmd_wrapper(options,cmd,sudo):
    if sudo:
        cmd = "/usr/bin/sudo %s" % (cmd)
    options.log.info("running command and waiting for it to finish %s" % (cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    stdout,stderr = p.communicate()
    return (p.returncode, stdout, stderr)

def cmd_wrapper_detatched(options,cmd,sudo):
    if sudo:
        cmd = "/usr/bin/sudo %s" % (cmd)
    options.log.info("running detached command %s" % (cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    return

def inflate_data(options,compressed_data):
    try:
       uncompressed_data = zlib.decompress(compressed_data)
    except zlib.error:
       uncompressed_data = zlib.decompress(compressed_data, -zlib.MAX_WBITS)
    return uncompressed_data

def ungzip_data(options,compressed_data):
    try:
        compressed_data = StringIO.StringIO(compressed_data)
        gziptmp = gzip.GzipFile(fileobj=compressed_data)
        uncompressed_data = gziptmp.read()
        return uncompressed_data
    except:
        options.log.error("unzip failure")
        return compressed_data

def dechunk_data(options,chunked_data):
    #wonder if there is a better way without walking every byte in the body.
    dechunked_body = ""
    while 1:
        m_chunk_len = re.match(r'^(?P<chunk_len>[a-zA-F0-9]+)(:[^\r\n]+)?\r\n',chunked_data)
        if m_chunk_len != None:
            chunk_start = m_chunk_len.start()
            chunk_end = m_chunk_len.end()

            #convert the chunk len from hex to dec
            dec_chunk_len = int(m_chunk_len.group('chunk_len'), 16)

            #this is the last chunk
            if dec_chunk_len == 0:
                options.log.debug("we hit the 0 chunk we are all done")
                break
            else:
                #strip the chunklen
                chunked_data = chunked_data.lstrip(chunked_data[:chunk_end - 1])
                    
                #walk the bytes adding them to the dechunked_buffer
                i = 0
                while i < dec_chunk_len:
                    dechunked_body = dechunked_body + chunked_data[i]
                    i = i + 1
                #remove the \r\n blank line
                chunked_data = chunked_data.lstrip(chunked_data[:dec_chunk_len + 2])
        else:
            #print "couldn't find chunk"
            break
 
    return dechunked_body

def escape_replace_payload(payload):
    payload = payload.replace('\\n', '\n')
    payload = payload.replace('\\r', '\r')
    payload = payload.replace('\\t', '\t')
    payload = payload.replace('\\f', '\f')
    payload = payload.replace('\\v', '\v')
    payload = payload.replace('\\b', '\b')
    return payload

def parse_payload(options,host,port,payload,normalize):
    request={}
    options.current_req_id =  "%s-%s-%s" % (host,port,time.time())
    payload = escape_replace_payload(payload)
    payload = encode_find_and_replace(options,payload)  
    
    #If we are not going to normalize the request just return the unparsed version
    if not normalize:
        options.log.debug("Not normalizing request sending unparsed payload")
        request['raw_payload'] = payload
        request['parsed_payload'] = payload

        #Save the request to a file that can later be read via raw
        if options.save_requests:
            save_request(options,"req-%s" % options.current_req_id,request['parsed_payload'])
        
        return request;
    
    request['raw_payload'] = payload
    request['parsed_payload'] = ""
    #m = re.match(r'^(?P<method>[^\s]+)\s+(?P<uri>[^\s]+)\s+(?P<proto>[^\/]+)\/(?P<version>[^\r\n]+)\r?\n(?P<headers>.+)?(\r?\n\r?\n(?P<body>))?',payload,re.DOTALL)
    m = re.match(r'^(?P<method>[^\s]+)\s+(?P<uri>[^\s]+)\s+(?P<proto>[^\/]+)\/(?P<version>[^\r\n]+)(\r?\n)+(?P<headers_and_body>.+)?',payload,re.DOTALL)
    if m:
        request['method']=m.group('method')
        options.log.debug("method:%s" % (m.group('method')))
        request['uri']=m.group('uri') 
        options.log.debug("uri:%s" % (m.group('uri')))
        request['proto'] = m.group('proto')
        options.log.debug("proto:%s" % (m.group('proto')))
        request['version'] = m.group('version')
        options.log.debug("version:%s" % (m.group('version')))
        
        request['parsed_payload'] = request['parsed_payload'] + "%s %s %s/%s\r\n" %(request['method'],request['uri'],request['proto'],request['version'])

        #Store a urlparsed version of the request
        request['urlparsed'] = urlparse("%s://%s:%s%s" % (request['proto'].lower(),host,port,request['uri']))

        #Store query as a list of tuples
        if request['urlparsed'].query != '':
            request['query_list'] = parse_qsl(request['urlparsed'].query)
            options.log.debug("query as list:\n")
            for q_tuple in request['query_list']:
                if q_tuple[0] and q_tuple[1]:
                    options.log.debug("\t%s: %s" % (q_tuple[0],q_tuple[1]))
                               
        #Deal with headers
        request['headers_list']=[[[]]]
        request['headers_dict'] = {}            
        if m.group('headers_and_body')!= None:
            #store a version of the headers as a single buffer
            m_headers_all = re.match(r'(?P<headers_all>([^\r\n]+\:\s*[^\r\n]+\r?\n)+)\r?\n',m.group('headers_and_body'))  
            if m_headers_all:
                request['raw_headers'] = m_headers_all.group('headers_all')
                options.log.debug("raw_headers:\n%s" % (request['raw_headers']))
                
            #store headers as a list of tuples retain header order
            for m_header in re.finditer('(?P<header_name>[^\r\n]+)\:\s*(?P<header_value>[^\r\n]+)\r?\n',m.group('headers_and_body')):
                request['headers_list'].append((m_header.group('header_name'),m_header.group('header_value')))
                #XXX This is vulnerable to HPP we will always end up with the last value seen.
                request['headers_dict'][m_header.group('header_name')] = m_header.group('header_value')
                
            options.log.debug("headers as a list:\n")    
            for header in request['headers_list']:
                if header[0] and header[1]:
                    options.log.debug("\t%s: %s" % (header[0],header[1]))
                    if header[0] == "Host" and options.replace_host_header == True:
                        options.log.debug("\t Replaced with Host: %s:%s" % (host,port))
                        request['parsed_payload'] = request['parsed_payload'] + "%s: %s:%s\r\n" % ("Host",host,port)
                    else:
                        request['parsed_payload'] = request['parsed_payload'] + "%s: %s\r\n" % (header[0],header[1])
                               
            request['parsed_payload'] = request['parsed_payload'] + "\r\n" 
            
            #assume the rest of the payload is the body        
            #m_body = re.match(r'^.+\r?\n\r?\n(P?<body>.+)',m.group('headers_and_body'),re.DOTALL)
            m_body = re.match(r'^([^\r\n]+\:\s*[^\r\n]+\r?\n)*\r?\n(?P<body>.+)',m.group('headers_and_body'),re.DOTALL)
            if m_body != None:
                body = m_body.group('body')
                request['parsed_payload'] = request['parsed_payload'] + body
                request['raw_body'] = body
        else:
            request['headers_list'].append(("Host","%s:%s" % (host,port)))
            request['headers_list'].append(("User-Agent","Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)"))
            
            options.log.debug("headers as a list:\n")    
            for header in request['headers_list']:
                if header[0] and header[1]:
                    options.log.debug("\t%s: %s" % (header[0],header[1]))
                    request['parsed_payload'] = request['parsed_payload'] + "%s: %s\r\n" % (header[0],header[1])
            request['parsed_payload'] = request['parsed_payload'] + "\r\n"
    else:
        options.log.warning("failed to parse payload:\n %s" % (payload))
        if options.exit_on_parse_error == True:
            options.log.error("exiting due to parsing failure")
            sys.exit(-1)
        else:
            options.log.warning("going to attempt to send request we could not parse")
            request['parsed_payload'] = payload
    
          
    #Save the request to a file that can later be read via raw
    if options.save_requests:
        save_request(options,"req-%s" % options.current_req_id,request['parsed_payload'])
        
    return (request)

def send_request(options,request):
    if options.send_mode == "raw_socket":
        (parsed_response) = send_raw_socket(options,options.host,options.port,request['parsed_payload'],False)
    elif options.send_mode == "jnovak_send_rst_bad_chksum":
        jne=JudyNovakEvade()
        (parsed_response) = jne.jnovak_send_rst_bad_chksum(options,options.host,options.port,request['parsed_payload'])
    elif options.send_mode == "jnovak_send_overlap_bad_chksum":
        jne=JudyNovakEvade()
        (parsed_response) = jne.jnovak_send_overlap_bad_chksum(options,options.host,options.port,request['parsed_payload'])
    elif options.send_mode == "jnovak_send_bogus_ecn_flags":
        jne=JudyNovakEvade()
        (parsed_response) = jne.jnovak_send_bogus_ecn_flags(options,options.host,options.port,request['parsed_payload'])
    elif options.send_mode == "jnovak_sequence_wrap":
        jne=JudyNovakEvade()
        (parsed_response) = jne.jnovak_sequence_wrap(options,options.host,options.port,request['parsed_payload'])
    elif options.send_mode == "jnovak_multiple_syns":
        jne=JudyNovakEvade()
        (parsed_response) = jne.jnovak_multiple_syns(options,options.host,options.port,request['parsed_payload'])
    elif options.send_mode == "jnovak_rst_syn_again":
        jne=JudyNovakEvade()
        (parsed_response) = jne.jnovak_rst_syn_again(options,options.host,options.port,request['parsed_payload'])
    elif options.send_mode == "jnovak_syn_pushflag":
        jne=JudyNovakEvade()
        (parsed_response) = jne.jnovak_syn_pushflag(options,options.host,options.port,request['parsed_payload'])
    elif options.send_mode == "jnovak_syn_urgflag":
        jne=JudyNovakEvade()
        (parsed_response) = jne.jnovak_syn_urgflag(options,options.host,options.port,request['parsed_payload']) 
    else:
        options.log.error("unknown send type of %s exiting" % (options.send_mode))
        sys.exit(-1)
    return parsed_response

def send_raw_socket(options,host,port,payload,tcpsplice):
    options.log.debug("attempting to send %s:%s %s" % (host,port,payload))
    ipaddy = socket.gethostbyname(host)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(30)
    response = ""
    response_len = 0
    content_len_header = None
    response_header_len = None
    response_body_len = None
    # connect to server
    try:
        s.connect((ipaddy, port))
    except:
        options.log.error("failed to make socket connection to %s:%s" % (ipaddy,port))
        parsed_response = parse_raw_response(options,response,response_len)
        if options.save_requests_on_fail:
            save_request(options,"req-failure-%s" % options.current_req_id,payload)
        s.close()
        return parsed_response

    if tcpsplice:
        parts = payload_splitter(options,payload,"random")
        for part in parts:
            options.log.debug("sending %s" % (parts[part]))
            try:
                s.send(parts[part])
            except:
                options.log.error("failed to send part %s" % (parts[part]))
                parsed_response = parse_raw_response(options,response,response_len)
                if options.save_requests_on_fail:
                    save_request(options,"req-failure-%s" % options.current_req_id,payload)
                s.close()
                return parsed_response
    else:
        try:        
            s.send(payload)
        except:
            options.log.error("failed to send part %s" % (payload))
            parsed_response = parse_raw_response(options,response,response_len)
            if options.save_requests_on_fail:
                save_request(options,"req-failure-%s" % options.current_req_id,payload)
            s.close()
            return parsed_response

    while(1):
        try:
            data = s.recv(1024)
        except:
            options.log.error("failed to read from socket going to attempt to parse what we have")
            parsed_response = parse_raw_response(options,response,response_len)
            if options.save_requests_on_fail:
                save_request(options,"req-failure-%s" % options.current_req_id,payload)
            s.close()
            return parsed_response
                    
        if data:
            response = response + data
            response_len = response_len + len(data)
            if content_len_header == None:
                response_match = re.match(r'^(?P<headers>([^\r\n]+\r?\n)+\r?\n)',response,re.DOTALL)
                if response_match != None:
                    response_header_len = len(response_match.group('headers'))
                    options.log.debug("header match on socket %s header_len %s" % (response_match.group('headers'),response_header_len))
                    content_header = re.search(r'Content-Length\:\s(?P<content_len>\d+)\r?\n',response_match.group('headers'))
                    if content_header != None:
                        content_len_header = int(content_header.group('content_len'))
                        options.log.debug('found content length header of %s' % (content_len_header))
                        body_bytes = int(response_len - response_header_len)
                        if body_bytes >= content_len_header:
                            options.log.debug("Read all content as specified by content length header")
                            break
            else:
                body_bytes = int(response_len - response_header_len)
                if body_bytes >= content_len_header:
                    options.log.debug("Read all content as specified by content length header")
                    break
                else:
                    options.log.debug("Read %s body bytes expecting %s" % (body_bytes,content_len_header))
        if not data:
            break

    s.close()
    parsed_response = parse_raw_response(options,response,response_len) 
    return parsed_response

#Parse response for raw socket requests
def parse_raw_response(options,raw_response,raw_response_len):
    response={}
    
    response['raw_response'] = raw_response
    options.log.debug("response:\n%s\response_len:%s" % (response['raw_response'],raw_response_len))
    #m = re.match(r'^(?P<proto>[^\/]+)\/(?P<version>\d\.\d)\s+(?P<http_stat_code>\d+)\s+(?P<http_stat_msg>[^\r\n]+)\r?\n(?P<headers_and_body>.+)?',raw_response,re.DOTALL)
    m = re.match(r'^(?P<status_line>(?P<proto>[^\/]+)\/(?P<version>\d\.\d)\s+(?P<status>(?P<http_stat_code>\d+)\s+(?P<http_stat_msg>[^\r\n]+))\r?\n)(?P<headers_and_body>.+)?',raw_response,re.DOTALL)
    if m:
        #Save the whole status line ex: HTTP/1.1 200 OK
        response['status_line'] = m.group('status_line')
        options.log.debug("status_line:%s" % (m.group('status_line')))
        
        #Save the stat code and msg. For Ivan's tests this is RESPONSE_STATUS ex: 200 OK 
        response['status'] = m.group('status')
        options.log.debug("status:%s" % (m.group('status')))
        
        #Protocol name ex: HTTP
        response['proto'] = m.group('proto')
        options.log.debug("proto:%s" % (m.group('proto')))
        
        #Protocol version ex:1.1
        response['version'] = m.group('version')
        options.log.debug("version:%s" % (m.group('version')))
        
        #HTTP Status code ex: 200
        response['http_stat_code'] = m.group('http_stat_code')
        options.log.debug("http_stat_code:%s" % (m.group('http_stat_code')))
        
        #HTTP Status message ex: OK
        response['http_stat_msg'] = m.group('http_stat_msg')
        options.log.debug("http_stat_msg:%s" % (m.group('http_stat_msg')))
        
        if m.group('headers_and_body')!= None:
            #create a buffer containing all headers
            m_headers = re.match(r'^(?P<headers>([^\r\n]+\:\s*[^\r\n]+\r?\n)+\r\n)',m.group('headers_and_body'))
            if m_headers != None:
                response['headers'] = m_headers.group('headers')
                
            #create a ordered list of headers with a tuple of header_name, header_value
            response['headers_list'] = [[[]]]
            for m_header in re.finditer(r'(?P<header_name>[^\r\n]+)\:\s*(?P<header_value>[^\r\n]+)\r?\n',m_headers.group('headers')):
                if m_header.group('header_name') == 'Content-Encoding':
                       response['content_encoding'] = m_header.group('header_value')

                if m_header.group('header_name') == 'Transfer-Encoding':
                       response['transfer_encoding'] = m_header.group('header_value')

                options.log.debug("header_name:%s header_value:%s" % (m_header.group('header_name'),m_header.group('header_value')))
                response['headers_list'].append((m_header.group('header_name'),m_header.group('header_value')))    

            #assume the rest of the payload is the body
            options.log.debug("headers and body:\n%s" % m.group('headers_and_body'))        
            m_body = re.match(r'^([^\r\n]+\:\s*[^\r\n]+\r?\n)*\r?\n(?P<body>.+)',m.group('headers_and_body'),re.DOTALL)
            if m_body != None:
                response['body'] = m_body.group('body')
                options.log.debug("body len %s" % (len(response['body'])))
                if response.has_key('transfer_encoding'):
                    if response['transfer_encoding'] == 'chunked':
                        response['body'] = dechunk_data(options,response['body'])
                       
                if response.has_key('content_encoding'):
                    if response['content_encoding'] == 'gzip':
                        response['body'] = ungzip_data(options,response['body'])
                    elif response['content_encoding'] == 'deflate':
                        response['body'] = decompress_data(options,response['body'])
                options.log.debug("response body:\n%s" % (response['body']))
            else:
                options.log.debug("no response body found")
    else:
        options.log.warning("could not parse http response")
   
    #Save the request to a file that can later be read via raw
    if options.save_requests:
        save_request(options,"resp-%s" % options.current_req_id,response['raw_response'])
        
    return response
              
def payload_splitter(options,payload,no_parts):
    parts = {}
    
    #split the payload into a random amount of parts
    if no_parts == "random":
        no_parts = random.randint(1,len(payload))
            
    bytes_per_part = len(payload) / no_parts
    bytes_left_over = len(payload) % no_parts
    total_byte_cnt = 0
    part_cnt = 1
    while part_cnt <= no_parts:
        part_byte_cnt = 0
        parts[part_cnt]= ""
        while part_byte_cnt < bytes_per_part:
            parts[part_cnt] = parts[part_cnt] + payload[total_byte_cnt] 
            total_byte_cnt = total_byte_cnt + 1
            part_byte_cnt = part_byte_cnt + 1
        options.log.debug("total_byte_cnt %s part cnt %s part %s" % (total_byte_cnt, part_cnt, parts[part_cnt]))
        part_cnt = part_cnt + 1
    if bytes_left_over > 0:
        while total_byte_cnt < len(payload):
            parts[no_parts] = parts[no_parts] + payload[total_byte_cnt]
            total_byte_cnt = total_byte_cnt + 1
    for key in parts:
        options.log.debug("%s:%s" % (key,parts[key]))
    return parts
   
def bo_test(options,host,port,request):
    payload = ""
    buff_overflow_list=["A" * 256,  "A" * 513, "A" * 1025, "A" * 65536, "A" * 131072]
    #Look for overflow in request method
    for buf in buff_overflow_list:
        #method overflow
        payload = request['method'] + buf + " " + request['uri'] + " " + request['proto']+ "/" + request['version'] + "\r\n"
        for header in request['headers']:
            if header[0] and header[1]:
                payload = payload + "%s: %s\r\n" % (header[0],header[1])
        payload = payload + "\r\n"
        options.log.debug(payload)
        send_raw_socket(host,port,payload,False)
        
        #uri overflow
        payload = request['method'] + " " + request['uri'] + buf + " " + request['proto']+ "/" + request['version'] + "\r\n"
        for header in request['headers']:
            if header[0] and header[1]:
                payload = payload + "%s: %s\r\n" % (header[0],header[1])
        payload = payload + "\r\n"
        options.log.debug(payload)
        send_raw_socket(host,port,payload,False)
        
        #proto overflow
        payload = request['method'] + " " + request['uri'] + " " + request['proto'] + buf + "/" + request['version'] + "\r\n"
        for header in request['headers']:
            if header[0] and header[1]:
                payload = payload + "%s: %s\r\n" % (header[0],header[1])
        payload = payload + "\r\n"
        options.log.debug(payload)
        send_raw_socket(host,port,payload,False)    

        #version overflow
        payload = request['method'] + " " + request['uri'] + " " + request['proto'] + "/" + request['version'] + buf + "\r\n"
        for header in request['headers']:
            if header[0] and header[1]:
                payload = payload + "%s: %s\r\n" % (header[0],header[1])
        payload = payload + "\r\n"
        options.log.debug(payload)
        send_raw_socket(host,port,payload,False)

def get_file_size(file_name):
    try:
        ost_results = os.stat(file_name)
        ost_size = ost_results[6]
    except:
        ost_size = 0

    return ost_size

def read_file_from_offset_and_update(options,file_name,offset):
    try:
        f = open(file_name,'r')
        f.seek(int(offset))
        buf = f.read()
        f.close()
        new_offset = get_file_size(file_name)
    except:
        options.log.error("failed to read from file:%s at offset:%i bailing" % (file_name,offset))
        sys.exit(-1)
    return (buf,new_offset)

def do_file_matching(options):
    options.match_list = []

    for file_name in options.file_matcher_dict:
        print options.file_matcher_dict[file_name]
        (tmp_log,options.file_matcher_dict[file_name]['position']) = read_file_from_offset_and_update(options,file_name,options.file_matcher_dict[file_name]['position'])
        if options.file_matcher_dict[file_name].has_key('re'):
            for match in options.file_matcher_dict[file_name]['re']:
                m = re.search(r'%s' % (match),tmp_log)
                if m != None:
                    options.match_list.append("we had a match of %s in log file %s" % (match,file_name))
                else:
                    options.log.debug("failed to find a match of %s in log file %s" % (match,file_name))
        else:
            options.log.debug("no regex patterns to match for file %s" % (file_name))

        if options.file_matcher_dict[file_name].has_key('simple'):
            for match in options.file_matcher_dict[file_name]['simple']:
                if tmp_log.find(match) >= 0:
                    options.match_list.append("we had a match of %s in log file %s" % (match,file_name))
                else: 
                    options.log.debug("failed to find a match of %s in log file %s" % (match,file_name))
        else:
            options.log.debug("no simple patterns to match for file %s" % (file_name))
            
def do_buff_match(options,buffer,match,type):

    if type == 'simple':
        if buffer.find(match) >= 0:
            options.log.debug("we had a match of %s in log file %s" % (match,buffer))
            return True
        else:
            options.log.error("failed to find match of %s in log file %s" % (match,buffer))
            return False
    elif type == 'simple_negated':
        if buffer.find(match) <= 0:
            options.log.debug("we had a negated match of %s in log file %s" % (match,buffer))
            return True
        else:
            options.log.error("failed to find negated match of %s in log file %s" % (match,buffer))
            return False
    elif type == 're':
        if re.search(r'%s' % (match),buffer) != None:
            options.log.debug("we had a match of %s in log file %s" % (match,buffer))
            return True
        else:
            options.log.error("failed to find match of %s in buffer %s" % (match,buffer))
            return False
    elif type == 're_negated':
        if re.search(r'%s' % (match),buffer) == None:
            options.log.debug("we had a negated match of %s in log file %s" % (match,buffer))
            return True
        else:
            options.log.error("failed to find negated match of %s in buffer %s" % (match,buffer))
            return False
    else:
        options.log.debug("unknown match type" % (type))
        return False
    
def parse_output_match_string(options):
    options.file_matcher_dict = deepdict()
    if options.output_re_match:
        matches = options.output_re_match.split(":+:+")
        for match in matches:
            entry_list =  match.split("+=+=")

            if not options.file_matcher_dict[entry_list[0]].has_key('type'):
                options.file_matcher_dict[entry_list[0]]['type'] = entry_list[1]

            if not options.file_matcher_dict[entry_list[0]].has_key('position'):
                options.file_matcher_dict[entry_list[0]]['position'] = get_file_size(entry_list[0])

            options.file_matcher_dict[entry_list[0]]['re'] = []
            tmp_re_list = entry_list[2].split("#=#=")
            for regex in tmp_re_list:
                options.file_matcher_dict[entry_list[0]]['re'].append('%s' % (regex))

    if options.output_in_match:
        matches = options.output_in_match.split(":+:+")
        for match in matches:
            entry_list =  match.split("+=+=")

            if not options.file_matcher_dict[entry_list[0]].has_key('type'):
                options.file_matcher_dict[entry_list[0]]['type'] = entry_list[1]

            if not options.file_matcher_dict[entry_list[0]].has_key('position'):
                options.file_matcher_dict[entry_list[0]]['position'] = get_file_size(entry_list[0])

            options.file_matcher_dict[entry_list[0]]['in'] = []
            tmp_re_list = entry_list[2].split("#=#=")
            for match in tmp_re_list:
                options.file_matcher_dict[entry_list[0]]['in'].append('%s' % (match))

                
def save_request(options,file,payload):
    try:
        f = open(file,'w')
        f.write(payload)
        f.close()
        options.log.debug("saved payload to file %s" % file)
    except:
        options.log.error("failed to save payload to file %s" % file)
    
