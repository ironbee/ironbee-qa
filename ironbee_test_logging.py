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
import logging
import sys
def setup_logger(file_loglevel,console_loglevel=None):
    level_dict = {'debug': logging.DEBUG,
                  'info': logging.INFO,
                  'warning': logging.WARNING,
                  'error': logging.ERROR,
                  'critical': logging.CRITICAL}
    file_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    if level_dict.has_key(file_loglevel):
        logging.basicConfig(filename='ironbee_test.log',level=level_dict.get(file_loglevel),format=file_format)
        if level_dict.has_key(console_loglevel):
            console = logging.StreamHandler()
            console.setLevel(level_dict.get(console_loglevel))
            formatter = logging.Formatter(file_format)
            console.setFormatter(formatter)
            logging.getLogger('').addHandler(console) 
        else:
            print "invalid file loglevel %s" % (console_loglevel)
            sys.exit(-1)                 
        return logging
    else:
        print "invalid file loglevel %s" % (file_loglevel)
        sys.exit(-1)
        

