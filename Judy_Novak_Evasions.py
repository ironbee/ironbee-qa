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

#This file contains IDS evasion techniques discovered and authored by Judy Novak credit should be assigned as such.
#The code here is simply a modification of Judys hard work to get her tests to fit into the IronBee QA tool.
#Thank you so much Judy for making this type of info public and allowing me to use it here!!!
#
#Judy is an amazing researcher. If this type of thing interests you I suggest you take her SANS class SEC567: Power Packet Crafting with Scapy.
#Also check out the PacketSatan blog to which she frequently posts http://www.packetstan.com/


import random, time

try:
    from scapy.all import *
except:
    options.log.debug("Failed to Import scapy are you sure it's installed? bailing...")
    sys.exit(-1)

class JudyNovakEvade:
    
    #This is a very silly non-robust way of dealing server responses, but was easy to add
    def callback(self,pkt):
        if pkt.seq != self.my_ack:
            self.log.debug("seq hole expected seq %s but got %s" % (self.my_ack,pkt.seq))
            return
        else:
            self.log.debug("expected seq %s and actual seq %s match" % (self.my_ack,pkt.seq))  
           
        flags = pkt.sprintf("%TCP.flags%")
        self.log.debug("flags %s" % (flags))
        
        try:
            raw = pkt.load
            if pkt.seq not in self.seq_seen:
                self.seq_seen.append(pkt.seq)
                if Padding in pkt:
                    if pkt.Padding != raw:
                        self.pkt_list.append(raw)
                else:
                    self.pkt_list.append(raw)
            else:
                self.log.debug("skipping packet we have already seen this one %s" % (pkt.seq))
                if "F" in flags:
                    RST=TCP(ack=self.my_ack, seq=self.next_seq, sport=self.sp, dport=self.dp, flags="RA")
                    send(self.ip/RST)
                    raise NameError('all done')
                
                self.log.debug(self.seq_seen)
                return     
        except:
            raw = None
            if pkt.seq not in self.seq_seen:
                self.seq_seen.append(pkt.seq)
                self.log.debug(self.seq_seen)
            else:
                self.log.debug("skipping packet we have already seen this one  %s" % (pkt.seq))
                if "F" in flags:
                    self.log.debug("FIN seen on seq we already have RST and stop sniff()")
                    RST=TCP(ack=self.my_ack, seq=self.next_seq, sport=self.sp, dport=self.dp, flags="RA")
                    send(self.ip/RST)
                    raise NameError('all done')
                
                self.log.debug(self.seq_seen)
                return
               
        if raw != None:
            self.log.debug("We have payload %s" % (raw))
            self.my_ack = pkt.seq + len(raw)
            self.next_seq = pkt.ack
        else:
            self.log.debug("We don't have a payload")
            self.my_ack = pkt.seq + 1
            self.next_seq = pkt.ack
            
        if "F" not in flags:
            try:
                ACK=TCP(ack=self.my_ack, sport=self.sp, dport=self.dp, flags="A", seq=self.next_seq)
                send(self.ip/ACK)
            except:
                self.log.debug("failed to send ACK")
        else:
            self.log.debug("FIN seen sending reset and stop sniff()")
            RST=TCP(ack=self.my_ack, seq=self.next_seq, sport=self.sp, dport=self.dp, flags="RA")
            send(self.ip/RST)
            #This can be anything as long as you catch the same exception in try/except for sniff()  
            raise NameError('all done')
           
    #Judy Novak Description: Send a reset with a bad TCP checksum and then send "malicious" payload.
    def jnovak_send_rst_bad_chksum(self,options,host,port,payload):
    	from ironbee_test_utils import *
        self.next_seq = 0
        self.my_ack = 0
        self.pkt_list = []
        self.seq_seen = []
        self.topt = None
        self.log = options.log
        
        self.log.debug("attempting to send %s:%s %s" % (host,port,payload))
        self.sp = random.randint(1024,65535)
        self.dp = port

        self.isn = random.randint(0,4294967295)
        
        self.parts = payload_splitter(options,payload,3)
     
        self.insert_iptables_rule = "iptables %s OUTPUT -p tcp -d %s --dport %s --sport %s --tcp-flags RST RST -j DROP" % ("-I",host,port,self.sp)
        self.rm_iptables_rule = "iptables %s OUTPUT -p tcp -d %s --dport %s --sport %s --tcp-flags RST RST -j DROP" % ("-D",host,port,self.sp)
    
        self.log.debug("attempting to add fw rule to filter resets from target")
        cmd_wrapper(options,self.insert_iptables_rule,True)    

        self.dip = socket.gethostbyname(host)
        self.ip=IP(dst=self.dip)
        
        SYN=TCP(sport=self.sp, dport=port, flags="S", seq=self.isn)
        SYNACK=sr1(self.ip/SYN)
        
        self.my_ack = SYNACK.seq + 1 
        self.next_seq = SYN.seq + 1
        
        ACK=TCP(ack=self.my_ack, sport=self.sp, dport=80, flags="A", seq=self.next_seq)
        send(self.ip/ACK)
        
        PUSH=TCP(ack=self.my_ack, seq=self.next_seq, sport=self.sp, dport=80, flags="PA")
        send(self.ip/PUSH/self.parts[1])
        self.next_seq = ACK.seq + len(self.parts[1])
        time.sleep(1)
     
        RST=TCP(ack=self.my_ack, seq=self.next_seq, sport=self.sp, dport=port, flags="RA", chksum=12345)
        send(self.ip/RST)
    
        PUSH=TCP(ack=self.my_ack, seq=self.next_seq, sport=self.sp, dport=port, flags="PA")
        send(self.ip/PUSH/self.parts[2])
        self.next_seq = PUSH.seq + len(self.parts[2])
        time.sleep(1)
    
        PUSH=TCP(ack=self.my_ack, seq=self.next_seq, sport=self.sp, dport=port, flags="PA")
        send(self.ip/PUSH/self.parts[3])
        self.next_seq = PUSH.seq + len(self.parts[3])

        try:
            sniff(filter="tcp and src %s and port %s and port %s" % (self.dip,port,self.sp), prn=self.callback, timeout=120)
        except NameError:
            self.log.debug("all done join packets")
            self.log.debug(self.pkt_list)
            
        response = ''.join(self.pkt_list)
        
        cmd_wrapper(options,self.rm_iptables_rule,True)
        self.log.debug("scapy_response:\n%s" % (response))
        parsed_response = parse_raw_response(options,response,len(response))
        return parsed_response
    
    #Judy Novak Description: Send a packet with bogus payload and a bad TCP checksum. 
    #Then overlap this segment with part of "malicious" payload.
    def jnovak_send_overlap_bad_chksum(self,options,host,port,payload):
    	from ironbee_test_utils import *
        self.next_seq = 0
        self.my_ack = 0
        self.pkt_list = []
        self.seq_seen = []
        self.topt = None
        self.log = options.log
        
        self.log.debug("attempting to send %s:%s %s" % (host,port,payload))
        self.sp = random.randint(1024,65535)
        self.dp = port
        
        self.isn = random.randint(0,4294967295)
        
        self.parts = payload_splitter(options,payload,2)
    
        #Scapy works behind the kernel's back so we need to filter outbound resets on this connection
        self.insert_iptables_rule = "iptables -I OUTPUT -p tcp -d %s --dport %s --sport %s --tcp-flags RST RST -j DROP" % (host,port,self.sp)
        self.rm_iptables_rule = "iptables -D OUTPUT -p tcp -d %s --dport %s --sport %s --tcp-flags RST RST -j DROP" % (host,port,self.sp)
    
        self.log.debug("attempting to add fw rule to filter resets from target")
        cmd_wrapper(options,self.insert_iptables_rule,True)    
        self.dip = socket.gethostbyname(host)
        self.ip=IP(dst=self.dip)
        
        SYN=TCP(sport=self.sp, dport=port, flags="S", seq=self.isn)
        synack=sr1(self.ip/SYN)
        self.my_ack=synack.seq + 1
        self.next_seq = SYN.seq + 1
        
        ACK=TCP(sport=self.sp, dport=port, flags="A", seq=self.next_seq, ack=self.my_ack)
        send(self.ip/ACK)
        
        junk = os.urandom(random.randint(20,1492))
        
        PUSH=TCP(sport=self.sp, dport=port, flags="PA", seq=self.next_seq, ack=self.my_ack,chksum=12345)
        send(self.ip/PUSH/junk)
        time.sleep(1)
        
        PUSH=TCP(sport=self.sp, dport=port, flags="PA", seq=self.next_seq, ack=self.my_ack)
        send(self.ip/PUSH/self.parts[1])
        self.next_seq=PUSH.seq + len(self.parts[1])
        time.sleep(1)
        
        PUSH=TCP(sport=self.sp, dport=port, flags="PA", seq=self.next_seq, ack=self.my_ack)
        send(self.ip/PUSH/self.parts[2])
        self.next_seq=PUSH.seq + len(self.parts[2])

        try:
            sniff(filter="tcp and src %s and port %s and port %s" % (self.dip,port,self.sp), prn=self.callback, timeout=120)
        except NameError:
            self.log.debug("all done join packets")
            self.log.debug(self.pkt_list)
            
        response = ''.join(self.pkt_list)
    
        cmd_wrapper(options,self.rm_iptables_rule,True)
        self.log.debug("scapy_response:\n%s" % (response))
        parsed_response = parse_raw_response(options,response,len(response))
        return parsed_response
    
    #Judy Novak Description: ECN flags set on all segments.
    def jnovak_send_bogus_ecn_flags(self,options,host,port,payload):
    	from ironbee_test_utils import *
        self.next_seq = 0
        self.my_ack = 0
        self.pkt_list = []
        self.seq_seen = []
        self.topt = None
        self.log = options.log
        
        self.log.debug("attempting to send %s:%s %s" % (host,port,payload))
        self.sp = random.randint(1024,65535)
        self.dp = port
        
        self.isn = random.randint(0,4294967295)
        
        self.parts = payload_splitter(options,payload,2)
    
        #Scapy works behind the kernel's back so we need to filter outbound resets on this connection
        self.insert_iptables_rule = "iptables -I OUTPUT -p tcp -d %s --dport %s --sport %s --tcp-flags RST RST -j DROP" % (host,port,self.sp)
        self.rm_iptables_rule = "iptables -D OUTPUT -p tcp -d %s --dport %s --sport %s --tcp-flags RST RST -j DROP" % (host,port,self.sp)
    
        self.log.debug("attempting to add fw rule to filter resets from target")
        cmd_wrapper(options,self.insert_iptables_rule,True)    
        self.dip = socket.gethostbyname(host)
        self.ip=IP(dst=self.dip)
        
        SYN=TCP(sport=self.sp, dport=port, flags="SEC", seq=self.isn)
        synack=sr1(self.ip/SYN)
        self.my_ack=synack.seq + 1
        self.next_seq = SYN.seq + 1
        
        ACK=TCP(sport=self.sp,dport=port, flags="AEC", seq=self.next_seq, ack=self.my_ack)
        send(self.ip/ACK)
        
        PUSH=TCP(sport=self.sp, dport=port, flags="PECA", seq=self.next_seq, ack=self.my_ack)
        send(self.ip/PUSH/self.parts[1])
        self.next_seq=PUSH.seq + len(self.parts[1])
        time.sleep(1)
        
        PUSH=TCP(sport=self.sp, dport=port, flags="PECA", seq=self.next_seq, ack=self.my_ack)
        send(self.ip/PUSH/self.parts[2])
        self.next_seq=PUSH.seq + len(self.parts[2])
        try:
            sniff(filter="tcp and src %s and port %s and port %s" % (self.dip,port,self.sp), prn=self.callback, timeout=120)
        except NameError:
            self.log.debug("all done join packets")
            self.log.debug(self.pkt_list)
            
        response = ''.join(self.pkt_list)
            
        cmd_wrapper(options,self.rm_iptables_rule,True)
        self.log.debug("scapy_response:\n%s" % (response))
        parsed_response = parse_raw_response(options,response,len(response))
        return parsed_response
    
    #Judy Novak Description:  One-byte segments that wrap TCP sequence number in middle of "malicious" payload.
    def jnovak_sequence_wrap(self,options,host,port,payload):
    	from ironbee_test_utils import *
        self.next_seq = 0
        self.my_ack = 0
        self.pkt_list = []
        self.seq_seen = []
        self.topt = None
        self.log = options.log
        
        self.log.debug("attempting to send %s:%s %s" % (host,port,payload))
        self.isn = 4294967289
        self.max_seq = 4294967295
        self.sp = random.randint(1024,65535)
        #Scapy works behind the kernel's back so we need to filter outbound resets on this connection
        self.insert_iptables_rule = "iptables -I OUTPUT -p tcp -d %s --dport %s --sport %s --tcp-flags RST RST -j DROP" % (host,port,self.sp)
        self.rm_iptables_rule = "iptables -D OUTPUT -p tcp -d %s --dport %s --sport %s --tcp-flags RST RST -j DROP" % (host,port,self.sp)
    
        self.log.debug("attempting to add fw rule to filter resets from target")
        cmd_wrapper(options,self.insert_iptables_rule,True)    
        self.dip = socket.gethostbyname(host)
        
        self.ip=IP(dst=self.dip)
        SYN=TCP(sport=self.sp, dport=port, flags="S", seq=self.isn)
        synack=sr1(self.ip/SYN)
        self.my_ack=synack.seq + 1
        
        ACK=TCP(sport=self.sp, dport=port, flags="A", seq=self.isn+1, ack=self.my_ack)
        send(self.ip/ACK)
        self.next_seq = ACK.seq
        
        i = 0
        while i < (len(payload) -1):
            PUSH=TCP(sport=self.sp, dport=port, flags="PA", seq=self.next_seq, ack=self.my_ack)
            send(self.ip/PUSH/payload[i])
                
            if (self.next_seq == self.max_seq):
                self.next_seq = 0
            else:
                self.next_seq=PUSH.seq + 1   
            i = i + 1
        
        #send the last byte    
        PUSH=TCP(sport=self.sp, dport=port, flags="PA", seq=self.next_seq, ack=self.my_ack)
        send(self.ip/PUSH/payload[-1])
        self.next_seq = PUSH.seq + 1
        
        try:
            sniff(filter="tcp and src %s and port %s and port %s" % (self.dip,port,self.sp), prn=self.callback, timeout=120)
        except NameError:
            self.log.debug("all done join packets")
            self.log.debug(self.pkt_list)
            
        response = ''.join(self.pkt_list) 
    
        cmd_wrapper(options,self.rm_iptables_rule,True)
        self.log.debug("scapy_response:\n%s" % (response))
        parsed_response = parse_raw_response(options,response,len(response))
        return parsed_response
    
    #Judy Novak Description: Send a SYN with bad TCP checksum and TCP Timestamp value of 100.
    #Follow with a SYN with a good TCP checksum and a Timestamp value of 10.  Rest of session uses TS of 10.
    def jnovak_multiple_syns(self,options,host,port,payload):
    	from ironbee_test_utils import *
        self.next_seq = 0
        self.my_ack = 0
        self.pkt_list = []
        self.seq_seen = []
        self.topt = None
        self.log = options.log
        
        self.log.debug("attempting to send %s:%s %s" % (host,port,payload))
        self.sp = random.randint(1024,65535)
        self.dp = port
        
        self.isn = random.randint(0,4294967295)
        
        self.parts = payload_splitter(options,payload,2)
    
        #Scapy works behind the kernel's back so we need to filter outbound resets on this connection
        self.insert_iptables_rule = "iptables -I OUTPUT -p tcp -d %s --dport %s --sport %s --tcp-flags RST RST -j DROP" % (host,port,self.sp)
        self.rm_iptables_rule = "iptables -D OUTPUT -p tcp -d %s --dport %s --sport %s --tcp-flags RST RST -j DROP" % (host,port,self.sp)
    
        self.log.debug("attempting to add fw rule to filter resets from target")
        cmd_wrapper(options,self.insert_iptables_rule,True)    
        self.dip = socket.gethostbyname(host)
        self.ip=IP(dst=self.dip)
        
        self.topt = [('MSS', 1460), ('NOP', None), ('NOP', None), ('Timestamp', (100, 0)), ]
        SYN=TCP(sport=self.sp, dport=port, flags="S", seq=self.isn, chksum=1234, options=self.topt)
        send(self.ip/SYN)
        
        
        self.topt = [('MSS', 1460), ('NOP', None), ('NOP', None), ('Timestamp', (10, 0)), ]
        SYN=TCP(sport=self.sp, dport=port, flags="S", seq=self.isn, options=self.topt)
        SYNACK=sr1(self.ip/SYN)
        
        self.my_ack = SYNACK.seq + 1 
        self.next_seq = self.isn + 1
        
        self.topt = [ ('NOP', None), ('NOP', None), ('Timestamp', (10, 0)), ]
        ACK=TCP(ack=self.my_ack, sport=self.sp, dport=port, flags="A", seq=self.next_seq, options=self.topt)
        send(self.ip/ACK)
        
        PUSH=TCP(ack=self.my_ack, seq=self.next_seq, sport=self.sp, dport=port, flags="PA", options=self.topt)
        send(self.ip/PUSH/self.parts[1])
        self.next_seq = ACK.seq + len(self.parts[1])  
        time.sleep(1)
        
        PUSH=TCP(ack=self.my_ack, seq=self.next_seq, sport=self.sp, dport=port, flags="PA", options=self.topt)
        send(self.ip/PUSH/self.parts[2])
        self.next_seq = len(self.parts[2])
        
        try:
            sniff(filter="tcp and src %s and port %s and port %s" % (self.dip,port,self.sp), prn=self.callback, timeout=120)
        except NameError:
            self.log.debug("all done join packets")
            self.log.debug(self.pkt_list)
         
        response = ''.join(self.pkt_list)
            
        cmd_wrapper(options,self.rm_iptables_rule,True)
        self.log.debug("scapy_response:\n%s" % (response))
        parsed_response = parse_raw_response(options,response,len(response))
        return parsed_response
    
    #Judy Novak Description: Establish and close a session.  
    #Immediately restart it with an ISN 1 more than previous one and send "malicious" payload.  
    #For Linux test, wrote a script to immediately restart netcat for 2nd session since it doesn't have a persistent listen option like Windows.
    def jnovak_rst_syn_again(self,options,host,port,payload):
    	from ironbee_test_utils import *
        self.next_seq = 0
        self.my_ack = 0
        self.pkt_list = []
        self.seq_seen = []
        self.topt = None
        self.log = options.log
 
        self.log.debug("attempting to send %s:%s %s" % (host,port,payload))
        self.sp = random.randint(1024,65535)
        self.dp = port
        
        self.isn = random.randint(0,4294967295)
        
        self.parts = payload_splitter(options,payload,2)
    
        #Scapy works behind the kernel's back so we need to filter outbound resets on this connection
        self.insert_iptables_rule = "iptables -I OUTPUT -p tcp -d %s --dport %s --sport %s --tcp-flags RST RST -j DROP" % (host,port,self.sp)
        self.rm_iptables_rule = "iptables -D OUTPUT -p tcp -d %s --dport %s --sport %s --tcp-flags RST RST -j DROP" % (host,port,self.sp)
    
        self.log.debug("attempting to add fw rule to filter resets from target")
        cmd_wrapper(options,self.insert_iptables_rule,True)    
        self.dip = socket.gethostbyname(host)
        self.ip=IP(dst=self.dip)
        
        SYN=TCP(sport=self.sp, dport=port, flags="S", seq=self.isn)
        synack=sr1(self.ip/SYN)
        self.my_ack=synack.seq + 1
        self.next_seq = self.isn+1
        
        ACK=TCP(sport=self.sp, dport=port, flags="A", seq=self.next_seq, ack=self.my_ack)
        send(self.ip/ACK)
        self.next_seq = ACK.seq    
        
        RST=TCP(ack=self.my_ack, seq=self.next_seq, sport=self.sp, dport=port, flags="RA")
        send(self.ip/RST)
        time.sleep(1)    
        
        SYN=TCP(sport=self.sp, dport=port, flags="S", seq=self.isn+1)
        SYNACK=sr1(self.ip/SYN)
        
        self.my_ack = SYNACK.seq + 1 
        self.next_seq = SYN.seq + 1
        
        ACK=TCP(sport=self.sp, dport=port, flags="A", seq=self.next_seq, ack=self.my_ack)
        send(self.ip/ACK)
        self.next_seq = ACK.seq

        PUSH=TCP(sport=self.sp, dport=port, flags="PA", seq=self.next_seq, ack=self.my_ack)
        send(self.ip/PUSH/self.parts[1])
        self.next_seq=PUSH.seq + len(self.parts[1])
        time.sleep(1)
        
        PUSH=TCP(sport=self.sp, dport=port, flags="PA", seq=self.next_seq, ack=self.my_ack)
        send(self.ip/PUSH/self.parts[2])
        self.next_seq=PUSH.seq + len(self.parts[2])

        try:
            sniff(filter="tcp and src %s and port %s and port %s" % (self.dip,port,self.sp), prn=self.callback, timeout=120)
        except NameError:
            self.log.debug("all done join packets")
            self.log.debug(self.pkt_list)
            
        response = ''.join(self.pkt_list)
    
        cmd_wrapper(options,self.rm_iptables_rule,True)
        self.log.debug("scapy_response:\n%s" % (response))
        parsed_response = parse_raw_response(options,response,len(response))
        return parsed_response
    
    #Judy Novak Description: Send a SYN with PUSH flag set.  Linux and Windows Vista accept this.
    def jnovak_syn_pushflag(self,options,host,port,payload):
    	from ironbee_test_utils import * 
        self.next_seq = 0
        self.my_ack = 0
        self.pkt_list = []
        self.seq_seen = []
        self.topt = None
        self.log = options.log
        
        self.log.debug("attempting to send %s:%s %s" % (host,port,payload))
        self.sp = random.randint(1024,65535)
        self.dp = port
        
        self.isn = random.randint(0,4294967295)
        
        self.parts = payload_splitter(options,payload,2)
    
        #Scapy works behind the kernel's back so we need to filter outbound resets on this connection
        self.insert_iptables_rule = "iptables -I OUTPUT -p tcp -d %s --dport %s --sport %s --tcp-flags RST RST -j DROP" % (host,port,self.sp)
        self.rm_iptables_rule = "iptables -D OUTPUT -p tcp -d %s --dport %s --sport %s --tcp-flags RST RST -j DROP" % (host,port,self.sp)
    
        self.log.debug("attempting to add fw rule to filter resets from target")
        cmd_wrapper(options,self.insert_iptables_rule,True)    
        self.dip = socket.gethostbyname(host)
        self.ip=IP(dst=self.dip)
        
        SYN=TCP(sport=self.sp, dport=port, flags="SP", seq=self.isn)
        synack=sr1(self.ip/SYN)
        self.my_ack=synack.seq + 1
        self.next_seq = SYN.seq + 1
        
        ACK=TCP(sport=self.sp, dport=port, flags="A", seq=self.next_seq, ack=self.my_ack)
        send(self.ip/ACK)
        
        PUSH=TCP(sport=self.sp, dport=port, flags="PA", seq=self.next_seq, ack=self.my_ack)
        send(self.ip/PUSH/self.parts[1])
        self.next_seq=PUSH.seq + len(self.parts[1])
        time.sleep(1)
        
        PUSH=TCP(sport=self.sp, dport=port, flags="PA", seq=self.next_seq, ack=self.my_ack)
        send(self.ip/PUSH/self.parts[2])
        self.next_seq=PUSH.seq + len(self.parts[2])

        try:
            sniff(filter="tcp and src %s and port %s and port %s" % (self.dip,port,self.sp), prn=self.callback, timeout=120)
        except NameError:
            self.log.debug("all done join packets")
            self.log.debug(self.pkt_list)
            
        response = ''.join(self.pkt_list)
    
        cmd_wrapper(options,self.rm_iptables_rule,True)
        self.log.debug("scapy_response:\n%s" % (response))
        parsed_response = parse_raw_response(options,response,len(response))
        return parsed_response    
    
    #Send a SYN with URG flag set.  Linux and Window Vista accept this.
    def jnovak_syn_urgflag(self,options,host,port,payload):
    	from ironbee_test_utils import *    
        self.next_seq = 0
        self.my_ack = 0
        self.pkt_list = []
        self.seq_seen = []
        self.topt = None
        self.log = options.log
 
        self.log.debug("attempting to send %s:%s %s" % (host,port,payload))
        self.sp = random.randint(1024,65535)
        self.dp = port
        
        self.isn = random.randint(0,4294967295)
        
        self.parts = payload_splitter(options,payload,2)
    
        #Scapy works behind the kernel's back so we need to filter outbound resets on this connection
        self.insert_iptables_rule = "iptables -I OUTPUT -p tcp -d %s --dport %s --sport %s --tcp-flags RST RST -j DROP" % (host,port,self.sp)
        self.rm_iptables_rule = "iptables -D OUTPUT -p tcp -d %s --dport %s --sport %s --tcp-flags RST RST -j DROP" % (host,port,self.sp)
    
        self.log.debug("attempting to add fw rule to filter resets from target")
        cmd_wrapper(options,self.insert_iptables_rule,True)    
        self.dip = socket.gethostbyname(host)
        self.ip=IP(dst=self.dip)
        
        SYN=TCP(sport=self.sp, dport=port, flags="SU", seq=self.isn)
        synack=sr1(self.ip/SYN)
        self.my_ack=synack.seq + 1
        self.next_seq = SYN.seq + 1
        
        ACK=TCP(sport=self.sp, dport=port, flags="A", seq=self.next_seq, ack=self.my_ack)
        send(self.ip/ACK)
        
        PUSH=TCP(sport=self.sp, dport=port, flags="PA", seq=self.next_seq, ack=self.my_ack)
        send(self.ip/PUSH/self.parts[1])
        self.next_seq=PUSH.seq + len(self.parts[1])
        time.sleep(1)
        
        PUSH=TCP(sport=self.sp, dport=port, flags="PA", seq=self.next_seq, ack=self.my_ack)
        send(self.ip/PUSH/self.parts[2])
        self.next_seq=PUSH.seq + len(self.parts[2])

        try:
            sniff(filter="tcp and src %s and port %s and port %s" % (self.dip,port,self.sp), prn=self.callback, timeout=120)
        except NameError:
            self.log.debug("all done join packets")
            self.log.debug(self.pkt_list)
            
        response = ''.join(self.pkt_list)
    
        cmd_wrapper(options,self.rm_iptables_rule,True)
        self.log.debug("scapy_response:\n%s" % (response))
        parsed_response = parse_raw_response(options,response,len(response))
        return parsed_response    

