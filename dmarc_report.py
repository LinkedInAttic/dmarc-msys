#!/usr/bin/env python
#--
#-- DMARC report generator
#-- 
#Copyright 2012 Linkedin
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.

import sys
from datetime import date
from datetime import timedelta
import time
import getopt
import os
import errno
import dns.resolver
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.encoders import encode_base64
import zipfile
from struct import *
from socket import *


# change the following to suit your organisation
dmarclog = "/var/log/eccluster/"
dmarcreport = "/var/log/dmarcreports/"
org_name = "example.com"
org_email = "postmaster@example.com"
extra_contact_info = "http://help.example.com"
report_id = "stuff"
report_from = 'dmarc-noreply@example.com'

debugemail='fmartin@example.com'

# no more changes after here

def usage():
    print "dmarc_report.py parses log files created by momentum and generate daily aggregate reports"

def ip_isprivate(ip):
  f = unpack('!I',inet_pton(AF_INET,ip))[0]
  private = (["127.0.0.0","255.0.0.0"],["192.168.0.0","255.255.0.0"],["172.16.0.0","255.240.0.0"],["10.0.0.0","255.0.0.0"])
  for net in private:
    mask = unpack('!I',inet_aton(net[1]))[0]
    p = unpack('!I',inet_aton(net[0]))[0]
    if (f & mask) == p:
      return True
  return False

def dmarc_report_email(domain):
  domain=domain.lower()
  emaillist=[]

  try:
    answers = dns.resolver.query('_dmarc.%s' % domain, 'TXT')
  except dns.exception.DNSException as e:
    answers=[]
  for rdata in answers:
    dnstxt=rdata.to_text()
    if dnstxt[1:9]=="v=DMARC1":
       dnstxt=dnstxt[1:-1]
       records=dnstxt.split(";")
       for record in records:
          record=record.strip()
          if record[0:4]=="rua=":
            rua=record[4:].split(',')
            for mail in rua:
              if mail[0:7]=="mailto:":
                email=mail[7:]
                (elocal,edomain)=email.split('@')
                edomain=edomain.lower()
                if edomain.find(domain) or edomain==domain:
                  emaillist.append(email)
                else:
                  try:
                    reportanswers = dns.resolver.query('%s._report._dmarc.%s' % (domain,edomain), 'TXT')
                  except dns.exception.DNSException as e:
                    reportanswers=[]
                  for reportdata in reportanswers:
                    reportdatatxt=reportdata.to_text()
                    if reportdatatxt[1:9]=="v=DMARC1":
                      emaillist.append(email)
  return emaillist

try:
    opts, args = getopt.getopt(sys.argv[1:], "hc:d", ["help", "days="])                                
except getopt.GetoptError, err:
        usage()
        sys.exit(2)
global debug
debug = False
days = 1
for opt, arg in opts:
    if opt in ("-h", "--help"):
        usage()     
        sys.exit()
    elif opt == '-d':
        debug = True
    elif opt in ("-c", '--days'):
        days = int(arg)


today = date.today()
yesterday = today - timedelta(days)
day1 = time.mktime(yesterday.timetuple())
dday2 = today - timedelta(days-1)
day2 = time.mktime(dday2.timetuple())

directory = '%s%s/dmarclog/' % (dmarclog,yesterday.strftime('%Y/%m/%d'))

dicreport = {}

if debug: print(directory)
for root, dirs, files in os.walk(directory):
  if debug: print root, dirs, files
  for file in files:
    filename = '%s/%s' % (root,file)
    if debug: print filename
    f = open(filename)
    for line in f:
      try:
        (tag,timestamp,domain,ip,record) = line.split('@',4)
	if tag == "DMARC" and not ip_isprivate(ip):
          record = ip+'@'+record
          if dicreport.has_key(domain):
             dicrecord=dicreport[domain]
             if dicrecord.has_key(record):
		dicrecord[record]=dicrecord[record]+1
             else:
                dicrecord[record]=1
             dicreport[domain]=dicrecord
          else:
             dicrecord = {}
	     dicrecord[record]=1
             dicreport[domain]=dicrecord
             
      except ValueError:
        pass
    f.close()

for domain in dicreport:
  print domain
  sday1 = "%s" % day1
  sday1 = sday1[0:-2]
  sday2 = "%s" % day2
  sday2 = sday2[0:-2]
  filename = "%s!%s!%s!%s" % (org_name,domain,sday1,sday2)
  directory = '%s%s' % (dmarcreport,yesterday.strftime('%Y/%m/%d'))
  report_unique_id = "%s!%s" % (report_id,filename)
  if debug: print ('%s/%s.xml' % (directory,filename))
  try:
    os.makedirs(directory)
  except OSError, e:
    if e.errno != errno.EEXIST:
        raise

  frep = open ('%s/%s.xml' % (directory,filename),"w")

  frep.write('<?xml version="1.0" encoding="UTF-8" ?>\n')
  frep.write('<feedback>\n')
  frep.write('  <report_metadata>\n')
  frep.write('    <org_name>%s</org_name>\n' % org_name)
  frep.write('    <email>%s</email>\n' % org_email)
  frep.write('    <extra_contact_info>%s</extra_contact_info>\n' % extra_contact_info)
  frep.write('    <report_id>%s</report_id>\n' % report_unique_id)
  frep.write('    <date_range>\n')
  frep.write('      <begin>%s</begin>\n' % sday1)
  frep.write('      <end>%s</end>\n' % sday2)
  frep.write('    </date_range>\n')
  frep.write('  </report_metadata>\n')

  dicrecord = dicreport[domain]

  policy_published=""
  for record in dicrecord:
    (ip,adkim,aspf,p,sp,policy_requested,pct,disposition,dmarc_dkim,dmarc_spf,header_from,spf,spf_domain,spf_result,dkim) = record.split('@',14)
    dkim = dkim[0:-1]
    new_policy_published = ('%s@%s@%s@%s@%s@%s' % (domain,adkim,aspf,p,sp,pct))
    if new_policy_published != policy_published:
      frep.write('  <policy_published>\n')
      frep.write('    <domain>%s</domain>\n' % domain)
      frep.write('    <adkim>%s</adkim>\n' % adkim)
      frep.write('    <aspf>%s</aspf>\n' % aspf)
      frep.write('    <p>%s</p>\n' % p)
      frep.write('    <sp>%s</sp>\n' % sp)
      frep.write('    <pct>%s</pct>\n' % pct)
      frep.write('  </policy_published>\n')
      policy_published = new_policy_published
    frep.write('  <record>\n')
    frep.write('   <row>\n')
    frep.write('     <source_ip>%s</source_ip>\n' % ip)
    frep.write('     <count>%s</count>\n' % dicrecord[record])
    frep.write('     <policy_evaluated>\n')
    frep.write('       <disposition>%s</disposition>\n' % disposition)
    frep.write('       <dkim>%s</dkim>\n' % dmarc_dkim)
    frep.write('       <spf>%s</spf>\n' % dmarc_spf)
    frep.write('     </policy_evaluated>\n')
    frep.write('   </row>\n')
    frep.write('   <identifiers>\n')
    frep.write('     <header_from>%s</header_from>\n' % header_from)
    frep.write('   </identifiers>\n')
    frep.write('   <auth_results>\n')
    frep.write('     <spf>\n')
    frep.write('       <domain>%s</domain>\n' % spf_domain)
    frep.write('       <result>%s</result>\n' % spf_result)
    frep.write('     </spf>\n')
    # let's iterate over dkim
    (tag,dkim) = dkim.split('@',1)
    if tag=="DKIM":
      partdkim=dkim.split('@')
      for i in range(0,len(partdkim),2):
        frep.write('     <dkim>\n')
        frep.write('       <domain>%s</domain>\n' % partdkim[i])
        frep.write('       <result>%s</result>\n' % partdkim[i+1])
        frep.write('     </dkim>\n')
    frep.write('   </auth_results>\n')
    frep.write('  </record>\n')
  frep.write('</feedback>\n')

  frep.close()
  #report is finished, ship it?
  emaillist=dmarc_report_email(domain)
  print emaillist
  if debug: emaillist=[debugemail]

  #first compress
  zf = zipfile.ZipFile('%s/%s.zip' % (directory,filename), mode='w')
  try:
    zf.write('%s/%s.xml' % (directory,filename), filename+'.xml')
  finally:
    zf.close()
 
  for email in emaillist:
    #then encode in a message
    fp = open('%s/%s.zip' % (directory,filename))
    zipmsg = MIMEApplication(fp.read(),'zip',_encoder=encode_base64)
    fp.close()
    zipmsg.add_header('Content-Disposition', 'attachment', filename=filename+'.zip')

    msg = MIMEMultipart()
    msg['From']=report_from
    msg['To']=email
    msg['Subject']=filename
    msg.attach(zipmsg)
   
    # and ship
    s = smtplib.SMTP('localhost')
    s.sendmail(report_from, email, msg.as_string())
    s.quit()
