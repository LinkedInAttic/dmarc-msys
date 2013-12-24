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
#
# Version 1.4

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
import gzip
from struct import *
from socket import *
import ipaddr


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
  private = ("127.0.0.0/8","192.168.0.0/16","172.16.0.0/12","10.0.0.0/8","fc00::/7","fe80::/10")
  try:
    f=ipaddr.IPAddress(ip)
  except ValueError:
    print 'address/netmask is invalid: %s' % ip
  for net in private:
    try:
      p=ipaddr.IPNetwork(net)
    except ValueError:
      print 'address/netmask is invalid: %s' % net
    if f in p:
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
                try: 
                  (elocal,edomain)=email.split('@',1)
                except ValueError:
                  print 'email cannot be decoded: %s' % email
                  edomain=""
                  elocal=""
                  pass
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
        if line[0:6]=="DMARC1":
          (tag,timestamp,msgid,domain,ip,record) = line.split('@',5)
        else:
          (tag,timestamp,domain,ip,record) = line.split('@',4)
        if tag[0:5] == "DMARC" and not ip_isprivate(ip):
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
  filename = "%s!%s!%s!%s!%s" % (org_name,domain,sday1,sday2,report_id)
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
  frep.write('    <report_id>%s</report_id>\n' % filename)
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
    if disposition!="reject" and disposition!="quarantine" and disposition!="none":
      frep.write('       <disposition>none</disposition>\n')
    else:
      frep.write('       <disposition>%s</disposition>\n' % disposition)
    frep.write('       <dkim>%s</dkim>\n' % dmarc_dkim)
    frep.write('       <spf>%s</spf>\n' % dmarc_spf)
    if disposition!="reject" and disposition!="quarantine" and disposition!="none":
      frep.write('       <reason>\n')
      frep.write('         <type>%s</type>\n' % disposition)
      frep.write('         <comment></comment>\n')
      frep.write('       </reason>\n')
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
  zf = gzip.open('%s/%s.xml.gz' % (directory,filename),'wb')
  frep = open('%s/%s.xml' % (directory,filename),'rb')
  try:
    zf.writelines(frep)
  finally:
    zf.close()
    frep.close()
 
  for email in emaillist:
    #then encode in a message
    fp = open('%s/%s.xml.gz' % (directory,filename))
    gzipmsg = MIMEApplication(fp.read(),'gzip',_encoder=encode_base64)
    fp.close()
    gzipmsg.add_header('Content-Disposition', 'attachment', filename=filename+'.xml.gz')

    msg = MIMEMultipart()
    msg['From']=report_from
    msg['To']=email
    msg['Subject']= 'Report Domain: %s Submitter: %s Report-ID: %s' % (domain,org_name,filename)
    msg.attach(gzipmsg)

    # and ship
    try:
      s = smtplib.SMTP('localhost')
      s.sendmail(report_from, email, msg.as_string())
      s.quit()
    except Exception:
      print "Error: unable to send email"
