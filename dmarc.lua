--
-- DMARC parsing validating and reporting
-- 
--[[ Copyright 2012 Linkedin

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
   ]]
-- version 1.19
--

--[[ This requires the dp_config.lua scripts to contain a dmarc entry
--that will specify whitelists when the policy should not be applied.
--ruf: to enable sending forensic reports. If there is an email, reports
--will also be sent to this address regarding of the domain policy,
--if external is false no report is sent but to the email address.
--debug: to enable verbose logging in paniclog
--check_domain: verify that the domain in From: header can be emailed
--check_domain_debug: logs but do not reject the email

-- DMARC check
msys.dp_config.dmarc = {
    debug = true,
    check_domain = true,
    check_domain_debug = true,
  ruf = {
    enable = true,
    email = "dmarc@example.com",
    external = false
  },
  local_policy = {
    check = true,
    honor_whitelist = { "whitelist" }
  },
  trusted_forwarder = {
    check = true,
    honor_whitelist = { "whitelist" }
  },
  mailing_list = {
    check = true,
    honor_whitelist = { "whitelist" }
  }
};

The following functions are required in custom_policy.lua, 
this will load domains that pass dkim in dmarc_dkim_domains
and all the domains that have a DKIM-Signature header
note: ec_dkim_domains returns the domain in i= if found otherwise d= 

siv/dmarc_dkim.siv
-- siv-begin
$domains = ec_dkim_domains;

if isset $domains 0 {
  $domains_string = join " " $domains;
} else {
  $domains_string = "";
}
 
vctx_mess_set "dmarc_dkim_domains" $domains_string;
-- siv-end

/opt/msys/ecelerity/etc/conf/default/lua/dmarc-msys.lua
function msys.dp_config.custom_policy.pre_validate_data(msg, ac, vctx)
-- the following has a memory leak so we use a sieve script instead
--  local domains = msys.validate.dkim.get_domains(msg, vctx);
--  vctx:set(msys.core.VCTX_MESS, "dmarc_dkim_domains",domains);
-- 
--  
  --- see if there are DKIM headers in the message                                 
  local dkim_domains ="";
  local dkim_domainsi = "";
  local dk=msg:header('DKIM-Signature');
  local ddomain = "";
  local idomain = "";
  for k,v in pairs(dk) do
    print ("DKIM:"..tostring(v));
    ddomain ="";
    idomain = ""
    local dke = explode(";",v);
    for i=0,#dke do
      -- print ("dke:"..tostring(dke[i]));
      if string.sub(dke[i],2,3) == "d=" then
         ddomain = string.lower(string.sub(dke[i],4));
      end
      if string.sub(dke[i],2,3) == "i=" then
         local itag = string.lower(string.sub(dke[i],4));
         local var = msys.pcre.match(itag,"^.*@(?<domain>\\w+)$");
         if var then
           idomain = var["domain"];
         end
      end
    end
    dkim_domains =  dkim_domains .. " " .. ddomain;
    if idomain ~= "" then
      dkim_domainsi =  dkim_domainsi .. " " .. idomain;
    else
      dkim_domainsi =  dkim_domainsi .. " " .. ddomain;
    end
  end  
  vctx:set(msys.core.VCTX_MESS, "dkim_domains",dkim_domains);
  vctx:set(msys.core.VCTX_MESS, "dkim_domainsi",dkim_domainsi);
  
  -- rewriting authentication results to follow RFC5451
  local spf = msg:context_get(msys.core.ECMESS_CTX_MESS,"spf_status");
  local domains = msys.pcre.split(vctx:get(msys.core.VCTX_MESS, "dmarc_dkim_domains"), "\\s+");
  local dkim_domains = msys.pcre.split(dkim_domains, "\\s+");
  local dkim_domainsi = msys.pcre.split(dkim_domainsi, "\\s+");

  local mailfrom = msg:mailfrom();
  local hostname = tostring(gethostname());
  
  local authentication_results = tostring(hostname) .. "; iprev=pass policy.iprev="..ip_from_addr_and_port(tostring(ac.remote_addr)).."; spf="..tostring(spf).." smtp.mailfrom="..tostring(mailfrom);

  if dkim_domainsi ~= nil and #dkim_domainsi >= 1 then
    for i=1,#dkim_domainsi do
        local found=false;
        if domains ~= nil and #domains >= 1 then
          for j=1,#domains do
            if domains[j] == dkim_domainsi[i] then
              found=true;
            end
          end
        end
        if found then
          authentication_results = authentication_results .. "; dkim=pass header.d=" .. tostring(dkim_domains[i]);
        else
          authentication_results = authentication_results .. "; dkim=fail header.d=" .. tostring(dkim_domains[i]);
        end
    end
  else
    authentication_results = authentication_results .. "; dkim=neutral (message not signed) header.d=none";
  end
  -- remove all authentication-results as we will put ours
  msg:header('Authentication-Results',"");
  
  local ret = dmarc_validate_data(msg, ac, vctx, authentication_results);

  if ret == nil then
    ret=msys.core.VALIDATE_CONT;
  end
  
  return ret;
end

And don't forget to load the sieve script and the lua module in the ecelerity.conf

sieve "sieve1" {
  Script data_phase1 {
     Source = "siv/dmarc_dkim.siv"
  }
}

scriptlet "scriptlet" {
  # this loads default scripts to support enhanced control channel features
  script "boot" {
    source = "msys.boot"
  }
  script "dmarc" {
    source = "lua/dmarc-msys"
  }
}

]]

require("msys.pbp");
require("msys.core");
require("dp_config");
require("msys.validate.dkim");
require("msys.extended.vctx");
require("msys.extended.message");

local mod = {};
local jlog;
local debug = false;

if msys.dp_config.dmarc.debug ~= nil and
  msys.dp_config.dmarc.debug == true then
  debug = true;
end

-- explode(seperator, string)
local function explode(d,p)
  local t, ll, i
  t={[0]=""}
  ll=0
  i=0;
  if(#p == 1) then return {p} end
  while true do
    l=string.find(p,d,ll,true) -- find the next d in the string
    if l~=nil then -- if "not not" found then..
      t[i] = string.sub(p,ll,l-1); -- Save it in our array.
      ll=l+1; -- save just after where we found it for searching next time.
      i=i+1;
    else
      t[i] = string.sub(p,ll); -- Save what's left in our array.
      break -- Break at end, as it should be, according to the lua manual.
    end
  end
  return t
end

-- IPv4 and IPv6
local function ip_from_addr_and_port(addr_and_port)
  local ip="UNKNOWN";
  local _, count = string.gsub(addr_and_port, ":", "")
  if debug then print("addr_and_port"..tostring(addr_and_port)); end
  if addr_and_port ~= nil then
    if count<2 then
      ip = string.match(addr_and_port, "(.*):%d");
    else
      ip = string.match(addr_and_port, "(.*)%.%d");
    end
  end
  if ip == nil then
    print("can't decode:"..tostring(addr_and_port));
    ip="UNKNOWN";
  end
  if debug then print("ip"..tostring(ip)); end
  return ip;
end

local function dmarc_log(report)
  if debug then print("dmarc_log"); end
  if (jlog == nil) then
    jlog = msys.core.io_wrapper_open("jlog:///var/log/ecelerity/dmarclog.cluster=>master", msys.core.O_CREAT | msys.core.O_APPEND | msys.core.O_WRONLY, 0660);
  end
  jlog:write(report,string.len(report));
  if debug then print("end of dmarc_log");end
end

psl = nil
function loadpsl()
   local psl={};
   file = "/opt/msys/ecelerity/etc/conf/default/lua/pslpuny.txt"
   for line in io.lines(file) do 
      local mark="";
      local domain = line;
      if string.sub(line,1,1)=="*"  then
         mark = "*";
         domain = string.sub(line,3); 
      end
      if string.sub(line,1,1)=="!" then
         mark = "!";
         domain = string.sub(line,2); 
      end   
      psl[domain]=mark;
  end
  return psl;
end

function getOrgDomain(domain)
   if psl==nil then
      psl=loadpsl();
   end
   if psl==nil then
      return(nil);
   end

   domain=string.lower(tostring(domain));
   if string.sub(domain,1,1)=="." then
      domain=string.sub(domain,2);
   end
   if domain=="nil" then
      return(nil);
   end

   t = explode(".",domain);
   local found=false;
   if t ~= nil and #t >= 1 then
      seekdomain=t[#t];
      for j=#t,0,-1 do         
         if psl[seekdomain] then
            if psl[seekdomain]=="" then
               if j>=1 then
                  orgDomain=t[j-1].."."..seekdomain;
               else
                  orgDomain=nil;
               end
            elseif psl[seekdomain]=="*" then
               if j>=2 then
                  orgDomain=t[j-2].."."..t[j-1].."."..seekdomain;
               else
                  orgDomain=nil;
               end
            elseif psl[seekdomain]=="!" then
               orgDomain=seekdomain;
            else
               orgDomain=seekdomain;
            end
            found=true;
         else
            if found then
               break;
            end
         end
         if j>=1 then
            seekdomain=t[j-1].."."..seekdomain;
         end
      end
      if found then
         return(orgDomain);
      end
      
      if #t>=1 then
         orgDomain=t[#t-1].."."..t[#t]
      else
         orgDomain=nil;
      end
      return(orgDomain)
   else
      return(nil);
   end
   return(nil);
end

local function dmarc_find(domain)
  local dmarc_found = false;
  local dmarc_record = "";
  local results, errmsg = msys.dnsLookup("_dmarc." .. tostring(domain), "txt");
  if results ~= nil then
    for k,v in ipairs(results) do
      if string.sub(v,1,8) == "v=DMARC1" then
        dmarc_found = true;
        dmarc_record = v;
        break;
      end
    end
  end
  return dmarc_found, dmarc_record;
end

local function dmarc_search(from_domain)
  -- Now let's find if the domain has a DMARC record using the public suffix list.
  local dmarc_found = false;
  local dmarc_record = "";

  local domain;
  local domain_policy = false;

  domain = string.lower(from_domain);
  dmarc_found, dmarc_record = dmarc_find(domain);
  if dmarc_found == false then
    domain = getOrgDomain(domain);
    if domain ~= nil then
      dmarc_found, dmarc_record = dmarc_find(domain);
    else
      domain = string.lower(from_domain);
    end
  else
    domain_policy = true;
  end

  if debug and dmarc_found then 
    print("dmarc_record:"..tostring(dmarc_record));
    print("domain:"..tostring(domain));
    print("domain_policy:"..tostring(domain_policy));
  end  
  return dmarc_found,dmarc_record,domain,domain_policy;
end

local function dmarc_search2(from_domain)
  -- Now let's find if the domain has a DMARC record using DNS tree traversal.
  local dmarc_found = false;
  local dmarc_record = "";

  local t = msys.pcre.split(string.lower(from_domain), "\\.");
  local domain;
  local domain_policy = false;
  if t ~= nil and #t >= 2 then
    domain = string.lower(from_domain);
    dmarc_found, dmarc_record = dmarc_find(domain);
    if dmarc_found == false then
      for j=math.min(#t-2,4),1,-1 do
        if j==1 then
          domain = t[#t - 1] .. "." .. t[#t];
          dmarc_found, dmarc_record = dmarc_find(domain);
          if dmarc_found then
            break;
          end        
        end
        if j==2 then
          domain = t[#t - 2] .. "." .. t[#t - 1] .. "." .. t[#t];
          dmarc_found, dmarc_record = dmarc_find(domain);
          if dmarc_found then
            break;
          end
        end
        if j==3 then
          domain = t[#t - 3] .. "." .. t[#t - 2] .. "." .. t[#t - 1] .. "." .. t[#t];
          dmarc_found, dmarc_record = dmarc_find(domain);
          if dmarc_found then
            break;
          end
        end
        if j==4 then
          domain = t[#t - 4] .. "." .. t[#t - 3] .. "." .. t[#t - 2] .. "." .. t[#t - 1] .. "." .. t[#t];
          dmarc_found, dmarc_record = dmarc_find(domain);
          if dmarc_found then
            break;
          end
        end
      end
    else
      domain_policy = true;
    end
  end

  if debug and dmarc_found then 
    print("dmarc_record:"..tostring(dmarc_record));
    print("domain:"..tostring(domain));
    print("domain_policy:"..tostring(domain_policy));
  end  
  return dmarc_found,dmarc_record,domain,domain_policy;
end

local function ruf_mail_list(ruf,domain)
  local maillist="";
  if msys.dp_config.dmarc.ruf.email ~= nil then
    maillist=msys.dp_config.dmarc.ruf.email..",";
  end
  if msys.dp_config.dmarc.ruf.external==nil or msys.dp_config.dmarc.ruf.external==false then
    maillist=string.sub(maillist,1,-2);
    return maillist;
  end
  if ruf==nil or ruf=="" then
    return maillist;
  end
  local kv_pairs = msys.pcre.split(ruf, "\\s*,\\s*");
  for k, v in ipairs(kv_pairs) do
    local ruflocal,rufdomain = string.match(v, "mailto:%s*(.+)@(.+)");
    ruflocal = string.lower(tostring(ruflocal));
    rufdomain = string.lower(tostring(rufdomain));
    if debug then print ("ruf:"..ruflocal.."@"..rufdomain); end
    if string.find("."..rufdomain, "."..domain, 1, true) ~=nil then
      maillist=maillist..ruflocal.."@"..rufdomain..",";
    else
      local results, errmsg = msys.dnsLookup(domain.."._report._dmarc." .. tostring(rufdomain), "txt");
      if results ~= nil then
        for k2,v2 in ipairs(results) do
          if string.sub(v2,1,8) == "v=DMARC1" then
            maillist=maillist..ruflocal.."@"..rufdomain..",";
            break;
          end
        end
      end
    end
  end
  maillist=string.sub(maillist,1,-2);
  return maillist;
end

local function dmarc_forensic(ruf,domain,dmarc_status, ip, delivery, msg)
  local maillist = ruf_mail_list(ruf,domain);
  if debug then print("ruf mail list:"..maillist); end
  if maillist==nil or maillist=="" then
    return msys.core.VALIDATE_CONT;
  end 
  -- get the mesage ready to be sent
  
  local headers = {};
  
  local imsg = msys.core.ec_message_new(now);
  local imailfrom = "dmarc-noreply@linkedin.com";
  local mailfrom = msg:mailfrom();
  local rcptto = msg:rcptto();
  local msgidtbl = msg:header("Message-Id");
  local msgid = "";
  if msgidtbl ~= nil and #msgidtbl>=1 then
    msgid = msgidtbl[1];
  end
  local today = os.date("%a, %d %b %Y %X %z")

  headers["To"] = "dmarc-noreply@linkedin.com";
  headers["From"] = "dmarc-noreply@linkedin.com";
  headers["Subject"] = "DMARC Forensic report for "..tostring(domain).." Mail-From:"..tostring(mailfrom).." IP:"..tostring(ip);

  local parttext = "Content-Type: text/plain; charset=\"US-ASCII\"\r\n"..
  "Content-Transfer-Encoding: 7bit\r\n\r\n"..
  "This is an email abuse report for an email message received from IP "..tostring(ip).." on "..tostring(today)..".\r\n"..
  "The message below did not meet the sending domain's dmarc policy.\r\n"..
  "For more information about this format please see http://tools.ietf.org/html/rfc6591 .\r\n\r\n";

  local partfeedback = "Content-Type: message/feedback-report\r\n\r\n"..
  "Feedback-Type: auth-failure\r\n"..
  "User-Agent: Lua/1.0\r\n"..
  "Version: 1.0\r\n"..
  "Original-Mail-From: "..tostring(mailfrom).."\r\n"..
  "Original-Rcpt-To: "..tostring(rcptto).."\r\n"..
  "Arrival-Date: "..today.."\r\n"..
  "Message-ID: "..tostring(msgid).."\r\n"..
  "Authentication-Results: "..tostring(dmarc_status).."\r\n"..
  "Source-IP: "..tostring(ip).."\r\n"..
  "Delivery-Result: "..tostring(delivery).."\r\n"..
  "Auth-Failure: dmarc\r\n"..
  "Reported-Domain: "..tostring(domain).."\r\n\r\n";

  ---- build message
  -- insert headers
  local io = msys.core.ec_message_builder(imsg,2048);
  -- write the headers
  local boundary = imsg:makeBoundary();
  local len_boundary = #boundary;
  local k,v;
  for k,v in pairs(headers) do
    if string.lower(k) != "content-type" and v != nil then
      io:write(k, #k);
      io:write(": ", 2);
      io:write(v, #v);
      io:write("\r\n", 2);
    end
  end
  local tmp = "Content-Type: multipart/report; report-type=feedback-report;\r\n    boundary=\""..boundary.."\"\r\n";
  io:write(tmp, #tmp);

  io:write("\r\n", 2);

  -- first boundary: text
  io:write("--", 2);
  io:write(boundary, len_boundary);
  io:write("\r\n", 2);

  io:write(parttext, #parttext);

  -- second boundary: feedback report

  io:write("--", 2);
  io:write(boundary, len_boundary);
  io:write("\r\n", 2);

  io:write(partfeedback, #partfeedback);

  -- third boundary: attached email
  io:write("--", 2);
  io:write(boundary, len_boundary);
  io:write("\r\n", 2);

  io:write("Content-Type: message/rfc822\r\n", 30);
  io:write("Content-Disposition: inline\r\n\r\n", 31);

  local tmp_str = msys.core.string_new();
  tmp_str.type = msys.core.STRING_TYPE_IO_OBJECT;
  tmp_str.backing = io;
  msg:render_to_string(tmp_str, msys.core.EC_MSG_RENDER_OMIT_DOT);

  io:write("\r\n--", 4)
  io:write(boundary, len_boundary)
  io:write("--\r\n", 4)

  -- end of the message
  io:write("\r\n.\r\n", 5)
  io:close()
  io = nil

  imsg:inject(imailfrom, maillist);

  if debug then print("ruf sent"); end
  return msys.core.VALIDATE_CONT;

end

local function dmarc_work(msg, ac, vctx, authentication_results, from_domain, envelope_domain, dmarc_found, dmarc_record, domain, domain_policy)
  if debug and dmarc_found then
    print("from_domain",from_domain);
    print("envelope_domain",envelope_domain);
  end

  local ip = ip_from_addr_and_port(tostring(ac.remote_addr));

  -- Check SPF and alignment
  local spf_alignement = "none";
  local spf_status = vctx:get(msys.core.VCTX_MESS, "spf_status");
  if debug and dmarc_found then print("spf_status",spf_status); end
  if spf_status ~= nil and spf_status == "pass" then
    if from_domain == envelope_domain then
      spf_alignement="strict";
    elseif string.find("."..from_domain, "."..envelope_domain, 1, true) ~=nil or 
      string.find("."..envelope_domain, "."..from_domain, 1, true) ~=nil then
      spf_alignement = "relaxed";
    end    
  end
  if debug and dmarc_found then print("spf_alignement",spf_alignement); end

  -- Check DKIM and alignment
  local dkim_alignement = "none";
  if debug and dmarc_found then print("dmarc_dkim_domains:"..tostring(vctx:get(msys.core.VCTX_MESS, "dmarc_dkim_domains"))); end
  local dkim_domains = msys.pcre.split(vctx:get(msys.core.VCTX_MESS, "dmarc_dkim_domains"), "\\s+");
  for k, dkim_domain in ipairs(dkim_domains) do
    if dkim_domain == from_domain then
      dkim_alignement = "strict";
      break;
    elseif string.find("."..from_domain, "."..dkim_domain, 1, true) ~=nil or 
      string.find("."..dkim_domain, "."..from_domain, 1, true) ~=nil then
      dkim_alignement = "relaxed";
    end        
  end
  if debug and dmarc_found then print("dkim_alignement",dkim_alignement); end

  local real_pairs = {};
  if dmarc_found then
    local kv_pairs = msys.pcre.split(dmarc_record, "\\s*;\\s*")   
    for k, v in ipairs(kv_pairs) do
      local key, value = string.match(v, "([^=%s]+)%s*=%s*(.+)");
      local key = string.lower(tostring(key));
      real_pairs[key] = value;
      if debug then print(key.."="..value); end
    end
  end

  local dmarc_status;
  -- no policy enforcement bail out but give a status.
  if dmarc_found == false or real_pairs.v == nil or real_pairs.v ~= "DMARC1" or
    real_pairs.p == nil then     
    if spf_alignement ~= "none" or dkim_alignement ~= "none" then
      dmarc_status = "dmarc=pass (p=nil; dis=none) header.from=" .. tostring(from_domain);
    else
      dmarc_status = "dmarc=fail (p=nil; dis=none) header.from=" .. tostring(from_domain);
    end
    if debug then print(dmarc_status); end
    vctx:set(msys.core.VCTX_MESS, "dmarc_status",dmarc_status);
    if dmarc_status ~= nil then
      authentication_results = authentication_results .. "; " .. dmarc_status;
    end
    vctx:set(msys.core.VCTX_MESS, "authentication_results",tostring(authentication_results));
    msg:header('Authentication-Results', authentication_results,"prepend");
    return msys.core.VALIDATE_CONT;
  end

  -- find if we have DMARC pass with all the options
  local dmarc_spf = "fail";
  local dmarc_dkim = "fail";
  if real_pairs.aspf == nil then
    real_pairs["aspf"] = "r";
  else
    real_pairs["aspf"] = string.lower(real_pairs["aspf"]);
  end
  if real_pairs.adkim == nil then
    real_pairs["adkim"] = "r";
  else
    real_pairs["adkim"] = string.lower(real_pairs["adkim"]);
  end
  if real_pairs.aspf == "r" and spf_alignement ~= "none" then
    dmarc_spf = "pass";
  end
  if real_pairs.aspf == "s" and spf_alignement == "strict" then
    dmarc_spf = "pass";
  end
  if real_pairs.adkim == "r" and dkim_alignement ~= "none" then
    dmarc_dkim = "pass";
  end
  if real_pairs.adkim == "s" and dkim_alignement == "strict" then
    dmarc_dkim = "pass";
  end
  
  local dmarc = "fail";
  if dmarc_dkim == "pass" or dmarc_spf == "pass" then
    dmarc = "pass";    
  end
  if debug then print("dmarc",dmarc,"dmarc_spf",dmarc_spf,"dmarc_dkim",dmarc_dkim); end
  
  -- time to find the policy
  local policy_requested = "none";
  local policy = "none";
  
  if debug then print("domain_policy:"..tostring(domain_policy)); end 
  if domain_policy == false and real_pairs.sp == nil then
    domain_policy = true;
  end
  
  real_pairs["p"] = string.lower(real_pairs["p"]);
  if domain_policy == true then
    if real_pairs.p=="quarantine" or real_pairs.p=="reject" then
      policy_requested = real_pairs.p;
    end
  else
    if real_pairs.sp ~= nil then
      real_pairs["sp"] = string.lower(real_pairs["sp"]);
      if real_pairs.sp=="quarantine" or real_pairs.sp=="reject" then
        policy_requested = real_pairs.sp;
      end
    end
  end 
  
  if real_pairs.p == nil then
    real_pairs["p"] = "none"
  end

  if real_pairs.sp == nil then
    real_pairs["sp"] = real_pairs.p
  end 

  policy = policy_requested;

  if real_pairs.pct == nil then
    real_pairs["pct"] = "100";
  end
  
  if dmarc == "pass" then
    policy="none";
  else 
    -- Check if the pct argument is defined.  If so, enforce it
    if real_pairs.pct ~= nil and tonumber(real_pairs.pct) < 100 then
      if math.random(100) < tonumber(real_pairs.pct) then
        -- Not our time to run, just check and log
        if real_pairs.p ~= nil then
          if real_pairs.p == "reject" then
            policy = "quarantine";
          elseif real_pairs.p == "quarantine" then
            policy = "sampled_out";
          else
            policy = "none";
          end
        end        
      end
    end

    -- dmarc whitelist check
    if msys.dp_config.dmarc.local_policy ~= nil and
      msys.dp_config.dmarc.local_policy.check == true and
      msys.pbp.check_whitelist(vctx, msys.dp_config.dmarc.local_policy) == true then
      policy = "local_policy";
    end

    if msys.dp_config.dmarc.trusted_forwarder ~= nil and
      msys.dp_config.dmarc.trusted_forwarder.check == true and
      msys.pbp.check_whitelist(vctx, msys.dp_config.dmarc.trusted_forwarder) == true then
      policy = "trusted_forwarder";
    end

    if msys.dp_config.dmarc.mailing_list ~= nil and
      msys.dp_config.dmarc.mailing_list.check == true and
      msys.pbp.check_whitelist(vctx, msys.dp_config.dmarc.mailing_list) == true then
      local mlm = msg:header('list-id');
      if mlm ~= nil and #mlm>=1 then
        policy = "mailing_list";
      else
        local mlm = msg:header('list-post');
        if mlm ~= nil and #mlm>=1 then
          policy = "mailing_list";
        end
      end
    end
  end

  -- set the DMARC status for posterity
  dmarc_status = "dmarc="..tostring(dmarc).." (p="..tostring(policy_requested).."; dis="..tostring(policy)..")".." header.from="..tostring(from_domain);
  vctx:set(msys.core.VCTX_MESS, "dmarc_status",dmarc_status);
  if debug then print("dmarc_status",dmarc_status); end
    
  if dmarc_status ~= nil then
    authentication_results = authentication_results .. "; " .. dmarc_status;
  end
  vctx:set(msys.core.VCTX_MESS, "authentication_results",tostring(authentication_results));
  msg:header('Authentication-Results', authentication_results,"prepend");

  -- let's log in paniclog because I don't know where else to log
  local report = "DMARC1@"..tostring(msys.core.get_now_ts()).."@"..tostring(msg.id).."@"..tostring(domain).."@"..ip..
  "@"..tostring(real_pairs.adkim).."@"..tostring(real_pairs.aspf).."@"..tostring(real_pairs.p).."@"..tostring(real_pairs.sp)..
  "@"..tostring(policy_requested).."@"..tostring(real_pairs.pct).."@"..tostring(policy).."@"..tostring(dmarc_dkim).."@"..tostring(dmarc_spf)..
  "@"..tostring(from_domain).."@SPF@"..tostring(envelope_domain).."@"..tostring(spf_status).."@DKIM";

  if debug then print("dkim_domains:"..tostring(vctx:get(msys.core.VCTX_MESS, "dkim_domains"))); end
  local found_dkim_domains = msys.pcre.split(vctx:get(msys.core.VCTX_MESS, "dkim_domains"), "\\s+");
  local found_dkim_domainsi = msys.pcre.split(vctx:get(msys.core.VCTX_MESS, "dkim_domainsi"), "\\s+");

  if found_dkim_domainsi ~= nil and #found_dkim_domainsi >= 1 then
    for i=1,#found_dkim_domainsi do
      local found=false;
      if dkim_domains ~= nil and #dkim_domains >= 1 then
        for j=1,#dkim_domains do
          if debug then print(">"..found_dkim_domainsi[i].."<>"..dkim_domains[j].."<>"..found_dkim_domains[i].."<"); end
          if dkim_domains[j] == found_dkim_domainsi[i] then
            found=true;
          end
        end
      end
      if found then
        report = report .. "@" .. found_dkim_domains[i] .. "@pass";
      else
        report = report .. "@" .. found_dkim_domains[i] .. "@fail";
      end
    end
  else
    if dkim_domains ~= nil and #dkim_domains >= 1 then
      report = report .. "@" .. dkim_domains[1] .. "@pass";
    else
      report = report .. "@@none";
    end
  end
  report = report .."\n";
  if debug then print("report",report); end
  status,res = msys.runInPool("IO", function () dmarc_log(report); end, true);
  
  -- send forensic report
  if dmarc=="fail" and (policy ~= "local_policy" and policy ~= "trusted_forwarder" and policy ~= "mailing_list") then
    if msys.dp_config.dmarc.ruf.enable ~= nil and
      msys.dp_config.dmarc.ruf.enable == true then
      if real_pairs["ruf"] ~= nil and real_pairs["ruf"] ~= "" then
        real_pairs["ruf"] = string.lower(real_pairs["ruf"]);
        -- we have a ruf so we could send a forensic report
        local delivery = "delivered";
        if policy == "reject" then
          delivery = "reject";
        end
        status,res = msys.runInPool("IO", function () dmarc_forensic(real_pairs["ruf"],domain,dmarc_status, ip, delivery, msg); end, false);
      end
    end
  end
  
  -- and now we can enforce it  
  if policy == "reject" then
    local mlm = msg:header('list-id');
    if mlm ~= nil and #mlm>=1 then
      -- we found a list-id let's note that as we may want to whitelist
      print("DMARC MLM whitelist potential List-Id:"..mlm[1].." "..ip);
    end
    local mlm = msg:header('list-post');
    if mlm ~= nil and #mlm>=1 then
      -- we found a list-id let's note that as we may want to whitelist
      print("DMARC MLM whitelist potential List-Post:"..mlm[1].." "..ip);
    end
    return vctx:pbp_disconnect(550, "5.7.1 Email rejected per DMARC policy for "..tostring(domain));
  end
  
  if debug then print("end of dmarc_work"); end
  return msys.core.VALIDATE_CONT;
end

function dmarc_validate_data(msg, ac, vctx, authentication_results)

  local mailfrom = msg:mailfrom();
  
  local domains = msg:address_header("From", "domain");
  
  local headerfrom = msg:header('From');
  
  -- various checks regarding dmarc
  if #headerfrom > 1 then
    msg:header('Authentication-Results', authentication_results,"prepend");
    return vctx:pbp_disconnect(550, "5.7.1 An email with more than one From: header is invalid cf RFC5322 3.6");
  end
  
  -- various checks regarding dmarc
  if domains == nil or #domains == 0 then
    -- No From header, reject 
    if mailfrom ~= nil and mailfrom ~= "" then
      -- this is not a bounce
      if #headerfrom < 1 then
        msg:header('Authentication-Results', authentication_results,"prepend");
        return vctx:pbp_disconnect(550, "5.7.1 Can't find a RFC5322 From: header, this is annoying with DMARC and required by RFC5322 3.6");
      else
        msg:header('Authentication-Results', authentication_results,"prepend");
        return vctx:pbp_disconnect(550, "5.7.1 RFC5322 3.6.2 requires a domain in a correctly formed header From: "..tostring(headerfrom[1]));
      end
    else
      -- this is a bounce and there is no domain to tie to DMARC so bail out.
      msg:header('Authentication-Results', authentication_results,"prepend");
      return msys.core.VALIDATE_CONT;
    end
  end
  
  if #domains > 1 then
    if #domains > 2 or string.lower(domains[1]) ~= string.lower(domains[2]) then
      msg:header('Authentication-Results', authentication_results,"prepend");
      return vctx:pbp_disconnect(550, "5.7.1 It is difficult to do DMARC with an email with too many domains in the header From: "..tostring(headerfrom[1]));
    end
  end
  
  local from_domain = string.lower(domains[1]);
  local envelope_domain = string.lower(vctx:get(msys.core.VCTX_MESS,
   msys.core.STANDARD_KEY_MAILFROM_DOMAIN));

  if envelope_domain == "" then
    envelope_domain = string.lower(msys.expandMacro("%{vctx_conn:ehlo_domain}"));
  end
  
  -- let's check the domain is emailable
  if msys.dp_config.dmarc.check_domain ~= nil and
    msys.dp_config.dmarc.check_domain == true then
   
    local results, errmsg = msys.dnsLookup(from_domain, "MX");

    if results == nil and errmsg ~= "NXDOMAIN" then
      results, errmsg = msys.dnsLookup(from_domain, "A");
    end
    if results == nil and errmsg ~= "NXDOMAIN" then
      results, errmsg = msys.dnsLookup(from_domain, "AAAA");
    end

    if results == nil then
      if errmsg == "NXDOMAIN" then 
        if msys.dp_config.dmarc.check_domain_debug ~= nil and
          msys.dp_config.dmarc.check_domain_debug == true then
          local subject = msg:header('Subject');
          local to = msg:header('To');
          print ("5.7.1 Cannot email domain in From: "..tostring(headerfrom[1]).." To: "..tostring(to[1]).." Subject: "..tostring(subject[1]));
        else
          msg:header('Authentication-Results', authentication_results,"prepend");
          return vctx:pbp_disconnect(550, "5.7.1 Cannot email domain in From: "..tostring(headerfrom[1]));
        end
      else
        if msys.dp_config.dmarc.check_domain_debug ~= nil and
          msys.dp_config.dmarc.check_domain_debug == true then
          local subject = msg:header('Subject');
          local to = msg:header('To');
          print ("Check domain temporary resolution failure in From: "..tostring(headerfrom[1]).." To: "..tostring(to[1]).." Subject: "..tostring(subject[1]));
        else
          msg:header('Authentication-Results', authentication_results,"prepend");
          return vctx:pbp_action(451, "Check domain temporary resolution failure in From: "..tostring(headerfrom[1]));
        end
      end
    end   
  end


  -- Now let's find if the domain has a DMARC record.
  -- we do it here as it is more efficient than in the CPU pool
  local dmarc_found, dmarc_record, domain, domain_policy = dmarc_search(from_domain);
  
  -- If we get here we have exactly one result in results.
  local status, ret = msys.runInPool("CPU", function()
    return dmarc_work(msg, ac, vctx, authentication_results, from_domain, envelope_domain, dmarc_found, dmarc_record, domain, domain_policy);
    end);

  return ret;
end

-- vim:ts=2:sw=2:et:
