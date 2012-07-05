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
-- version 1.1
--

--[[ This requires the dp_config.lua scripts to contain a dmarc entry
--that will specify whitelists when the policy should not be applied.

-- DMARC check
msys.dp_config.dmarc = {
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
this will load domains that pass dkim
and all the domains that have a dkim header

function msys.dp_config.custom_policy.pre_validate_data(msg, ac, vctx)
-- the following has a memory leak so we use a sieve script instead
--  local domains = msys.validate.dkim.get_domains(msg, vctx);
--  vctx:set(msys.core.VCTX_MESS, "dmarc_dkim_domains",domains);
-- siv-begin
-- $domains = ec_dkim_domains;
--
-- if isset $domains 0 {
--   $domains_string = join " " $domains;
-- } else {
--   $domains_string = "";
-- }
-- 
-- vctx_mess_set "dmarc_dkim_domains" $domains_string;
-- siv-end
-- 
-- and we are not sure that this function is executed
-- before this module!
--  
  --- see if there are DKIM headers in the message                                 
  local dkim_domains ="";
  local dk=msg:header('DKIM-Signature');
  for k,v in pairs(dk) do
    print ("DKIM:"..tostring(v));
    dke = explode(";",v);
    for i=0,#dke do
      print ("dke:"..tostring(dke[i]));
      if string.sub(dke[i],2,3) == "d=" then
        dkim_domains =  dkim_domains .. " " .. string.lower(string.sub(dke[i],4));
      end
    end
  end  
  vctx:set(msys.core.VCTX_MESS, "dkim_domains",dkim_domains);

  local ret = dmarc_validate_data(msg, ac, vctx);

  if ret == nil then
  	ret=msys.core.VALIDATE_CONT;
  end
  
  return ret;
end

]]

require("msys.pbp");
require("msys.core");
require("dp_config");
require("msys.validate.dkim");
require("msys.extended.vctx");
require("msys.extended.message");

local mod = {};
local jlog;
local debug = true;

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
  if debug then print("addr_and_port"..tostring(addr_and_port)); end
  if addr_and_port ~= nil then
    ip = string.match(addr_and_port, "(.*):%d");
  end
  if ip == nil then
    print("can't decode:"..tostring(addr_and_port));
    ip="UNKNOWN";
  end
  if debug then print("ip"..tostring(ip)); end
  return ip;
end

local function dmarc_log(report)
  print("dmarc_log");
  if (jlog == nil) then
    jlog = msys.core.io_wrapper_open("jlog:///var/log/ecelerity/dmarclog.cluster=>master", msys.core.O_CREAT | msys.core.O_APPEND | msys.core.O_WRONLY, 0660);
  end
  jlog:write(report,string.len(report));
  print("end of dmarc_log");
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
  -- Now let's find if the domain has a DMARC record.
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


local function dmarc_work(msg, ac, vctx, from_domain, envelope_domain, dmarc_found, dmarc_record, domain, domain_policy)
  if debug and dmarc_found then
    print("from_domain",from_domain);
    print("envelope_domain",envelope_domain);
  end

  -- Check SPF and alignment
  local spf_alignement = "none";
  local spf_status = vctx:get(msys.core.VCTX_MESS, "spf_status");
  if debug and dmarc_found then print("spf_status",spf_status); end
  if spf_status ~= nil and spf_status == "pass" then
    if from_domain == envelope_domain then
      spf_alignement="strict";
    elseif string.find(from_domain, envelope_domain) ~=nil or 
           string.find(envelope_domain, from_domain) ~=nil then
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
    elseif string.find(from_domain, dkim_domain) ~=nil or 
           string.find(dkim_domain, from_domain) ~=nil then
      dkim_alignement = "relaxed";
    end        
  end
  if debug and dmarc_found then print("dkim_alignement",dkim_alignement); end

  local real_pairs = {};
  if dmarc_found then
    local kv_pairs = msys.pcre.split(dmarc_record, "\\s*;\\s*")   
    for k, v in ipairs(kv_pairs) do
      local key, value = string.match(v, "([^=%s]+)%s*=%s*(.+)");
      real_pairs[key] = value;
      if debug then print(key.."="..value); end
    end
  end
  
  local dmarc_status;
  -- no policy enforcement bail out but give a status.
  if dmarc_found == false or real_pairs.v == nil or real_pairs.v ~= "DMARC1" or
     real_pairs.p == nil then     
    if spf_alignement ~= "none" or dkim_alignement ~= "none" then
      dmarc_status = "dmarc=pass d=" .. tostring(from_domain) .. " (p=nil; dis=none)";
    else
      dmarc_status = "dmarc=fail d=" .. tostring(from_domain) .. " (p=nil; dis=none)";
    end
    vctx:set(msys.core.VCTX_MESS, "dmarc_status",dmarc_status);
    return msys.core.VALIDATE_CONT;
  end
  
  -- find if we have DMARC pass with all the options
  local dmarc_spf = "fail";
  local dmarc_dkim = "fail";
  if real_pairs.aspf == nil then
    real_pairs["aspf"] = "r";
  end
  if real_pairs.adkim == nil then
    real_pairs["adkim"] = "r";
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
  
  if domain_policy == true then
    if real_pairs.p=="quarantine" or real_pairs.p=="reject" then
      policy_requested = real_pairs.p;
    end
  else
    if real_pairs.sp ~= nil then
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
        policy = "sampled_out";
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
      if mlm ~= nill and #mlm>=1 then
        policy = "mailing_list";
      end
    end
  end

    -- set the DMARC status for posterity
  dmarc_status = "dmarc="..tostring(dmarc).." d="..tostring(domain).." (p="..tostring(policy_requested).."; dis="..tostring(policy)..")";
  vctx:set(msys.core.VCTX_MESS, "dmarc_status",dmarc_status);
  if debug then print("dmarc_status",dmarc_status); end

  -- let's log in paniclog because I don't know where else to log
  local report = "DMARC@"..tostring(msys.core.get_now_ts()).."@"..tostring(domain).."@"..ip_from_addr_and_port(tostring(ac.remote_addr))..
                 "@"..tostring(real_pairs.adkim).."@"..tostring(real_pairs.aspf).."@"..tostring(real_pairs.p).."@"..tostring(real_pairs.sp)..
                 "@"..tostring(policy_requested).."@"..tostring(real_pairs.pct).."@"..tostring(policy).."@"..tostring(dmarc_dkim).."@"..tostring(dmarc_spf)..
                 "@"..tostring(from_domain).."@SPF@"..tostring(envelope_domain).."@"..tostring(spf_status).."@DKIM";

  if debug then print("dkim_domains:"..tostring(vctx:get(msys.core.VCTX_MESS, "dkim_domains"))); end
  local found_dkim_domains = msys.pcre.split(vctx:get(msys.core.VCTX_MESS, "dkim_domains"), "\\s+");

  if found_dkim_domains ~= nil and #found_dkim_domains >= 1 then
    for i=1,#found_dkim_domains do
        local found=false;
        if dkim_domains ~= nil and #dkim_domains >= 1 then
          for j=1,#dkim_domains do
            if debug then print(">"..found_dkim_domains[i].."<>"..dkim_domains[j].."<"); end
            if dkim_domains[j] == found_dkim_domains[i] then
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
  
  -- and now we can enforce it  
  if policy == "reject" then
    local mlm = msg:header('list-id');
    if mlm ~= nil and #mlm>=1 then
      -- we found a list-id let's note that as we may want to whitelist
      print("DMARC MLM whitelist potential "..mlm[1].." "..ip_from_addr_and_port(tostring(ac.remote_addr)));
    end

    vctx:set_code(554, "DMARC email rejected by policy");
    return msys.core.VALIDATE_DONE;
  end
  
  if debug then print("end of dmarc_work"); end
  return msys.core.VALIDATE_CONT;
end

function dmarc_validate_data(msg, ac, vctx)
  
  local domains = msg:address_header("From", "domain");
  
  -- various checks regarding dmarc
  if domains == nil or #domains == 0 then
	  -- No From header, reject 
	  return vctx:pbp_disconnect(554, "DMARC validation requires a From Header");
  end
  
  if #domains > 1 then
	  -- too many domains in From header, reject 
	  return vctx:pbp_disconnect(554, "DMARC validation requires a single domain in the From Header");
  end
  
  local from_domain = string.lower(domains[1]);
  local envelope_domain = string.lower(vctx:get(msys.core.VCTX_MESS,
                                   msys.core.STANDARD_KEY_MAILFROM_DOMAIN));
  
  -- Now let's find if the domain has a DMARC record.
  -- we do it here as it is more efficient than in the CPU pool
  local dmarc_found, dmarc_record, domain, domain_policy = dmarc_search(from_domain);
                                   
  -- If we get here we have exactly one result in results.
  local status, ret = msys.runInPool("CPU", function()
      return dmarc_work(msg, ac, vctx, from_domain, envelope_domain, dmarc_found, dmarc_record, domain, domain_policy);
    end);

  return ret;
end

-- vim:ts=2:sw=2:et:
