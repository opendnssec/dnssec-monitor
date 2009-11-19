#!/usr/bin/ruby
#
# $Id$
#
# Copyright (c) 2009 Nominet UK. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Based on the Perl dnssec_monitor project from IIS (se.) :
# That project : Copyright (c) 2006 .SE (The Internet Infrastructure Foundation).

require 'rubygems'
require 'dnsruby'
include Dnsruby
require 'syslog'
include Syslog::Constants
require 'options_parser.rb'

# @TODO@ We need to be able to read OpenDNSSEC config files.
# @TODO@ Should we somehow share the auditor and monitor parse.rb and config.rb?
# @TODO@ Check the parent DS record
# @TODO@ Get tolerances from OpenDNSSEC files, if available (and values not specified on command line)
# @TODO@ Validate from a signed root

module DnssecMonitor
  class Controller
    # Control a set of ZoneMonitors to do the right thing
    def initialize(options)
      @ret_val = 999
      @options = options
      check_options
      if (!options.zone)
        log(LOG_ERR, "No zone name specified")
        exit(1)
      end
      name_loader = NameLoader.new
      @name_list = name_loader.load_names(@options)
      @ipv6ok = support_ipv6?
      if (!@ipv6ok)
        log(LOG_INFO,"No IPv6 connectivity - not checking AAAA NS records")
      end
    end

    def check_options
      # @TODO@ See if we are configured to use opendnssec configuration files.
      # If so, then load them up, and override existing options.
    end

    def support_ipv6?
      udp = UDPSocket.new(Socket::AF_INET6)
      dns = DNS.new
      ipv6ok = false
      dns.each_resource("k.root-servers.net", Types.AAAA) { |rr|
        begin
          udp.connect(rr.address.to_s, 53)
          ipv6ok = true
        rescue Exception
        end
      }
      return ipv6ok
    end
    def log(priority, message)
      # Maintain the current max syslog error level
      if (priority.to_i < @ret_val)
        @ret_val = priority.to_i
      end
      if ($syslog) # Called from Nagios plugin
        $syslog.log(priority, "#{priority}:#{message}")
      else
        if @options.syslog
          Syslog.open("dnssec_monitor", Syslog::LOG_PID |
            Syslog::LOG_CONS, @options.syslog) { |syslog|
            syslog.log(priority, message)
          }
        else
          print("#{priority} : #{message}\n")
        end
      end
    end
    def check_zone()
      @ret_val = 999
      nameservers = @options.nameservers
      if (!nameservers)
        nameservers = get_nameservers(@options.zone)
      end
      threads = []
      nameservers.each {|nameserver|
        thread = Thread.new() {
          monitor = ZoneMonitor.new(@options, nameserver, self, @name_list)
          monitor.check_zone
        }
        threads.push(thread)
        thread.run
      }
      threads.each {|thread|
        thread.join
      }
      if (@ret_val == 999)
        return 0
      else
        return @ret_val
      end
    end

    def get_nameservers(zone)
      # Get the nameservers for the zone
      msg = nil
      recursor = Recursor.new()
      begin
        msg = recursor.query(zone, "NS")
      rescue Exception => e
        log(LOG_ERR, "Can't find authoritative servers for #{zone} : #{e}")
        exit(3)
      end

      ret = recursor.query(zone, Types::SOA)
      ret.each_resource() { |rr|
        if ((rr.type == Types::SOA) && (rr.name.to_s != zone.to_s ))
          log(LOG_ERR, "SOA name reported from #{recursor} is #{rr.name}, but should be #{zone}")
        end
      }
      nameservers = []
      msg.answer.rrsets(Types::NS)[0].rrs.each {|rr| nameservers.push(rr.nsdname)}
      # Then build up the list of addresses for them
      ns_addrs = []
      types = [Types::A]
      types.push(Types::AAAA) if @ipv6ok
      types.each {|type|
        nameservers.each {|ns|
          ret = recursor.query(ns, type)
          ret.answer.rrsets(type).each {|rrset|
            rrset.rrs.each {|rr|
              ns_addrs.push(rr.address)
            }
          }
        }
      }
      return ns_addrs
    end
  end

  class NameLoader
    # Load the list of domains in the zone (or a zonefile)
    def load_names(options)
      name_list = nil
      # Now load the namefile or zonefile, if appropriate
      if (options.name_list)
        # Do nothing - this overrides files
        name_list = options.name_list
      elsif (options.zonefile)
        name_list = load_zonefile(options)
      elsif (options.namefile)
        name_list = load_namefile(options)
      else
        # @TODO@ Load the zone names by walking the zone?
        # Should this be an explicit option?
        #      if (nsec_signed)
        #        name_list = walk_zone(options)
        #      end
      end
      return name_list
    end

    def load_namefile(options)
      name_list = nil
      # Load the namefile into the name_list
      if (!File.exist?options.namefile)
        log(LOG_ERR, "Name file #{options.namefile} does not exist")
      else
        name_list = {}
        line_num = 0
        IO.foreach(options.namefile) {|line|
          line_num += 1
          split = line.split
          name = split[0]
          begin
            name = Dnsruby::Name.create(name)
            name_list[name] = []
            (split.length-1).times {|i|
              name_list[name].push(Types.new(split[i+1]))
            }
          rescue Exception => e
            log(LOG_ERR, "Can't understand line #{line_num} of #{options.namefile} : #{line}")
          end
        }
      end
      return name_list
    end

    def load_zonefile(options)
      name_list = nil
      # Load the zonefile into the name_list
      if (!File.exist?options.zonefile)
        log(LOG_ERR, "Zone file #{options.zonefile} does not exist")
      else
        name_list = {}
        zone_reader = Dnsruby::ZoneReader.new(options.zone)
        line_num = 0
        IO.foreach(options.zonefile) {|line|
          line_num += 1
          begin
            rr = zone_reader.process(line)
            name_list[rr.name] = rr.type
          rescue Exception => e
            log(LOG_ERR, "Can't understand line #{line_num} of #{options.zonefile} : #{line}")
          end
        }
      end
      return name_list
    end
  end

  class ZoneMonitor
    def initialize(options, nameserver, controller, name_list)
      @zone = options.zone
      @name_list = name_list
      @options = options
      @nameserver = nameserver
      @controller = controller
      @controller.log(LOG_INFO, "Making resolver for : #{nameserver}")
      @res = Resolver.new(nameserver.to_s)
      @verifier = SingleVerifier.new(SingleVerifier::VerifierType::ROOT)
    end
    def check_zone()
      Dnssec.clear_trust_anchors
      Dnssec.clear_trusted_keys
      # Run-once monitor for a single zone - report any errors to syslog, and
      # return a code indicating the most severe error we encountered.
      error = 0
      @controller.log(LOG_INFO, "Checking #{@zone} zone on #{@nameserver} nameserver")
      begin
        fetch_zone_keys
        check_apex
        check_nxdomain(Types.NS, @options.wildcard)
        check_parent_ds
        if (@name_list)
          @name_list.each {|domain, types|
            if (types.length == 0)
              # Check something here...
              check_domain(domain)
            else
              types.each {|type|
                check_domain(domain, type)
              }
            end
          }
        end
        #      return error
        @controller.log(LOG_INFO, "Finished checking on #{@nameserver}")
      rescue ResolvTimeout => e
        @controller.log(LOG_WARNING, "Failed to check #{@nameserver} - no response")
      rescue OtherResolvError => e
        @controller.log(LOG_WARNING, "Failed to check #{@nameserver} : #{e}")
      end
    end

    def query(name, type, res = @res)
      ret = query_ignore_nxdomain(name, type, res)
      if (ret.rcode == RCode::NXDomain)
        raise Dnsruby::ResolvError::NXDomain.new
      end
      return ret
    end

    def query_ignore_nxdomain(name, type, res = @res)
      if (!@sender)
        @sender = PacketSender.new
      end
      msg = Message.new(name, type)
      @sender.prepare_for_dnssec(msg)
      ret, error = res.send_plain_message(msg)
      if (error && !(Dnsruby::NXDomain === error))
        raise error
      end
      return ret
    end

    def fetch_zone_keys
      # Get the keys for the zone
      @ksks = []
      @zsks = []
      @verifier.clear_trust_anchors
      @verifier.clear_trusted_keys
      ret = query(@zone, Types.DNSKEY)
      ret.answer.rrsets(Types.DNSKEY).each {|rrset|
        rrset.rrs.each {|rr|
          if  ((rr.protocol == 3) &&  (rr.zone_key?))
            @verifier.add_trusted_key(RRSet.new(rr))
            if (rr.sep_key?)
              @controller.log(LOG_INFO,"Adding ksk : #{rr.key_tag}")
              @ksks.push(rr)
            else
              @controller.log(LOG_INFO,"Adding zsk : #{rr.key_tag}")
              @zsks.push(rr)
            end
          end
        }
      }
      if (@ksks.length == 0)
        @controller.log(LOG_ERR, "No KSKs found in the zone")
      end
      if (@zsks.length == 0)
        @controller.log(LOG_ERR, "No ZSKs found in the zone")
      end
      ret.answer.rrsets(Types.DNSKEY).each {|rrset|
        # Verify with both ZSKs and KSKs
        verify_rrset(rrset, @ksks)
        verify_rrset(rrset, @zsks)
      }
    end

    def verify_rrset(rrset, keys)
      # except for the zone apex, there should be no RRSIG for NS RRsets
      if ((rrset.type == Types.NS) && (rrset.name.to_s != @zone.to_s))
        return
      end
      if (rrset.sigs.length == 0)
        @controller.log(LOG_ERR, "No RRSIGS found in #{rrset.name}, #{rrset.type} RRSet")
        return
      end
      # @TODO@ There should be no RRSIG for glue records or unsigned delegations
      begin
        @verifier.verify_rrset(rrset, keys)
        @controller.log(LOG_INFO, "#{rrset.name}, #{rrset.type} verified OK")
      rescue VerifyError => e
        @controller.log(LOG_ERR, "#{rrset.name}, #{rrset.type} verification failed : #{e}, #{rrset}")
      end

    end

    def verify_answer(pkt)
      [pkt.answer, pkt.authority, pkt.additional].each {|x| x.rrsets.each {|rrset|
          verify_rrset(rrset, @zsks)
        }
      }
    end

    def check_apex

      # Get all rrsigs for the zone apex
      # Check their lifetimes etc.
      check_apex_rrsigs

      # Get the SOA for the zone and check it
      # Verify the RRSIG record
      [Types.SOA, Types.NS].each {|type|
        ret = query(@zone, type)
        answer = ret.answer
        answer.rrsets(type).each {|rrset|
          verify_rrset(rrset, @zsks)
        }
        if (answer.rrsets(type).length == 0)
          @controller.log(LOG_ERR, "No #{type} record found for zone")
        end
      }

    end

    def check_apex_rrsigs
      # Get the RRSIG records for the zone apex and check their expiry
      ret = query(@zone, Types.RRSIG)
      ret.answer.rrsets(Types.RRSIG).each {|sigs|
        check_expire_zsk(sigs)
        check_expire_ksk(sigs)
      }
    end

    def check_expire_zsk(sigs)
      check_expire_with_keys(sigs, @zsks, @options.zsk_expire_critical,
        @options.zsk_expire_warn)
    end

    def check_expire_ksk(sigs)
      check_expire_with_keys(sigs, @ksks, @options.ksk_expire_critical,
        @options.ksk_expire_warn)
    end

    def check_expire_with_keys(sigs, keys, critical, warn)
      sigs.each {|sig|
        days = (sig.expiration - Time.now.to_i) / (60 * 60 * 24)
        keys.each {|k|
          if (sig.key_tag == k.key_tag)
            key_type = ""
            if (k.sep_key?)
              key_type = "KSK"
            else
              key_type = "ZSK"
            end
            if (days < 0)
              @controller.log(LOG_ERR, "#{key_type}(key_tag #{k.key_tag}): RRSIG for #{k} has expired")
            end
            if (critical && (days <= critical))
              @controller.log(LOG_ERR, "#{key_type}(key_tag #{k.key_tag}): RRSIG for #{k} will expire in #{days} days (#{key_type.downcase}critical is #{critical})")
            end
            if (warn && (days <= warn))
              @controller.log(LOG_WARNING, "#{key_type}(key_tag #{k.key_tag}): RRSIG for #{k} will expire in #{days} days (#{key_type.downcase}warn is #{warn})")
            end
          end
        }
      }
    end

    def check_nxdomain(type, wildcard = false) # @TODO@
      # @TODO@ -
      name = "dklfjhwiouy4r9cefuyenwfuyenw" + ".#{@zone}" # get_random_name # @TODO@ !!!

      zone = nil

      @controller.log(LOG_INFO, "Checking non-existing domain for #{name}, #{type}")
      # fetch qname/IN/qtype
      packet = query_ignore_nxdomain(name, type)
      if (!wildcard)
        if (packet.rcode != RCode.NXDomain)
          @controller.log(LOG_ERR, "#{name}/IN/#{type} should not exist")
          return
        end
      end

      # fetch SOA from authority section
      zone = packet.authority.rrsets(Types.SOA)[0].name

      if (!zone)
        @controller.log(LOG_ERR, "no SOA found NXDOMAIN authority section")
      end


      if ((packet.authority.rrsets(Types.NSEC).length == 0) &&
            (packet.authority.rrsets(Types.NSEC3).length == 0))
        @controller.log(LOG_ERR, "no NSEC/NSEC3 found in authority section")
      else
        if (((packet.authority.rrsets(Types.NSEC)[0] &&
                  packet.authority.rrsets(Types.NSEC)[0].sigs.length == 0)) &&
              (packet.authority.rrsets(Types.NSEC3)[0] &&
                (packet.authority.rrsets(Types.NSEC3)[0].sigs.length == 0)))
          @controller.log(LOG_ERR, "no NSEC/NSEC3 RRSIG found")
        end
      end

      # verify signatures using available ZSK
      packet.authority.rrsets(Types.NSEC).each {|rrset|
        verify_rrset(rrset, @zsks)
      }
    end

    def check_parent_ds # @TODO@
      # @TODO@ Check the parent DS - either in the normal DNS or the ISC DLV registry
    end

    def get_nameservers_for_child(zone)
      # Get the nameservers for the zone
      msg = nil
      begin
        msg = @res.query(zone, "NS")
      rescue Exception => e
        log(LOG_ERR, "Can't find authoritative servers for #{zone} : #{e}")
        return false
      end

      nameservers = []
      msg.authority.rrsets(Types::NS)[0].rrs.each {|rr| nameservers.push(rr.nsdname)}
      # Then build up the list of addresses for them
      ns_addrs = []
      types = [Types::A]
      types.push(Types::AAAA) if @ipv6ok
      types.each {|type|
        nameservers.each {|ns|
          msg.additional.rrsets(type).each {|rrset|
            rrset.rrs.each {|rr|
              ns_addrs.push(rr.address)
            }
          }
        }
      }
      return ns_addrs
    end

    def check_child_ds(name)
      ret = query(name, Types::DS)
      if (ret.rcode == RCode::NXDOMAIN)
        @controller.log(LOG_ERR, "No records found at #{name}")
        return false
      end
      if (ret.answer.rrsets(Types::DS).length > 0)
        ns_addrs = get_nameservers_for_child(name)
        return if !ns_addrs
        ns_addr_strs = ns_addrs.map{|n| n.to_s}
        # Now get the DNSKEYs for the child zone
        resolver = Dnsruby::Resolver.new({:nameservers => ns_addr_strs})
        key_msg = query(name, Types::DNSKEY, resolver)
        key_rrsets = key_msg.answer.rrsets(Types::DNSKEY)
        if (key_rrsets.length == 0)
          @controller.log(LOG_WARNING, "Can't validate DS records for #{name}, as no DNSKEY records are present in the #{name} zone")
          return true
        end
        key_rrset = key_rrsets[0]
        ret.answer.rrsets(Types::DS)[0].rrs.each {|ds|
          # Check ds against child's DNSKEY records (if any).
          if !Dnssec.verify_rrset(key_rrset, RRSet.new(ds))
            @controller.log(LOG_WARNING, "Validation failure for DS record (#{ds.key_tag}) for #{name}")
          else
            @controller.log(LOG_INFO,"Successfully checked DS (#{ds.key_tag}) for #{name}")
            # Now check that the DNSKEY with the DS key tag has the SEP flag set
            key_rrset.rrs.each {|key|
              if (key.key_tag == ds.key_tag)
                if (!key.sep_key?)
                  log(LOG_WARNING, "#{name} zone has non-SEP DNSKEY for DS (#{ds.key_tag})")
                end
              end
            }
          end
        }
      end
      return true
    end

    def check_domain(name, type = nil)
      # Check RRSIG if type is nil
      type = Types::RRSIG if !type
      return if !check_child_ds(name)
      check_sigs(name, type)
    end

    # Check the RRSIG expiry, etc. for a specific domain
    def check_sigs(name, type)
      @controller.log(LOG_INFO, "Checking #{name}, #{type}")
      ret = query_ignore_nxdomain(name, Types::RRSIG)
      if (ret.rcode == RCode::NXDOMAIN)
        @controller.log(LOG_ERR, "No records found at #{name}")
        return false
      end
      warn = @options.domain_expire_warn
      critical = @options.domain_expire_critical
      (ret.answer.rrsets(Types::RRSIG) + ret.authority.rrsets(Types::RRSIG)).each {|sigs|
        sigs.each {|sig|
          days = (sig.expiration - Time.now.to_i) / (60 * 60 * 24)
          if (days < 0)
            @controller.log(LOG_ERR, "RRSIG for #{name}, #{sig.type_covered} has expired")
          end
          if (critical && (days <= critical))
            @controller.log(LOG_ERR, "RRSIG for #{name}, #{sig.type_covered} will expire in #{days} days (critical is #{critical})")
          end
          if (warn && (days <= warn))
            @controller.log(LOG_WARNING, "RRSIG for #{name}, #{sig.type_covered} will expire in #{days} days (warn is #{warn})")
          end
        }
      }
    end

    def check_expire_zsk(sigs)
      check_expire_with_keys(sigs, @zsks, @options.zsk_expire_critical,
        @options.zsk_expire_warn)
    end
  end
  class Daemon
    # Run the ZoneMonitor as a daemon
    # Potentially run many ZoneMonitors for many zones.
  end

  # Now actually do something!
  begin
    options = OptionsParser.parse(ARGV)
  rescue Exception => e
    print "Eror reading options : #{e}\n"
    exit(3)
  end
  controller = Controller.new(options)
  ret = controller.check_zone
  exit(ret)
end
