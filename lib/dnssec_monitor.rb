#!/usr/bin/ruby

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

module DnssecMonitor
  class DomainLoader
    # Load the list of domains in the zone (or a zonefile)
  end
  class Controller
    # Control a set of ZoneMonitors to do the right thing
    def initialize(options)
      @options = options
      @ipv6ok = support_ipv6?
      @ret_val = 999
      if (!@ipv6ok)
        log(LOG_INFO,"No IPv6 connectivity - not checking AAAA NS records")
      end
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
          monitor = ZoneMonitor.new(@options, nameserver, self)
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
      nameservers = []
      # Get the nameservers for the zone
      recursor = Recursor.new()
      begin
      ret = recursor.query(zone, "NS")
      rescue Exception => e
        log(LOG_ERR, "Can't find authoritative servers : #{e}")
        exit 3
      end
      ret.answer.rrsets(Types.NS)[0].rrs.each {|rr| nameservers.push(rr.nsdname)}
      # Then build up the list of addresses for them
      ns_addrs = []
      types = [Types.A]
      types.push(Types.AAAA) if @ipv6ok
      types.each {|type|
        nameservers.each {|ns|
          ret = recursor.query(zone, Types::SOA)
          ret.each_resource() { |rr|
            if ((rr.type == Types::SOA) && (rr.name.to_s != zone.to_s ))
              log(LOG_ERR, "SOA name reported from #{ns} is #{rr.name}, but should be #{zone}")
            end
          }
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
  class ZoneMonitor
    def initialize(options, nameserver, logger)
      @zone = options.zone
      @options = options
      @nameserver = nameserver
      @logger = logger
      @logger.log(LOG_INFO, "Making resolver for : #{nameserver}")
      @res = Resolver.new(nameserver.to_s)
      @verifier = SingleVerifier.new(SingleVerifier::VerifierType::ROOT)
    end
    def check_zone()
      Dnssec.clear_trust_anchors
      Dnssec.clear_trusted_keys
      # Run-once monitor for a single zone - report any errors to syslog, and
      # return a code indicating the most severe error we encountered.
      error = 0
      @logger.log(LOG_INFO, "Checking #{@zone} zone on #{@nameserver} nameserver")
      begin
        fetch_zone_keys
        check_apex
        check_nxdomain(Types.NS, @options.wildcard)
        check_parent_ds
        #      if (nsec_signed and !have_some_domains_in_zone)
        #        walk_zone
        #      end
        #      if (have_some_domains_in_zone)
        #        domains.each {|domain|
        #          check_domain(domain)
        #        }
        #      end
        #      return error
        @logger.log(LOG_INFO, "Finished checking on #{@nameserver}")
      rescue ResolvTimeout => e
        @logger.log(LOG_WARNING, "Failed to check #{@nameserver} - no response")
      rescue OtherResolvError => e
        @logger.log(LOG_WARNING, "Failed to check #{@nameserver} : #{e}")
      end
    end

    def query(name, type)
      if (!@sender)
        @sender = PacketSender.new
      end
      msg = Message.new(name, type)
      @sender.prepare_for_dnssec(msg)
      ret, error = @res.send_plain_message(msg)
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
              @logger.log(LOG_INFO,"Adding ksk : #{rr.key_tag}")
              @ksks.push(rr)
            else
              @logger.log(LOG_INFO,"Adding zsk : #{rr.key_tag}")
              @zsks.push(rr)
            end
          end
        }
      }
      if (@ksks.length == 0)
        @logger.log(LOG_ERR, "No KSKs found in the zone")
      end
      if (@zsks.length == 0)
        @logger.log(LOG_ERR, "No ZSKs found in the zone")
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
        @logger.log(LOG_ERR, "No RRSIGS found in #{rrset.name}, #{rrset.type} RRSet")
        return
      end
      # @TODO@ There should be no RRSIG for glue records or unsigned delegations
      begin
        @verifier.verify_rrset(rrset, keys)
        @logger.log(LOG_INFO, "#{rrset.name}, #{rrset.type} verified OK")
      rescue VerifyError => e
        @logger.log(LOG_ERR, "#{rrset.name}, #{rrset.type} verification failed : #{e}, #{rrset}")
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
          @logger.log(LOG_ERR, "No #{type} record found for zone")
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
              @logger.log(LOG_ERR, "#{key_type}(key_tag #{k.key_tag}): RRSIG for #{k} has expired")
            end
            if (critical && (days <= critical))
              @logger.log(LOG_ERR, "#{key_type}(key_tag #{k.key_tag}): RRSIG for #{k} will expire in #{days} days (#{key_type.downcase}critical is #{critical})")
            end
            if (warn && (days <= warn))
              @logger.log(LOG_WARNING, "#{key_type}(key_tag #{k.key_tag}): RRSIG for #{k} will expire in #{days} days (#{key_type.downcase}warn is #{warn})")
            end
          end
        }
      }
    end

    def check_nxdomain(type, wildcard = false) # @TODO@
      # @TODO@ -
      name = "dklfjhwiouy4r9cefuyenwfuyenw" + ".#{@zone}" # get_random_name # @TODO@ !!!

      zone = nil

      @logger.log(LOG_INFO, "Checking non-existing domain for #{name}, #{type}\n")
      # fetch qname/IN/qtype
      packet = query(name, type)
      if (!wildcard)
        if (packet.rcode != RCode.NXDomain)
          @logger.log(LOG_ERR, "#{name}/IN/#{type} should not exist")
          return
        end
      end

      # fetch SOA from authority section
      zone = packet.authority.rrsets(Types.SOA)[0].name

      if (!zone)
        @logger.log(LOG_ERR, "no SOA found NXDOMAIN authority section")
      end


      if ((packet.authority.rrsets(Types.NSEC).length == 0) &&
            (packet.authority.rrsets(Types.NSEC3).length == 0))
        @logger.log(LOG_ERR, "no NSEC/NSEC3 found in authority section")
      else
        if (((packet.authority.rrsets(Types.NSEC)[0] &&
                  packet.authority.rrsets(Types.NSEC)[0].sigs.length == 0)) &&
              (packet.authority.rrsets(Types.NSEC3)[0] &&
                (packet.authority.rrsets(Types.NSEC3)[0].sigs.length == 0)))
          @logger.log(LOG_ERR, "no NSEC/NSEC3 RRSIG found")
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

    def check_domain
      check_child_ds # @TODO@
      check_sigs # @TODO@
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
