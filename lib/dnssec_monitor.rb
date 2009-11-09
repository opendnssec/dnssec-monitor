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

# @TODO@ Add functionality to load a list of names, either from the command-line,
# or a file, or a zone file.
# @TODO@ We need to be able to read OpenDNSSEC config files.
# @TODO@ Should we somehow share the auditor and monitor parse.rb, config.rb and preparser.rb?
# @TODO@ Check the RRSIGs for the list of names
# @TODO@ Check the parent DS record
# @TODO@ Check the DS records for the list of names
# @TODO@ Get tolerances from OpenDNSSEC files, if available (and values not specified on command line)
# @TODO@ Validate from a signed root

# @TODO@ Should we try to require 'kasp_auditor.rb' here? If it not available, then
# we can note that and not attempt to read from the KASP config files

module DnssecMonitor
  class DomainLoader
    # @TODO@ Load the list of domains in the zone (or a zonefile)
  end
  class Controller
    # Control a set of ZoneMonitors to do the right thing
    def initialize(options)
      @ret_val = 999
      @options = options
      if (!options.zone)
        log(LOG_ERR, "No zone name specified")
        exit(1)
      end
      load_names
      @ipv6ok = support_ipv6?
      if (!@ipv6ok)
        log(LOG_INFO,"No IPv6 connectivity - not checking AAAA NS records")
      end
    end

    def load_names
      @name_list = nil
      # Now load the namefile or zonefile, if appropriate
      if (@options.name_list)
        # Do nothing - this overrides files
        @name_list = @options.name_list
      elsif (@options.zonefile)
        # Load the zonefile into the name_list
        if (!File.exist?@options.zonefile)
          log(LOG_ERR, "Zone file #{@options.zonefile} does not exist")
        else
          @name_list = {}
          zone_reader = Dnsruby::ZoneReader.new(@options.zone)
          line_num = 0
          IO.foreach(@options.zonefile) {|line|
            line_num += 1
            begin
              rr = zone_reader.process(line)
              @name_list[rr.name] = rr.type
            rescue Exception => e
              log(LOG_ERR, "Can't understand line #{line_num} of #{@options.zonefile} : #{line}")
            end
          }
        end
      elsif (@options.namefile)
        # Load the namefile into the name_list
        if (!File.exist?@options.namefile)
          log(LOG_ERR, "Name file #{@options.namefile} does not exist")
        else
          @name_list = {}
          line_num = 0
          IO.foreach(@options.namefile) {|line|
            line_num += 1
            split = line.split
            name = split[0]
            begin
              name = Dnsruby::Name.create(name)
              @name_list[name] = []
              (split.length-1).times {|i|
                @name_list[name].push(Types.new(split[i+1]))
              }
            rescue Exception => e
              log(LOG_ERR, "Can't understand line #{line_num} of #{@options.namefile} : #{line}")
            end
          }
        end
      else
        # @TODO@ Load the zone names by walking the zone?
        # Should this be an explicit option?
        #      if (nsec_signed)
        #        @name_list = walk_zone
        #      end
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
    def initialize(options, nameserver, logger, name_list)
      @zone = options.zone
      @name_list = name_list
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

    def check_child_ds # @TODO@

    end

    def check_domain(name, type = nil)
      # Check RRSIG if type is nil
      type = Types::RRSIG if !type
      check_child_ds 
      check_sigs(name, type)
    end

    # Check the RRSIG expiry, etc. for a specific domain
    def check_sigs(name, type)
      @logger.log(LOG_INFO, "Checking #{name}, #{type}")
      ret = query(name, Types.RRSIG)
      if (ret.rcode == RCode::NXDOMAIN)
        @logger.log(LOG_ERR, "No records found at #{name}")
        return
      end
      warn = 10 # @TODO@
      critical = 10 # @TODO@
      ret.answer.rrsets(Types.RRSIG).each {|sigs|
        sigs.each {|sig|
          days = (sig.expiration - Time.now.to_i) / (60 * 60 * 24)
          if (days < 0)
            @logger.log(LOG_ERR, "RRSIG for #{name}, #{sig.type_covered} has expired")
          end
          if (critical && (days <= critical))
            @logger.log(LOG_ERR, "RRSIG for #{name}, #{sig.type_covered} will expire in #{days} days (critical is #{critical})")
          end
          if (warn && (days <= warn))
            @logger.log(LOG_WARNING, "RRSIG for #{name}, #{sig.type_covered} will expire in #{days} days (warn is #{warn})")
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
