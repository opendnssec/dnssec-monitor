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
require 'xsd/datatypes'
require 'rexml/document'
include REXML
require 'options_parser.rb'

#Dnsruby::TheLog.level = Logger::DEBUG

module DnssecMonitor
  class Controller
    class LoadOpenDnssecError < Exception
    end
    # Control a set of ZoneMonitors to do the right thing
    def initialize(options)
      @ret_val = 999
      @options = options
      @recursor = nil
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
      configure_verifiers
    end

    attr_reader :dlv_verifier

    def configure_verifiers
      configure_dlv_verifier
      configure_root_verifier
    end

    def configure_root_verifier
      if (@options.root_key)
        root_keys = load_keys(@options.root_key)
        if (root_keys)
          root_keys.each {|root_key|
            Dnssec.add_trust_anchor(root_key)
          }
        end
      end
    end

    def configure_dlv_verifier
      if (@options.dlv && @options.dlv_key)
        # Try loading DLV records from the configured DLV service instead
        # Load the DLV key from the file, and configure the verifier with it
        @dlv_verifier = SingleVerifier.new(SingleVerifier::VerifierType::DLV)
        dlv_keys = load_keys(@options.dlv_key)
        if (dlv_keys)
          dlv_keys.each {|dlv_key|
            @dlv_verifier.add_dlv_key(dlv_key)
          }
        end
      end
    end

    def load_keys(file)
      keys = []
      if File.exist?(file)
        zone_reader = Dnsruby::ZoneReader.new(@zone.to_s)
        IO.foreach(file) { |line|
          ret = zone_reader.process_line(line)
          # Load the key and return it to the user.
          # Use the Dnsruby::ZoneReader to load the RR from the file.
          if (ret)
            new_line, type, last_name = ret
            key = RR.create(new_line)
            keys.push(key)
            log(LOG_INFO, "Loaded key from #{file} : #{key}\n")
            #            return key
          end
        }
      end
      if (keys.length > 0)
        return keys
      end
      return nil
    end

    def check_options
      # See if we are configured to use opendnssec configuration files.
      # If so, then load them up, and override existing options.
      if (@options.opendnssec)
        begin
          conf_loader = OpenDnssecConfigLoader.new
          inception_offset, min_sig_lifetime = conf_loader.load_opendnssec_config(@options, self)
          if (!inception_offset)
            log(LOG_ERR, "Cannot find the OpenDNSSEC installation in #{@options.opendnssec}")
          else # override the default values
            @options.inception_offset = inception_offset
            @options.min_sig_lifetime = min_sig_lifetime
          end
        rescue Exception => e
          log(LOG_WARNING, "Can't load OpenDNSSEC configuration : #{e}")
        end
      end
    end

    def support_ipv6?
      ipv6ok = false
      begin
        udp = UDPSocket.new(Socket::AF_INET6)
        dns = DNS.new
        dns.each_resource("k.root-servers.net", Types.AAAA) { |rr|
          udp.connect(rr.address.to_s, 53)
          ipv6ok = true
        }
      rescue Exception
      end
      return ipv6ok
    end
    def log(priority, message)
      # Maintain the current max syslog error level
      if ((priority.to_i < @ret_val) && (priority <= LOG_WARNING))
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
      if (nameservers.length == 0)
        log(LOG_ERR, "Can't find authoritative nameservers for #{@options.zone}")
        exit(3)
      end
      threads = []
      nameservers.each {|nsname, nameserver|
        thread = Thread.new() {
          monitor = ZoneMonitor.new(@options, nameserver, nsname, self, @name_list)
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

    def get_recursor
      if !(@recursor)
        if (@options.hints)
          res_hints = Resolver.new({:nameserver => @options.hints})
          @recursor = Recursor.new(res_hints)
          Dnssec.default_resolver = res_hints
        else
          @recursor = Recursor.new
        end
      end
      return @recursor
    end

    def get_nameservers(zone)
      # Get the nameservers for the zone
      msg = nil
      recursor = get_recursor
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
      msg.answer.rrsets(Types::NS).each {|rrset|
        rrset.rrs.each {|rr| nameservers.push(rr.nsdname) if (rr.name.to_s == zone.to_s)}
      }
      # Then build up the list of addresses for them
      ns_addrs = {}
      types = [Types::A]
      types.push(Types::AAAA) if @ipv6ok
      ids = []
      count = 0
      mutex = Mutex.new
      types.each {|type|
        ids[count] = Thread.new {
          nameservers.each {|ns|
            found = false
            msg.additional.rrsets(type).each {|rrset|
              rrset.rrs.each {|rr|
                if (rr.name == ns)
                  found = true
                  mutex.synchronize {
                    ns_addrs[ns]=rr.address
                  }
                end
              }
            }
            if (!found)
              ret = recursor.query(ns, type) || Message.new
              ret.answer.rrsets(type).each {|rrset|
                rrset.rrs.each {|rr|
                  found = true
                  mutex.synchronize {
                    ns_addrs[ns]=rr.address
                  }
                }
              }
            end
          }
        }
        count += 1
      }
      ids.each {|id|
        id.join
      }
      return ns_addrs
    end
  end

  #This class loads the OpenDNSSEC configuration files to obtain values which
  #will be used by the Monitor as thresholds for warnings
  class OpenDnssecConfigLoader # :nodoc: all
    # This class loads and stores the Signatures element of the kasp.xml policy
    class Signatures # :nodoc: all
      attr_accessor :resign, :refresh, :jitter, :inception_offset, :validity
      def initialize(e)
        resign_text = e.elements['Resign'].text
        @resign = Signatures.xsd_duration_to_seconds(resign_text)
        refresh_text = e.elements['Refresh'].text
        @refresh = Signatures.xsd_duration_to_seconds(refresh_text)
        jitter_text = e.elements['Jitter'].text
        @jitter = Signatures.xsd_duration_to_seconds(jitter_text)
        inception_offset_text = e.elements['InceptionOffset'].text
        @inception_offset = Signatures.xsd_duration_to_seconds(inception_offset_text)

        @validity = Validity.new(e.elements['Validity'])
      end
      class Validity
        attr_accessor :default, :denial
        def initialize(e)
          default_text = e.elements['Default'].text
          @default = Signatures.xsd_duration_to_seconds(default_text)
          denial_text = e.elements['Denial'].text
          @denial = Signatures.xsd_duration_to_seconds(denial_text)
        end
      end

      def self.xsd_duration_to_seconds xsd_duration # :nodoc: all
        # XSDDuration hack
        xsd_duration = "P0DT#{$1}" if xsd_duration =~ /^PT(.*)$/
        xsd_duration = "-P0DT#{$1}" if xsd_duration =~ /^-PT(.*)$/
        a = XSD::XSDDuration.new xsd_duration
        from_min = 0 | a.min * 60
        from_hour = 0 | a.hour * 60 * 60
        from_day = 0 | a.day * 60 * 60 * 24
        from_month = 0 | a.month * 60 * 60 * 24 * 31
        from_year = 0 | a.year * 60 * 60 * 24 * 365
        # XSD::XSDDuration seconds hack.
        x = a.sec.to_s.to_i + from_min + from_hour + from_day + from_month + from_year
        return x
      end
    end

    def load_opendnssec_config(options, parent) # :nodoc: all
      # Load the config file
      @parent = parent
      zonelist_file, kasp_file =
        load_config_xml(options.opendnssec +
          (options.opendnssec[options.opendnssec.length - 2, 1] ==
            File::SEPARATOR ? "" : File::SEPARATOR) +
          "conf.xml")
      # @TODO@ Do we want to override the syslog provided by the client? Almost
      # undoubtedly not. Do we want to use it as well? Maybe...

      policy = load_policy_from_zonelist(zonelist_file, options.zone)
      return nil, nil if !policy

      # Load kasp.xml
      return load_kasp_file(kasp_file, policy)
    end

    def load_policy_from_zonelist(zonelist_file, zone) # :nodoc: all
      # Load the zonelist.xml, locate the zone and find the policy in use
      File.open((zonelist_file.to_s+"").untaint, 'r') {|file|
        doc = REXML::Document.new(file)
        doc.elements.each("ZoneList/Zone") {|z|
          # First load the config files
          zone_name = z.attributes['name']
          if (zone_name.to_s == zone.to_s)
            policy = z.elements['Policy'].text
            return policy
          end
        }
      }
      @parent.log(LOG_WARNING, "Can't find #{zone} zone in #{zonelist_file}")
      return nil
    end

    def load_kasp_file(kasp_file, policy) # :nodoc: all
      inception_offset = nil
      min_sig_lifetime = nil
      # Locate the policy in use by the zone
      # Load the values of interest from the Signatures element for that policy
      found = false
      File.open((kasp_file+"").untaint, 'r') {|file|
        doc = REXML::Document.new(file)

        # Now find the appropiate policy
        doc.elements.each('KASP/Policy') {|p|
          if (p.attributes['name'] == policy)
            found = true
            # Load the values from the Signatures element
            signatures = Signatures.new(p.elements['Signatures'])
            inception_offset = signatures.inception_offset
            min_sig_lifetime = signatures.validity.default + inception_offset
          end
        }
      }
      if (!found)
        @parent.log(LOG_WARNING, "Can't find #{policy} policy in #{kasp_file} - not loading config")
      end
      return inception_offset, min_sig_lifetime
    end

    def load_config_xml(conf_file) # :nodoc: all
      zonelist = ""
      kasp = ""
      begin
        File.open((conf_file + "").untaint , 'r') {|file|
          doc = REXML::Document.new(file)
          begin
            zonelist = doc.elements['Configuration/Common/ZoneListFile'].text
          rescue Exception
            raise LoadOpenDnssecError.new("Can't read zonelist location from conf.xml")
          end
          begin
            kasp = doc.elements['Configuration/Common/PolicyFile'].text
          rescue Exception
            raise LoadOpenDnssecError.new("Can't read KASP policy location from conf.xml")
          end
          return zonelist, kasp
        }
      rescue Errno::ENOENT
        raise LoadOpenDnssecError.new("Can't find config file : #{conf_file}")
      end
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
    def initialize(options, nameserver, nsname,  controller, name_list)
      @zone = options.zone
      @name_list = name_list
      @options = options
      @nameserver = nameserver
      @nsname = nsname
      @controller = controller
      @controller.log(LOG_INFO, "Making resolver for : #{nameserver}, #{nsname}")
      @res = Resolver.new(nameserver.to_s)
      @verifier = SingleVerifier.new(SingleVerifier::VerifierType::ROOT)
    end
    def check_zone()
      #      Dnssec.clear_trust_anchors
      #      Dnssec.clear_trusted_keys
      # Run-once monitor for a single zone - report any errors to syslog, and
      # return a code indicating the most severe error we encountered.
      error = 0
      @controller.log(LOG_INFO, "Checking #{@zone} zone on #{@nsname}(#{@nameserver}) nameserver")
      begin
        fetch_zone_keys
        check_apex
        check_nxdomain(Types.NS, @options.wildcard)
        if (@options.do_validation_checks)
          check_parent_ds
          check_validation_from_root
        end
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
        @controller.log(LOG_INFO, "Finished checking on #{@nsname}(#{@nameserver})")
      rescue ResolvTimeout => e
        @controller.log(LOG_WARNING, "Failed to check #{@nsname}(#{@nameserver}) - no response")
      rescue OtherResolvError => e
        @controller.log(LOG_WARNING, "Failed to check #{@nsname}(#{@nameserver}) : #{e}")
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
            #            Dnssec.add_trusted_key(RRSet.new(rr))
            if (rr.sep_key?)
              @controller.log(LOG_INFO,"(#{@nsname}): Adding ksk : #{rr.key_tag}")
              @ksks.push(rr)
            else
              @controller.log(LOG_INFO,"(#{@nsname}): Adding zsk : #{rr.key_tag}")
              @zsks.push(rr)
            end
          end
        }
      }
      if (@ksks.length == 0)
        @controller.log(LOG_ERR, "(#{@nsname}): No KSKs found in the zone")
      end
      if (@zsks.length == 0)
        @controller.log(LOG_ERR, "(#{@nsname}): No ZSKs found in the zone")
      end
      ret.answer.rrsets(Types.DNSKEY).each {|rrset|
        # Verify with both ZSKs and KSKs
        verify_rrset(rrset, @ksks)
        #        verify_rrset(rrset, @zsks)
      }
    end

    def verify_rrset(rrset, keys)
      # except for the zone apex, there should be no RRSIG for NS RRsets
      if ((rrset.type == Types.NS) && (rrset.name.to_s != @zone.to_s))
        return
      end
      if (rrset.sigs.length == 0)
        @controller.log(LOG_ERR, "(#{@nsname}): No RRSIGS found in #{rrset.name}, #{rrset.type} RRSet")
        return
      end
      # @TODO@ There should be no RRSIG for glue records or unsigned delegations
      begin
        @verifier.verify_rrset(rrset, keys)
        @controller.log(LOG_INFO, "(#{@nsname}): #{rrset.name}, #{rrset.type} verified OK")
      rescue VerifyError => e
        @controller.log(LOG_ERR, "(#{@nsname}): #{rrset.name}, #{rrset.type} verification failed : #{e}, #{rrset}")
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
        sigs.each {|sig|
          check_expire_zsk(sig)
          check_expire_ksk(sig)
          check_sig_inception(@zone, sig)
          check_sig_validity(@zone, sig)
        }
      }
    end

    def check_expire_zsk(sig)
      check_expire_with_keys(sig, @zsks, @options.zsk_expire_critical,
        @options.zsk_expire_warn)
    end

    def check_expire_ksk(sig)
      check_expire_with_keys(sig, @ksks, @options.ksk_expire_critical,
        @options.ksk_expire_warn)
    end

    def check_expire_with_keys(sig, keys, critical, warn)
      days = (sig.expiration - Time.now.to_i).to_f/(60 * 60 * 24).to_f
      keys.each {|k|
        if (sig.key_tag == k.key_tag)
          key_type = ""
          if (k.sep_key?)
            key_type = "KSK"
          else
            key_type = "ZSK"
          end
          if (days < 0)
            @controller.log(LOG_ERR, "(#{@nsname}): #{key_type}(key_tag #{k.key_tag}): RRSIG for #{k} has expired")
          end
          if (critical && (days <= critical))
            @controller.log(LOG_ERR, "(#{@nsname}): #{key_type}(key_tag #{k.key_tag}): RRSIG for #{k} will expire in #{days} days (#{key_type.downcase}critical is #{critical})")
          end
          if (warn && (days <= warn))
            @controller.log(LOG_WARNING, "(#{@nsname}): #{key_type}(key_tag #{k.key_tag}): RRSIG for #{k} will expire in #{days} days (#{key_type.downcase}warn is #{warn})")
          end
        end
      }
    end

    def check_nxdomain(type, wildcard = false) # @TODO@
      # @TODO@ -
      name = "dklfjhwiouy4r9cefuyenwfuyenw" + ".#{@zone}" # get_random_name # @TODO@ !!!

      zone = nil

      @controller.log(LOG_INFO, "(#{@nsname}): Checking non-existing domain for #{name}, #{type}")
      # fetch qname/IN/qtype
      packet = query_ignore_nxdomain(name, type)
      if (!wildcard)
        if (packet.rcode != RCode.NXDomain)
          @controller.log(LOG_ERR, "(#{@nsname}): #{name}/IN/#{type} should not exist")
          return
        end
      end

      # fetch SOA from authority section
      zone = packet.authority.rrsets(Types.SOA)[0].name

      if (!zone)
        @controller.log(LOG_ERR, "(#{@nsname}): no SOA found NXDOMAIN authority section")
      end


      if ((packet.authority.rrsets(Types.NSEC).length == 0) &&
            (packet.authority.rrsets(Types.NSEC3).length == 0))
        @controller.log(LOG_ERR, "(#{@nsname}): no NSEC/NSEC3 found in authority section")
      else
        if (((packet.authority.rrsets(Types.NSEC)[0] &&
                  packet.authority.rrsets(Types.NSEC)[0].sigs.length == 0)) &&
              (packet.authority.rrsets(Types.NSEC3)[0] &&
                (packet.authority.rrsets(Types.NSEC3)[0].sigs.length == 0)))
          @controller.log(LOG_ERR, "(#{@nsname}): no NSEC/NSEC3 RRSIG found")
        end
      end

      # verify signatures using available ZSK
      packet.authority.rrsets(Types.NSEC).each {|rrset|
        verify_rrset(rrset, @zsks)
      }
    end

    def get_parent_for(name)
      if (name.labels.length <= 1)
        return Name.create(".")
      end
      n = Name.new(name.labels()[1, name.labels.length-1], name.absolute?)
      return n
    end

    def check_parent_ds
      # Find the parent
      parent = get_parent_for(@zone)
      nss = @controller.get_nameservers(parent)
      nameservers = []
      nss.each {|nsname, nameserver|
        nameservers.push(nameserver.to_s)
      }
      res = Resolver.new({:nameserver => nameservers})
      # Then look up the DS record for the child
      begin
        response = res.query(@zone, "DS")
      rescue Exception => e
        @controller.log(LOG_ERR, "Can't find DS records for #{@zone} in parent zone (#{parent}.) : #{e}")
        return
      end
      ds_rrset = response.answer.rrset(@zone, "DS")
      dlv = false
      if (ds_rrset.length == 0)
        # Is there a configured DLV service?
        if (@options.dlv_key)
          @controller.log(LOG_INFO, "Trying to load DLV records for #{@zone}")
          temp = @controller.dlv_verifier.query_dlv_for(@zone)
          if temp
            ds_rrset = temp
            dlv = true
          end
        end
      end
      # Get the DNSKEYs for the target zone
      key_response = query(@zone, Types.DNSKEY)
      key_rrset = key_response.answer.rrset(@zone, "DNSKEY")
      # And make sure it hooks up to the zone in question
      #  Try to verify the child's DNSKEY record against the DS record
      begin
        if (dlv)
          @controller.dlv_verifier.verify(key_rrset, ds_rrset)
        else
          @verifier.verify(key_rrset, ds_rrset)
        end
      rescue VerifyError => e
        @controller.log(LOG_ERR, "Couldn't verify parent's DS record (for #{@nsname}) (#{ds_rrset.rrs.length} DS RRs found for #{@zone}) : #{e}")
      end
    end

    def check_validation_from_root
      failed = true
      query = Message.new(@zone, Types.DNSKEY)
      msg = @res.send_message(query)
      begin
        @verifier.validate(msg, query)
      rescue VerifyError => e
      end
      if (!@options.root_key)
        msg.security_error = VerifyError.new("No root key configured")
      end
      if (msg.security_level == Message::SecurityLevel.SECURE)
        failed = false
      end
      if (failed && @controller.dlv_verifier)
        failed = !validate_from_dlv(msg)
      end
      if (failed)
        @controller.log(LOG_ERR, "Can't validate #{@zone} : #{msg.security_error}")
      end
    end

    def validate_from_dlv(msg)
      @controller.log(LOG_INFO, "Validating with DLV")
      query = Message.new()
      query.header.cd=true
      begin
        @controller.dlv_verifier.validate(msg, query)
        return (msg.security_level == Message::SecurityLevel.SECURE)
      rescue VerifyError => e
        msg.security_error = e
        return false
      end
    end

    def get_nameservers_for_child(zone)
      # Get the nameservers for the zone
      msg = nil
      begin
        msg = @res.query(zone, "NS")
      rescue Exception => e
        log(LOG_ERR, "(#{@nsname}): Can't find authoritative servers for #{zone} : #{e}")
        return false
      end

      nameservers = []
      msg.authority.rrsets(Types::NS).each {|rrset|
        rrset.rrs.each {|rr| nameservers.push(rr.nsdname)
        }
      }
      # Then build up the list of addresses for them
      ns_addrs = []
      types = [Types::A]
      types.push(Types::AAAA) if @ipv6ok
      ids = []
      count = 0
      mutex = Mutex.new
      types.each {|type|
        ids[count] = Thread.new {
          nameservers.each {|ns|
            found = false
            msg.additional.rrsets(type).each {|rrset|
              rrset.rrs.each {|rr|
                found = true
                mutex.synchronize {
                  ns_addrs.push(rr.address)
                }
              }
            }
            if (!found)
              recursor = @controller.get_recursor
              ret = recursor.query(ns, type)
              ret.answer.rrsets(type).each {|rrset|
                rrset.rrs.each {|rr|
                  found = true
                  mutex.synchronize {
                    ns_addrs.push(rr.address)
                  }
                }
              }
            end
          }
        }
        count += 1
      }
      ids.each {|id|
        id.join
      }
      return ns_addrs
    end

    def check_child_ds(name)
      ret = query(name, Types::DS)
      if (ret.rcode == RCode::NXDOMAIN)
        @controller.log(LOG_ERR, "(#{@nsname}): No records found at #{name}")
        return false
      end
      if (ret.answer.rrsets(Types::DS).length > 0)
        ns_addrs = get_nameservers_for_child(name)
        return if !ns_addrs
        ns_addr_strs = ns_addrs.map{|n| n.to_s}
        # Now get the DNSKEYs for the child zone
        resolver = Dnsruby::Resolver.new({:nameservers => ns_addr_strs})
        begin
          key_msg = query(name, Types::DNSKEY, resolver)
          key_rrsets = key_msg.answer.rrsets(Types::DNSKEY)
          if (key_rrsets.length == 0)
            @controller.log(LOG_WARNING, "(#{@nsname}): Can't validate DS records for #{name}, as no DNSKEY records are present in the #{name} zone")
            return true
          end
          key_rrset = key_rrsets[0]
          ret.answer.rrsets(Types::DS).each{|rrset| rrset.rrs.each {|ds|
              # Check ds against child's DNSKEY records (if any).
              if !Dnssec.verify_rrset(key_rrset, RRSet.new(ds))
                @controller.log(LOG_WARNING, "(#{@nsname}): Validation failure for DS record (#{ds.key_tag}) for #{name}")
              else
                @controller.log(LOG_INFO,"(#{@nsname}): Successfully checked DS (#{ds.key_tag}) for #{name}")
                # Now check that the DNSKEY with the DS key tag has the SEP flag set
                key_rrset.rrs.each {|key|
                  if (key.key_tag == ds.key_tag)
                    if (!key.sep_key?)
                      log(LOG_WARNING, "(#{@nsname}): #{name} zone has non-SEP DNSKEY for DS (#{ds.key_tag})")
                    end
                  end
                }
              end
            }}
        rescue ResolvTimeout => e
          @controller.log(LOG_WARNING, "(#{@nsname}): Timeout loading child keys for #{name}")
        end
      end
      return true
    end

    def check_domain(name, type = nil)
      # Check RRSIG if type is nil
      type = Types.RRSIG if !type
      if (!Name.create(name).absolute?)
        name = name.to_s + "." + @zone.to_s
      end
      check_sigs(name, type)
      check_child_ds(name)
    end

    # Check the RRSIG expiry, etc. for a specific domain
    def check_sigs(name, type)
      @controller.log(LOG_INFO, "(#{@nsname}): Checking #{name}, #{type.string}")
      ret = query_ignore_nxdomain(name, Types::RRSIG)
      if (ret.rcode == RCode::NXDOMAIN)
        @controller.log(LOG_ERR, "(#{@nsname}): No records found at #{name}")
        return false
      end
      sig_rrsets = ret.answer.rrsets(Types::RRSIG) + ret.authority.rrsets(Types::RRSIG)
      if (sig_rrsets.length == 0)
        @controller.log(LOG_ERR, "(#{@nsname}): No signatures found for #{name}, #{type.string}")
      end
      (sig_rrsets).each {|sigs|
        sigs.each {|sig|
          check_sig_expiry(name, sig)
          check_sig_inception(name, sig)
          check_sig_validity(name, sig)
        }
      }
    end

    def check_sig_inception(name, sig)
      # Use @options.inception_offset to check the RRSIG inception
      inception_since = Time.now.to_i - sig.inception
      if (inception_since < @options.inception_offset)
        @controller.log(LOG_ERR, "(#{@nsname}): RRSIG for #{name}, #{sig.type_covered} has an inception time #{inception_since} seconds in the past - should be at least #{@options.inception_offset}")
      end
    end

    def check_sig_validity(name, sig)
      # Use @options.min_sig_lifetime to check the RRSIG lifetime
      sig_lifetime = sig.expiration - sig.inception
      if (sig_lifetime < @options.min_sig_lifetime)
        @controller.log(LOG_ERR, "(#{@nsname}): RRSIG for #{name}, #{sig.type_covered} has a lifetime of #{sig_lifetime} seconds. Should be at least #{@options.min_sig_lifetime}")
      end
    end

    def check_sig_expiry(name, sig)
      warn = @options.domain_expire_warn
      critical = @options.domain_expire_critical
      days = (sig.expiration - Time.now.to_i).to_f/(60 * 60 * 24).to_f
      if (days < 0)
        @controller.log(LOG_ERR, "(#{@nsname}): RRSIG for #{name}, #{sig.type_covered} has expired")
      end
      if (critical && (days <= critical))
        @controller.log(LOG_ERR, "(#{@nsname}): RRSIG for #{name}, #{sig.type_covered} will expire in #{days} days (critical is #{critical})")
      end
      if (warn && (days <= warn))
        @controller.log(LOG_WARNING, "(#{@nsname}): RRSIG for #{name}, #{sig.type_covered} will expire in #{days} days (warn is #{warn})")
      end
    end

  end
  class Daemon
    # Run the ZoneMonitor as a daemon
    # Potentially run many ZoneMonitors for many zones.
  end

  # Now actually do something!
  begin
    options = OptionsParser.parse(ARGV)
  rescue OptionsParser::HelpExit
    exit(0)
  rescue Exception => e
    print "Error reading options : #{e}\n"
    exit(3)
  end
  controller = Controller.new(options)
  ret = controller.check_zone
  exit(ret)
end
