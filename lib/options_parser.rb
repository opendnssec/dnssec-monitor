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

require 'optparse'
require 'ostruct'
require 'dnsruby'

module DnssecMonitor
  class OptionsParser
    # Command-line interface
    # -z(one) : the zone to check
    # -n(ameservers) : comma-separated list of nameservers to check (rather than all for a zone)
    # -d(omains) : comma-separated list of known domains in the zone
    # -f(ile) : zone file containing all domains in zone - this allows NSEC(3) chains to be checked
    # -l(og) : Syslog facility to use
    # -h(elp) : help
    # -kskcritical : N : Error if KSK has less than N
    # -kskwarn : N : Warn if KSK has less than N
    # -zskcritical : N : Error if ZSK has less than N
    # -zskwarn : N : Warn if ZSK has less than N
    # -sigcritical : N : Error if normal RR signature has less than N
    # -sigwarn : N : Warn if normal RR signature has less than N
    # -siglife : N : Warn if signature lifetime is less than N
    # -siginception : N : Warn if signature inception isn't at least N in the past
    # These times are probably best expressed in XSD:Duration format
    # -w(orkingdirectory) : where to store any working files (for e.g. storing walked domains, tracking SOA - is this needed?)
    # -walk : If no domains are supplied, and zone is NSEC-signed, then walk the zone and check the records.
    #
    # Return a structure describing the options.
    #
    def self.parse(args, support_nagios = false)
      # The options specified on the command line will be collected in *options*.
      # We set default values here.
      #      path = "@sysconfdir@/opendnssec/".sub("${prefix}", "@prefix@")
      options = OpenStruct.new
      #      options.default_conf_file = path + "conf.xml"
      options.zone = nil
      options.daemonize = false
      options.ksk_expire_critical = 7
      options.ksk_expire_warn  = 14
      options.zsk_expire_critical = 1
      options.zsk_expire_warn  = 3
      options.domain_expire_critical = 1
      options.domain_expire_warn  = 3
      options.wildcard     = 0
      options.nagios_verbosity    = 0
      options.name_list = nil
      options.opendnssec = false
      options.inception_offset = 3600
      options.min_sig_lifetime = 3600
      options.do_validation_checks = true
      options.dlv = "dlv.isc.org."

      opts = OptionParser.new do |opts|
        opts.banner = "Usage: #{$0} [options]"

        opts.separator ""
        opts.separator "Specific options:"

        # zone_name
        opts.on("-z", "--zone [ZONE_NAME]",
          "Zone to monitor") do |zone|
          options.zone = Dnsruby::Name.create(zone)
        end

        opts.on("-n", "--nameservers <ns1>[,<ns2>,<ns3>,...]", Array,
          "Comma-separated list of nameservers", "to monitor for the zone. Defaults",
          "to the nameservers listed in the public DNS") do |list|
          options.nameservers = list
        end

        opts.on("--kskwarn [n]", "Warn if KSK RRSIG expiry is within n days",
          "Defaults to #{options.ksk_expire_warn}") do |n|
          options.ksk_expire_warn = n.to_f
        end

        opts.on("--kskcritical [n]", "Error if KSK RRSIG expiry is within n days",
          "Defaults to #{options.ksk_expire_critical}") do |n|
          options.ksk_expire_critical = n.to_f
        end

        opts.on("--zskwarn [n]", "Warn if the ZSK RRSIG expiry is within n days",
          "Defaults to #{options.zsk_expire_warn}") do |n|
          options.zsk_expire_warn = n.to_f
        end

        opts.on("--zskcritical [n]", "Error if ZSK RRSIG expiry is within n days",
          "Defaults to #{options.zsk_expire_critical}") do |n|
          options.zsk_expire_critical = n.to_f
        end

        opts.on("--dwarn [n]", "Warn if RRSIG expiry is within n days",
          "Defaults to #{options.domain_expire_warn}",
          "Only useful when a list of domains", "to check is supplied") do |n|
          options.domain_expire_warn = n.to_f
        end

        opts.on("--dcritical [n]", "Error if RRSIG expiry is within n days",
          "Defaults to #{options.domain_expire_critical}",
          "Only useful when a list of domains to",
          "check is supplied") do |n|
          options.domain_expire_critical = n.to_f
        end

        opts.on("--ods [ods_location]", "Load the OpenDNSSEC configuration files",
          "from this location and use values for",
          "InceptionOffset and ValidityPeriod",
          "from them. Otherwise, defaults will",
          "be used for these (#{options.inception_offset} for",
          "InceptionOffset, #{options.min_sig_lifetime} for ValidityPeriod).",
          "OpenDNSSEC must have been installed on this",
          "system if this option is used") do |location|
          options.opendnssec = location
        end

        opts.on("--[no-]wilcard",
          "NXDomain checks will be disabled if",
          "wildcards are enabled") do |on|
          options.wilcard = on
        end

        opts.on("--names name1,name2,name3...", Array,
          "List of names to check in the zone", 
          "Note that there must be no whitespace", "between the names") do |list|
          options.name_list = {}
          list.each {|n|
            options.name_list[Dnsruby::Name.create(n)] = []
          }
        end

        opts.on("--namefile file", "Name of file containing list of names (and ",
          "optional types) to check in the zone") do |f|
          options.namefile = f
        end

        opts.on("--zonefile file", "Name of zone file to load list of names to ",
          "check against zone") do |zf|
          options.zonefile= zf
        end

        opts.on("--[no-]validation", "Define whether to check parent DS records",
          "and validation from the root", "Defaults to #{options.do_validation_checks}") do |on|
          options.do_validation_checks = on
        end

        opts.on("--rootkey file", "Configure the key for the signed root",
          "Defines file to load root key from",
          "Validation from root will not be tested",
          "if this is not configured") do |rootkey|
          options.root_key = rootkey
        end

        opts.on("--dlv", "Configure the location of the DLV service",
          "Defaults to #{options.dlv}",
          "DLV will only be used if dlvkey is set") do |dlv|
          options.dlv = dlv
        end

        opts.on("--dlvkey file", "Configure the DLV key",
          "Defines file to load DLV key from",
          "DLV won't be used if this isn't set") do |dlvkey|
          options.dlv_key = dlvkey
        end

        opts.on("--hints hint1,hint2,hint3...", Array, "Configure the root hints",
          "Defines the servers to use as root",
          "Note that there must be no whitespace", "between the names") do |nss|
          options.hints = nss
        end


        if (support_nagios) # Running nagios_dnssec.rb
          opts.on("-v", "--verbose [n]", "Set the NAGIOS verbosity level to n",
            "Defaults to 0 (single line, minimal output, if -v not used",
            "defaults to 3 (Detailed output) if -v used with no number") do |n|
            options.nagios_verbosity = (n || 3).to_i
          end
        end


        #        # daemonize
        #        opts.on("-d", "--daemonize",
        #          "Run the dnssec monitor as a daemon",
        #          "Currently unsupported") do |ext|
        #          options.daemonize = true
        #        end

        # Syslog facility
        opts.on("-l", "--log [FACILITY]",
          "Specify the syslog facility to print results",
          "Defaults to print to console") do |log|
          syslog_facility = eval "Syslog::LOG_" + (log.upcase+"").untaint
          options.syslog = syslog_facility
        end



        opts.separator ""
        opts.separator "Common options:"

        # No argument, shows at tail.  This will print an options summary.
        # Try it and see!
        opts.on_tail("-h", "-?", "--help", "Show this message") do
          puts opts
          exit
        end

      end
      opts.parse(args)
      if (!support_nagios)
        if (options.ksk_expire_warn < options.ksk_expire_critical)
          print "--kskcritical (#{options.ksk_expire_critical}) is greater than --kskwarn (#{options.ksk_expire_warn}) " +
            ": changing --kskcritical to be #{options.ksk_expire_warn}\n"
          options.ksk_expire_critical = options.ksk_expire_warn
        end
        if (options.zsk_expire_warn < options.zsk_expire_critical)
          print "--zskcritical (#{options.zsk_expire_critical}) is greater than --zskwarn (#{options.zsk_expire_warn}) " +
            ": changing --zskcritical to be #{options.zsk_expire_warn}\n"
          options.zsk_expire_critical = options.zsk_expire_warn
        end
      end
      options

    end  # parse()
  end
end
