#!/usr/bin/env ruby

# Copyright (c) 2010 Nominet UK. All rights reserved.
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


# This NAGIOS plug-in checks the zone files being published by both the
# signed master and the unsigned master. It makes sure that the unsigned data
# in both are identical. This is to avoid the issue seen with .uk on 10/9/10.
# REQUIRES DNSRUBY VERSION 1.50 OR GREATER!!

require 'optparse'
require 'ostruct'
begin
  require 'dnsruby'
rescue LoadError
  require 'rubygems'
  require 'dnsruby'
end
include Dnsruby

class VerifyOptionsParser
  def self.parse(args)
    # The options specified on the command line will be collected in *options*.
    # We set default values here.
    #      path = "@sysconfdir@/opendnssec/".sub("${prefix}", "@prefix@")
    options = OpenStruct.new
    #      options.default_conf_file = path + "conf.xml"
    options.zone = nil
    options.nameserver_unsigned = []
    options.nameserver_signed = []
    options.nagios_verbosity    = 3
    options.tsig_key = nil

    opts = OptionParser.new do |opts|
      opts.banner = "Usage: #{$0} [options]"

      # zone_name
      opts.on("-z", "--zone <ZONE_NAME>",
        "Zone to verify") do |zone|
        options.zone = Dnsruby::Name.create(zone)
      end

      opts.on("-u", "--unsigned <ns1>[,<port>]", Array,
        "The nameserver serving the unsigned zone.",
        "A port can be specified (defaults 53)",
        "No whitespace between server and port",
        "e.g. -u 127.0.0.1,5353",
        "e.g. -u localhost,5553") do |list|
        if (list.length > 2)
          print "VERIFY CRITICAL: Error parsing nameserver : #{list.inspect}\n"
          exit(3)
        end
        if (list.length == 1)
          options.nameserver_unsigned = ([list[0], 53])
        else
          options.nameserver_unsigned = ([list[0], list[1].to_i])
        end
      end

      opts.on("-k", "--key <key>", String,
        "Sets the TSIG key for the nameserver",
        "serving the unsigned zone.",
        "Expects the name of a file which",
        "holds the TSIG key",
        "e.g. -k key_file") do |filename|
        # Load the TSIG key!!!
        # form : key <name> { algorithm <alg>; secret "<secret>"; };
        key_string = ""
        File.open((filename+"").untaint, 'r') {|file|
          while (line = file.gets)
            key_string += line.chomp + " "
          end
        }
        split = key_string.split
        if ((split[0] != "key") || (split[3] != "algorithm") ||
              (split[5] != "secret") || (split[7] != "};"))
          print "VERIFY CRITICAL: Can't read key file #{filename}\n"
          exit(3);
        end
        name = split[1].chomp(";")
        alg = split[4].chomp(";")
        key_string = split[6].chomp(";")
        key_string.delete!('"')
#        print "Creating TSIG key : #{name}, #{alg}, #{key_string}\n"

        options.tsig_key = [name, key_string]

#        print "TSIG: #{options.tsig_key}\n"

      end

      opts.on("-s", "--signed <ns1>[,<port>]", Array,
        "The nameserver serving the signed zone.",
        "A port can be specified (defaults 53)",
        "No whitespace between server and port",
        "e.g. -s 127.0.0.1,5353",
        "e.g. -s localhost,5553") do |list|
        if (list.length > 2)
          print "VERIFY CRITICAL: Error parsing nameserver : #{list.inspect}\n"
          exit(3)
        end
        if (list.length == 1)
          options.nameserver_signed = ([list[0], 53])
        else
          options.nameserver_signed = ([list[0], list[1].to_i])
        end
      end

      opts.on("-v", "--verbose [n]", "Set the NAGIOS verbosity level to n",
        "Defaults to 0 (single line, minimal output) if -v not used",
        "defaults to 3 (Detailed output) if -v used with no number") do |n|
        options.nagios_verbosity = (n || 3).to_i
      end

      #      # Syslog facility
      #      opts.on("-l", "--log [FACILITY]",
      #        "Specify the syslog facility for results",
      #        "Defaults to print to console") do |log|
      #        syslog_facility = eval "Syslog::LOG_" + (log.upcase+"").untaint
      #        options.syslog = syslog_facility
      #      end

      # No argument, shows at tail.  This will print an options summary.
      # Try it and see!
      opts.on_tail("-h", "-?", "--help", "Show this message") do
        puts opts
        #        raise HelpExit.new
        exit
      end

    end
    opts.parse(args)
    options

  end  # parse()

end

options = VerifyOptionsParser.parse(ARGV)
if (Dnsruby.version < 1.50)
  print "VERIFY CRITICAL: DNSRUBY VERSION 1.50 OR GREATER REQUIRED\n"
  exit(3)
end
if (!options.zone)
  print "VERIFY CRITICAL: No zone specified\n"
  exit(3)
end
if (options.nameserver_unsigned.length == 0)
  print "VERIFY CRITICAL: No nameserver specified for AXFR of unsigned zone\n"
  exit(3)
end
if (options.nameserver_signed.length == 0)
  print "VERIFY CRITICAL: No nameserver specified for AXFR of signed zone\n"
  exit(3)
end

# Load the unsigned zone
signed_zone = []
unsigned_zone = []
begin
  addr, port = options.nameserver_unsigned
  zt = Dnsruby::ZoneTransfer.new
  zt.transfer_type = Dnsruby::Types.AXFR
  zt.server = addr
  zt.port = port
  if (options.tsig_key)
    # Add in the TSIG key for the unsigned nameserver
    zt.tsig = options.tsig_key
  end
  unsigned_zone = zt.transfer(options.zone)
rescue Dnsruby::ResolvError => e
  print "VERIFY CRITICAL: Can't transfer unsigned zone\n"
  exit(3)
end
unsigned_zone.sort!

# Load the signed zone
begin
  addr, port = options.nameserver_signed
  zt = Dnsruby::ZoneTransfer.new
  zt.transfer_type = Dnsruby::Types.AXFR
  zt.server = addr
  zt.port = port
  signed_zone = zt.transfer(options.zone)
rescue Dnsruby::ResolvError => e
  print "VERIFY CRITICAL: Can't transfer signed zone\n"
  exit(3)
end
signed_zone.sort!

# Compare the data in the two zones - they should be sorted the same.
# Can ignore any DNSSEC records seen in the signed (but not unsigned) zone.
# Any other differences should raise an error
extra_unsigned = []
extra_signed = []
unsigned_soa = nil
unsigned_zone.each {|unsigned_rr|
  if (!signed_zone.delete(unsigned_rr))
    if (unsigned_rr.type == Types::SOA)
      # Store the SOA
      unsigned_soa = unsigned_rr
    else
      # record in unsigned zone which could not be found in signed zone!!
      extra_unsigned.push(unsigned_rr)
    end
  end
}
signed_zone.each {|signed_rr|
  # Additional signed RR! Check that it is a DNSSEC record
  if !([Types::DNSKEY, Types::RRSIG, Types::NSEC, Types::NSEC3, Types::NSEC3PARAM].include?signed_rr.type)
    # If not, then raise the alarm
    extra_signed.push(signed_rr)
  else
    signed_zone.delete(signed_rr)
  end
}

# Deal with the SOAs! There may well be an SOA record in extra_signed
extra_signed.each {|rr|
  if (rr.type == Types::SOA)
    # Deal with the SOA record - compare it against the unsigned_soa
    if ((unsigned_soa.mname == rr.mname) && (unsigned_soa.rname == rr.rname) &&
          (unsigned_soa.refresh == rr.refresh) && (unsigned_soa.retry == rr.retry) &&
          (unsigned_soa.expire == rr.expire) && (unsigned_soa.minimum == rr.minimum))
      # SOA is OK - remove it from the extra
      extra_signed.delete(rr)
    end
  end
}

if (extra_signed.length == 0) && (extra_unsigned.length == 0)
  print "VERIFY OK: Signed and unsigned zones match\n"
  exit(0)
end

# Collect up the errors, and report them back to NAGIOS at the specified verbosity level
print "VERIFY CRITICAL: Mismatch between signed and unsigned zones\n"
if ([0,1].include?options.nagios_verbosity)
  exit(2)
end
    
# High Nagios verbosity - send back all the extra records
extra_signed.each {|signed_rr|
  print "VERIFY CRITICAL: Extra record in signed zone : #{signed_rr}\n"
}
extra_unsigned.each {|unsigned_rr|
  print "VERIFY CRITICAL: Extra record in signed zone : #{unsigned_rr}\n"
}
exit(2)