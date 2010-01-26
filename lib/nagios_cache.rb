#!/usr/bin/env ruby

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

# This NAGIOS plug-in is designed to test KSK/ZSK rollover at the parent.
# It does this by communicating with a dedicated Unbound resolver (this
# is chosen for the ability to selectively remove RRSets from the cache).
# The resolver is primed with the historical cache for each test in turn.
# Each test then removes selected RRSets from the cache, before checking
# that the resolver still correctly validates the target zone.
#
# NB : This program expects to be run on the same machine as a dedicated
# instance of Unbound (www.unbound.net), which has been set up with the
# control facility unbound-control.

require 'optparse'
require 'ostruct'
begin
  require 'dnsruby'
rescue LoadError
  require 'rubygems'
  require 'dnsruby'
end
include Dnsruby

CACHE_FILE = "/var/tmp/cache.old"


class CacheCheckerOptionsParser
  def self.parse(args)
    # The options specified on the command line will be collected in *options*.
    # We set default values here.
    #      path = "@sysconfdir@/opendnssec/".sub("${prefix}", "@prefix@")
    options = OpenStruct.new
    #      options.default_conf_file = path + "conf.xml"
    options.nagios_verbosity    = 3
    options.nameserver = ["127.0.0.1", 53]

    opts = OptionParser.new do |opts|
      opts.banner = "Usage: #{$0} [options]"

      # zone_name
      opts.on("-z", "--zone <ZONE_NAME>",
        "Zone to monitor") do |zone|
        options.zone = Dnsruby::Name.create(zone)
      end

      opts.on("-c", "--config <config_file>",
        "Location of the Unbound config file",
        "(Optional)") do |c|
        options.config = c
      end

      #      opts.on("-n", "--nameserver <ns1>[,<port>]", Array,
      #        "A nameserver to monitor for the zone.",
      #        "A port can be specified (defaults 53)",
      #        "No whitespace between server and port",
      #        "Defaults to 127.0.0.1:53"
      #        #        "e.g. -n localhost,5553"
      #      ) do |list|
      #        if (list.length > 2)
      #          print "Error parsing nameserver : #{list.inspect}\n"
      #          exit(3)
      #        end
      #        if (list.length == 1)
      #          options.nameserver = [list[0], 53]
      #        else
      #          options.nameserver = [list[0], list[1].to_i]
      #        end
      #      end

      opts.on("--name <name>,<type>", Array,
        "A name and optional type (defaults to A)",
        "which should be checked in the target zone",
        "  e.g. --name example.com,MX") do |list|
        if (list.length > 2)
          print "Error parsing name : #{list.inspect}\n"
          exit(3)
        end
        if (list.length == 1)
          options.name_and_type_to_check = [list[0], Types.A]
        else
          options.name_and_type_to_check = [list[0], Types.new(list[1])]
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

def send_query(res, options)
  # Create the appropriate query
  name, type = options.name_and_type_to_check
  query = Message.new(name, type)
  query.do_caching = false
  query.do_validation = false
  query.header.cd = false
  # Get the response and check it
  begin
    ret = res.send_message(query)
    if ((ret.rcode != RCode.NOERROR) || (!ret.header.ad))
      return "Error validating query (rcode=#{ret.rcode}, AD=#{ret.header.ad})\n"
    end
    return nil
  rescue Exception => e
    print "CACHECHECKER CRITICAL: Error sending validation query : #{e}\n"
    exit(3)
  end
end

def get_unbound_command_start(options)
  s = "unbound-control "
  if (options.config)
    #    system "unbound-control -s #{addr}@#{port} -c #{options.config} #{msg}"
    s += "-c #{options.config} "
  end
  return s
end

def send_unbound(msg, options)
  #  addr, port = options.nameserver
  s = get_unbound_command_start(options)
  s += msg + " > /dev/null 2> /dev/null"
  system s #"unbound-control -c #{options.config} #{msg}"
end

def dump_cache(res, options)
  #  print "Dumping cache...\n"
  # Make sure that the resolver has a good cache - clear the cache
  send_unbound("flush_zone .", options)
  # And perform the validating query again.
  send_query(res, options)
  # And then store the cache
  s = get_unbound_command_start(options)
  s += "dump_cache > #{CACHE_FILE} 2> /dev/null"
  system s # "unbound-control dump_cache > cache.old"
  #  print "Cache dumped\n"
end

options = CacheCheckerOptionsParser.parse(ARGV)
if (!options.nameserver)
  print "CACHECHECKER CRTICAL: No nameserver specified for checks\n"
  exit(3)
end
if (!options.zone)
  print "CACHECHECKER CRITICAL: No zone specified\n"
  exit(3)
end
if (!options.name_and_type_to_check)
  print "CACHECHECKER CRITICAL: No name and type to check\n"
  exit(3)
end
# Create the Resolver object from options.nameserver
addr, port = options.nameserver
#print "Making resolver\n"
res = Resolver.new({:nameserver => addr, :port => port})
#print "Got resolver\n"
# tests stores a textual description of the test to be run, followed by
# a list of the types to wipe from the cache before sending the validation query.
tests = {"ZSK Rollover : neither DNSKEY nor RRSIG records in cache" => [Types.DNSKEY, Types.RRSIG],
  "ZSK Rollover : DNSKEY but no RRSIG records in cache" => [Types.RRSIG],
  "ZSK Rollover : RRSIG but no DNSKEY records in cache" => [Types.DNSKEY],
  "KSK Rollover : neither DS nor DNSKEY records in cache" => [Types.DS, Types.DNSKEY],
  "KSK Rollover : DS but no DNSKEY records in cache" => [Types.DNSKEY],
  "KSK Rollover : DNSKEY but no DS records in cache" => [Types.DS]
}
# Check if cache.old exists - if it doesn't, then quickly create it
if (File.exist?("#{CACHE_FILE}"))
  File.delete("#{CACHE_FILE}")
end
dump_cache(res, options)
#print "Starting tests\n"
count = 0
errors = {}
tests.each {|test, rrs_to_wipe|
  # First of all, make sure that the resolver cache is reset
  #  print "Flushing zone\n"
  send_unbound("flush_zone .", options)
  #  send_unbound("load_cache #{cache}", options)
  s = get_unbound_command_start(options)
  s += "load_cache "
  # Need to do this in a separate process, and ignore the "ok" response
  IO.popen("#{s} < #{CACHE_FILE}") {|fhi|
    while (line = fhi.gets) # Ignore the output
      #    output.push(line)
    end
  }
  ret_val = $?.exitstatus
  if (ret_val != 0)
    errors[test] = "Can't load_cache to unbound\n"
    next
  end

  # Then, delete the RRSets we want to delete
#    print "Setting up for : #{test}\n"
  rrs_to_wipe.each { |type|
    if (type == Types.RRSIG)
      # We want to wipe the RRSIG for a specific name and type.
      name, type = options.name_and_type_to_check
      send_unbound("flush_type #{name} #{type.string}", options)
    else
      # Wipe the specified RR for the zone from the cache
      send_unbound("flush_type #{options.zone} #{type.string}", options)
    end
  }
#  system "unbound-control dump_cache"
  # Then, send the validation query
  error = send_query(res, options)
  # And collect any errors
  errors[test] = error if error
  count += 1
}
dump_cache(res, options)
if (errors.length == 0)
  print "CACHECHECKER OK: All rollover scenarios checked\n"
  exit(0)
end
errors.each {|test, error|
  # Go through the results, and report the appropriate messages
  # and error code to Nagios.
  print "CACHECHECKER CRITICAL: Failed test for #{test} : #{error}\n"
  if ([0,1].include?options.verbosity)
    exit(3)
  end
}
exit(3)