#!/usr/bin/env ruby

# This NAGIOS plug-in uses external caching resolvers to continually check
# that the target zone validates successfully using cached responses.
# For example, it could use a BIND and an Unbound instance (configured with
# the root or DLV keys) to check that a caching resolver on the internet will
# be able to validate the target zone.

require 'optparse'
require 'ostruct'
require 'rubygems'
require 'dnsruby'
include Dnsruby

class RecursorOptionsParser
  def self.parse(args)
    # The options specified on the command line will be collected in *options*.
    # We set default values here.
    #      path = "@sysconfdir@/opendnssec/".sub("${prefix}", "@prefix@")
    options = OpenStruct.new
    #      options.default_conf_file = path + "conf.xml"
    options.zone = nil
    options.nameservers = []
    options.nagios_verbosity    = 3

    opts = OptionParser.new do |opts|
      opts.banner = "Usage: #{$0} [options]"

      # zone_name
      opts.on("-z", "--zone [ZONE_NAME]",
        "Zone to monitor") do |zone|
        options.zone = Dnsruby::Name.create(zone)
      end

      opts.on("-n", "--nameservers <ns1>[,<port>]", Array,
        "A new nameserver to monitor for the zone.",
        "A port can be specified (defaults 53)",
        "No whitespace between server and port",
        "e.g. -n 127.0.0.1,5353",
        "e.g. -n localhost,5553",
        "Use multiple times to configure multiple", "nameservers") do |list|
        if (list.length > 2)
          print "Error parsing nameserver : #{list.inspect}\n"
          exit(3)
        end
        if (list.length == 1)
          options.nameservers.push([list[0], 53])
        else
          options.nameservers.push([list[0], list[1].to_i])
        end
      end

      opts.on("-v", "--verbose [n]", "Set the NAGIOS verbosity level to n",
        "Defaults to 0 (single line, minimal output, if -v not used",
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

options = RecursorOptionsParser.parse(ARGV)
if (options.nameservers.length == 0)
  print "RECURSOR_CRTICAL: No nameservers specified for checks\n"
  exit(3)
end
if (!options.zone)
  print "RECURSOR CRITICAL: No zone specified\n"
  exit(3)
end
threads = []
count = 0
bad_answers = []
errors = []
options.nameservers.each { |ns_addr|
  threads[count] = Thread.new {
    addr, port = ns_addr
    #    print "Using nameserver on address : #{addr}, port : #{port}\n"
    res = Resolver.new({:nameserver => addr, :port => port})
    # Create the appropriate query
    query = Message.new(options.zone)
    query.do_caching = false
    query.do_validation = false
    query.header.cd = false
    # Get the response and check it
    ret = nil
    begin
      ret = res.send_message(query)
    rescue Exception => e
      Thread.exclusive {
        errors.push([addr, port, e])
        Thread.exit
      }
    end
    # Collate the errors found
    if ((ret.rcode != RCode.NOERROR) || (!ret.header.ad))
      Thread.exclusive {
        bad_answers.push([addr, port, ret])
      }
    end
  }
  count += 1
}
threads.length.times {|i|
  threads[i].join
}
# Now go through the list of errors and decide what to report
if ((bad_answers.length == 0) && (errors.length == 0))
  print "RECURSOR OK: Resolvers validate #{options.zone} successfully\n"
  exit(0)
end
# If verbosity is high, then send back all the errors
# If verbosity is low, then just send back the worst
# NAGIOS
# 1: Single line, minimal output. Summary
# 2: Multi line, configuration debug output
# >2: Lots of detail for problem diagnoses

if (bad_answers.length > 0)
  # Print bad answers
  bad_answers.each {|array|
    addr, port, ret = array

    print "RECURSOR CRITICAL: UNVALIDATED ANSWER FROM #{addr}:#{port}\n" # #{(options.nagios_verbosity > 2) ? ret : ""}\n"
    if (options.nagios_verbosity == 1)
      exit(3)
    end
  }
end
# Print errors
errors.each {|array|
  addr, port, exception = array
  print "RECURSOR WARNING: ERROR COMMUNICATING WITH #{addr}:#{port} : #{exception}\n"
    if (options.nagios_verbosity == 1)
      exit(4)
    end
}
exit(3)
