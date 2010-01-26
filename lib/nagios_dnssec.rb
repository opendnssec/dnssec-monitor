#!/usr/bin/env ruby
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


# Provide a command-line interface from Nagios to DnssecMonitor
# Return the Nagios error code
# Format errors according to Nagios convention

require 'syslog'
include Syslog::Constants
require 'options_parser.rb'
EXPIRY_MAX = 99999
def process_log(options, output, syslog = nil)
  nagios_buffer = []
  worst_nagios_error = 0
  worst_nagios_output = ""
  closest_to_expiry = EXPIRY_MAX
  nagios_message = ""
  num_worst_errors = 0
  output.each do |line|
    line.sub!("nagios_dnssec: ", "")
    syslog_error = line[0,1].to_i
    message = line[1,line.length]
    if (syslog)
      # Add this line to the user-specified syslog facility
      syslog.log(syslog_error, message)
    end

    # Turn this line into nagios format and error code
    nagios_error = get_nagios_error_from_syslog(syslog_error)
    nagios_message = get_nagios_msg_from_syslog(message, nagios_error)
    # Check the options.nagios_verbosity level
    case options.nagios_verbosity
    when 0..1
      # Print only the most critical error message
      # Keep record of the worst error level, and the shortest time remaining within that period
      if (nagios_error >= worst_nagios_error)
        num_worst_errors = 0
        closest_to_expiry = get_expiry_from(nagios_message)
        worst_nagios_error = nagios_error
        worst_nagios_output = nagios_message
      elsif (nagios_error == worst_nagios_error)
        num_worst_errors += 1
        new_closest_to_expiry = [get_expiry_from(nagios_message), closest_to_expiry].min
        if (new_closest_to_expiry < closest_to_expiry)
          closest_to_expiry = new_closest_to_expiry
          worst_nagios_output = nagios_message
        end
      end
      # Single line, minimal output. Summary
    when 2
      # Multi line, configuration debug output
      if (nagios_error > 0)
        nagios_buffer.push"#{nagios_message}"
      end
    when 3,4,5,6,7,8,9
      # Lots of detail for problem diagnoses
      nagios_buffer.push"#{nagios_message}"
    end
  end
  case options.nagios_verbosity
  when 0..1
    nagios_buffer = [worst_nagios_output].to_s.chomp
    if (num_worst_errors > 1)
      nagios_buffer += " : #{num_worst_errors - 1} other issues at this level - run with -v 3 for details"
    end
    nagios_buffer += "\n"
  when 2
    if (nagios_buffer.length == 0)
      nagios_buffer = [nagios_message]
    end
  end
  nagios_buffer.each {|l|
    print l
  }
end

# Return the number of days left until expiry (read from the monitor output)
def get_expiry_from(monitor_output)
  index = monitor_output.index("will expire in")
  return EXPIRY_MAX if !index
  text = monitor_output[index, 25]
  num_days = text.split()[3].to_i
  return num_days
end

def get_nagios_msg_from_syslog(message, nagios_error)
  nag_err_str = case nagios_error
  when 0 then "DNSSEC OK"
  when 1 then "DNSSEC WARNING"
  when 2 then "DNSSEC CRITICAL"
  when 3 then "DNSSEC UNKNOWN"
  end
  return "#{nag_err_str}: #{message}"
end

def get_nagios_error_from_syslog(err)
  if ((err == 3) || (err == 2))
    return 2
  end
  if (err == 4)
    return  1
  end
  return 0

end

# Parse the options to get our arguments - tell NAGIOS if we have problems
options = nil
begin
  options = DnssecMonitor::OptionsParser.parse(ARGV, true)
rescue Exception => e
  if ((ARGV[0] != "-h") && (ARGV[0] != "-?"))
    print "DNSSEC UNKNOWN: Eror reading options : #{e}\n"
    exit(3)
  else
    exit
  end
end
if (!options.zone)
  print "DNSSEC UNKNOWN: No zone specified\n"
  exit(3)
end

# We then pass the same options to dnssec_monitor, but we need to remove
# some NAGIOS-specific ones first of all.
# Remove the -l or --log option from ARGV
# And the nagios_verbosity switch
log_facility = nil
delete_verbose = false
delete_next = false
ARGV.each {|e|
  if (delete_next)
    log_facility = e
    ARGV.delete(e)
    delete_next = false
  end
  if (delete_verbose)
    delete_verbose = false
    if ((e[0,1]!="-") && (e!=options.zone.to_s))
      ARGV.delete(e)
    end
  end
  if ((e == "-l") || (e == "--log"))
    ARGV.delete(e)
    delete_next = true
  end
  if ((e == "-v") || (e == "--verbose"))
    ARGV.delete(e)
    delete_verbose = true
  end
}

# Now fire up the dnssec_monitor in another process, catching its syslog output
# and error return
output = []
  IO.popen("ruby dnssec_monitor.rb #{ARGV.join" "}") {|fhi|
  while (line = fhi.gets)
    output.push(line)
  end
  }
ret_val = $?.exitstatus
#print "Finished checking\n"
# Turn the exit code into a nagios exit code
nagios_ret = get_nagios_error_from_syslog(ret_val)
if (ret_val == 1)
  print(LOG_ERR, "DNSSEC Monitor failed (#{ret_val})\n")
  exit nagios_ret
end

# Now go through the captured syslog output, converting it to the appropriate
# NAGIOS verbosity-level messages, and forwarding to the real syslog.
if (log_facility)
  syslog_facility = eval "Syslog::LOG_" + (log_facility.upcase+"").untaint
  Syslog.open("nagios_dnssec", Syslog::LOG_PID |
    Syslog::LOG_CONS, syslog_facility) { |syslog|
    process_log(options, output, syslog)
  }
else
  # If the user hasn't specified syslog, then don't bother using it
  process_log(options, output)
end

#print "EXITING : #{nagios_ret}\n"
exit(nagios_ret)
