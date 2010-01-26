begin
  require 'timecop'
rescue LoadError
  require 'rubygems'
  require 'timecop'
end

# This file wraps dnssec_monitor.rb, allowing the test script to call the monitor
# in a new process, whilst setting the time that the monitor should think it is
# running at. This allows us to test time-dependant features.

begin
  Dir.chdir("lib")
rescue Exception
end
time = ARGV.delete_at(0)
Timecop.travel(Time.at(time.to_i)) {
  require 'dnssec_monitor.rb'
}

