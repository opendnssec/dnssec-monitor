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

## @TODO@ Test the Monitor!!!

# Write test server (need to run privileged to get port 53) which listens to and responds to
# queries for the zones of interest to the test code. Have it respond SERVFAIL to
# all other queries.

require 'test/unit'
require 'rubygems'
require 'timecop'

class TestMonitor < Test::Unit::TestCase
    # @TODO@
    # Set up the test environment
    #  o Authoritative servers
    #  o Recursive resolver? Not needed

  def test_dlv
    # DLV tests run against the live server, just to make sure there are some real-world tests.
    # In a new process, require 'dnssec_monitor.rb" with appropriate config
    # Remember to do this with Timecop!
    options = " -z se --dlvkey ../test/dlv.key "
    time = Time.now
    stderr = IO::pipe
    run_monitor(stderr, options, time, 0)
    stderr = IO::pipe
    time = Time.gm(2009, 11, 23, 13, 0, 0)
    run_monitor(stderr, options, time, 3)
    # @TODO@ Check the syslog output
  end

  def run_monitor(stderr, options, time, expected_ret)
    pid = fork {
      stderr[0].close
      STDERR.reopen(stderr[1])
      stderr[1].close

      Dir.chdir("lib")
      count = 0
      options.split.each {|option|
        ARGV[count] = option
        count += 1
      }

      Timecop.travel(time) do
        require 'dnssec_monitor.rb'
      end
      exit($?.exitstatus)
    }
    stderr[1].close
    Process.waitpid(pid)
    ret_val = $?.exitstatus
    assert_equal(expected_ret, ret_val, "Expected return of #{expected_ret} from successful monitor run")
  end
end