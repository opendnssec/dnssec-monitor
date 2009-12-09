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

## Test the Monitor


require 'test/unit'
require 'rubygems'
require 'timecop'
require 'socket'
require 'dnsruby'
include Dnsruby

class TestMonitor < Test::Unit::TestCase
  def start_ipv4_server
    # Write test server (need to run privileged to get port 53) which listens to and responds to
    # queries for the zones of interest to the test code. Have it respond SERVFAIL to
    # all other queries.
    # Make sure we use a large EDNS message size so we don't have to worry about TCP

    socket = UDPSocket.new
    socket.bind("127.0.0.1", 53)
    serve(socket)
  end

  def serve(socket)

    load_zones

    while (true)
      # Accept
      packet, info = socket.recvfrom(4096)
      break if packet=="shutdown"
      query = Message.decode(packet)

      answer = make_response(query)

      begin
        socket.send(answer.encode, 0, info[3], info[1])
      rescue Exception => e
        print "ERROR Sending : #{answer}\n#{e}\n"
        exit(1)
      end
    end

    # Shut down
    socket.close
  end

  def load_zones
    # We need to create a set of signed zones from the root down to
    # the zone of interest ("example.com."?).
    # So we need a signed root zone pointing to com.
    # And a signed com. pointing to example.com.
    # We also need a signed example.com. with a few valid records of various types.
    # Use NSEC3.
    # Sign all zones with a decent tolerance - make sure that the root zone and
    # com. are valid for longer than example.com. (which should have the shortest
    # signature lifetime).
    # Then store the zone files in the test folder, and load them into memory
    # when the test starts up. When a request comes in, figure out which zone
    # the query is aimed at, look up the appropriate response (making sure that
    # NSEC3 denial etc. is correct!) and send it.
    # Should be able to figure out what the actual queries will be in any case...
    #
    # UNSIGNED ZONES :
    #
    # Root zone :
    #
    # . IN SOA nic.com. hostmaster.com. 1 2H 5M 4W 3H
    # . IN NS alex
    # . IN NS alexd
    # alex. IN A 127.0.0.1
    # alexd IN A 127.0.0.1
    #
    # com. zone :
    #
    # com. IN SOA nic.com. hostmaster.com. 2 2H 5M 4W 3H
    # com. IN NS alex.com.
    # com. IN NS alexd.com.
    # alexd IN A 127.0.0.1
    # alex IN A 127.0.0.1
    #
    # example.com. zone :
    #
    # example.com. IN SOA nic.example.com. hostmaster.example.com. 3 2H 5M 4W 1H
    # alex IN A 1.2.3.4
    # alex IN TXT "alex"
    # alexd IN A 2.3.4.5

    example_com_reader = Dnsruby::ZoneReader.new("example.com.")
    @example_com_zone = example_com_reader.process_file("test/example.com")
    com_reader = Dnsruby::ZoneReader.new("com.")
    @com_zone = com_reader.process_file("test/com")
    root_reader = Dnsruby::ZoneReader.new(".")
    @root_zone = root_reader.process_file("test/root")
  end

  def make_response(query)
    # Figure out which server the client thinks it is speaking to, and craft the appropriate response.
    begin
      if (query.question()[0].qtype == "NS")
        # Strip the first label, and what's left identifies the zone we're interested in.
        zone = get_zone(lose_n_labels_from_start(query.question()[0].qname, 1))
        response  = make_ns_response(query, zone)
        return response
      elsif (query.question()[0].qtype == "DS")
        # Strip the first label, and what's left identifies the zone we're interested in.
        if (["alex.example.com", "alexd.example.com"].include?query.question()[0].qname.to_s)
          Dnsruby::TheLog.level = Logger::DEBUG
          response = query.clone
          query.header.qr = true
          query.header.aa = true
          return response
        end
        zone = get_zone(lose_n_labels_from_start(query.question()[0].qname, 1))
        response  = make_ds_response(query, zone)
        return response
      elsif (query.question()[0].qtype == "A")
        # Strip the first label, and what's left identifies the zone we're interested in.
        zone = get_zone(lose_n_labels_from_start(query.question()[0].qname, 1))
        response  = make_a_response(query, zone)
        return response
      elsif (query.question()[0].qtype == "RRSIG")
        # The query name identifies the zone we're interested in.
        if (query.question()[0].qname.to_s.index"alex")
          zone = @example_com_zone
          response = make_domain_rrsig_response(query, zone)
          return response
        else
          zone = get_zone(query.question()[0].qname)
          response  = make_rrsig_response(query, zone)
          return response
        end
      elsif (query.question()[0].qtype == "SOA")
        # The query name identifies the zone we're interested in.
        zone = get_zone(query.question()[0].qname)
        response  = make_soa_response(query, zone)
        return response
      elsif (query.question()[0].qtype == "DNSKEY")
        # The query name identifies the zone we're interested in.
        zone = get_zone(query.question()[0].qname)
        response  = make_dnskey_response(query, zone)
        return response
      end
    rescue ArgumentError => e
    end
    print "\n\nCAN'T HANDLE QUERY FOR : #{query}\n\n"
    query.header.rcode = RCode.SERVFAIL
    return query
  end

  def make_dnskey_response(query, zone)
    # @TODO@ Also need to create DNSKEY response - from parent, this should give DS for child
    # From target, this should give keys for current zone.
    # Could we hack it, and dd current zone DNSKEY in answer, and child DS/NS in authority with A in additional?
    response = query.clone
    query.header.qr = true
    query.header.aa = true
    answer_rrset = RRSet.new
    ns_rrsets = []
    ds_rrsets = []
    a_rrsets = []
    zone.each {|rr|
      # Load up the RRSets
      # DS in answer, NS in authority, A in additional (remembering RRSIGs)
      if ((get_type(rr) == "DNSKEY") && (query.question()[0].qname == rr.name))
        answer_rrset.add(rr)
      elsif get_type(rr) == "DS"
        add_to_rrsets(rr, ds_rrsets)
      elsif get_type(rr) == "NS"
        add_to_rrsets(rr, ns_rrsets)
      end
      if get_type(rr) == "A" # No AAAA in test zones
        add_to_rrsets(rr, a_rrsets)
      end
    }
    answer_rrset.each {|rr|
      response.add_answer(rr)
    }
    ns_rrsets.each {|ns_rrset|
      ns_rrset.each {|rr|
        response.add_authority(rr)
      }
    }
    ds_rrsets.each {|ds_rrset|
      ds_rrset.each {|rr|
        response.add_authority(rr)
      }
    }
    a_rrsets.each {|a_rrset|
      a_rrset.each {|rr|
        response.add_additional(rr)
      }
    }
    return response
  end

  def make_a_response(query, zone)
    # A (+RRSIG) in answer, ns (+RRSIGs) in authority, with A in additional
    response = query.clone
    query.header.qr = true
    query.header.aa = true
    answer_rrset = RRSet.new
    ns_rrsets = []
    a_rrsets = []
    zone.each {|rr|
      # Load up the RRSets
      # DS in answer, NS in authority, A in additional (remembering RRSIGs)
      if ((get_type(rr) == "A") && (query.question()[0].qname == rr.name))
        answer_rrset.add(rr)
      elsif get_type(rr) == "NS"
        add_to_rrsets(rr, ns_rrsets)
      end
      if get_type(rr) == "A" # No AAAA in test zones
        add_to_rrsets(rr, a_rrsets)
      end
    }
    answer_rrset.each {|rr|
      response.add_answer(rr)
    }
    ns_rrsets.each {|ns_rrset|
      ns_rrset.each {|rr|
        response.add_authority(rr)
      }
    }
    a_rrsets.each {|a_rrset|
      a_rrset.each {|rr|
        response.add_additional(rr)
      }
    }
    return response
  end

  def make_soa_response(query, zone)
    # A (+RRSIG) in answer, ns (+RRSIGs) in authority, with A in additional
    response = query.clone
    query.header.qr = true
    query.header.aa = true
    answer_rrset = RRSet.new
    ns_rrsets = []
    a_rrsets = []
    zone.each {|rr|
      # Load up the RRSets
      # SOA in answer, NS in authority, A in additional (remembering RRSIGs)
      if ((get_type(rr) == "SOA") && (query.question()[0].qname == rr.name))
        answer_rrset.add(rr)
      elsif get_type(rr) == "NS"
        add_to_rrsets(rr, ns_rrsets)
      end
      if get_type(rr) == "A" # No AAAA in test zones
        add_to_rrsets(rr, a_rrsets)
      end
    }
    answer_rrset.each {|rr|
      response.add_answer(rr)
    }
    ns_rrsets.each {|ns_rrset|
      ns_rrset.each {|rr|
        response.add_authority(rr)
      }
    }
    a_rrsets.each {|a_rrset|
      a_rrset.each {|rr|
        response.add_additional(rr)
      }
    }
    return response
  end

  def make_domain_rrsig_response(query, zone)
    # Need : record of interest + RRSIG in answer
    # Authority should contain NS records for zone servers (+RRSIGs)
    # Additional should contain A/AAAA records for the NS records (+RRSIGs)
    response = query.clone
    query.header.qr = true
    query.header.aa = true
    answer_rrsets = []
    ns_rrsets = []
    a_rrsets = []
    zone.each {|rr|
      # Load up the RRSets
      # DS in answer, NS in authority, A in additional (remembering RRSIGs)
      if rr.type == "RRSIG"
        add_to_rrsets(rr, answer_rrsets)
      end
    }
    answer_rrsets.each {|answer_rrset|
      answer_rrset.each {|rr|
        response.add_answer(rr)
      }
    }
    ns_rrsets.each {|ns_rrset|
      ns_rrset.each {|rr|
        response.add_authority(rr)
      }
    }
    a_rrsets.each {|a_rrset|
      a_rrset.each {|rr|
        response.add_additional(rr)
      }
    }
    return response
  end

  def make_rrsig_response(query, zone)
    # all RRSIGs in answer, with NS in authority and A in additional (remembering RRSIGs)
    response = query.clone
    query.header.qr = true
    query.header.aa = true
    rrsig_rrsets = []
    ns_rrsets = []
    a_rrsets = []
    zone.each {|rr|
      # Load up the RRSets
      # DS in answer, NS in authority, A in additional (remembering RRSIGs)
      if rr.type == "RRSIG"
        add_to_rrsets(rr, rrsig_rrsets)
      end
      if get_type(rr) == "NS"
        add_to_rrsets(rr, ns_rrsets)
      elsif get_type(rr) == "A" # No AAAA in test zones
        add_to_rrsets(rr, a_rrsets)
      end
    }
    rrsig_rrsets.each {|rrsig_rrset|
      rrsig_rrset.each {|rr|
        response.add_answer(rr)
      }
    }
    ns_rrsets.each {|ns_rrset|
      ns_rrset.each {|rr|
        response.add_authority(rr)
      }
    }
    a_rrsets.each {|a_rrset|
      a_rrset.each {|rr|
        response.add_additional(rr)
      }
    }
    return response
  end

  def denial(query, zone)
    # Construct denial response
    # What should this look like?
    # Nothing in answer section
    # Nothing in additional
    # Authority section should contain :
    # o SOA record for zone (+RRSIG)
    # o Three NSEC3 records (+RRSIGs). Can we just send them all back?
    response = query.clone
    response.header.rcode = RCode.NXDOMAIN
    query.header.qr = true
    query.header.aa = true
    soa_rrset = RRSet.new
    nsec3_rrsets = []
    zone.each {|rr|
      # Load up the RRSets
      # DS in answer, NS in authority, A in additional (remembering RRSIGs)
      if get_type(rr) == "SOA"
        soa_rrset.add(rr)
      elsif get_type(rr) == "NSEC3"
        add_to_rrsets(rr, nsec3_rrsets)
      end
    }
    soa_rrset.each {|rr|
      response.add_authority(rr)
    }
    nsec3_rrsets.each {|nsec3_rrset|
      nsec3_rrset.each {|rr|
        response.add_authority(rr)
      }
    }
    return response
  end

  def make_ns_response(query, zone)
    # This could either be for valid NS, or for the non-existent name
    # If for valid NS, then we can reply with NS in answer, and A in additional (remembering RRSIGs)
    # If for unknown name, then send an NSEC3 denial of existence.
    # So, first of all see if we can find the name - try to fill up the answer rrsets at the same time (save time)
    # If we can't find anything at all, then trigger NSEC3
    if (zone == @example_com_zone)
      return denial(query, zone)
    end
    response = query.clone
    query.header.qr = true
    query.header.aa = true
    ns_rrsets = []
    a_rrsets = []
    zone.each {|rr|
      # Load up the RRSets
      # NS in answer, NS in authority, A in additional (remembering RRSIGs)
      if ((get_type(rr) == "NS")) # && (rr.name.to_s == query.question()[0].qname.to_s))
        add_to_rrsets(rr, ns_rrsets)
      elsif get_type(rr) == "A" # No AAAA in test zones
        add_to_rrsets(rr, a_rrsets)
      end
    }
    ns_rrsets.each {|ns_rrset|
      ns_rrset.each {|rr|
        # @TODO@ Need to know if this is a query to the authoritative server or not.
        # Hard to know, since all servers run on the same socket...
        # HACK - stick NS records in both for now
        response.add_answer(rr)
        response.add_authority(rr)
      }
    }
    a_rrsets.each {|a_rrset|
      a_rrset.each {|rr|
        response.add_additional(rr)
      }
    }
    return response
  end

  def make_ds_response(query, zone)
    response = query.clone
    query.header.qr = true
    query.header.aa = true
    ds_rrset = RRSet.new
    ns_rrsets = []
    a_rrsets = []
    zone.each {|rr|
      # Load up the RRSets
      # DS in answer, NS in authority, A in additional (remembering RRSIGs)
      if get_type(rr) == "DS"
        ds_rrset.add(rr)
      elsif get_type(rr) == "NS"
        add_to_rrsets(rr, ns_rrsets)
      elsif get_type(rr) == "A" # No AAAA in test zones
        add_to_rrsets(rr, a_rrsets)
      end
    }
    ds_rrset.each {|rr|
      response.add_answer(rr)
    }
    ns_rrsets.each {|ns_rrset|
      ns_rrset.each {|rr|
        response.add_authority(rr)
      }
    }
    a_rrsets.each {|a_rrset|
      a_rrset.each {|rr|
        response.add_additional(rr)
      }
    }
    return response
  end

  def add_to_rrsets(rr, rrsets)
    found = false
    rrsets.each {|ns_rrset|
      found = ns_rrset.add(rr)
    }
    if (!found)
      rrsets.push(RRSet.new(rr))
    end
  end

  def get_type(rr)
    if rr.type == Types.RRSIG
      return rr.type_covered
    else return rr.type
    end
  end

  def get_zone(name)
    zone = case name.to_s
    when "" then @root_zone
    when "com" then @com_zone
    when "example.com" then @example_com_zone
    else
      raise ArgumentError.new("Unknown zone : #{name}")
    end
    return zone
  end

  def lose_n_labels_from_start(name, n)
    if (name.labels.length <= n)
      return Name.create(".")
    end
    n = Name.new(name.labels()[n, name.labels.length-n], name.absolute?)
    return n
  end

  def test_monitor
    # Set up the test environment
    #  o Authoritative servers
    thread = Thread.new {
      start_ipv4_server
    }
    run_tests
    # Might need to send a message to poke the server into stopping...
    socket = UDPSocket.open
    socket.connect(nil, 53)
    socket.send("shutdown", 0)

    thread.join
  end

  def check_server_works
    res = Resolver.new({:nameserver => "127.0.0.1"})
    ret =  res.query("example.com", "DS")
    assert(ret.answer.rrset("example.com", "DS").rrs.length > 0)
    q = Queue.new
    res.send_async(Message.new("notthere.example.com", "NS"), q, q)
    id, ret, err = q.pop
    assert(NXDomain === err)
    assert(ret.answer.rrsets.length == 0)
    ret =  res.query("alex.example.com", "A")
    assert(ret.answer.rrset("alex.example.com", "A").rrs.length > 0)
    ret =  res.query("example.com", "RRSIG")
    assert(ret.answer.rrsets("RRSIG").length > 0)
  end

  def test_dlv
    # DLV tests run against the live server, just to make sure there are some real-world tests.
    options = " -z se --dlvkey ../test/dlv.key --kskwarn 1 --kskcritical 1 --zskwarn 1 --zskcritical 1"
    time = Time.now
    run_monitor(options, time, 0)
    time = Time.gm(2009, 11, 23, 13, 0, 0)
    run_monitor(options, time, 3)
    # Can't really check the output here, as we don't know the current state
  end

  def run_tests
    check_server_works
    options = " --rootkey ../test/root.key -z example.com --hints 127.0.0.1 --zskwarn 1 --zskcritical 1 --kskwarn 1 --kskcritical 1 --names alexd,alex --dcritical 1 --dwarn 1"

    # Want a successful test
    time = Time.gm(2009, 11, 28, 13, 0, 0)
    output = run_monitor(options, time, 0)
    # Check the output
    assert(check_syslog(output, []))


    # Then set time to bad time, and check errors/warnings generated
    # Also, we should probably set up some validation failures - e.g. bad DS records, bad DNSKEY, etc.
    # Check the syslog output - we just want to see the error messages we're expecting.

    # Test checks on individual domains (in example.com)
    # Do these at same time as apex inception and expiration checks

    # Check signature expiration
    # Set time near end of validity for example.com RRSIGs
    expected_strings = []
    ["alexns.example", "alexdns.example"].each {|ns|
      4.times { |x|
        expected_strings.push("4 : (#{ns}): ZSK(key_tag 7877): RRSIG for example.com.	2678400	IN	DNSKEY	256 3 RSASHA1-NSEC3-SHA1 ( AwEAAfFF869A/FiM1z8LZdK1pEfMgQhp1Pzeg+jUAJiQECDkJwfoCOKbyZZ/n1KtUM8WdtTho6mPI99tKN9UctVh6XyuuklA6M2F2vgj7zB0zv1VeQNwx8kaSZmxhnV4L7XzVUZK9BLfLwj9XlSBSpPWfElN2Ih6bd8RENA0vfQsZ9vp ) ; key_tag=7877 will expire in 0.07")
        expected_strings.push("3 : (#{ns}): ZSK(key_tag 7877): RRSIG for example.com.	2678400	IN	DNSKEY	256 3 RSASHA1-NSEC3-SHA1 ( AwEAAfFF869A/FiM1z8LZdK1pEfMgQhp1Pzeg+jUAJiQECDkJwfoCOKbyZZ/n1KtUM8WdtTho6mPI99tKN9UctVh6XyuuklA6M2F2vgj7zB0zv1VeQNwx8kaSZmxhnV4L7XzVUZK9BLfLwj9XlSBSpPWfElN2Ih6bd8RENA0vfQsZ9vp ) ; key_tag=7877 will expire in 0.07")
        expected_strings.push("3 : (#{ns}): KSK(key_tag 18931): RRSIG for example.com.	2678400	IN	DNSKEY	257 3 RSASHA1-NSEC3-SHA1 ( AwEAAclPAcnkTHj2XSQfe/A3l15IOwr9+cfy5BxE8fVt2sSipf/Q1noqGAEBJ/2FLM8o3TGdVPOvcWhpHnTqoZwTwKhoA040CvielB/6rOwfZalQUaAijQZ48W3q6O/3tugHTzzgmpN0gsblwJZWe3k8zr/Z5W13TUFFgNRgZr8Y/8AqTOIctZY0l5yUgoWFvx7UQf+RR87xebgIAFHTE3VDHsZzdge6hKoMfQxI9tlc2ezDyIZpojti1B18LiPuIp3FPPFaK76cTmAtqo0pqwpq/z0ZUmjnvH8pXRafPM734CHbry7NBpJO3R7Jxg5r0SR+wN7/kmZ2uWLS9I8U/mJpgg0= ) ; key_tag=18931 will expire in 0.07")
        expected_strings.push("4 : (#{ns}): KSK(key_tag 18931): RRSIG for example.com.	2678400	IN	DNSKEY	257 3 RSASHA1-NSEC3-SHA1 ( AwEAAclPAcnkTHj2XSQfe/A3l15IOwr9+cfy5BxE8fVt2sSipf/Q1noqGAEBJ/2FLM8o3TGdVPOvcWhpHnTqoZwTwKhoA040CvielB/6rOwfZalQUaAijQZ48W3q6O/3tugHTzzgmpN0gsblwJZWe3k8zr/Z5W13TUFFgNRgZr8Y/8AqTOIctZY0l5yUgoWFvx7UQf+RR87xebgIAFHTE3VDHsZzdge6hKoMfQxI9tlc2ezDyIZpojti1B18LiPuIp3FPPFaK76cTmAtqo0pqwpq/z0ZUmjnvH8pXRafPM734CHbry7NBpJO3R7Jxg5r0SR+wN7/kmZ2uWLS9I8U/mJpgg0= ) ; key_tag=18931 will expire in 0.07")
        expected_strings.push("3 : (#{ns}): RRSIG for alex.example.com, SOA will expire in 0.07")
        expected_strings.push("4 : (#{ns}): RRSIG for alex.example.com, SOA will expire in 0.07")
        expected_strings.push("3 : (#{ns}): RRSIG for alex.example.com, DNSKEY will expire in 0.07")
        expected_strings.push("4 : (#{ns}): RRSIG for alex.example.com, DNSKEY will expire in 0.07")
        expected_strings.push("3 : (#{ns}): RRSIG for alex.example.com, NSEC3PARAM will expire in 0.07")
        expected_strings.push("4 : (#{ns}): RRSIG for alex.example.com, NSEC3PARAM will expire in 0.07")
        expected_strings.push("3 : (#{ns}): RRSIG for alex.example.com, NSEC3 will expire in 0.07")
        expected_strings.push("4 : (#{ns}): RRSIG for alex.example.com, NSEC3 will expire in 0.07")
        expected_strings.push("3 : (#{ns}): RRSIG for alex.example.com, A will expire in 0.07")
        expected_strings.push("4 : (#{ns}): RRSIG for alex.example.com, A will expire in 0.07")
        expected_strings.push("3 : (#{ns}): RRSIG for alex.example.com, TXT will expire in 0.07")
        expected_strings.push("4 : (#{ns}): RRSIG for alex.example.com, TXT will expire in 0.07")

        expected_strings.push("3 : (#{ns}): RRSIG for alexd.example.com, SOA will expire in 0.07")
        expected_strings.push("4 : (#{ns}): RRSIG for alexd.example.com, SOA will expire in 0.07")
        expected_strings.push("3 : (#{ns}): RRSIG for alexd.example.com, DNSKEY will expire in 0.07")
        expected_strings.push("4 : (#{ns}): RRSIG for alexd.example.com, DNSKEY will expire in 0.07")
        expected_strings.push("3 : (#{ns}): RRSIG for alexd.example.com, NSEC3PARAM will expire in 0.07")
        expected_strings.push("4 : (#{ns}): RRSIG for alexd.example.com, NSEC3PARAM will expire in 0.07")
        expected_strings.push("3 : (#{ns}): RRSIG for alexd.example.com, NSEC3 will expire in 0.07")
        expected_strings.push("4 : (#{ns}): RRSIG for alexd.example.com, NSEC3 will expire in 0.07")
        expected_strings.push("3 : (#{ns}): RRSIG for alexd.example.com, A will expire in 0.07")
        expected_strings.push("4 : (#{ns}): RRSIG for alexd.example.com, A will expire in 0.07")
        expected_strings.push("3 : (#{ns}): RRSIG for alexd.example.com, TXT will expire in 0.07")
        expected_strings.push("4 : (#{ns}): RRSIG for alexd.example.com, TXT will expire in 0.07")
      }
    }
    time = Time.gm(2009, 12, 02, 8, 0, 0)
    output = run_monitor(options, time, 3)
    assert(check_syslog(output, expected_strings))

    # Check signature inception
    # Set time near start of validity for example.com RRSIGs
    #    print "\nChecking near beginning of lifetime\n\n"
    expected_strings = []
    ["alexns.example", "alexdns.example"].each {|ns|
      expected_strings.push("3 : (#{ns}): RRSIG for example.com, SOA has an inception time ")
      expected_strings.push("3 : (#{ns}): RRSIG for example.com, DNSKEY has an inception time ")
      expected_strings.push("3 : (#{ns}): RRSIG for example.com, NSEC3PARAM has an inception time ")
      expected_strings.push("3 : (#{ns}): RRSIG for example.com, NSEC3 has an inception time ")

      # These are only here on account of the hacky test server...
      expected_strings.push("3 : (#{ns}): RRSIG for example.com, A has an inception time ")
      expected_strings.push("3 : (#{ns}): RRSIG for example.com, TXT has an inception time ")

      ["alex.example.com", "alexd.example.com"].each {|d|
        expected_strings.push("3 : (#{ns}): RRSIG for #{d}, A has an inception time ")
        expected_strings.push("3 : (#{ns}): RRSIG for #{d}, TXT has an inception time ")
        expected_strings.push("3 : (#{ns}): RRSIG for #{d}, DNSKEY has an inception time ")
        expected_strings.push("3 : (#{ns}): RRSIG for #{d}, SOA has an inception time ")
        expected_strings.push("3 : (#{ns}): RRSIG for #{d}, NSEC3 has an inception time ")
        expected_strings.push("3 : (#{ns}): RRSIG for #{d}, NSEC3PARAM has an inception time ")
      }
    }
    time = Time.gm(2009, 11, 27, 10, 0, 0)
    output = run_monitor(options, time, 3)
    assert(check_syslog(output, expected_strings))

    # @TODO@ Check parent DS incorrect
    # Perhaps we could set some flags so that the server serves up a corrupted DS record for example.com?
    # Also tests validation
  end

  def check_syslog(remaining_strings, expected_strings)
    remaining_strings.reverse.each {|line|
      if ((line.length == 0) || (line[0,1] == "6") || (line=="\n"))
        remaining_strings.delete(line)
        next
      end
      expected_strings.reverse.each {|expected|
        if (line.index(expected))
          remaining_strings.delete_if {|l| l.index(expected)} # (line)
          expected_strings.delete(expected)
          break
        end
      }


    }
    success = true
    expected_strings.each {|string|
      print "Couldn't find expected error : #{string}\n"
      success = false
    }
    remaining_strings.each {|line|
      print "Got unexpected error : #{line}\n"
      success= false
    }
    return success
  end

  def run_monitor(options, time, expected_ret)
    # In a new process, require 'dnssec_monitor.rb" with appropriate config
    # Remember to do this with Timecop!
    output = []
    IO.popen("ruby test/dnssec_monitor_time_shift.rb '#{time.to_i}' #{options}") {|fhi|
      while (line = fhi.gets)
        output.push(line)
        #        print line
      end
    }
    ret_val = $?.exitstatus
    if (expected_ret != 0)
      assert_equal(expected_ret, ret_val, "Expected return of #{expected_ret} from successful monitor run\n")
    end
    output.each {|line|
      if line.index("ns.example): No RRSIGS found in example.com, NS RRSet")
        output.delete(line) 
        #        print "Deleted NS RRSIGs error\n"
        next
      end
      if (expected_ret == 0)
        assert(!(line.index("3 :")), "Should have no errors")
        assert(!(line.index("4 :")), "Should have no warnings")
      end
    }
    return output
  end
end