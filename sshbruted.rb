#!/usr/bin/env ruby

# Copyright (c) 2006, Stephen Waits <steve@waits.net>
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or 
# without modification, are permitted provided that the following 
# conditions are met:
# 
# Redistributions of source code must retain the above copyright 
# notice, this list of conditions and the following disclaimer.
# 
# Redistributions in binary form must reproduce the above copyright 
# notice, this list of conditions and the following disclaimer in 
# the documentation and/or other materials provided with the 
# distribution.
# 
# Neither the name of the Waits Consulting, Inc. nor the names of 
# its contributors may be used to endorse or promote products 
# derived from this software without specific prior written 
# permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE 
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN 
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
# POSSIBILITY OF SUCH DAMAGE.

#
# Script to blacklist idiots brute forcing sshd.
#
# By: Stephen Waits <steve@waits.net>
#
# 1. Build sshd with TCP Wrapper support.
#
# 2. Add a line like "ALL : /etc/hosts.blacklist : deny" 
#    to your /etc/hosts.allow
# 
# 3. Run this script with appropriate rights
#    

require 'time'
require 'thread'

LOG_COMMAND  = "/usr/bin/tail -F /var/log/auth.log"
BLACKLIST    = "/etc/hosts.blacklist"
MAX_FAILURES = 2
TIME_LIMIT   = 30 * 60  # 30 minutes

class Blacklister	
	def initialize
		@iplog = Hash.new([])
		@iplog_lock = Mutex.new
	end
	
	def add_hit(ip,time)
		@iplog_lock.synchronize do
			@iplog[ip] += [time]
		end
	end
	
	def list
		badlist = []
		@iplog_lock.synchronize do
			# clean up stale entries
			@iplog.reject! { |ip,times| stale_entry(times)  }
		
			# create our blacklist
			@iplog.each { |ip,times| badlist << ip if fresh_count(times) >= MAX_FAILURES }
		end
		badlist.sort
	end

	private

	def fresh_count(times)
		fresh_times = times.select { |t| (Time.now - t) < TIME_LIMIT }
		fresh_times.size
	end
	
	def stale_entry(times)
		fresh_count(times) == 0
	end
end


blacklister = Blacklister.new


input_thread = Thread.new do
	regexp = /(.+) [^\s]+ sshd\[\d+\]: Failed ([^\s]+) for ([\w\s]+?) from ([\d\.]+) port (\d+) ssh2/
	logfile = IO.popen(LOG_COMMAND)
	while line = logfile.gets
		match = regexp.match(line)
		if match
			time = Time.parse(match[1])
			ip = match[4]
			blacklister.add_hit(ip,time)
		end
	end
end


output_thread = Thread.new do
	list = []
	loop do
		sleep 1
		new_list = blacklister.list.join("\n")
		if new_list != list
			File.open(BLACKLIST,"w") { |f| f.puts(new_list) }
			#puts "[#{Time.now}]\n#{new_list}"
			list = new_list
		end
	end
end


input_thread.join

