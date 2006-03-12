#!/usr/bin/env ruby

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

