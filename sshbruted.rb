
regexp = /(.+).+mailsystem sshd\[\d+\]: Failed ([\A ]+) for ([\A\s]+) from ([\d\.]+) port (\d+) ssh2/
match = regexp.match(subject)
if match
	result = match[1]
else
	result = ""
end

