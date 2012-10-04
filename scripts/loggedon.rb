users = []
client.sys.process.each_process do |x|
        users << x["user"]
end

users.sort!
users.uniq!
users.delete_if {|x| x =~ /^NT\ AUTHORITY/}
users.delete_if {|x| x == ""}
loggedin = users.join(', ')
