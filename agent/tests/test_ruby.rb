puts "Loading Ruby RASP Agent..."
require_relative '../../vandam-ruby/vandam'

sleep(1) # wait for activation

puts "\n--- Triggering RASP Events ---"
puts "1. Testing exec_call (system)..."
system("echo 'Hello from Ruby'")

puts "2. Testing eval_code (eval)..."
eval("1 + 1")

puts "3. Testing file_read (File.read)..."
begin
  File.read("/etc/passwd")
rescue
end

puts "4. Testing dynamic_load (Fiddle.dlopen)..."
begin
  require 'fiddle'
  Fiddle.dlopen("libc.so.6")
rescue
end

puts "Ruby test complete."
sleep(1)
