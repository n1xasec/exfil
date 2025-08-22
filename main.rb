#!/usr/bin/env ruby

require 'socket'
require 'digest'
require 'optparse'
require 'openssl'
require 'base64'
require "securerandom"

HEADER = "=======EXFIL======="
SEPARATOR = "==================="

options = {}

parser = OptionParser.new do |opts|
  opts.banner = "Usage: exfil -m <listen|send> [options]"

  opts.on("-m", "--mode MODE", "Mode: listen or send") do |m|
    options[:mode] = m
  end

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

def encrypt(chunk, key)
  cipher = OpenSSL::Cipher.new("aes-256-cbc")
  cipher.encrypt
  cipher.key = [key].pack("H*")
  iv = cipher.random_iv

  encrypted = cipher.update(chunk) + cipher.final
  return iv + encrypted
end

def decrypt(chunk, key)
  decipher = OpenSSL::Cipher.new("aes-256-cbc")
  decipher.decrypt
  decipher.key = [key].pack("H*")

  iv = chunk[0,16]
  ciphertext = chunk[16..]

  decipher.iv = iv
  decrypted = decipher.update(ciphertext) + decipher.final
  return decrypted
end

# Sets up a listener using the given parameters
def listener(port, file, is_encrypted=false, key=nil)
  begin
    puts HEADER
    server = TCPServer.new(port)

    if is_encrypted
      if !key
        key = SecureRandom.hex(32)
      end
      puts "Key: " + key
    end

    puts "Listening for connections..."
    client = server.accept

    puts "Connection received from #{client.peeraddr[2]}"

    # The listener creates a new file and writes the received data in chunks
    File.open(file, "wb") do |f|
      while chunk = client.read(1024)
        if chunk == "ERROR"
          raise "An error happened while sending the file"
        end
        chunk = is_encrypted ? decrypt(chunk, key) : chunk
        f.write(chunk)
      end
    end
    puts "File received."

    # SHA hash of the file is printed on both ends to confirm the integrity of the file
    puts "SHA256: " + Digest::SHA256.file(file).hexdigest
    puts SEPARATOR
  rescue => e
    puts "Error: #{e.message}"
  end
end

# The client attempts to send a file to the receiver using the given parameters
def sender(address, port, file, is_encrypted=false, key="")
  puts HEADER
  puts "Sending #{file} to #{address}:#{port}"

  begin
    # Trying to connect to the server
    socket = TCPSocket.new(address, port.to_i)

    # Opens the file, reads and sends the data in chunks to avoid storing data in memory
    begin
      File.open(file, "rb") do |f|
        while chunk = f.read(1024)
          chunk = is_encrypted ? encrypt(chunk, key) : chunk
          socket.write(chunk)
        end
      end
      socket.close
      puts "File sent successfully!"

      # SHA hash of the file is printed on both ends to confirm the integrity of the file
      puts "SHA256: " + Digest::SHA256.file(file).hexdigest
      puts SEPARATOR

    rescue => e
      socket.write("ERROR")
      raise "An error happened while sending the file"

    end
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