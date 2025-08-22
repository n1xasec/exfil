# EXFIL

Exfil is a CLI tool written in Ruby for easily transferring files between two hosts. The tool uses a client-server model and allows
for using AES-256 encryption via an auto-generated or a manually assigned key.

## Features

- Ease of use & flexibility
- Reliable connection between clients
- Symmetric encryption
- Manual / automatic encryption key

## Requirements and Installation
- Ruby
- Gem
- Bundler
- Two computers on the same logical network

1. Cloning the repository

```shell
git clone https://github.com/n1xasec/exfil.git
cd exfil/
```

2. Installing the dependencies

```shell
bundle install
```

3. Running the program

```shell
ruby exfil.rb -h
```

## Parameters and Usage Examples

To set up a listener we can use the following command:

```shell
ruby exfil.rb -m listen -p 4444 -f output.txt
```
The parameter `-m` is used to tell the program whether we are setting up a listener or a sender.
`-p` tells which port to listen on and `-f` will set the output file.

```shell
ruby exfil.rb -m send -a 192.168.1.100 -p 4444 -f input.txt
```

The `-a` flag is used for setting the address of the server. That's where the file will be sent to.

We also have the option to use encryption. All we have to do is add the `-e` and `-k` flags on both sides.

```shell
ruby exfil.rb -m listen -p 4444 -f output.txt -e -k <encryption_key>
```

The listener can also generate an encryption key if we don't set it manually.
The same parameters are needed on the sender side. In that case both parameters are necessary.

