====== Simple SIP and tptf parse and split to calls tool =====

# Purposes:
Simple SIP and TPTF parse tool. Saves packages for each call. 

# Requirements:
1. python == 2.7
2. python-dev

# Installation:
    cd sipload
    virtualenv env
    source env/bin/activate
    python setup.py install or python setup.py install

# Prepare:
Pcap file must have layer 2 ethernet, SIP, SAI related TPTF

# Run:
get_calls -f pcap_file -o outdir

# Help:
get_calls -h
