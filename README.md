====== Simple SIP and tptf parse and split to calls tool =====

Requirements:
    python == 2.7
    python-dev

Installation:
    cd sipload
    virtualenv env
    source env/bin/activate
    python setup.py install or python setup.py install

Purposes:
    Simple SIP and TPTF parse tool. Saves packages for each call. 

Run:
    get_calls -f <pcap file> -o outdir

Help:
    get_calls -h
