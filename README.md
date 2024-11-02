SPF-DKIM-DMARC Checker

A command-line tool to check SPF, DKIM, and DMARC records against one or multiple domains.


The SPF-DKIM-DMARC Checker (AKA "SDD") is a Go-based script for BBH and Pentesters that allows you to verify the presence and correctness of SPF, DKIM, and DMARC records for domains, comes in handy in the recon phase prior to Red Teaming engagements and phishing campaigns.

It supports checking:

Single domains

Multiple domains from a file

Domains piped via standard input

    

Installation:

    git clone https://github.com/r3dcl1ff/SDD.git

    cd SDD

    go build sdd.go

    cp sdd /usr/local/bin


Usage:

    -u string
    Specify a single domain to check.

    -l string
    Provide a file containing a list of domains (one per line).

    -m string
    Set the mode of operation: spf, dkim, dmarc, or all (default is all).

    -v
    Enable verbose output for detailed information.

    -s string
    Specify a file containing custom DKIM selectors.

    Example:

    cat targets.txt | sdd -m dmarc

    sdd-checker -u example.com -m dkim -s selectors.txt
    


License:

This project is licensed under the MIT License.

Contributing:

Contributions are welcome! Please open an issue or submit a pull request with your improvements.
