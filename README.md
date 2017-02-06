# sslcheck
Simple cmd line tool to check used SSL/TLS ciphers in a client-server connection

This is a very simple WIP tool, which allows probing of TLS/SSL client/server handshakes.
The tools has two modes:
    - client - This mode sniffs for a connection between a SSL/TLS client and server and identifies all ciphers used in the handshake
    - server - This mode brute forces a server to determine valid TLS/SSL ciphers

As a result, a JSON report is written out to disk.

This is a quick and dirty solution, and a very rough draft.
