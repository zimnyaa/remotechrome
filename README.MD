# `remotechrome` -- a PoC for remote chrome cookie dumping and pivoting with Chrome DevTools and port forwarding
```
explained over at tishina.in/ops/remotechrome
```
```
usage: remotechrome.py [-h] -session-id SESSION_ID -datadir DATADIR [-renew] [-json] [-localport LOCALPORT] [-openport OPENPORT] [-ts] [-debug] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key] [-dc-ip ip address] [-keytab KEYTAB] target

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -session-id SESSION_ID
                        an existed logon session to use
  -datadir DATADIR      username to resolve the chrome data directory
  -renew                assume chrome is already accessible
  -json                 dump cookies as json
  -localport LOCALPORT  port for chrome remote debugging (on local host)
  -openport OPENPORT    port for port forwarding
  -ts                   adds timestamp to every logging output
  -debug                Turn DEBUG output ON

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
  -keytab KEYTAB        Read keys for SPN from keytab file
```
```
usage: remotechrome_curl.py [-h] -target TARGET -url URL [-postdata POSTDATA]

options:
  -h, --help          show this help message and exit
  -target TARGET      a host:port string to connect to CDP
  -url URL            the URL to fetch with a GET/POST request
  -postdata POSTDATA  data for a POST request
```
```
pydevtools is adapted from https://github.com/marty90/PyChromeDevTools
to add rudimentary session support.
```