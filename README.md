# SubSnipe 🚀⚡

`SubSnipe` is a multi-threaded tool designed to help finding subdomains that are vulnerable to takeover. It takes a domain as input, and searches `crt.sh` to search for known subdomains.

Next, we query for each subdomain if it has a `CNAME record`. If so, we try to fingerprint it and check if the top-level domain of the `CNAME` is known to be vulnerable to subdomain takeover. The fingerprinting logic leverages https://github.com/EdOverflow/can-i-take-over-xyz.

Say we find that `test.someapp.com` has a `CNAME` to `abcd1234.azurewebsites.net`. Since `azurewebsites.net` domains can potentially be leveraged for subdomain takeover, `SubSnipe` flags this as `exploitable`. Of course, for this to be a vulnerability, you need to be able to register `abcd1234.azurewebsites.net`, so as a next step, you need to verify if this domain is available (at the moment, `SubSnipe` doesn't do this for you).

# Built-in Help 🆘

Help is built-in!

- `subsnipe --help` - outputs the help.

# How to Use ⚙

```text
Usage:
    subsnipe <domain>

Example:
    ./subsnipe google.com
```

# Setup ✅

- You can simply run this tool from source via `go run .` 
- You can build the tool yourself via `go build`

# Bug Reports 🐞

If you find a bug, please file an Issue right here in GitHub, and I will try to resolve it in a timely manner.