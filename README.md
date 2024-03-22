![Go Version](https://img.shields.io/github/go-mod/go-version/dub-flow/subsnipe)

# SubSnipe 🚀⚡

`SubSnipe` is a multi-threaded tool designed to help finding subdomains that are vulnerable to takeover. It can be used in two different ways:

1. Provide a domain as input and the tool then searches `crt.sh` to search for known subdomains
2. Provide the path to a file that already contains subdomains

Next, `Subsnipe` queries for each subdomain if it has a `CNAME record`. If so, we try to fingerprint it and check if the top-level domain of the `CNAME` is known to be vulnerable to subdomain takeover. The fingerprinting logic leverages https://github.com/EdOverflow/can-i-take-over-xyz.

Say we find that `test.someapp.com` has a `CNAME` to `abcd1234.azurewebsites.net`. Since `azurewebsites.net` domains can potentially be leveraged for subdomain takeover, `SubSnipe` flags this as a domain that is generally `exploitable`. Of course, for this to be a vulnerability, you need to be able to register `abcd1234.azurewebsites.net`, so as a next step, you need to verify if this domain is available to for you to register.

In the last step, `SubSnipe` tries to do this for you by checking if the `CNAME`, e.g. `abcd1234.azurewebsites.net`, can actually be taken over. If it could verify that the domain can very likely be taken over, it tags the domain with `Takeover Likely Possible!` in the `output.md`.

# Built-in Help 🆘

Help is built-in!

- `subsnipe --help` - outputs the help.

# How to Use ⚙

```text
SubSnipe identifies potentially take-over-able subdomains

Usage:
  subsnipe [flags]

Examples:
./subsnipe -d test.com
./subsnipe -f subdomains.txt

Flags:
  -d, --domain string       The domain to query for subdomains
  -h, --help                help for subsnipe
  -f, --subdomains string   Path to the file containing subdomains to query (subdomains are separated by new lines)
```

# Setup ✅

- You can simply run this tool from source via `go run .` 
- You can build the tool yourself via `go build`
- You can build the `docker` image yourself via `docker build . -t fw10/subsnipe`

# Run via Docker 🐳

1. Traverse **into** the directory where you want the `output.md` to be stored to 
    - Note that you cannot provide the `-output` paramter when running `SubSnipe` via docker
    - The reason is that the directory for the `output.md` needs to be mounted into the container
2. From within there, run `docker run -it --rm -v "$(pwd):/app/output" fw10/subsnipe -d <domain>`

Note that the docker version of the app is very slow at the moment (which is something I plan to look into eventually - I assume it's a network latency thing)

# Run Tests 🧪

- To run the tests, run `go test` or `go test -v` (for more details)

# Example Output 📋

```
### Is Exploitable

- CNAME for blablub.test.com is: blablub.cloudapp.azure.com. (found matching fingerprint - vulnerable)
- CNAME for mail.test.com is: mail.azurewebsites.net. (found matching fingerprint - vulnerable)
- CNAME for static.test.com is: static-test.azureedge.net. (found matching fingerprint 'vulnerable') -> `Takeover Likely Possible!`

### Not Exploitable

- CNAME for *.test.com is: test-loadbalancer.us-east-1.elb.amazonaws.com. (found matching fingerprint - safe)

### Exploitability Unknown

- CNAME for map.test.com is: test-map.lync.com.
```

# Releases 🔑 

- The `Releases` section contains some already compiled binaries for you so that you might not have to build the tool yourself
- For the `Mac releases`, your Mac may throw a warning (`"cannot be opened because it is from an unidentified developer"`)
    - To avoid this warning in the first place, you could simply build the app yourself (see `Setup`)
    - Alternatively, you may - at your own risk - bypass this warning following the guidance here: https://support.apple.com/guide/mac-help/apple-cant-check-app-for-malicious-software-mchleab3a043/mac
    - Afterwards, you can simply run the binary from the command line and provide the required flags

# Bug Reports 🐞

If you find a bug, please file an Issue right here in GitHub, and I will try to resolve it in a timely manner.