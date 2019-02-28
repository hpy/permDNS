# permDNS - Subdomain discovery through alterations and permutations

permDNS is a a rewrite of the popular DNS recon tool altDNS by @infosec-au.
It allows for the discovery of subdomains that conform to patterns. permDNS takes in words that could be present in subdomains under a domain (such as test, dev, staging) as well as takes in a list of subdomains that you know of.

From these two lists that are provided as input to permDNS, the tool then generates a _massive_ output of "altered" or "mutated" potential subdomains that could be present. It saves this output so that it can then be used by your favourite DNS bruteforcing tool.

Alternatively, the `-r` flag can be passed to permDNS so that once this output is generated, the tool can then resolve these subdomains (multi-threaded) and save the results to a file.

permDNS works best with large datasets. Having an initial dataset of 200 or more subdomains should churn out some valid subdomains via the alterations generated.

# Installation

`pip install -r requirements.txt`

# Usage

`# ./permDNS.py -i subdomains.txt -o data_output -w words.txt -r -s results_output.txt`

- `subdomains.txt` contains the known subdomains for an organization
- `data_output` is a file that will contain the _massive_ list of altered and permuted subdomains
- `words.txt` is your list of words that you'd like to permute your current subdomains with (i.e. `admin`, `staging`, `dev`, `qa`) - one word per line
- the `-r` command resolves each generated, permuted subdomain
- the `-s` command tells permDNS where to save the results of the resolved permuted subdomains. `results_output.txt` will contain the final list of permuted subdomains found that are valid and have a DNS record.
- the `-n` command will add number pre/post suffix to every domain (0-9,00-09)
- the `-sd` command will automatically restart the permutation and scan process on any found subdomains.
- the `-ds` command will search permutations upto n levels beyond the domainlist - ie: *.*.example.com (Warning - Slow!)
- the `-t` command limits how many threads the resolver will use simultaneously (10 by default).
- the `-b` command limits the permutations to bruteforce by indexes using wordlist only.
- `-d 1.1.1.1,1.0.0.1` overrides the system default DNS resolver and will use the specified IP addresses as the resolving servers. Setting this to the authoritative DNS server of the target domain *may* increase resolution performance 

# Screenshots

<img src="https://i.imgur.com/fkfZqkl.png" width="600px"/>

<img src="https://i.imgur.com/Jyfue26.png" width="600px"/>

