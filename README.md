# CVEAllTheThings

A collection of CVE exploit scripts written in mostly Python.

## Installation

Either clone the one CVE repo you need or you can clone all of them like this: `git clone https://github.com/cc3305/CVEAllTheThings --recursive --shallow-submodules`

Most scripts can be used the same way, but always check the help (`python3 CVE-XXXX-yyyy.py -h`) for more information

## Contribution

Open a new PR with a submodule for the CVE added.
Use the `generate_template.py` to generate a template for the CVE script. Orient yourself on the already existing CVE script (the more recently added, the better).
To update the submodule of your own CVE script in this repo, open a PR (please dont do this too often)

## Additional Info
- Most scripts are written in python and have the same structure, but some CVEs require a different approach (e.g. if the exploit needs compiled C code, etc.)
- Inspired by the [trickest/cve](https://github.com/trickest/cve) repo
- Credit to the original discovery and the existing exploit script that were looked at during development is always given in the README of the exploit and/or in the code. If you want your name/repo/blog out of any readme or have any copyright issue, contact me on twitter
