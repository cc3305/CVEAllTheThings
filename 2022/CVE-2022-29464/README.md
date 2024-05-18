# CVE-2022-29464

> A preauth arbitrary file upload that leads to RCE in WSO2

## Summary of the CVE

CVE-2022-29464 is a RCE vulnerability for WSO2 discovered by Orange Tsai. A unauthenticated arbitrary file upload allows an attacker to execute code by uploading a malicious JSP file.

## Affected Versions

- WSO2 API Manager 2.2.0 - 4.0.0
- WSO2 Identity Server 5.2.0 - 5.11.0
- WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0, 5.6.0
- WSO2 Identity Server as Key Manager 5.3.0 - 5.11.0
- WSO2 Enterprise Integrator 6.2.0 - 6.6.0
- WSO2 Open Banking AM 1.4.0 - 2.0.0
- WSO2 Open Banking KM 1.4.0 - 2.0.0

## Anomalies

Uploads a JSP shell

## References

- [Deep Dive into the CVE-2022-29464 RCE exploit - ONSEC Research Team, Dec 28 2022](https://blog.onsec.io/deep-dive-into-the-cve-2022-29464-rce-exploit/)
- [Github POC - hakivvi, Apr 27 2022](https://github.com/hakivvi/CVE-2022-29464)
- [CVE-details - CVSS Score 10.0](https://www.cvedetails.com/cve/CVE-2022-29464/)
