# CVE-2021-22205 

> Preauth RCE via exiftool on Gitlab CE/EE 

## Summary of the CVE

GitLab uses ExifTool to scan every tiff/jpeg/jpg file to remove any tags that are not whitelisted.
But because ExifTool doesn't use file extensions to determine filetype but it rather uses the content of the file, which allows an attacker to upload any file, rename it to tiff/jpeg/jpg and "abuse" any of the ExifTool supported parsers.
When parsing DjVu files ExifTool evals DjVu annotation tokens to convert C escape sequences.

## Affected Versions

- Gitlab CE/EE >= 11.9, < 13.8.8 
- Gitlab CE/EE >= 13.9, < 13.9.6
- Gitlab CE/EE >= 13.10, < 13.8.8

## Anomalies

Uploads a image file to the server

## References

- [Original Report - vakzz, Apr 07 2021] (https://gitlab.com/gitlab-org/gitlab/-/issues/327121)
- [Github POC - Al1ex, Oct 29 2021](https://github.com/Al1ex/CVE-2021-22205)
- [CVE-details - CVSS Score 10.0](https://www.cvedetails.com/cve/CVE-2021-22205/)
