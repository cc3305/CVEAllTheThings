#!/usr/bin/env python3
from pathlib import Path
import argparse
from typing import Optional
import requests
import re
from dataclasses import dataclass
from sh import git
import os
from urllib.parse import urlparse

debug = False

args = None

TEMPLATE_PATH = Path("./_template_script/")
TEMPLATE_SCRIPT = TEMPLATE_PATH / "CVE-XXXX-yyyy.py"
TEMPLATE_README = TEMPLATE_PATH / "README.md"
TEMPLATE_REQUIREMENTS = TEMPLATE_PATH / "requirements.txt"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVELIST_RAW_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
REQUEST_TIMEOUT = 20
GITHUB_API_TOKEN_ENV = "GITHUB_API_TOKEN"

_RE_COMBINE_WHITESPACE = re.compile(r"\s+")


@dataclass
class VersionRange:
    product_name: str
    max_version: str
    max_including: bool
    min_version: str
    min_including: bool
    exclusions: Optional[list[str]]
    single: bool = False

    def __str__(self) -> str:
        max_version_symbol = "<" + ("=" if self.max_including else "")
        min_version_symbol = ">" + ("=" if self.min_including else "")
        if self.min_version == "" and self.max_version == "":
            return f"{self.product_name}"
        if not self.single:
            return f"{self.product_name} {min_version_symbol} {self.min_version} {max_version_symbol} {self.max_version}"
        return f"{self.product_name} {self.min_version}" 

@dataclass
class CVEDetails:
    identifier: str
    summary: str | None
    scores: list[float]
    references: list[str]
    affected_version: list[VersionRange]

    def avg_score(self) -> str:
        """
        Returns the average scores of the scores

        Returns:
            str: The average or "n/a"
        """
        if len(self.scores) < 1:
            return "n/a"
        return str(sum(self.scores) / len(self.scores))

    def highest_score(self) -> str:
        """
        Returns the highest scores of the scores

        Returns:
            str: The highest score or "n/a"
        """
        if len(self.scores) < 1:
            return "n/a"
        return str(max(self.scores))

def log_error(msg: str):
    """
    Logs a error
    Arguments:
        msg(str): The message to log
    """
    print(f"[!] {msg}")

def log_info(msg: str):
    """
    Logs info
    Arguments:
        msg(str): The message to log
    """
    print(f"[*] {msg}")

def log_debug(msg: str):
    """
    Logs debug info
    Arguments:
        msg(str): The message to log
    """
    if not debug:
        return
    print(f"[~] {msg}")

def log_fatal(msg: str):
    """
    Logs a fatal error
    Arguments:
        msg(str): The message to log
    """
    print(f"[!!] {msg}")

def parse_args() -> tuple[bool, argparse.Namespace]:
    """                                                                                                                         
    Returns the parsed arguments passed in via argparse                                                                         
    Required arguments are marked by a star (*)                                                                                 
                                                                
    Returns:                                                                                                                    
        bool, argparse.Namespace: True if success, False otherwise and the parsed args
    """
    log_debug("Parsing args")
    parser = argparse.ArgumentParser(description="CVE exploit script template generator by cc3305")
    parser.add_argument("IDENTIFIER", action="store", help="CVE Number in the format CVE-XXXX-yyyy")
    parser.add_argument("--create-remote-repo", action="store_true", help="Create a private GitHub repo using GITHUB_API_TOKEN and push the generated files")
    result = parser.parse_args()
    if not is_valid_cve_identifier(result.IDENTIFIER):
        log_error(f"{result.IDENTIFIER} is not a valid CVE Number")
        return False, result
    return True, result

def is_valid_cve_identifier(ident: str):
    """
    Check if the identifier is valid

    Arguments:
        ident(str): The identifier

    Returns:
        bool: True if the identifier is valid.
    """
    cve_pattern = r"CVE-\d{4}-\d{4,}"
    return not re.fullmatch(cve_pattern, ident) is None

def check_files() -> bool:
    """
    Checks the file integrity

    Returns:
        True if all files exist, False otherwise
    """
    paths = [TEMPLATE_PATH, TEMPLATE_SCRIPT, TEMPLATE_README, TEMPLATE_REQUIREMENTS]
    for path in paths:
        if not path.exists():
            log_error(f"File '{path}' does not exist")
            return False
        log_debug(f"'{path}' exists")
    return True

def version_entry_to_range(product_name: str, version_entry: dict) -> VersionRange | None:
    """
    Convert a CVE List affected version entry into a VersionRange

    Arguments:
        product_name(str): The affected product name
        version_entry(dict): A version entry from the CVE List record

    Returns:
        VersionRange: The parsed version range or None if the version is not affected
    """
    if version_entry.get("status") != "affected":
        return None

    min_version = version_entry.get("version")
    max_version = version_entry.get("lessThanOrEqual") or version_entry.get("lessThan") or min_version
    max_including = "lessThanOrEqual" in version_entry or "lessThan" not in version_entry

    if min_version is None and max_version is None:
        return VersionRange(product_name, "", False, "", False, [], False)
    if min_version == max_version and max_including:
        return VersionRange(product_name, max_version, True, min_version, True, [], True)
    return VersionRange(product_name, max_version, max_including, min_version, True, [])

def parse_cvelist_affected(record: dict) -> list[VersionRange]:
    """
    Parse affected versions from a CVE List V5 record

    Arguments:
        record(dict): The CVE List record

    Returns:
        list[VersionRange]: The affected version ranges
    """
    affected_versions = []
    cna_container = record.get("containers", {}).get("cna", {})
    for affected_product in cna_container.get("affected", []):
        product_name = affected_product.get("product") or affected_product.get("vendor") or ""
        product_name = _RE_COMBINE_WHITESPACE.sub(" ", product_name).strip()
        if product_name == "":
            log_debug(f"Skipping affected product without a name")
            continue

        versions = affected_product.get("versions", [])
        if len(versions) < 1:
            affected_versions.append(VersionRange(product_name, "", False, "", False, [], False))
            continue

        for version_entry in versions:
            version_range = version_entry_to_range(product_name, version_entry)
            if version_range is None:
                continue
            affected_versions.append(version_range)
    return affected_versions

def parse_nvd_scores(cve_data: dict) -> list[float]:
    """
    Parse CVSS scores from a NVD CVE object

    Arguments:
        cve_data(dict): The NVD CVE object

    Returns:
        list[float]: The parsed CVSS scores
    """
    scores = []
    for metrics in cve_data.get("metrics", {}).values():
        for metric in metrics:
            score = metric.get("cvssData", {}).get("baseScore")
            if score is None:
                continue
            scores.append(float(score))
    return scores

def parse_nvd_summary(cve_data: dict) -> str:
    """
    Parse the english summary from a NVD CVE object

    Arguments:
        cve_data(dict): The NVD CVE object

    Returns:
        str: The summary or "" if there is none
    """
    for description in cve_data.get("descriptions", []):
        if description.get("lang") == "en":
            value = description.get("value")
            if value is None:
                return ""
            return value
    return ""

def parse_nvd_references(cve_data: dict) -> list[str]:
    """
    Parse references from a NVD CVE object

    Arguments:
        cve_data(dict): The NVD CVE object

    Returns:
        list[str]: The parsed reference URLs
    """
    references = []
    for reference in cve_data.get("references", []):
        url = reference.get("url")
        if url is None:
            continue
        references.append(url)
    return references

def cvelist_url(identifier: str) -> str:
    """
    Build the CVE List V5 raw GitHub URL for an identifier

    Arguments:
        identifier(str): The CVE identifier

    Returns:
        str: The raw CVE List V5 URL
    """
    year = parse_year(identifier)
    cve_number = int(identifier.split("-")[2])
    cve_bucket = cve_number // 1000
    return f"{CVELIST_RAW_URL}/{year}/{cve_bucket}xxx/{identifier}.json"

def get_nvd_details(identifier: str) -> tuple[bool, dict | None]:
    """
    Get CVE details from the NVD API

    Arguments:
        identifier(str): The CVE identifier

    Returns:
        tuple[bool, dict]: True if the NVD details were fetched successfully and the CVE object
    """
    log_debug("Getting NVD details")
    try:
        resp = requests.get(NVD_API_URL, params={"cveId": identifier}, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.RequestException as e:
        log_error(f"Could not fetch NVD details: {e}")
        return False, None

    if resp.status_code != 200:
        log_error(f"Could not fetch NVD details, failed with error code {resp.status_code}")
        return False, None

    data = resp.json()
    vulnerabilities = data.get("vulnerabilities", [])
    if len(vulnerabilities) != 1:
        log_error(f"NVD returned {len(vulnerabilities)} results for {identifier}")
        return False, None
    return True, vulnerabilities[0].get("cve", {})

def get_cvelist_details(identifier: str) -> tuple[bool, dict | None]:
    """
    Get CVE details from CVEProject/cvelistV5

    Arguments:
        identifier(str): The CVE identifier

    Returns:
        tuple[bool, dict]: True if the CVE List record was fetched successfully and the record
    """
    log_debug("Getting CVE List details")
    url = cvelist_url(identifier)
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.RequestException as e:
        log_error(f"Could not fetch CVE List details: {e}")
        return False, None

    if resp.status_code != 200:
        log_error(f"Could not fetch CVE List details, failed with error code {resp.status_code}")
        return False, None

    return True, resp.json()


def get_cve_details() -> tuple[bool, CVEDetails | None]:
    """
    Parses CVE details from the NVD API and affected versions from CVE List V5

    Returns:
        tuple[bool, CVEDetails]: True if everything went ok and the parsed CVEDetails
    """
    log_debug("Getting CVE details")
    # These should not be None, but just make sure (and make the linter shut up)
    assert args is not None, "Args are None while parsing CVE details"
    assert args.IDENTIFIER is not None, "CVE identifier is None while parsing CVE details"

    nvd_ok, nvd_cve = get_nvd_details(args.IDENTIFIER)
    if not nvd_ok:
        return False, None

    cvelist_ok, cvelist_record = get_cvelist_details(args.IDENTIFIER)
    if not cvelist_ok:
        return False, None

    if nvd_cve is None or cvelist_record is None:
        log_error(f"Could not parse CVE details")
        return False, None

    details = CVEDetails(args.IDENTIFIER, None, [], [], [])

    details.summary = parse_nvd_summary(nvd_cve)
    details.references = parse_nvd_references(nvd_cve)
    details.scores = parse_nvd_scores(nvd_cve)
    details.affected_version = parse_cvelist_affected(cvelist_record)

    return True, details

def parse_year(identifier: str) -> str:
    """
    Parse the year from a CVE-XXXX-yyyy identifier

    Arguments:
        identifier(str): the identifier

    Returns:
        str: the year or "" if it couldnt be parsed
    """
    cve_pattern = r"CVE-(\d{4})-\d{4,}"
    matches = re.match(cve_pattern, identifier)
    if matches is None:
        log_fatal(f"Could not parse year from identifier {identifier}")
        return ""
    return matches.groups()[0]

def construct_template(details: CVEDetails) -> tuple[bool, Path | None]:
    """
    Construct the template of the CVE

    Arguments:
        details(CVEDetails): The details for the template

    Returns:
        tuple[bool, Path]: True if everything went ok and the Path to the folder
    """
    log_debug("Writing all the files")
    year = parse_year(details.identifier)
    if year == "":
        return False, None
    # Create the folder
    folder_path = Path("./") / year / details.identifier
    if folder_path.is_dir():
        log_fatal(f"Folder {folder_path} already exists")
        return False, None
    folder_path.mkdir(parents=True)
    script_path = folder_path / f"{details.identifier}.py"
    readme_path = folder_path / f"README.md"
    requirements_path = folder_path / f"requirements.txt"
    write_script_ok = write_script(script_path, details)
    write_readme_ok = write_readme(readme_path, details)
    write_req_ok = write_requirements(requirements_path, details)
    return write_script_ok and write_readme_ok and write_req_ok, folder_path

def affected_versions_to_string(details: CVEDetails) -> str | None:
    """
    Convert the affected versions to a string

    Arguments:
        details(CVEDetails): The details

    Returns:
        str: The affected versions as a string
    """
    formatted_string = ""
    for version in details.affected_version:
        formatted_string += f"- {str(version)}\n"
    return formatted_string.rstrip() if formatted_string != "" else None

def references_to_string(details: CVEDetails) -> str | None:
    """
    Convert the references to a string

    Arguments:
        details(CVEDetails): The details

    Returns:
        str: The references as a string
    """
    references = [f"- [NVD - CVSS Score {details.highest_score()}](https://nvd.nist.gov/vuln/detail/{details.identifier})"]
    seen_references = set()
    for reference in details.references:
        if reference in seen_references:
            continue
        seen_references.add(reference)
        domain = urlparse(reference).netloc or reference
        references.append(f"- [Reference - {domain}]({reference})")
    return "\n".join(references) if len(references) > 0 else None

def write_readme(new_readme_path: Path, details: CVEDetails) -> bool:
    """
    Write the readme

    Arguments:
        details(CVEDetails): The details

    Returns:
        bool: True if everything was successful
    """
    content = TEMPLATE_README.read_text()

    summary = details.summary or "Unable to parse CVE summary"
    content = content.replace("summary here", summary)

    affected_version = affected_versions_to_string(details) or "Unable to parse affected versions"
    affected_versions_template_string = "- Version < 1.10\n- Version 1.2 - 1.20"
    content = content.replace(affected_versions_template_string, affected_version)

    references = references_to_string(details) or "Unable to parse references????"
    references_template_string = "- [Blog title - Author, Date](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/_template_vuln/README.md)\n- [CVE-details - CVSS Score](https://www.cvedetails.com/cve/CVE-XXXX-yyyy/)"
    content = content.replace(references_template_string, references)

    content = content.replace("CVE-XXXX-yyyy", details.identifier)

    new_readme_path.write_text(content)
    return True

def write_requirements(new_req_path: Path, _: CVEDetails) -> bool:
    """
    Write the requirements

    Arguments:
        details(CVEDetails): The details

    Returns:
        bool: True if everything was successful
    """
    new_req_path.write_text(TEMPLATE_REQUIREMENTS.read_text())
    return True

def write_script(new_script_path: Path, details: CVEDetails) -> bool:
    """
    Write the script

    Arguments:
        details(CVEDetails): The details

    Returns:
        bool: True if everything was successful
    """
    content = TEMPLATE_SCRIPT.read_text()
    content = content.replace("CVE-XXXX-yyyy", details.identifier)
    new_script_path.write_text(content)
    return True

def test_key(token: str) -> bool:
    """
    Tests a github api token

    Arguments:
        token(str): The api token

    Returns:
        true: True if the key works, False otheriwse
    """
    headers = {"Authorization": f"token {token}"}
    resp = requests.get("https://api.github.com", headers=headers)
    return resp.status_code == 200

def load_github_api_token() -> tuple[bool, str]:
    """
    Loads the github api token from the environment

    Returns:
        bool, str: True if the github api token has been loaded and the token
    """
    token = os.environ.get(GITHUB_API_TOKEN_ENV)
    if token is None:
        log_error(f"{GITHUB_API_TOKEN_ENV} is not set")
        return False, ""
    token = token.strip()
    if token == "":
        log_error(f"{GITHUB_API_TOKEN_ENV} is empty")
        return False, ""

    return True, token

def create_github_repo(token: str, identifier: str) -> dict:
    """
    Creates a remote private github repo

    Arguments:
        token(str): The token for the github api
        identifier(str): The identifier of the CVE used as the name

    Returns:
        dict: The json response
    """
    headers = {"Authorization": f"token {token}"}
    data = {
        "name": identifier,
        "private": True,
        "description": f"{identifier} exploit script",
        "has_wiki": False,
        "has_projects": False
    }
    resp = requests.post("https://api.github.com/user/repos", headers=headers, json=data)
    error = ""
    match resp.status_code:
        case 201:
            pass
        case 302:
            error = "Not modified"
        case 400:
            error = "Bad request"
        case 401:
            error = "Not authenticated"
        case 403:
            error = "Wrong permissions"
        case 422:
            error = "Validation failed or endpoint was spammed"

    if error != "":
        log_error(f"Something went wrong while creating the github repo: {error}")
        return {}
    resp_json = resp.json()
    log_info(f"Created private repo {resp_json['html_url']}")
    return resp_json

def setup_git(path: Path) -> tuple[bool, str]:
    """
    Sets up a local git repo and pushes the generated local files to a private github repo

    Arguments:
        path(Path): The path to the locally generated files.

    Returns:
        bool, str: True if successful and the url to the github repo
    """
    log_debug("Setting up git repo")
    # Create a git repo locally
    git_path = path / ".git"
    git_path.mkdir()

    original_path = os.getcwd()
    os.chdir(path)

    # Init the git repo
    path_git = git.bake()
    path_git.init()

    if not args.create_remote_repo:
        log_info("Remote repo creation skipped, but local repo was created")
        return False, ""

    # Load and check the github api token only if remote creation was requested
    token_ok, token = load_github_api_token()
    if not token_ok:
        log_fatal("Github api token could not be loaded, but local repo was created")
        return False, ""

    token_valid = test_key(token)
    if not token_valid:
        log_fatal("Github api token is invalid, but local repo was created")
        return False, ""

    # Create a new github repo
    resp_json = create_github_repo(token, path.name)
    github_url = resp_json["ssh_url"]

    # Add all the files and push
    # git remote add origin git@github.com:cc3305/CVE-XXXX-yyyy.git
    path_git.remote.add("origin", github_url)
    # git branch -M main
    path_git.branch("-M", "main")
    # git add .
    path_git.add(".")
    # git commit -m "generated from template"
    path_git.commit("-m", "generated from template")
    # git push --set-upstream origin main
    path_git.push("--set-upstream", "origin", "main")   
    log_debug("Added files to git repo")
    # Go back to main directory
    os.chdir(original_path)
    main_git = git.bake()
    # git submodule add -b main --depth 1 repo_url path
    main_git.submodule.add("-b", "main", "--depth", "1", github_url, path)
    log_debug("Pushed files to github")
    return True, github_url

def main():
    """
    Main function
    """
    global args
    args_ok, args = parse_args()
    if not args_ok:
        log_fatal(f"Args provided are incorrect")
        exit(1)

    path_ok = check_files()
    if not path_ok:
        log_fatal(f"File integrity checks failed")
        exit(1)

    details_ok, details = get_cve_details()
    if not details_ok:
        log_fatal(f"Could not parse details")
        exit(1)
    assert details is not None, "Details is None, even though parsing succeded"

    success, path = construct_template(details)
    if not success:
        log_fatal(f"Could not create generate files")
        return
    log_info(f"Success! Saved under '{path}'")
    assert path is not None, "Path is None, even though constructing succeded"

    git_ok, url = setup_git(path)
    if not git_ok:
        return
    log_info(f"Created local gitrepo and pushed files to '{url}'") 

if __name__ == "__main__":
    main()
