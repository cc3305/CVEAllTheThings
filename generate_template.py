#!/usr/bin/env python3
from pathlib import Path
import argparse
from typing import Optional
import requests
import re
from dataclasses import dataclass
from bs4 import BeautifulSoup

args = None

TEMPLATE_PATH = Path("./_template_script/")
TEMPLATE_SCRIPT = TEMPLATE_PATH / "CVE-XXXX-yyyy.py"
TEMPLATE_README = TEMPLATE_PATH / "README.md"
TEMPLATE_REQUIREMENTS = TEMPLATE_PATH / "requirements.txt"

_RE_COMBINE_WHITESPACE = re.compile(r"\s+")
_RE_VERSION_MATCHER = re.compile(r".* \((>=|<=|=<|>|=|<)\) (\S+) .* \((>=|<=|=<|>|=|<)\) (\S+)")


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
    parser = argparse.ArgumentParser(description="CVE exploit script template generator by cc3305")
    parser.add_argument("IDENTIFIER", action="store", help="CVE Number in the format CVE-XXXX-yyyy")
    result = parser.parse_args()
    if not is_valid_cve_identifier:
        log_error(f"{result.IDENTIFIER} is not a valid CVE Number")
        return False, result
    return True, result

def is_valid_cve_identifier(ident: str):
    cve_pattern = r"CVE-\d{4}-\d{4,}"
    return not re.fullmatch(cve_pattern, ident) is None

# https://stackoverflow.com/questions/736043/checking-if-a-string-can-be-converted-to-float-in-python
def is_float(element: any) -> bool:
    """
    Check if something is a float
    Arguments:
        element(any): The element to check
    Returns:
        bool: True if the element is a float, false otherwhise
    """
    # If you expect None to be passed:
    if element is None: 
        return False
    try:
        float(element)
        return True
    except ValueError:
        return False


def check_files() -> bool:
    """
    Checks the file integrity
    Returns:
        True if all files exist, False otherwise
    """
    paths = [TEMPLATE_PATH, TEMPLATE_SCRIPT, TEMPLATE_README, TEMPLATE_REQUIREMENTS]
    for path in paths:
        if not path.exists():
            log_error(f"File {path} does not exist")
            return False
    return True

def parse_versions(soup) -> list[VersionRange]:
    affected_versions = []
    affected_version_element = soup.find("ul", {"id": "affectedCPEsList"})
    if affected_version_element is None:
        log_debug(f"Could not parse affected versions")
    else:
        all_lis = affected_version_element.findAll("li")
        for li in all_lis:
            product_name_element = li.find("div")
            product_name_parts = product_name_element.text.split("Version")
            # This is pretty bad but oh well
            product_name = product_name_parts[0]
            # Normalize the product name
            product_name = product_name.replace("»", "")
            product_name = _RE_COMBINE_WHITESPACE.sub(" ", product_name).strip()

            if len(product_name_parts) < 2:
                log_debug(f"No version for {product_name}")
                continue

            # If there is only one version listed we need to split by "Version" if there are multiple its "Versions"
            product_version = product_name_parts[1]
            if "Versions" in product_name_element.text:
                product_version = product_name_element.text.split("Versions")[1]
            else:
                # Single version, string looks like this ": VERSION"
                version = product_version[2:]
                affected_versions.append(VersionRange(product_name, version, True, version, True, [], True))
                continue
            # Version looks like this "from including (>=) 7.16.0 and  before (<) 7.16.4"
            # Dont really care about the text so just keep everything in () and the version numbers
            product_version = product_version.strip()
            version_matches = _RE_VERSION_MATCHER.match(product_version)
            if version_matches is None:
                print(f"Could not parse version {product_name} {product_version}")
                continue
            if len(version_matches.groups()) < 4:
                print(f"Could not find all version parts for {product_name} {product_version}")
                continue
            # Find out which version is the min and max and which of them are inclusive
            operator_one = version_matches.groups()[0]
            version_one = version_matches.groups()[1]
            operator_two = version_matches.groups()[2]
            version_two = version_matches.groups()[3]
            min = max = ""
            min_inclusive = max_inclusive = False
            for operator, version in zip([operator_one, operator_two], [version_one, version_two]):
                if ">" in operator:
                    min = version
                    min_inclusive = "=" in operator
                if "<" in operator:
                    max = version
                    max_inclusive = "=" in operator

            vr = VersionRange(product_name, max, max_inclusive, min, min_inclusive, [])
            affected_versions.append(vr)
    return affected_versions

def parse_scores(soup) -> list[float]:
    # Parse the scores
    score_table_element = soup.find("table", {"class": "table table-borderless"})
    scores = []
    if score_table_element is None:
        log_debug("Could not parse scores from cve details")
    else:
        all_trs = score_table_element.find_all("tr")
        visible_trs = [tr for tr in all_trs if tr.get("id") is None]
        for tr in visible_trs:
            tds = tr.find_all("td")
            if len(tds) < 7:
                continue
            score = tds[0].text
            if is_float(score):
                scores.append(float(score))
            else:
                log_debug(f"Could not parse score '{score}' to float")

    return scores

def parse_references(soup) -> list:

    cve_cards_elements = soup.findAll("div", {"class": "cved-card"})
    references_cve_card_element = None
    for cve_card in cve_cards_elements:
        card_h2 = cve_card.findChild("h2")
        if card_h2 is not None and "References" in card_h2.text:
            references_cve_card_element = cve_card
            break

    links = []
    all_lis = references_cve_card_element.find_all("li", {"class": "list-group-item border-0 border-top list-group-item-action"})
    for li in all_lis:
        link = li.find("a")
        if link is None:
            log_debug(f"Could not find link for li {li}")
            continue
        links.append(link.get("href")) 
    return links

def parse_summary(soup) -> str:
    # Try parse the summary
    summary = soup.find("div", {"id": "cvedetailssummary"})
    if summary is None:
        log_debug("Could not parse summary from cve details")
        return ""
    return summary.text

def parse_ident(soup) -> str:
    # Check if the CVE identifier can be found on the page
    identifier_element = soup.find("div", {"id": "cvedetails-title-div"})
    if identifier_element is None:
        log_error("Could not parse title on cve details")
        return ""
    identifier = identifier_element.findChild("a")
    if identifier is None:
        log_error("Could not parse identifier of cve on cve details")
        return ""
    return identifier.text

def parse_error_message(soup) -> str:
    # Check if the cve exists, if not there is a element with the class "alert alert-secondary my-4" which has the error message
    potential_error_message_container = soup.find("div", {"class": "alert alert-secondary my-4"})
    if potential_error_message_container is not None:
        # Error message is the first bold text
        potential_error_message = potential_error_message_container.findChild("b", recursive=False)
        error = "Unkown"
        if potential_error_message is not None:
            error = potential_error_message.text
        return error
    return ""


def get_cve_details() -> tuple[bool, CVEDetails | None]:
    # These should not be None, but just make sure (and make the linter shut up)
    assert args is not None, "Args are None while parsing cve details"
    assert args.IDENTIFIER is not None, "CVE Identifier is None while parsing cve details"

    # Need user agent so we dont get blocked by cf
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"}
    url = f"https://www.cvedetails.com/cve/{args.IDENTIFIER}/"
    resp = requests.get(url, headers=headers)
    # 429 means blocked by cf
    if resp.status_code == 429:
        log_error(f"Could not parse cve details, blocked")
        return False, None
    if resp.status_code != 200:
        log_error(f"Could not parse cve details, cant reach website?")
        return False, None

    return parse_cve_details(resp)

def parse_cve_details(response: requests.Response) -> tuple[bool, CVEDetails | None]:
    soup = BeautifulSoup(response.text, "html.parser")

    error = parse_error_message(soup)
    if error != "":
        log_error(f"Could not parse cve details: {error}")
        return False, None

    identifier = parse_ident(soup)
    if identifier == "":
        return False, None

    details = CVEDetails(identifier, None, [], [], [])

    details.summary = parse_summary(soup)
    details.references = parse_references(soup) 
    details.scores = parse_scores(soup)
    details.affected_version = parse_versions(soup)

    return True, details



def main():
    global args
    args_ok, args = parse_args()
    if not args_ok:
         log_fatal(f"Args incorrect")
    path_ok = check_files()
    if not path_ok:
        log_fatal(f"File integrity")
        exit(1)
    details_ok, details = get_cve_details()
    if not details_ok:
        log_fatal(f"Could not parse details")
        exit(1)
    assert details is not None, "Details None even though parsing succeded"
    for af in details.affected_version:
        print(af)

if __name__ == "__main__":
    main()
