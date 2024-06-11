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

@dataclass
class VersionRange:
    max_version: str
    min_version: str
    exclusions: list[str]

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


def get_cve_details():
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
        return False
    if resp.status_code != 200:
        log_error(f"Could not parse cve details, cant reach website?")
        return False

    soup = BeautifulSoup(resp.text, "html.parser")
    # Check if the cve exists, if not there is a element with the class "alert alert-secondary my-4" which has the error message
    potential_error_message_container = soup.find("div", {"class": "alert alert-secondary my-4"})
    if potential_error_message_container is not None:
        # Error message is the first bold text
        potential_error_message = potential_error_message_container.findChild("b", recursive=False)
        error = "Unkown"
        if potential_error_message is not None:
            error = potential_error_message.text
        log_error(f"Could not parse cve details: {error}")
        return False

    # Check if the CVE identifier can be found on the page
    identifier_element = soup.find("div", {"id": "cvedetails-title-div"})
    if identifier_element is None:
        log_error("Could not parse title on cve details")
        return False
    identifier = identifier_element.findChild("a")
    if identifier is None:
        log_error("Could not parse identifier of cve on cve details")
        return False

    details = CVEDetails(identifier.text, None, [], [], [])
    
    # Try parse the summary
    summary = soup.find("div", {"id": "cvedetailssummary"})
    if summary is None:
        log_debug("Could not parse summary from cve details")
    else:
        details.summary = summary.text

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

    details.scores = scores

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
    details.references = links

    for ref in details.references:
        print(ref)



def main():
    global args
    args_ok, args = parse_args()
    if not args_ok:
         log_fatal(f"Args incorrect")
    path_ok = check_files()
    if not path_ok:
        log_fatal(f"File integrity")
        exit(1)
    details = get_cve_details()

if __name__ == "__main__":
    main()
