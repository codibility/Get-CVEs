
from packages.api_calls import *
from packages.local_calls import *


class ActionTemplate:
    def __init__(self, name: str, function: str, online_req: str, requirements: str = None):
        self.name = name
        self.function = function
        self.online_required = online_req

        if requirements != None:
            self.requirements = requirements





actions = [
    ActionTemplate("Get CVEs based on Published date range", get_cve_based_on_pub_date, True),
    ActionTemplate("Search if output contains keywords", keyword_search, True),
    ActionTemplate("Search by CVE id", search_by_cveId, True),
    ActionTemplate( "Based on CVSS V2 Severity", based_on_cvssV2Severity, True),
    ActionTemplate("Based on CVSS V3 Severity", based_on_cvssV3Severity, True),
    ActionTemplate("Has Cert Alerts", hasCertAlerts, True),
    ActionTemplate("Has Cert Notes", hasCertNotes, True),
    ActionTemplate("Match specified keywords exactly", keywordExactMatch, True),
    ActionTemplate("Get CVEs based on modification date range", get_cve_based_on_mod_date, True),
    ActionTemplate("Results per page", resultsPerPage, True),
    ActionTemplate("Start Index", startIndex, True),
    ActionTemplate("Update Local Storage (Perform git pull from cve repo)", update_local_database, True),
    ActionTemplate("Show recent CVEs", show_recent_cves, False),
    ActionTemplate("Update Hot Keywords", update_hot_keywords, False),
    ActionTemplate("Local Functions", get_from_local, True), # Should only show up on the online functions
    ActionTemplate("Search by CWEs", search_by_cwe, False),
    ActionTemplate("Search by CWEs (Specific)", search_by_cwe_must_match, False)
]
