from packages.api_calls import *
from packages.local_calls import *


class ActionTemplate:
    def __init__(self, name: str, function: str, online_req: str, action_id: int, requirements: list = [], avoid_together: list = []):
        self.name = name
        self.function = function
        self.online_required = online_req
        self.id = action_id
        self.requirements = requirements
        self.avoid_together = avoid_together





actions = [
    ActionTemplate("Get CVEs based on Published date range", get_cve_based_on_pub_date, "both", 0),
    ActionTemplate("Search if output contains keywords", keyword_search, "both", 1),
    ActionTemplate("Search by CVE id", search_by_cveId, "both", 2),
    ActionTemplate("Based on CVSS V2 Severity", based_on_cvssV2Severity, "online", 3, avoid_together=[2]),
    ActionTemplate("Based on CVSS V3 Severity", based_on_cvssV3Severity, "online", 4, avoid_together=[3]),
    ActionTemplate("Has Cert Alerts", hasCertAlerts, "online", 5),
    ActionTemplate("Has Cert Notes", hasCertNotes, "online", 6),
    ActionTemplate("Match specified keywords exactly", keywordExactMatch, "both", 7, requirements=[1]),
    ActionTemplate("Get CVEs based on modification date range", get_cve_based_on_mod_date, "online", 8),
    ActionTemplate("Results per page", resultsPerPage, "online", 9),
    ActionTemplate("Start Index", startIndex, "online", 10),
    ActionTemplate("Update Local Storage (Perform git pull from cve repo)", update_local_database, "online", 11),
    ActionTemplate("Show recent CVEs", show_recent_cves, "both", 12),
    ActionTemplate("Update Hot Keywords", update_hot_keywords, "both", 13),
    ActionTemplate("Local Functions", get_from_local, "online", 14), # Should only show up on the online functions
    ActionTemplate("Search by CWEs", search_by_cwe, "offline", 15),
    ActionTemplate("Search by CWEs (Exact Match)", search_by_cwe_must_match, "offline", 16)
]

option_map = [{"name": x.name, "function": x.function, "id": x.id} for x in actions]
