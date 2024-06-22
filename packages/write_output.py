import json, os
from termcolor import colored


def process_results(vuln, data, res):
    totalResults = data["totalResults"]
 
    all_cve_ids = [x for x in vuln.keys()]


    
        
    
    def next_set(current_index):
        if current_index + 10 > len(all_cve_ids):
            current_index -= len(all_cve_ids)
        else:
            current_index += 10
        
        output_to_terminal(current_index)
        

    def prev_set(current_index: int):
        if current_index - 10 < 0:
            current_index = 0
        else:
            current_index -= 10

        output_to_terminal(current_index)


    def output_to_terminal(current_index=0):
        os.system("clear")
        print("-" * 40, "\n")

        if current_index == 0:
            chosen_range = 10
        else:
            chosen_range = current_index + 10
        

        for i in range(current_index, chosen_range):
            try:
                i = all_cve_ids[i]
            except:
                return
            print(colored("CVE ID:", "blue", attrs=["bold"]), i)
            tmp_cve = [x for x in vuln[i].keys()]
            for j in tmp_cve:
                print(colored(f"{j}:", "blue", attrs=["bold"]), vuln[i][j])
            print("-" * 40, "\n")
        controls = [{"name": "Next Batch", "value": next_set},
                {"name": "Previous Batch", "value": prev_set}]
        print(
        colored(
            f'\n\n[*] Current index is {current_index + 10} out of {totalResults}',
            "green",
            attrs=["bold"],
        )
        )
        for k,v in enumerate(controls):
            print(
            colored(
            f'{[k]} {v["name"]}',
            "green",
            attrs=["bold"],
            )
            )
        inpt = input("Enter input > ")
        if inpt  == "q":
            print(colored("quitting", "red"))
            return

        if inpt == "":
            inpt = 0

        try:
            inpt = int(inpt)
        except:
            print(colored("Value entered is not a number: ", "red"), inpt)
            output_to_terminal(current_index)
            return
        
        if inpt > 1 or inpt < 0:
            print(colored("Value entered is exceeds specified options: ", "red"), inpt)
            
        controls[inpt]["value"](current_index)
        return

                

    

    print("-" * 40, "\n")
    print(
    colored(
        f'[*] Printing first 10',
        "green",
        attrs=["bold"],
    )
    )
    output_to_terminal()

    return


def process_json(res: bytes, params: dict):

    # Getting the search terms if any to apply color to them
    search_terms = ""
    if "keywordSearch" in params.keys():
        search_terms = params["keywordSearch"]
        if " " in search_terms:
            search_terms = search_terms.lower().split()
    
    if len(res) == 0:
        print(
            colored(
                "[*] Something went wrong somewhere",
                "red",
                attrs=["bold"],
            ),
            "\nquitting ...",
        )
        quit()
    data = json.loads(res)

    cve_ids = []

    if data["totalResults"] == 0:
        print(
            colored(
                "[*] No vulnerabilies found using search parameters specified",
                "red",
                attrs=["bold"],
            ),
            "\nquitting ...",
        )
        quit()

    print(
        colored(
            f'[*] Search parameters returned {data["totalResults"]} {"vulnerabilities" if data["totalResults"] > 1 else "vulnerability"}',
            "green",
            attrs=["bold"],
        )
    )

    print(
        colored(
            f'[*] Start Index is {data["startIndex"]}',
            "green",
            attrs=["bold"],
        )
    )


    vuln = {}
    for i in data["vulnerabilities"]:
        # if vulnStatus is REJECTED continue
        VulnStatus = i["cve"]["vulnStatus"]
        cve_id = i["cve"]["id"]
        if VulnStatus == "Rejected":
            print(colored(f'[-] {cve_id} returned REJECTED', "red", attrs=["bold"]))
            if data["totalResults"] == 1:
                quit()
            else:
                continue

        cve_description = i["cve"]["descriptions"][0]["value"]
        metrics = i["cve"]["metrics"]
        vul_pub_date = i["cve"]["published"]
        vul_pub_date = vul_pub_date[:vul_pub_date.find("T")]
        vul_mod_date = i["cve"]["lastModified"]
        vul_mod_date = vul_mod_date[:vul_mod_date.find("T")]
        references = i["cve"]["references"][0]["url"]

        format_cve_desc = cve_description.split()
        for i in format_cve_desc:
            if isinstance(search_terms, list):
                if i.lower() in search_terms:
                    text = colored(i, "yellow", attrs=["bold"])
                    format_cve_desc[format_cve_desc.index(i)] = text
            else:
                if search_terms.lower() == i.lower():
                    text = colored(i, "yellow", attrs=["bold"])
                    format_cve_desc[format_cve_desc.index(i)] = text
        cve_description = " ".join(format_cve_desc)

        cve_ids.append(cve_id)

        cvssMetricV31 = metrics.get("cvssMetricV31", {})
        cvssMetricV2 = metrics.get("cvssMetricV2", {})

        primary_source = {}
        secondary_source = {}

        if cvssMetricV31 != {}:
            for k in cvssMetricV31:
                if k["type"].lower() == "primary":
                    primary_source = cvssMetricV31[cvssMetricV31.index(k)]
                if k["type"].lower() == "secondary":
                    secondary_source = cvssMetricV31[cvssMetricV31.index(k)]

        elif cvssMetricV2 != {}:
            for k in cvssMetricV2:
                if k["type"].lower() == "primary":
                    primary_source = cvssMetricV2[cvssMetricV2.index(k)]
                if k["type"].lower() == "secondary":
                    secondary_source = cvssMetricV2[cvssMetricV2.index(k)]

        else:
            pass
            # print(
            #     colored(
            #         "[*] No cvssMetricV31 and cvssMetricV2 Found", "red", attrs=["bold"]
            #     )
            # )

        primary_base_score = 0
        primary_source_ref = ""
        primary_base_severity = ""
        if primary_source != {}:
            primary_base_score = primary_source["cvssData"]["baseScore"]
            primary_source_ref = primary_source["source"]
            try:
                primary_base_severity = primary_source["cvssData"]["baseSeverity"]
            except:
                primary_base_severity = primary_source["baseSeverity"]

        secondary_base_score = None
        secondary_source_ref = ""
        secondary_base_severity = ""
        if secondary_source != {}:
            secondary_base_score = secondary_source["cvssData"]["baseScore"]
            secondary_source_ref = secondary_source["source"]
            try:
                secondary_base_severity = secondary_source["cvssData"]["baseSeverity"]
            except:
                secondary_base_severity = secondary_source["baseSeverity"]

        # Giving the Base scores colors based on how high they are:
        scores = [primary_base_score, secondary_base_score]
        for i in scores:
            if i == None:
                continue
            if i >= 9.0:
                scores[scores.index(i)] = colored(
                    f"{i}", "red", attrs=["bold", "blink"]
                )
            elif i >= 7.0:
                scores[scores.index(i)] = colored(
                    f"{i}", "red", attrs=["bold"]
                )
            elif i >= 4.0:
                scores[scores.index(i)] = colored(
                    f"{i}", "yellow", attrs=["bold"])
            else:
                scores[scores.index(i)] = colored(f"{i}", "green")
        primary_base_score, secondary_base_score = scores

        # Giving colors to base severity
        severity = [primary_base_severity, secondary_base_severity]
        for i in severity:
            if i == "":
                continue
            if i == "CRITICAL":
                severity[severity.index(i)] = colored(
                    f"{i}", "red", attrs=["bold", "blink"]
                )
            elif i == "HIGH":
                severity[severity.index(i)] = colored(
                    f"{i}", "red", attrs=["bold"]
                )
            elif i == "MEDIUM":
                severity[severity.index(i)] = colored(
                    f"{i}", "yellow", attrs=["bold"])
            else:
                severity[severity.index(i)] = colored(
                    f"{i}", "green", attrs=["bold"])
        primary_base_severity, secondary_base_severity = severity
        
        
        important_data = [
            {
             "vul_pub_date": vul_pub_date,
             "vul_mod_date": vul_mod_date,
             "description": cve_description,
             "vuln_status": VulnStatus,
             "primary_base_score": primary_base_score,
             "primary_Source": primary_source_ref,
             "primary_base_severity": primary_base_severity,
             "secondary_base_score": secondary_base_score,
             "secondary_source": secondary_source_ref,
             "secondary_base_severity": secondary_base_severity,
             "reference_url": references
             }
        ]

        vuln[cve_id] = important_data[0]

    process_results(vuln, data, res)
