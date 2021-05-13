import re
from pocsuite3.lib.core.data import conf
from pocsuite3.lib.core.data import logger

def regex_rule(files):
    if not conf.rule_filename:
        conf.rule_filename = "rule.rule"
    for file_name in files:
        regx_rules = ["name = '(.*)'",
                      "suricata_request = '''([\s\S]*?)'''",
                      "references = \['(.*)'\]", "createDate = '(.*)'", "updateDate = '(.*)'",
                      "vulID = '(.*)'",
                      "version = '(.*)'",
                      "suricata_response = '''([\s\S]*?)'''",
                      ]

        information_list = {"name": "0",
                            "suricata_request": "1",
                            "references": "2",
                            "createDate": "3",
                            "updateDate": "4",
                            "vulID": "5",
                            "version": "6",
                            "suricata_response": "7",
                            "flowbits": ""}

        f = open(file_name, "r", encoding="utf-8")
        st = f.read()
        for key, value in information_list.items():
            if value:
                pattern = re.compile(regx_rules[int(value)])
                cve_list = pattern.findall(st)
                if cve_list:
                    if "name" in regx_rules[int(value)]:
                        information_list[key] = cve_list[0].replace("\n", "")
                    else:
                        if "suricata_request" not in regx_rules[int(value)] and "suricata_response" not in regx_rules[int(value)]:
                            information_list[key] = cve_list[0].replace("\n", "").replace(" ", "")
                        else:
                            information_list[key] = cve_list[0].replace("\n", "")
                else:
                    information_list[key] = ""
        if not information_list["suricata_request"]:
            continue
        if "、" in information_list["vulID"]:
            information_list["vulID"] = information_list["vulID"].split("、")[0]
        elif not information_list["vulID"]:
            information_list["vulID"] = 0
        if information_list["suricata_response"] and not conf.rule_req:
            # 6220553==seebug.(　ˇωˇ)
            rule_to_server = '''alert http any any -> any any (msg:"{}";flow:established,to_server;{}classtype:web-application-attack;reference:url,{}; metadata:created_at {}, updated_at {};flowbits:set,{};flowbits:noalert;sid:{};rev:{};)'''.format(
                information_list["name"], information_list["suricata_request"], information_list["references"],
                information_list["createDate"], information_list["updateDate"], information_list["name"].replace(" ", "_"),
                6220553 + int(float(information_list["vulID"])) * 2, int(float(information_list["version"])))

            rule_to_client = '''alert http any any -> any any (msg:"{}";flow:established,to_client;{}classtype:web-application-attack;reference:url,{}; metadata:created_at {}, updated_at {};flowbits:isset,{};sid:{};rev:{};)'''.format(
                information_list["name"], information_list["suricata_response"], information_list["references"],
                information_list["createDate"], information_list["updateDate"], information_list["name"].replace(" ", "_"),
                6220553 + int(float(information_list["vulID"])) * 2 + 1, int(float(information_list["version"])))
        else:
            rule_to_server = '''alert http any any -> any any (msg:"{}";flow:established,to_server;{}classtype:web-application-attack;reference:url,{}; metadata:created_at {}, updated_at {};sid:{};rev:{};)'''.format(
                information_list["name"], information_list["suricata_request"], information_list["references"],
                information_list["createDate"], information_list["updateDate"],
                6220553 + int(float(information_list["vulID"])) * 2,
                int(float(information_list["version"])))
            rule_to_client = ""
        with open(conf.rule_filename, "a", encoding="utf-8") as f:
            f.write(rule_to_server+"\n")
            f.write(rule_to_client+"\n")
        f.close()
        logger.info("{} rule is:".format(file_name[file_name.rfind("\\")+1:]))
        print(rule_to_server)
        print(rule_to_client)
