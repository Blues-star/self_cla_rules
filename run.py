import json
import threading
import pathlib
import requests
import re
import yaml

yaml.SafeDumper.org_represent_str = yaml.SafeDumper.represent_str


def repr_str(dumper, data):
    if '\n' in data:
        # print(data)
        return dumper.represent_scalar(u'tag:yaml.org,2002:str',
                                       data,
                                       style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)
    return dumper.org_represent_str(data)


yaml.add_representer(str, repr_str)

proxy = {"http": "http://127.0.0.1:1080", "https": "http://127.0.0.1:1080"}

config = json.load(open("config/config.json", "r", encoding="utf-8"))
header = {
    "User-Agent":
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"  # noqa: E501
}
res = requests.get(config['rule_url'], headers=header)
res = res.text.replace("- ", "  - ")
res = "rules:\n" + res

rule_queue = []  # {"name":k,"url":v["url"]}
rule_dict = {}
task_list = []
# https://dler.cloud/Rules/Clash/Provider/Reject.yaml
# https://ghproxy.com/https://github.com/dler-io/Rules/blob/main/Clash/Provider/Reject.yaml


def get_rule():
    while len(rule_queue) > 0:
        try:
            rule = rule_queue.pop()
            yamlname = rule["url"].split('/')[-1]
            target_url = f"https://gh-proxy.com/https://github.com/dler-io/Rules/blob/main/Clash/Provider/{yamlname}"
            res = requests.get(target_url, headers=header)
            assert res.status_code == 200
            print("[+] " + rule["name"] + "  " + target_url)
            item = yaml.load(res.text, Loader=yaml.FullLoader)
            rule_dict[rule["name"]] = item["payload"]
        except Exception as e:
            print("")
            print(target_url)
            target_url = f"https://gh-proxy.com/https://github.com/dler-io/Rules/blob/main/Clash/Provider/Media/{yamlname}"
            res = requests.get(target_url, headers=header)
            assert res.status_code == 200
            print("[+] " + rule["name"] + "  " + target_url)
            item = yaml.load(res.text, Loader=yaml.FullLoader)
            rule_dict[rule["name"]] = item["payload"]


ruleobj = yaml.load(res, Loader=yaml.FullLoader)

# https://github.com/dler-io/Rules/blob/main/Clash/Provider/Microsoft.yaml
# https://dler.cloud/Rules/Clash/Provider/Reject.yaml
# https://ghproxy.com/https://github.com/dler-io/Rules/blob/main/Clash/Provider/Reject.yaml

# https://ghproxy.com/https://raw.githubusercontent.com/dler-io/Rules/main/Clash/Provider/Media/Fox%20Now.yaml
# https://ghproxy.com/https://raw.githubusercontent.com/dler-io/Rules/main/Clash/Provider/Media/Fox%20Now.yaml

for k, v in ruleobj["rule-providers"].items():
    assert v["url"].endswith(".yaml")
    url: str = f"https://mirror.ghproxy.com/{v['url']}"
    print(url)
    ruleobj["rule-providers"][k]["url"] = url
    rule_queue.append({"name": k, "url": url})


groupobj: dict = yaml.load(open("config/group.yaml", "r", encoding="utf-8"),
                           Loader=yaml.FullLoader)
for item in task_list:
    item.join()
rule_dir = pathlib.Path("rules")
rule_dir.mkdir(exist_ok=True)
rule_files = rule_dir.glob("*.yaml")
# print(groupobj["extra-rule-providers"].keys())
assert "ChatGPT" in groupobj["extra-rule-providers"].keys()
for item in rule_files:
    if item.is_file(
    ) and item.stem not in groupobj["extra-rule-providers"].keys():
        assert item.stem != "ChatGPT"
        item.unlink()

# for groupname, item_group in groupobj["rule—groups"].items():
#     new_rulegroup = {"payload": []}
#     for item in item_group:
#         new_rulegroup["payload"] += rule_dict[item]
#     with open("rules/" + groupname + ".yaml", "w", encoding="utf-8") as f:
#         yaml.dump(new_rulegroup, f)

examples = {
    "type": "http",
    "behavior": "classical",
    "url":
    'https://mirror.ghproxy.com/https://github.com/Blues-star/self_cla_rules/blob/main/rules/{}',
    "path": "./Rules/{}",
    "interval": 86400,
}

import ast

with open("script.py", "r", encoding="utf-8") as f:
    code = f.read()
    tree = ast.parse(code)

ruleset_action = {}
for groupname, grouplist in groupobj["rule—groups"].items():
    for item in grouplist:
        ruleset_action[item] = groupname

for node in ast.walk(tree):
    # 替换ruleset_action
    if isinstance(node, ast.Assign):
        if isinstance(node.targets[0], ast.Name):
            if node.targets[0].id == "ruleset_action":
                node.value = ast.Dict(
                    keys=[
                        ast.Constant(value=k) for k in ruleset_action.keys()
                    ],
                    values=[
                        ast.Constant(value=v) for v in ruleset_action.values()
                    ],
                )

rules = []
for groupname, grouplist in groupobj["rule—groups"].items():
    for item in grouplist:
        rules.append(
            f"RULE-SET,{item},{groupname}")

new_rule_yaml = {
    "rules": rules + ["GEOIP,CN,国内流量", "MATCH,Others"],  # noqa: E501
    "script": {
        "code": ast.unparse(tree)
    },
    "rule-providers": ruleobj["rule-providers"]
}
for groupname, item_group in groupobj["extra-rule-providers"].items():
    new_rule_yaml["rule-providers"][groupname] = item_group

with open("new_rule.yaml", "w", encoding="utf-8") as f:
    yaml.dump(new_rule_yaml,
              f,
              allow_unicode=True,
              default_flow_style=False,
              explicit_start=True,
              encoding="utf-8")
