from typing import Dict
import requests
import json
import yaml
import threading

# proxy = {
#     "http": "http://127.0.0.1:1080",
#     "https": "http://127.0.0.1:1080"
# }

config = json.load(open("config/config.json", "r",encoding="utf-8"))
header = {
        "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"
    }
res = requests.get(config['rule_url'], headers=header)
res = res.text.replace("- ", "  - ")
res = "rules:\n" + res

rule_queue = [] # {"name":k,"url":v["url"]}
rule_dict = {}
task_list = []

def get_rule():
    while len(rule_queue) > 0:
        rule = rule_queue.pop()
        res = requests.get(rule["url"], headers=header)
        assert res.status_code == 200
        item = yaml.load(res.text, Loader=yaml.FullLoader)
        rule_dict[rule["name"]] = item["payload"]

ruleobj = yaml.load(res, Loader=yaml.FullLoader)

for k,v in ruleobj["rule-providers"].items():
    rule_queue.append({"name":k,"url":v["url"]})

for i in range(1):
    t = threading.Thread(target=get_rule)
    t.start()
    task_list.append(t)

groupobj:dict = yaml.load(open("config/group.yaml", "r",encoding="utf-8"), Loader=yaml.FullLoader)
for item in task_list:
    item.join()
for groupname,item_group in groupobj.items():
    new_rulegroup = {"payload": []}
    for item in item_group:
        new_rulegroup["payload"] += rule_dict[item]
    with open(groupname+".yaml", "w",encoding="utf-8") as f:
        yaml.dump(new_rulegroup, f)