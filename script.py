def main(ctx, metadata):
        ruleset_action = {"Reject": "AdBlock",
            "Special": "DIRECT",
            "Netflix": "Netflix",
            "Spotify": "Spotify",
            "YouTube": "YouTube",
            "Disney Plus": "Disney",
            "Bilibili": "Asian TV",
            "IQ": "Asian TV",
            "IQIYI": "Asian TV",
            "Letv": "Asian TV",
            "Netease Music": "Asian TV",
            "Tencent Video": "Asian TV",
            "Youku": "Asian TV",
            "WeTV": "Asian TV",
            "ABC": "Global TV",
            "Abema TV": "Global TV",
            "Amazon": "Global TV",
            "Bahamut": "Global TV",
            "BBC iPlayer": "Global TV",
            "DAZN": "Global TV",
            "Discovery Plus": "Global TV",
            "encoreTVB": "Global TV",
            "F1 TV": "Global TV",
            "Fox Now": "Global TV",
            "Fox+": "Global TV",
            "HBO Go": "Global TV",
            "HBO Max": "Global TV",
            "Hulu Japan": "Global TV",
            "Hulu": "Global TV",
            "Japonx": "Global TV",
            "JOOX": "Global TV",
            "KKBOX": "Global TV",
            "KKTV": "Global TV",
            "Line TV": "Global TV",
            "myTV SUPER": "Global TV",
            "Niconico": "Global TV",
            "Pandora": "Global TV",
            "PBS": "Global TV",
            "Pornhub": "Global TV",
            "Soundcloud": "Global TV",
            "ViuTV": "Global TV",
            "Telegram": "Telegram",
            "Crypto": "Crypto",
            "Discord": "Discord",
            "Steam": "Steam",
            "Speedtest": "Speedtest",
            "PayPal": "PayPal",
            "Microsoft": "Microsoft",
            "ChatGPT": "ChatGPT",
            "Apple Music": "Apple TV",
            "Apple News": "Apple TV",
            "Apple TV": "Apple TV",
            "Apple": "Apple",
            "Google FCM": "Google FCM",
            "Scholar": "Scholar",
            "PROXY": "Proxy",
            "Domestic": "Domestic",
            "Domestic IPs": "Domestic",
            "LAN": "DIRECT"
          }

        port = int(metadata["dst_port"])

        if metadata["network"] == "UDP" and port == 443:
            ctx.log('[Script] matched QUIC traffic use reject')
            return "REJECT"

        port_list = [21, 22, 23, 53, 80, 123, 143, 194, 443, 465, 587, 853, 993, 995, 998, 2052, 2053, 2082, 2083, 2086, 2095, 2096, 3389, 5222, 5228, 5229, 5230, 8080, 8443, 8880, 8888, 8889]
        if port not in port_list:
            ctx.log('[Script] not common port use direct')
            return "DIRECT"

        if metadata["dst_ip"] == "":
            metadata["dst_ip"] = ctx.resolve_ip(metadata["host"])

        for ruleset in ruleset_action:
            if ctx.rule_providers[ruleset].match(metadata):
                return ruleset_action[ruleset]

        if metadata["dst_ip"] != "":
            code = ctx.geoip(metadata["dst_ip"])
            if code == "CN":
                ctx.log('[Script] Geoip CN')
                return "国内流量"

        ctx.log('[Script] FINAL')
        return "Others"