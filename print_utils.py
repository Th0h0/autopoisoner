def potential_verbose_message(message, args, url="default"):
    if args.verbose:
        if message == "ERROR":
            print(f"[VERBOSE] Request Error for {url}")
        elif message == "CANARY":
            print(f"[VERBOSE] CANARY reflection in {url}. Confirming cache poisoning in progress ...")
        elif message == "STATUS_CODE":
            print(f"[VERBOSE] STATUS_CODE difference in {url}. Confirming cache poisoning in progress ...")
        elif message == "LENGTH":
            print(f"[VERBOSE] LENGTH difference in {url}. Confirming cache poisoning in progress ...")
        elif message == "UNSUCCESSFUL":
            print(f"[VERBOSE] Unsuccessful vulnerability confirmation on {url}\n")
        elif message == "CRAWLING":
            print(f"[VERBOSE] Crawling. Scanning : {url}")

def behavior_or_confirmed_message(behaviorOrConfirmed, behaviorType, explicitCache, url, header = "default", outputFile = "default", LOCK = "default"):

    messageDict = {"REFLECTION": "HEADER REFLECTION",
                   "STATUS": "DIFFERENT STATUS-CODE",
                   "LENGTH": "DIFFERENT RESPONSE LENGTH",
                   "BEHAVIOR": "[INTERESTING BEHAVIOR]",
                   "CONFIRMED": "VULNERABILITY CONFIRMED! |"
                   }

    if header != "default":
        message = f"{messageDict[behaviorOrConfirmed]} {messageDict[behaviorType]} | EXPLICIT CACHE : {explicitCache} | URL: {url} | HEADER : {header}\n"
        print(message)
        if behaviorOrConfirmed == "CONFIRMED":
            with LOCK:
                outputFile.write(message)
    else:
        message = f"{messageDict[behaviorOrConfirmed]} PORT {messageDict[behaviorType]} | EXPLICIT CACHE : {explicitCache} | URL: {url} | HEADER : {header}\n"
        print(message)
        if behaviorOrConfirmed == "CONFIRMED":
            with LOCK:
                outputFile.write(message)