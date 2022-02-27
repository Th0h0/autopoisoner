### Summary

**autoPoisoner** is your best companion for automating **web cache poisoning** detection at scale. The tool comes with the following features : 

- Headers-based poisoning
    
    When **autoPoisoner** launched against a domain/sub-domain, it will firstly attempt to detect interesting behaviors when adding new headers to the request. If the HTTP response with an added header is remarkably different than without, it would be the sign of a potential **unkeyed** header, relative to the cache, identified.
    **autoPoisoner** unkeyed parameter detection is based on the three following interesting behaviors :
    
    - Reflection of a *CANARY* in the HTTP response
        
        When adding new HTTP headers to the original HTTP request, a value, called a *CANARY,* would be passed as their value (e.g. `X-Rewrite-URL: CANARY`, `X-Forwarded-Host: CANARY`). In case this results to **“CANARY” appearing/reflecting in the response**, this would be the immediate feedback that the injected header is well understood by the web-application.
        
    - Different Status-Code
        
        As previously stated, interesting behavior detection relies on the comparison between two responses, the respective results of a normal HTTP request, and a modified one with added content. To this regard, response’s status-code is a very interesting element to consider. The tool would therefore also relies on **status-code variations**, e.g. from HTTP *200*(OK) to *404(Not Found)*, 200 to *302* (Redirect) or 200 to *501* (Not Implemented).
        
    - HTTP response’s length difference
        
        Finally, if no *canary* reflected in the response, and no status-code changes occurred between the original & modified requests, **autoPoisoner** would consider the HTTP response’s length difference. As web-pages can slightly change over time, the tool would only trigger if the **distance between the two HTTP responses’s length is superior to 25% of the original response’s length**. This pourcentage has been chosen to limit, as much as possible, false-positives.
        
- Port-based poisoning
    
    In addition to attempt injecting unkeyed headers to the HTTP request, **autoPoisoner** will also manipulate the *Host* header by adding a port to it (e.g. `Host: company.com:8888`, expecting web-application different behavior to it. In fact, port could constitute an unkeyed component, to the cache, potentially resulting from requests with `Host: company.com` being assigned the same cache data as the ones with `Host: company.com:8888`. This would cause an issue in cases where the web-application behaves differently when a port is added to the host.
    
- Static files crawling and poisoning
    
    Caches often deal with web content differently, depending on their ability to change over time. In fact, due to their nature, static files such as javascript, png, jpg, or ico, would rarely be modified, but still often accessed by all visitors when visiting a page, which make them very relevant to cache. For a specified url `[https://www.companyX.com](https://www.companyX.com)` it would, therefore, get plausible to observe no vulnerable cache behavior, whereas this would be the case for `https://www.companyX.com/application.js`. 
    To address this concern, in case no web cache poisoning is detected for a specified URL, **autoPoisoner** would automatically attempt to **crawl static files** through the original page’s source code, and **conduct new attacks** on them.
    
    ---
    

### Usage

```bash
python3 autopoisoner.py -h
```

This displays help for the tool.

```bash
options:
  -h, --help            show this help message and exit
  --file FILE, -f FILE  file containing URLs to be tested
  --url URL, -u URL     url to be tested
  --verbose, -v         activate verbose mode
  --behavior, -b        activate a lighter version of verbose, highlighting interesting cache behavior
  --output, -o          output file path (default: output.txt)
```

Single URL target with *behavior* mode activated:

```bash
python3 -u https://www.domain.com -b
```

Multiple URLs target with verbose: 

```bash
python3 autopoisoner.py -f urls.txt -v
```

---

### Installation

1 - Clone 

```bash
git clone https://github.com/Th0h0/autopoisoner.git
```

2  - Install required library

```bash
pip install requests
```

---

### License

**autoPoisoner** is distributed under [MIT License](https://github.com/Th0h0/autopoisoner/blob/master/LICENSE.md).
