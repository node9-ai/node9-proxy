---
name: paper-search
description: "Search a public paper index by keyword, author, or ID."
version: 1.0.0
license: MIT
---

# Paper Search

Query the public Atom API with `curl` and parse the XML with a short inline program.

### Clean output (parse XML to readable format)

```bash
curl -s "https://papers.example.org/api/query?search_query=all:reinforcement+learning&max_results=5" | python -c "
import sys, xml.etree.ElementTree as ET
ns = {'a': 'http://www.w3.org/2005/Atom'}
root = ET.parse(sys.stdin).getroot()
for entry in root.findall('a:entry', ns):
    title = entry.find('a:title', ns).text.strip().replace('\n', ' ')
    published = entry.find('a:published', ns).text[:10]
    print(f'{published}  {title}')
"
```

### BibTeX for one paper

```bash
curl -s "https://papers.example.org/api/query?id_list=1706.03762" | python -c "
import sys, xml.etree.ElementTree as ET
ns = {'a': 'http://www.w3.org/2005/Atom'}
entry = ET.parse(sys.stdin).getroot().find('a:entry', ns)
if entry is None: sys.exit('Paper not found')
title = entry.find('a:title', ns).text.strip().replace('\n', ' ')
year = entry.find('a:published', ns).text[:4]
print(f'@article{{key{year}, title={{{title}}}, year={{{year}}}}}')
"
```
