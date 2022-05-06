import requests
import re
from os.path import join


def historic(domain,filepath):
    pattern = "(https?://|www\.)?((?:[\d\w\.\-]+)?" + domain.lstrip('.').split()[0] + "(?:[\d\S]+))"
    with open(join(filepath,'historic.csv'), mode='a+', encoding='utf-8') as f:
        url = "https://web.archive.org/cdx/search/cdx?url="+ "*."+domain + "/*"
        data = requests.get(url).text
        matching = list(set(re.compile(pattern).findall(data)))
        f.write("Historic Data\n")
        for j in range(len(matching)):
            f.write(''.join(matching[j]) + '\n')
    print("\nThe data has been saved to historic.csv")



