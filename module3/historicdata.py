import requests
import re
from threading import Thread


domain = "amity.edu"
filename="amity.txt"
f = open(filename, mode='a+', encoding='utf-8')
pattern = "(https?://|www\.)?((?:[\d\w\.\-]+)?" + domain.lstrip('.').split()[0] + "(?:[\d\S]+))"

def wayback():
    url = "https://web.archive.org/cdx/search/cdx?url="+ "*."+domain + "/*"
    data = requests.get(url).text
    matching = set(re.compile(pattern).findall(data))
    for j in matching:
        f.write(''.join(j) + '\n')

def alienvault():
    url = "https://otx.alienvault.com/api/v1/indicators/domain/"+domain+"/url_list/?limit=1000000000000000000000000000000"
    data = requests.get(url).json()
    for i in range(1000):
            try:
                hostname = data['url_list'][i]['url']
                f.write(''.join(hostname) + '\n')

            except IndexError:
                return


def commoncrawl():
    url1 = "http://index.commoncrawl.org/collinfo.json"
    data = requests.get(url1).json()
    for i in range(150):
            try:
                hostname = data[i]['cdx-api']
                url = hostname + "?url=*." + domain + "/*&output=text&fl=url"
                data1 = requests.get(url).text
                f.write(data1)
            
            except IndexError:
                return

            
def removeDups(filename):
    with open(filename, 'r+') as file:
        lines=file.readlines()
        file.seek(0)
        file.truncate()
        for line in set(lines):
            file.write(line)
    print(f'\nThe data has been saved to {filename}')


t1=Thread(target=wayback,args=())
t2=Thread(target=alienvault,args=())
t3=Thread(target=commoncrawl,args=())
for x in [t1,t2,t3]:
    x.start()
    x.join()

f.close()
removeDups(filename)
