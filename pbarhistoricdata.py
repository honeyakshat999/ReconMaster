import requests
import re
from threading import Thread
import sys

domain = "amity.edu"
filename="amity.txt"
f = open(filename, mode='a+', encoding='utf-8')
pattern = "(https?://|www\.)?((?:[\d\w\.\-]+)?" + domain.lstrip('.').split()[0] + "(?:[\d\S]+))"

def progressbar(it, prefix="", size=100, file=sys.stdout):
    count = len(it)
    def show(j):
        x = int(size*j/count)
        file.write("{}[{}{}] \r".format(prefix, "█"*x, "."*(size-x)))
        file.flush()
    show(0)
    for i, item in enumerate(it):
        yield item
        show(i+1)
    file.write("\n")
    file.flush()

def wayback():
    url = "https://web.archive.org/cdx/search/cdx?url="+ "*."+domain + "/*"
    data = requests.get(url).text
    matching = list(set(re.compile(pattern).findall(data)))
    for j in progressbar(range(len(matching)), prefix="Fetching Data 1/3: ", size=50):
        f.write(''.join(matching[j]) + '\n')

def alienvault():
    url = "https://otx.alienvault.com/api/v1/indicators/domain/"+domain+"/url_list/?limit=1000000000000000000000000000000"
    data = requests.get(url).json()
    for i in progressbar(range(1000) if len(data['url_list'])>1000 else range(len(data['url_list'])), prefix="Fetching Data 2/3: ", size=50):
        try:
            hostname = data['url_list'][i]['url']
            f.write(''.join(hostname) + '\n')
            
        except IndexError:
            return


def commoncrawl():
    url1 = "http://index.commoncrawl.org/collinfo.json"
    data = requests.get(url1).json()
    for i in progressbar(range(150) if len(data)>150 else range(len(data)), prefix="Fetching Data 3/3: ", size=50):
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
        data=list(set(lines))
        for x in progressbar(range(len(data)), prefix="Writing Data:      ", size=50):
            file.write(data[x])
    print(f'\nThe data has been saved to {filename}')


t1=Thread(target=wayback,args=())
t2=Thread(target=alienvault,args=())
t3=Thread(target=commoncrawl,args=())
for x in [t1,t2,t3]:
    x.start()
    x.join()

f.close()
removeDups(filename)
