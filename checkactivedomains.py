import requests
from multiprocessing import Pool
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


maxprocessors=4

def readata():
    with open(inputfile,'r+') as file:
        data=file.read().splitlines()
    return data

def active_urls(url):
    try:
        if requests.get(f"http://{url}",verify=False).status_code==200:
            return url
    except:
        return

def writedata(urls):
    with open(outputfile,'a+') as file:
        print("\nActive Domains:\n")
        for x in urls:
            if x:
                print(x)
                file.write(x+'\n')
        print(f"\nThe data has been saved to {outputfile}")


if __name__=='__main__':
    inputfile,outputfile=input('Enter filename/filepath of domains: '),input('Enter filepath/filename of output file: ')
    data=readata()
    with Pool(maxprocessors) as p:
        checked_urls=p.map(active_urls,data)
    writedata(checked_urls)
