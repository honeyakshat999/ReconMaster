import socket, threading
from pandas import DataFrame
from os.path import join
from utils.utilities import Helper


logger=Helper.LOGGER

def TCP_connect(ip, port_number, delay, output):
    TCPsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    TCPsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    TCPsock.settimeout(delay)
    try:
        TCPsock.connect((ip, port_number))
        output[port_number] = 'Listening'
    except:
        output[port_number] = ''



def scan_ports(host_ip, delay):

    threads = []     
    output = {}   

    for i in range(49152):
        t = threading.Thread(target=TCP_connect, args=(host_ip, i, delay, output))
        threads.append(t)


    for i in range(49152):
        threads[i].start()


    for i in range(49152):
        threads[i].join()

    return output



def init_portscaning(url,filepath,timeout):
    try:
        logger.info("Attempting To Scan Port Ranging From 0 to 49152")
        host_ip = url
        delay = timeout
        listeningports=scan_ports(host_ip, delay)
        logger.info("Successfully Scaned Port")
        logger.info("Attempting To Save Scan Data")
        (DataFrame.from_dict(listeningports,orient='index')
                    .reset_index().rename(columns={"index":"port",0:"status"})
                    .query("status=='Listening'").to_csv(join(filepath,"scaning.csv"),index=None))
        logger.info("Successfully Saved Scan Data to scaning.csv")
    except Exception as e:
        logger.error(f"Unable to Scan Port Ranging From 0 to 49152 Due To Following Error : {e}")
    
