from asyncio.log import logger
import requests
import re
import os
from utils import helper


logger=helper.LOGGER

def init_historic(domain,filepath):
    try:
        logger.info("Attempting To Fetch Historic Data")
        pattern = "(https?://|www\.)?((?:[\d\w\.\-]+)?" + domain.lstrip('.').split()[0] + "(?:[\d\S]+))"
        if not os.path.exists(helper.get_config('save_path')):
            os.mkdir(helper.get_config("save_path"))
        with open(os.path.join(filepath,'historic.csv'), mode='a+', encoding='utf-8') as f:
            url = "https://web.archive.org/cdx/search/cdx?url="+ "*."+domain + "/*"
            data = requests.get(url).text
            matching = list(set(re.compile(pattern).findall(data)))
            logger.info("Successfully Fetch Historic Data")
            logger.info("Attempting To Save Historic Data")
            f.write("Historic Data\n")
            for j in range(len(matching)):
                f.write(''.join(matching[j]) + '\n')
            logger.info("Successfully Saved Historic Data in historic.csv")
    except Exception as e:
        logger.error(f"Unable To Fetch Historic Data Due To Following Error : {e}")