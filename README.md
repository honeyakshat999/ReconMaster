<p align="center">
  <img src="https://user-images.githubusercontent.com/45512833/175888798-a50e1e4e-0424-4f37-b776-73b562d73356.png" alt="recon">
</p>


# ReconMaster
ReconMaster is a Reconnamace enumeration tool. it will automate the gathering, analyzing, and representing information based on the target. generally, for each task, we have to run multiple tools and scripts manually, this tool will reduce all manual work, also make it efficient. These tools will also find bugs based on information gathered. This tool includes many modules on which a user can get information, some of them are as follows subdomain, Dorking, directory enum, port scanning, acquisition, subdomain takeovers, etc. the main motive of the tool is to reduce time and efforts of the pentesters and give full pakage of tools at one place.


## Installation

```
git clone https://github.com/honeyakshat999/ReconMaster.git
sudo apt-get install -y python3
pip3 install -r requirements.txt
```

If you want to have a virtual environment then:

* For `mac` and `linux` :

```
git clone https://github.com/honeyakshat999/ReconMaster.git
sudo apt-get install -y python3     #If you already have python3 installed skip this step
pip3 install virtualenv
python3 -m virtualenv venv          #creating virtual environment
source venv/bin/activate            #activating virtual environment
pip3 install -r requirements.txt    #installing dependencies in virtual environment
#deactivate                         #use this for getting out from virtual environment
```

* For `windows` :

```
::go to https://www.python.org/downloads/ and download and install python(If you already have python3 installed skip this step)
python -m venv venv                   ::creating virtual environment
venv\Scripts\activate                 ::activating virtual environment
pip install -r requirements.txt       ::installing dependencies in virtual environment
::venv\Scripts\deactivate             ::use this for getting out from virtual environment
```

## Usage

Run `reconmaster.py` with arguments as follows :

* `-h` or `--help`             : help regarding reconmaster and list all the accepted parameters
* `-U` or `--url` (required)   : for entering the domain e.g google.com
* `-E` or `--engine`           : for entering the prefered engine(default `all`) e.g bing

commands:

* For `linux` and `mac` :
```
python3 reconmaster.py -U google.com
#with Engine:
python3 reconmaster.py -U google.com -E duckduckgo
```
* For `windows` :
```
python reconmaster.py -U google.com
::with Engine:
python reconmaster.py -U google.com -E duckduckgo
```

## Server

After the data is gathered ,processed and saved then for displaying that data the server starts

The server starts with default `url` and `port` as follows :
* `url`  : `127.0.0.1`
* `port` : `5000`

So you can access it by pasting the below url to any browser :
```
http://127.0.0.1:5000
```

## Upcoming Update

The next update is rolling out very soon, **Stay Tuned :)**

What's new in next update :

* Improved User Interface
* Improved Efficiency
* Faser Execution than current version
* Probably A New Module



**Note :** This tool is made for educational purposes and to help security researchers. Any actions or activities performed using this is solely your responsibility
