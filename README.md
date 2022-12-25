<p align="center">
  <img src="https://user-images.githubusercontent.com/45512833/175888798-a50e1e4e-0424-4f37-b776-73b562d73356.png" alt="recon">
</p>


# ReconMaster
ReconMaster is a Reconnamace enumeration tool. it will automate the gathering, analyzing, and representing information based on the target. generally, for each task, we have to run multiple tools and scripts manually, this tool will reduce all manual work, also make it efficient. These tools will also find bugs based on information gathered. This tool includes many modules on which a user can get information, some of them are as follows subdomain, Dorking, directory enum, port scanning, acquisition, subdomain takeovers, etc. the main motive of the tool is to reduce time and efforts of the pentesters and give full pakage of tools at one place.


## Installation

```
git clone https://github.com/honeyakshat999/ReconMaster.git
```

After Cloning :

* For `mac` and `linux` :

```
sudo apt-get install -y python3                         #If you already have python3 installed skip this step
chmod +x click.sh                                       #give execution permission
.\click.sh                                              #execute this it will automatically gather all the requirements 
                                                        #and create and activate virtual environment
```

* For `windows` :

```
::go to https://www.python.org/downloads/ or go to microsoft store and download and install python(If you already have python installed skip this step)
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned     #if ExecutionPolicy is setted to restricted(by default) it's like giving execution permission    
.\click.ps1                                             #execute this it will automatically gather all the requirements 
                                                        #and create and activate virtual environment
```

## Usage

Run `reconmaster.py` with arguments as follows :

* `-h` or `--help`             : help regarding reconmaster and list all the accepted parameters
* `-U` or `--url` (required)   : for entering the domain e.g google.com
* `-E` or `--engine`           : for entering the prefered engine(default `all`) e.g bing
* `-S` or `--serveronly`       : for running only server(default `false`)

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

## Current Update

previous version : v1.2.1

current version after update : v1.2.3

what's done in update :

* Added Server Shutdown from UI
* Pages(displaying data in batches) in Historic Data Module
* Minor improvements in UI
* improved logs

## Upcoming Update

The next update is rolling out very soon, **Stay Tuned :)**

What's new in next update :
* Bugfixes
* Improved UI
* Faser Execution than current version(Although it is still fast)
* Probably A New Module


## Update History

version : v1.2.1

* Added Login functionality
* Added dashboard page
* Minor improvements in UI
* Minor improvements in code

**Note :** This tool is made for educational purposes and to help security researchers. Any actions or activities performed using this is solely your responsibility
