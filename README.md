# lazy_nessus
If you deal with PCI or have a need to extract periodically scheduled scan report from nessus, then this tool can do this for you while you can focus on other things rather than clicking on same UI every time. You need to manually edit the sites variable as per your need. This is not a complete nessus parser but a decent effort to automate your boring task.


# How to use
lazy_nessus.py [URL:PORT] [Username] [Password]

Lazy_nessus takes 3 arguments by default:
1- URL to nessus login page
2- Username 
3- Password 

Example:

lazy_nessus.py https://127.0.0.1:8834 admin password

NOTE: Please read the comments in code before using it, you might need to curate it as per your environment.
# Requirements
python3
