#README File

This python script was written when working with on a Federal project where the customer did not  have access 
to their FGTs and we had to migrate a Check Point R80 environment into a FMG instance to then be pushed down to the managed FGTs.

At the time the FortiConverter tool did not fully support converting R80, however there were tools available 
in Check Point to export to spreadsheets.
Spreadsheets were then produced from the Check Point environment and then exported as TAB delimited format.

This python script was then used to read the .txt TAB delimited spreadsheets for different functions:
A list of functions are listed below:

The following options are available:
1 - Import address objects from Excel Spreadsheet.  Spreadsheet name:  address-objects.txt
2 - Import host objects from Excel Spreadsheet.  Spreadsheet name:   host-objects.txt
3 - Import IP Range Address objects from Excel Spreadsheet.  Spreadsheet name:   iprange.txt
4 - Import service objects from Excel Spreadsheet.  Spreadsheet name:   service-objects.txt
5 - Import address group objects from Excel Spreadsheet.  Spreadsheet name:   addrgrp.txt
6 - Import service group objects from Excel Spreadsheet.  Spreadsheet name:   servicegrp.txt
7 - Import VIP objects from Excel Spreadsheet.  Spreadsheet name:   vip.txt
8 - Import IPPool objects from Excel Spreadsheet.  Spreadsheet name:   ippool.txt
9 - Import Policy Rules from Excel Spreadsheet.  Does NOT apply NAT/IPPool. Spreadsheet name:   rulebase.txt
10 - Apply NAT/IPPools from Excel Spreadsheet. NOTE - Uses spreadsheet from Option 9. Spreadsheet name:   rulebase.txt
11 - Assign Existing Security Profiles to Existing Policy Rules. Spreadsheet name:   securityprofile-rules.txt


NOTE:  Its important to note that this python script supports Workspace Mode Locking, given that the customer's environment
was enabled with that feature.

This python script was written to be modular and can be added onto and enhanced with further functions.
i.e SDWAN deployments, etc.
That being said, its important for the users of the script to recognize that order of operation is important
and is something that must be taken into consideration.
This is an automation tool and was written to ease the process of a conversion/migration where spreadsheets could be utilized.
Note the spreadsheets are given above and must be in the same folder as the python script.
They also must be saved as TAB delimited.
NOTE:  Also the script currently supports FMG 6.0.x and will need to be modified to support more recent versions of FMG.

A video is supplied in the folder as well to go over the operation.

Written by:
John Mark Kellerman
Sept 2019
