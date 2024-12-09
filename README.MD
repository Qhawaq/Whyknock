*** WHYKNOCK 

A Serviceless port-knocking based on nft tables filter with non deterministic knocking schema.


CREDITS 

This script is based on a previous work made by many authors and communities, in this case 
you can recover the original work here: https://tamiko.43-1.org/developer/portknock.ruleset
and here: https://wiki.nftables.org/wiki-nftables/index.php/Port_knocking_example

These credits are 


WHAT IS IT PROGRAM FOR ?

This program ( script ) creates a set of nft tables rules, in a selectable default directory, to implement 
a new, non deterministic, firewall-knocking schema. 

These rules creates a 'filter' with an high priorty respect to standard firewall filtering like iptables
and for this reason the new filter is completely hide to those who use standard firewall frameworks.
It acts before standard firewall frameworks and leaves them to operate as before.


WHAT IS MEANT BY "SERVICELESS" ?

From literature, all software for firewall-knocking uses a separate "service" ( or "knocking server") which receive, behind the firewall, the packets forming the knock
sequence and, when the sequence is valid, it opens the standard firewall used injecting a new rule in it.

But if service software fails for any reason, an aftermath it will lock out all access attempt also if you are a remote legal user who sent right koncking sequence.

In our case, THERE IS NO separate service to run ! All magic is made by nft table, so you have nothing to "launch as service" the only thing
you will do will be load the rules file ( .nft ) using the command nft. So you have not to fight with service startups sequence, complicated setups, and 
you don't worry about the unexpected service block and its consequences.  

WHAT IS MEANT BY "NON DTERMINISTIC" ?

The "firewall knocking" idea is non new at all, many declinations of this idea, during paste years, was produced
and all of them function in a correct way ( think to the famous "knockd" ecc ... ). 

But all of them  have in common one weak point: As first thing you will be forced to establish the exact series and timing of ports to be knocked,
when done, this sequence will be fixed and always remain the same. This fixed schema, can be understand by a mailicious hacker who can try to hack   
the rest of knocking mechanism used. 

In this new, "non deterministic", mode THERE IS NO fixed ports schema , ports are chosen at random at every knocking packet send to target.

Of course, also this mechanism can be hacked, but some other countermeasures are kept to foolish an attacker:
every knocking packet contains a key in a random position in the payload space of packet, so the attacker needs not also to know only the ports, 
but it also must know the keys and their exact relative position in payload, things that varying at every packet send to targt host.


HOW WE USE THIS SOFTWARE ?

The thing is ridicolus simple . 

The only thing you need is a valid python 3.x installation ( or also a venv ) in your machine, 
once you have downloaded this repository, you must install additional python packages contained in 'requirements.txt' file.
Then you can launch the script as usual using the command 'python3 whiknock.py' or, if you are using Linux, 
you can set the execute flag of the script with command 'chmod 755 whiknock.py' and after simply inovke 
'myknock.py' to run it. 

Stop ( :) )


WHAT HAPPENS WHEN THIS SCRIPT RUNS ?

1] The script search for IP address or DNS Name in its .ini file.

2a] If found a valid profile for the host specified as IP/DNS in the .ini file, it extracts 
   key informations and number of packet to be used to knocking the hosa and send to it the knock sequence to host and end.
   If you try to connect the specified host (e.g. with ssh ) you should be have a 'green light' by target host nft and can work with it. 

2b] If NOT FOUND a valid profile, the script prompt you if you desire to create a new profile for the host specified by IP address or DNS name that
you have passed as command line parameter. If you say "Yes", the script prompts you, about the number of keys (packets to send) it must create for that host

3] The script creates a file in a separate directory a file named as <IP address>.nft or <DNS Name>.nft and ends normally

4] Now, you must copy the file made in pass 3 in the target host specified.
When done you are ready to install the filter using the 'nft' command ( Usually 'nft -f <filename.nft>' ).
Pay attention, please,  when you load it the filter starts immediately !

WHAT ABOUT PASSOWRD COMMAND LINE PARAMETER, WHY IT HAS A 'DEFAULT' IN SCRIPT  ?

The PASSWORD parameter accepts a 32 char ( bytes ) to use as encryption password to protects the "per host" recorded keys in .ini file
As you can note , a 32 chars password it not so simply to remember so a default is provided in the code of script in order to avoid that 
you don't take care of this protection, for bother or lazyness, and leave keys unprotected into files ... 
SO YOU ARE WARMLY INVITED TO CHANGE DEFAULT PASSWORD IN CODE WRITTEN AT LINE 26 ( DFL_PWD ) !!!!!! 

OF COURSE IS MUCH BETTER YOU USE A DIFFERENT PASSWORD FOR EACH HOST PROFILE YOU CONFIGURE !!! 
this can be done when invoke the script using '-P' parameters. If you don't use it the default password
wil be used.
ARE YOU WARNED ABOUT THIS !!!


COMMAND LINE PARAMETERS:

We have only one required parameter that is the IP address or DNS name of the target host ( the host that will be "knocked" ),
all other parameters are optional.









