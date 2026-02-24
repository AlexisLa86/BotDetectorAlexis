# BotDetectorAlexis
This is my bot detector showcase which does a few things. 1. It parses through a log file and collects a number of data points 2. It classifies certain recurring IPs based on suspicious behaviour.

I wanted to make a mock dashboard simulating how it might look when a website or service comes under attack from a hihgly distributed botnet. The actual log file has been made to reflect that as you see a high number of uniquie IPs, I´ll get into it more below.

Functionality:
Regex is the backbone parsing the data from our logs into different dictionaries

Behavioral Threat Detection:I chose a couple of parameters, looking at specific behavioural patterns some stand out such as ips trying to acccess wordpress login pages which may indicate malicious behaviour as directly acessing these is out of the norm for a regular user. Robots.txt is of course fine as this is simply SOP for a web crawler but patterns of attempts to access ['wp-login.php', '.env', 'admin', 'config'] were logged as suspicious.

Time signature: To further describe the attack pattern the peak access times are shown using 404 by the hour which has one major drawback, it could simply coincide with maintenance or a legitimate higher user count perhaps connected to a campaign, these are things to be taken into account but what this data could show is that during regular office hours there is a lull with bots then peaking at 21:00. I believe this may indicate a system of red flagging to avoid detection of higher CPU strains peak business hours which would then be flagged, this indicates a botnet running on, lets say a network of work desktops. 

 I´ve also added some information regarding the top targets, obviously very handy as the next logical step is "why are we being targeted here?".
