# Insteon-Tools

These tools are used to 1) listen for Insteon devices and 2) identify and label any devices based on their device category, if possible.

## Installation instructions:
1) Ensure a working RfCat / YardStick One. See instructions here: http://forum.universal-devices.com/topic/17474-how-to-receive-send-log-spoof-all-insteon-rf-traffic/ 
Or here: https://bitbucket.org/atlas0fd00m/rfcat/overview

2) Ensure Wireshark is latest version (2.0.4.) See Wireshark -> Help -> About Wireshark. Must be compiled with Lua as well. If using an not-quite-updated Ubuntu distro (like 14.04 LTS), follow these instructions: http://ubuntuhandbook.org/index.php/2015/11/install-wireshark-2-0-in-ubuntu-15-10-wily/

3) Once Wireshark is updated, I recommand putting the Insteon-dissector.lua in the /usr/share/wireshark directory. 

4) Find the init.lua file (link in /usr/share/wireshark/ -> /etc/wireshark/init.lua 
   Either: a) replace it with the file here or 
           b) add a line at the very end to dofile(<path to Insteon-dissector.lua>).
           
5) Restart Wireshark to ensure no issue with the init.lua and Insteon-dissector configs. Will need configure a user defined protocol. In Wireshark go to  Edit->Preferences->Protocols->DLT_USER->Edit. Click +, Select User 0 (DLT=147), type "Insteon" in the payload protocol column. If everything has gone well, this box should be green. Click Ok. Ok again.

## Running Instructions:
1) For off-line mode, run:
     - ./insteondump.py -o <filename>  
The end product is a filename.pcap with any Insteon traffic that was collected.
2 Additional files are created, filename.raw and filename.insteondump. filename.insteondump can be put into
./insteonanalyzer -i filename.insteondump for network "map" analysis on what was collected.

2) For livemode:<br>
     - mkfifo <pipename><br>
     - wireshark -i <pipename><br>
     - ./insteondump.py -l -p <pipename><br>
     - Wait for some traffic (don't kill the pipe or Wireshark just yet)<br>
     - In a second terminal, run: ./isnteonscanner -i 1 (requires a 2nd YardStick to be plugged in). <br>
        -- This program reads device IDs saved in insteon.devices file, then spoofs ping and ID request from each devices     to every other device. ID request responses contain the device category from the responder.

