# Insteon-Tools

These tools are used to 1) listen for Insteon devices and 2) identify and label any devices based on their device category, if possible.

## Installation instructions:
1) Ensure a working RfCat / YardStick One. See instructions here: http://forum.universal-devices.com/topic/17474-how-to-receive-send-log-spoof-all-insteon-rf-traffic/ 
Or here: https://bitbucket.org/atlas0fd00m/rfcat/overview

2) Ensure Wireshark is latest version (2.0.4.) See Wireshark -> Help -> About Wireshark. Must be compiled with Lua as well. If using an not-quite-updated Ubuntu distro (like 14.04 LTS), follow these instructions: http://ubuntuhandbook.org/index.php/2015/11/install-wireshark-2-0-in-ubuntu-15-10-wily/

3) Now's a good time to download these files. I recommand putting the Insteon-dissector.lua in the /usr/share/wireshark directory. 

4) Find Wireshark's original init.lua file (link in /usr/share/wireshark/ -> /etc/wireshark/init.lua)<br> 
   Either: a) replace it with this init.lua file here or b) add a line at the very end to dofile(<path to Insteon-dissector.lua>).<br>
           
5) Restart Wireshark to ensure no issue with the init.lua and Insteon-dissector configs. Then in Wireshark go to  Edit->Preferences->Protocols->DLT_USER->Edit. Click +, Select User 0 (DLT=147), type "Insteon" in the payload protocol column. If everything has gone well, this box should be green. Click Ok. Ok again.<br>
- If you use another profile, this code will need to be changed to reflect that. The insteondump.py and pcapcreator.py       programs will need to be modified accordingly.

## Running Instructions:
1) For off-line mode, run:<br>
- ./insteondump.py -o \<filename\>  <br>
-- The end product is a filename.pcap with any Insteon traffic that was collected.<br>
-- 2 Additional files are created, filename.raw and filename.insteondump. <br>
-- filename.insteondump can be put into ./insteonanalyzer -i filename.insteondump for network "map" analysis on what     was collected.

2) For live mode:<br>
- mkfifo \<pipename\><br>
- wireshark -i \<pipename\> and start listening on the pipe once wireshark starts.<br>
- ./insteondump.py -l -p \<pipename\><br>
- Wait for some traffic (don't kill the pipe or Wireshark just yet)<br>
- In a second terminal, run: ./isnteonscanner -i 1 (requires a 2nd YardStick to be plugged in). <br>
-- This program reads device IDs saved in insteon.devices file, then spoofs ping and ID request from each devices to every other device. ID request responses contain the device category from the responder.

