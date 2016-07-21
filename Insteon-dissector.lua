--script-name: Insteon-dissctor.lua
-- author: mays85
----------------------------------------
-- creates a Proto object, but doesn't register it yet
local insteon = Proto("Insteon","Insteon")

-- start declaring some fields.
-- first, the flags.
local pf_flags              = ProtoField.new   ("Flags", "insteon.flags", ftypes.UINT8, nil, base.HEX)

local pf_flag_broadcast		= ProtoField.new   ("Broadcast/NAK", "insteon.flags.broadcast", ftypes.BOOLEAN, 
	{"this is a broadcast","this is not a broadcast"}, 8, 0x80, "is this a broadcast?")

local pf_flag_group			= ProtoField.new   ("Group/Not-Group", "insteon.flags.group", ftypes.BOOLEAN, 
	{"this is a group message", "this is not a group message"}, 8, 0x40, "is this a group msg?")

local pf_flag_acknowledge	= ProtoField.new   ("Acknowledge", "insteon.flags.acknowledge", ftypes.BOOLEAN, 
	{"acknowledgement", "not an acknowledgement"}, 8, 0x20, "is this an acknowledgement?")

local pf_flag_extended		= ProtoField.new   ("Message Type", "insteon.flags.extended", ftypes.BOOLEAN, 
	{"Extended Message", "Standard Message"}, 8, 0x10, "is this a standard messsage or extended messages?")

local pf_flag_hopsleft		= ProtoField.new   ("Hops Left", "insteon.flags.hopsleft", ftypes.UINT8, 
	nil, base.DEC, 0x0C, "hops left")

local pf_flag_maxhops		= ProtoField.new   ("Max Hops", "insteon.flags.hopsleft", ftypes.UINT8, 
	nil, base.DEC, 0x03, "max hops")

-- now the other parts of the message.
local pf_src_addr			= ProtoField.new   ("Source", "insteon.source", ftypes.BYTES, nil, base.NONE) -- consider making these bytes into strings
local pf_dst_addr			= ProtoField.new   ("Destination", "insteon.destination", ftypes.BYTES, nil, base.NONE) -- consider making these bytes into strings
local pf_cmd1				= ProtoField.new   ("Command 1", "insteon.cmd1", ftypes.BYTES, nil, base.NONE)
local pf_cmd2				= ProtoField.new   ("Command 2", "insteon.cmd2", ftypes.BYTES, nil, base.NONE)
local pf_crc				= ProtoField.new   ("CRC", "insteon.crc", ftypes.BYTES, nil, base.NONE)

-- this one is only used for extended messages.
local pf_usr_data			= ProtoField.new   ("Data", "insteon.data", ftypes.BYTES, nil, base.NONE)

-- a few others for special things:
local pf_firmware			= ProtoField.new   ("Firwmware", "insteon.firmware", ftypes.BYTES, nil, base.NONE)
local pf_devType			= ProtoField.new   ("Device Type", "insteon.device_type", ftypes.BYTES, nil, base.NONE)
local pf_devSubType			= ProtoField.new   ("Device Subtype", "insteon.device_subtype", ftypes.BYTES, nil, base.NONE)

-- must explicitly tell the insteon.fields what all of tis' fields are.
insteon.fields = {pf_flags, pf_flag_broadcast, pf_flag_group, 
					pf_flag_acknowledge, pf_flag_extended, 
					pf_flag_hopsleft, pf_flag_maxhops, pf_src_addr, 
					pf_dst_addr, pf_cmd1, pf_cmd2, pf_crc, pf_usr_data, pf_firmware, pf_devType, pf_devSubType}

					
-- time to get some "fields". This allows me to do different
-- things based on the flags, etc.
local broadcast_field       = Field.new("insteon.flags.broadcast")
local group_field     		= Field.new("insteon.flags.group")
local acknowledgement_field	= Field.new("insteon.flags.acknowledge")
local extended_field		= Field.new("insteon.flags.extended")

-- some helper functions to get those fields.
local function isBroadcast() return broadcast_field()() end
local function isGroupMsg() return group_field()() end
local function isAcknowledgement() return acknowledgement_field()() end
local function isExtended() return extended_field()() end


-- this is basically like the main() of the program.
function insteon.dissector(tvbuf,pktinfo,root)
	pktinfo.cols.protocol:set("Insteon")
	
	local pktlen = tvbuf:reported_length_remaining()
	local tree = root:add(insteon, tvbuf:range(0, pktlen))
	
	-- flag information tree.
	local flagrange = tvbuf:range(0,1)
	local flag_tree = tree:add(pf_flags, flagrange)
		
		local firstbit_flag_tree = flag_tree:add(pf_flag_broadcast, flagrange)
		local secondbit_flag_tree = flag_tree:add(pf_flag_group, flagrange)
		local thirdbit_flag_tree = flag_tree:add(pf_flag_acknowledge, flagrange)
		local fourth_flag_tree = flag_tree:add(pf_flag_extended, flagrange)
		local fifthsixth_flag_tree = flag_tree:add(pf_flag_hopsleft, flagrange)
		local seveneight_flag_tree = flag_tree:add(pf_flag_maxhops, flagrange)
			
	
	-- need to do some different things if it's a broadcast_field, a group_field, etc.
	
	-- 0x000 -- Direct Message
	if not isBroadcast() and not isGroupMsg() and not isAcknowledgement() then
		tree:add(pf_dst_addr, tvbuf:range(1,3))
		local destination_address = tvbuf:range(1, 3)
		tree:add(pf_src_addr, tvbuf:range(4,3))
		local source_address = tvbuf:range(4, 3)
		pktinfo.cols.src:set(tostring(source_address)) -- sets the src column
		pktinfo.cols.dst:set(tostring(destination_address)) -- sets the destination column
		pktinfo.cols.info:set("Direct Message") -- sets the information column.
		
	-- 0x001 -- Acknowledgement message
	elseif not isBroadcast() and not isGroupMsg() and isAcknowledgement() then
		tree:add(pf_dst_addr, tvbuf:range(1,3))
		local destination_address = tvbuf:range(1, 3)
		tree:add(pf_src_addr, tvbuf:range(4,3))
		local source_address = tvbuf:range(4, 3)
		pktinfo.cols.src:set(tostring(source_address)) -- sets the src column
		pktinfo.cols.dst:set(tostring(destination_address)) -- sets the destination column
		pktinfo.cols.info:set("Acknowledgement of Direct Message")
	
	-- 0x010
	elseif not isBroadcast() and isGroupMsg() and not isAcknowledgement() then
		tree:add(pf_dst_addr, tvbuf:range(1,3))
		local destination_address = tvbuf:range(1, 3)
		tree:add(pf_src_addr, tvbuf:range(4,3))
		local source_address = tvbuf:range(4, 3)
		pktinfo.cols.src:set(tostring(source_address)) -- sets the src column
		pktinfo.cols.dst:set(tostring(destination_address)) -- sets the destination column
		pktinfo.cols.info:set("Group Cleanup Direct Message")
				
	-- 0x011
	elseif not isBroadcast() and isGroupMsg() and isAcknowledgement() then
		tree:add(pf_dst_addr, tvbuf:range(1,3))
		local destination_address = tvbuf:range(1, 3)
		tree:add(pf_src_addr, tvbuf:range(4,3))
		local source_address = tvbuf:range(4, 3)
		pktinfo.cols.src:set(tostring(source_address)) -- sets the src column
		pktinfo.cols.dst:set(tostring(destination_address)) -- sets the destination column
		pktinfo.cols.info:set("ACK of Group Cleanup Direct Message")
		
		
	-- 0x100 -- Broadcasts include device category, subcategory and firmware
	elseif isBroadcast() and not isGroupMsg() and not isAcknowledgement() then
		pktinfo.cols.info:set("Broadcast Message")
		tree:add(pf_src_addr, tvbuf:range(1,3))
		local source_address = tvbuf:range(1, 3)
		pktinfo.cols.src:set(tostring(source_address)) -- sets the src column
		-- get firmware
		tree:add(pf_firmware, tvbuf:range(4,1))
		local firmware = tvbuf:range(4, 1)

		-- get device sub type
		tree:add(pf_devSubType, tvbuf:range(5,1))
		local subType = tvbuf:range(5, 1)

		-- get device type
		tree:add(pf_devType, tvbuf:range(6,1))
		local subType = tvbuf:range(6, 1)

		-- too weird to put this info in the dest column. tell user to look at the info pane.
		pktinfo.cols.dst:set("Firmware & Dev Type") -- sets the destination column

	-- 0x101
	elseif isBroadcast() and not isGroupMsg() and isAcknowledgement() then
		tree:add(pf_dst_addr, tvbuf:range(1,3))
		local destination_address = tvbuf:range(1, 3)
		tree:add(pf_src_addr, tvbuf:range(4,3))
		local source_address = tvbuf:range(4, 3)
		pktinfo.cols.src:set(tostring(source_address)) -- sets the src column
		pktinfo.cols.dst:set(tostring(destination_address)) -- sets the destination column
		pktinfo.cols.info:set("NAK of Direct Message")
		
		
	-- 0x110
	elseif isBroadcast and isGroupMsg and not isAcknowledgement() then
		tree:add(pf_src_addr, tvbuf:range(1,3))
		local source_address = tvbuf:range(1, 3)
		--For Group Broadcast messages Destination Address is:
			--Group Number [0 - 255]
		tree:add(pf_dst_addr, tvbuf:range(4,1))
		local destination_address = tvbuf:range(4, 1)
		pktinfo.cols.src:set(tostring(source_address)) -- sets the src column
		pktinfo.cols.dst:set(tostring("Group: "..destination_address)) -- sets the destination column
		pktinfo.cols.info:set("Group Broadcast Message")
		

		
	-- 0x111
	elseif isBroadcast() and isGroupMsg() and isAcknowledgement() then
		tree:add(pf_dst_addr, tvbuf:range(1,3))
		local destination_address = tvbuf:range(1, 3)
		tree:add(pf_src_addr, tvbuf:range(4,3))
		local source_address = tvbuf:range(4, 3)
		pktinfo.cols.src:set(tostring(source_address)) -- sets the src column
		pktinfo.cols.dst:set(tostring(destination_address)) -- sets the destination column
		pktinfo.cols.info:set("NAK of Group Cleanup Direct Message")	
	end
		

	-- command 1 is 1 byte
	tree:add(pf_cmd1, tvbuf:range(7,1))
	local command1 = tvbuf:range(7, 1)
	
	-- command 2 is 1 byte
	tree:add(pf_cmd2, tvbuf:range(8,1))
	local destination_address = tvbuf:range(8,1)
	
	-- if not extended then 1 byte CRC
	if not isExtended() then	
		tree:add(pf_crc, tvbuf:range(9,1))
		local CRC = tvbuf:range(9,1)
		-- TODO: consider adding into the info portion the fact that it is an extended message.
	-- otherwise, extended data contains 14 bytes user data.
	else
		tree:add(pf_usr_data, tvbuf:range(9,14))
		local user_data = tvbuf:range(9,14)
		-- meaning the CRC is the 23rd (24th) byte.
		tree:add(pf_crc, tvbuf:range(23,1))
		local CRC = tvbuf:range(23,1)
	end
end