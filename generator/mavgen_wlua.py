#!/usr/bin/env python
'''
parse a MAVLink protocol XML file and generate a Wireshark LUA dissector

Copyright Holger Steinhaus 2012
Released under GNU GPL version 3 or later

Instructions for use: 
1. python -m pymavlink.tools.mavgen --lang=WLua mymavlink.xml -o ~/.wireshark/plugins/mymavlink.lua
2. convert binary stream int .pcap file format (see ../examples/mav2pcap.py)
3. open the pcap file in Wireshark
'''
from __future__ import print_function

from builtins import range

import os
import re
from . import mavparse, mavtemplate

t = mavtemplate.MAVTemplate()


def type_size(mavlink_type):
    # infer size of mavlink types
    re_int = re.compile('^(u?)int(8|16|32|64)_t$')
    int_parts = re_int.findall(mavlink_type)
    if len(int_parts):
        return (int(int_parts[0][1]) // 8)
    elif mavlink_type == 'float':
        return 4
    elif mavlink_type == 'double':
        return 8
    elif mavlink_type == 'char':
        return 1
    else:
        raise Exception('unsupported MAVLink type - please fix me')


def get_field_info(field):
    mavlink_type = field.type
    size = type_size(mavlink_type)
    count = field.array_length if field.array_length > 0 else 1

    if mavlink_type == "char":
        # char (string) types
        field_type = "ftypes.STRING"
        tvb_func = "string"
        size = count
        count = 1
    elif "int" in mavlink_type:
        # (u)int types
        field_type = "ftypes." + mavlink_type.replace("_t", "").upper()
        tvb_func = "le_" + ("u" if "u" in mavlink_type else "") + "int" + ("64" if "64" in mavlink_type else "")
    elif field.enum:
        # enum types in float/double fields (these will come up at least with command params)
        field_type = "ftypes.UINT32"
        tvb_func = "le_" + mavlink_type
    else:
        # float/double
        field_type = "ftypes." + mavlink_type.upper()
        tvb_func = "le_" + mavlink_type

    return mavlink_type, field_type, tvb_func, size, count


def generate_preamble(outf):
    print("Generating preamble")
    t.write(outf, 
"""
-- Wireshark dissector for the MAVLink protocol (please see http://qgroundcontrol.org/mavlink/start for details) 

unknownFrameBeginOffset = 0
local bit = require "bit32"
mavlink_proto = Proto("mavlink_proto", "MAVLink protocol")
f = mavlink_proto.fields

-- from http://lua-users.org/wiki/TimeZone
local function get_timezone()
    local now = os.time()
    return os.difftime(now, os.time(os.date("!*t", now)))
end
local signature_time_ref = get_timezone() + os.time{year=2015, month=1, day=1, hour=0}

payload_fns = {}

protocolVersions = {
    [0xfd] = "MAVLink 2.0",
    [0xfe] = "MAVLink 1.0",
    [0x55] = "MAVLink 0.9"
}

""" )
    
    
def generate_body_fields(outf):
    t.write(outf, 
"""
f.magic = ProtoField.uint8("mavlink_proto.magic", "Magic value / version", base.HEX, protocolVersions)
f.length = ProtoField.uint8("mavlink_proto.length", "Payload length")
f.incompatibility_flag = ProtoField.uint8("mavlink_proto.incompatibility_flag", "Incompatibility flag")
f.compatibility_flag = ProtoField.uint8("mavlink_proto.compatibility_flag", "Compatibility flag")
f.sequence = ProtoField.uint8("mavlink_proto.sequence", "Packet sequence")
f.sysid = ProtoField.uint8("mavlink_proto.sysid", "System id", base.HEX)
f.compid = ProtoField.uint8("mavlink_proto.compid", "Component id", base.HEX)
f.msgid = ProtoField.uint24("mavlink_proto.msgid", "Message id", base.DEC, messageName)
f.payload = ProtoField.uint8("mavlink_proto.payload", "Payload", base.DEC, messageName)
f.crc = ProtoField.uint16("mavlink_proto.crc", "Message CRC", base.HEX)
f.signature_link = ProtoField.uint8("mavlink_proto.signature_link", "Link id", base.DEC)
f.signature_time = ProtoField.absolute_time("mavlink_proto.signature_time", "Time")
f.signature_signature = ProtoField.bytes("mavlink_proto.signature_signature", "Signature")
f.rawheader = ProtoField.bytes("mavlink_proto.rawheader", "Unparsable header fragment")
f.rawpayload = ProtoField.bytes("mavlink_proto.rawpayload", "Unparsable payload")

""")


def generate_msg_table(outf, msgs):
    t.write(outf, """
messageName = {
""")
    for msg in msgs:
        assert isinstance(msg, mavparse.MAVType)
        t.write(outf, """
    [${msgid}] = '${msgname}',
""", {'msgid':msg.id, 'msgname':msg.name})

    t.write(outf, """
}

""")


def generate_enum_table(outf, enums):
    t.write(outf, """
enumEntryName = {
""")
    for enum in enums:
        assert isinstance(enum, mavparse.MAVEnum)
        t.write(outf, """
    ["${enumname}"] = {
""", {'enumname': enum.name})

        for entry in enum.entry:
            t.write(outf, """
        [${entryvalue}] = "${entryname}",
""", {'entryvalue': entry.value, 'entryname': entry.name})

        t.write(outf, """
    },
""")

    t.write(outf, """
}
""")


def generate_msg_fields(outf, msg):
    assert isinstance(msg, mavparse.MAVType)
    for f in msg.fields:
        assert isinstance(f, mavparse.MAVField)
        mavlink_type, field_type, _, _, count = get_field_info(f)
        values = "enumEntryName. " + f.enum if f.enum else "nil"
        
        for i in range(0,count):
            if count>1: 
                array_text = '[' + str(i) + ']'
                index_text = '_' + str(i)
            else:
                array_text = ''
                index_text = ''
                
            t.write(outf,
"""
f.${fmsg}_${fname}${findex} = ProtoField.new("${fname}${farray} (${ftypename})", "mavlink_proto.${fmsg}_${fname}${findex}", ${ftype}, ${fvalues})
""", {'fmsg':msg.name, 'ftype':field_type, 'ftypename': mavlink_type, 'fname':f.name, 'findex':index_text, 'farray':array_text, 'fvalues':values})

    t.write(outf, '\n\n')

def generate_field_dissector(outf, msg, field, offset):
    assert isinstance(field, mavparse.MAVField)
    
    _, _, tvb_func, size, count = get_field_info(field)
    
    # handle arrays, but not strings
    
    for i in range(0,count):
        if count>1: 
            index_text = '_' + str(i)
        else:
            index_text = ''
        t.write(outf,
"""
    field_offset = offset + ${foffset}
    if (field_offset + ${fbytes} <= limit) then
        tree:add_le(f.${fmsg}_${fname}${findex}, buffer(field_offset, ${fbytes}), buffer(field_offset, ${fbytes}):${ftvbfunc}())
    elseif (field_offset < limit) then
        tree:add_le(f.${fmsg}_${fname}${findex}, buffer(field_offset, limit - offset - ${foffset}), padded(field_offset, ${fbytes}):${ftvbfunc}())
    else
        tree:add_le(f.${fmsg}_${fname}${findex}, padded(field_offset, ${fbytes}):${ftvbfunc}())
    end
""", {'fname':field.name, 'fmsg': msg.name, 'foffset':offset, 'fbytes':size, 'findex':index_text, 'ftvbfunc':tvb_func})
    

def generate_payload_dissector(outf, msg):
    assert isinstance(msg, mavparse.MAVType)

    total_size = 0
    offsets = {}
    for f in msg.ordered_fields:
        _, _, _, size, count = get_field_info(f)
        offsets[f.name] = total_size
        total_size += size * count

    t.write(outf, 
"""
-- dissect payload of message type ${msgname}
function payload_fns.payload_${msgid}(buffer, tree, msgid, offset, limit, pinfo)
    local padded, field_offset
    if (offset + ${msgbytes} > limit) then
        padded = buffer(0, limit):bytes()
        padded:set_size(offset + ${msgbytes})
        padded = padded:tvb("Untruncated payload")
    end
""", {'msgid':msg.id, 'msgname':msg.name, 'msgbytes': total_size})

    # parse command name if applicable
    if msg.name in ("COMMAND_INT", "COMMAND_LONG", "COMMAND_ACK", "COMMAND_CANCEL") and "command" in offsets:
        t.write(outf,
"""
    if enumEntryName.MAV_CMD ~= nil then
        cmdid = padded(offset + ${foffset}, 2):le_uint()
        cmdname = enumEntryName.MAV_CMD[cmdid]
        if cmdname ~= nil then
            pinfo.cols.info:append(": " .. cmdname)
        end
    end
""", {'foffset': offsets["command"]})
    
    for f in msg.fields:
        generate_field_dissector(outf, msg, f, offsets[f.name])

    t.write(outf, 
"""
    return offset
end


""")
    

def generate_packet_dis(outf):
    t.write(outf, 
"""
-- dissector function
function mavlink_proto.dissector(buffer,pinfo,tree)
    local offset = 0
    local msgCount = 0
    
    -- loop through the buffer to extract all the messages in the buffer
    while (offset < buffer:len()) 
    do
        msgCount = msgCount + 1
        local subtree = tree:add (mavlink_proto, buffer(), "MAVLink Protocol ("..buffer:len()..")")

        -- decode protocol version first
        local version = buffer(offset,1):uint()
        local protocolString = ""
    
    	while (true)
		do
            protocolString = protocolVersions[version]
            if (protocolString ~= nil) then
                break
            else
                protocolString = "unknown"
                -- some unknown data found, record the begin offset
                if (unknownFrameBeginOffset == 0) then
                    unknownFrameBeginOffset = offset
                end
               
                offset = offset + 1
                
                if (offset < buffer:len()) then
                    version = buffer(offset,1):uint()
                else
                    -- no magic value found in the whole buffer. print the raw data and exit
                    if (unknownFrameBeginOffset ~= 0) then
                        if (msgCount == 1) then
                            pinfo.cols.info:set("Unknown message")
                        else
                            pinfo.cols.info:append("  Unknown message")
                        end
                        size = offset - unknownFrameBeginOffset
                        subtree:add(f.rawpayload, buffer(unknownFrameBeginOffset,size))
                        unknownFrameBeginOffset = 0
                    end
                    return
                end
            end	
        end
        
        if (unknownFrameBeginOffset ~= 0) then
            pinfo.cols.info:append("Unknown message")
            size = offset - unknownFrameBeginOffset
            subtree:add(f.rawpayload, buffer(unknownFrameBeginOffset,size))
            unknownFrameBeginOffset = 0
            -- jump to next loop
            break
        end
        
        -- some Wireshark decoration
        pinfo.cols.protocol = protocolString

        -- HEADER ----------------------------------------
    
        local msgid
        local length
        local incompatibility_flag

        if (version == 0xfe) then
            if (buffer:len() - 2 - offset > 6) then
                -- normal header
                local header = subtree:add(buffer(offset, 6), "Header")
                header:add(f.magic, buffer(offset,1), version)
                offset = offset + 1
            
                length = buffer(offset,1)
                header:add(f.length, length)
                offset = offset + 1
            
                local sequence = buffer(offset,1)
                header:add(f.sequence, sequence)
                offset = offset + 1
            
                local sysid = buffer(offset,1)
                header:add(f.sysid, sysid)
                offset = offset + 1
        
                local compid = buffer(offset,1)
                header:add(f.compid, compid)
                offset = offset + 1
            
                pinfo.cols.src = "System: "..tostring(sysid:uint())..', Component: '..tostring(compid:uint())
        
                msgid = buffer(offset,1):uint()
                header:add(f.msgid, buffer(offset,1), msgid)
                offset = offset + 1
            else 
                -- handle truncated header
                local hsize = buffer:len() - 2 - offset
                subtree:add(f.rawheader, buffer(offset, hsize))
                offset = offset + hsize
            end
        elseif (version == 0xfd) then
            if (buffer:len() - 2 - offset > 10) then
                -- normal header
                local header = subtree:add(buffer(offset, 10), "Header")
                header:add(f.magic, buffer(offset,1), version)
                offset = offset + 1
                length = buffer(offset,1)
                header:add(f.length, length)
                offset = offset + 1
                incompatibility_flag = buffer(offset,1):uint()
                header:add(f.incompatibility_flag, buffer(offset,1), incompatibility_flag)
                offset = offset + 1
                local compatibility_flag = buffer(offset,1)
                header:add(f.compatibility_flag, compatibility_flag)
                offset = offset + 1
                local sequence = buffer(offset,1)
                header:add(f.sequence, sequence)
                offset = offset + 1
                local sysid = buffer(offset,1)
                header:add(f.sysid, sysid)
                offset = offset + 1
                local compid = buffer(offset,1)
                header:add(f.compid, compid)
                offset = offset + 1
                pinfo.cols.src = "System: "..tostring(sysid:uint())..', Component: '..tostring(compid:uint())
                msgid = buffer(offset,3):le_uint()
                header:add(f.msgid, buffer(offset,3), msgid)
                offset = offset + 3
            else 
                -- handle truncated header
                local hsize = buffer:len() - 2 - offset
                subtree:add(f.rawheader, buffer(offset, hsize))
                offset = offset + hsize
            end
        end


        -- BODY ----------------------------------------
    
        -- dynamically call the type-specific payload dissector    
        local msgnr = msgid
        local dissect_payload_fn = "payload_"..tostring(msgnr)
        local fn = payload_fns[dissect_payload_fn]
        local limit = buffer:len() - 2

        if (length) then
            length = length:uint()
        else
            length = 0
        end

        if (offset + length < limit) then
            limit = offset + length
        end
    
        if (fn == nil) then
            pinfo.cols.info:append ("Unknown message type   ")
            subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Unknown message type")
            size = buffer:len() - 2 - offset
            subtree:add(f.rawpayload, buffer(offset,size))
            offset = offset + size
        else
            local payload = subtree:add(f.payload, buffer(offset, limit - offset), msgid)
            pinfo.cols.dst:set(messageName[msgid])
            if (msgCount == 1) then
            -- first message should over write the TCP/UDP info
                pinfo.cols.info = messageName[msgid]
            else
                pinfo.cols.info:append("   "..messageName[msgid])
            end
            fn(buffer, payload, msgid, offset, limit, pinfo)
            offset = limit
        end

        -- CRC ----------------------------------------

        local crc = buffer(offset,2)
        subtree:add_le(f.crc, crc)
        offset = offset + 2

        -- SIGNATURE ----------------------------------

        if (version == 0xfd and incompatibility_flag == 0x01) then
            local signature = subtree:add("Signature")

            local link = buffer(offset,1)
            signature:add(f.signature_link, link)
            offset = offset + 1

            local signature_time = buffer(offset,6):le_uint64()
            local time_secs = signature_time / 100000
            local time_nsecs = (signature_time - (time_secs * 100000)) * 10000
            signature:add(f.signature_time, buffer(offset,6), NSTime.new(signature_time_ref + time_secs:tonumber(), time_nsecs:tonumber()))
            offset = offset + 6

            local signature_signature = buffer(offset,6)
            signature:add(f.signature_signature, signature_signature)
            offset = offset + 6
        end

    end
end


""")
    


def generate_epilog(outf):
    print("Generating epilog")
    t.write(outf, 
"""   
-- bind protocol dissector to USER0 linktype

wtap_encap = DissectorTable.get("wtap_encap")
wtap_encap:add(wtap.USER0, mavlink_proto)

-- bind protocol dissector to port 14550 and 14580

local udp_dissector_table = DissectorTable.get("udp.port")
udp_dissector_table:add(14550, mavlink_proto)
udp_dissector_table:add(14580, mavlink_proto)
""")

def generate(basename, xml):
    '''generate complete lua implemenation'''
    if basename.endswith('.lua'):
        filename = basename
    else:
        filename = basename + '.lua'

    msgs = []
    enums = []
    filelist = []
    for x in xml:
        msgs.extend(x.message)
        enums.extend(x.enum)
        filelist.append(os.path.basename(x.filename))

    for m in msgs:
        m.order_map = [ 0 ] * len(m.fieldnames)
        for i in range(0, len(m.fieldnames)):
            m.order_map[i] = m.ordered_fieldnames.index(m.fieldnames[i])

    print("Generating %s" % filename)
    outf = open(filename, "w")
    generate_preamble(outf)
    generate_msg_table(outf, msgs)
    generate_enum_table(outf, enums)
    generate_body_fields(outf)
    
    for m in msgs:
        generate_msg_fields(outf, m)
    
    for m in msgs:
        generate_payload_dissector(outf, m)
    
    generate_packet_dis(outf)
#    generate_enums(outf, enums)
#    generate_message_ids(outf, msgs)
#    generate_classes(outf, msgs)
#    generate_mavlink_class(outf, msgs, xml[0])
#    generate_methods(outf, msgs)
    generate_epilog(outf)
    outf.close()
    print("Generated %s OK" % filename)

