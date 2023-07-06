--[[
  ******************************************************************************
  * @file    st_ble_dissector.lua
  * @author  MCD Application Team
  * @brief   Dissector for the STM32 BLE Sniffer protocol
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2023 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
--]]

_G.debug = require("debug")

local HEADER_LEN_BYTES  = 10
local RSSI_INDEX        = 0
local RSSI_LENGTH       = 1
local CHANNEL_INDEX     = RSSI_INDEX + RSSI_LENGTH
local CHANNEL_LENGTH    = 1
local CONNECTION_COUNTER_INDEX  = CHANNEL_INDEX + CHANNEL_LENGTH
local CONNECTION_COUNTER_LENGTH = 2
local FLAGS_INDEX       = CONNECTION_COUNTER_INDEX + CONNECTION_COUNTER_LENGTH
local FLAGS_LENGTH      = 1
local CRCOK_BIT_INDEX   = 0
local DIRECTION_BIT_INDEX       = 1
local PHY_BIT_INDEX     = 2
local ENC_BIT_INDEX     = 3
local TIMESTAMP_INDEX   = FLAGS_INDEX + FLAGS_LENGTH
local TIMESTAMP_LENGTH  = 4
local BOARDID_INDEX   = TIMESTAMP_INDEX + TIMESTAMP_LENGTH
local BOARDID_LENGTH  = 1
local ACCESS_ADDRESS_LENGTH  = 4

ST_BLE = Proto("ST_BLE", "STMicroelectronics BLE sniffer header")

local f_flags = ProtoField.uint8("ST_BLE.flags", "flags", base.HEX, nil, 0, "Flags")
local crc_tfs = {
                "OK",
                "Incorrect"
                }
local f_crcok = ProtoField.bool("ST_BLE.crcok", ".... ...X CRC", base.None, crc_tfs, 0, "Cyclic Redundancy Check state")
local direction_tfs = {
                      "Master -> Slave",
                      "Slave -> Master",
                      "-"
                      }
local f_direction = ProtoField.uint8("ST_BLE.direction", ".... ..X. Direction", base.None, direction_tfs, 0, "Direction")
local phy_tfs = {
                "2M",
                "1M"
                }
local f_phy = ProtoField.bool("ST_BLE.phy", ".... .X.. PHY", base.None, phy_tfs, 0, "PHY")
local enc_tfs = {
                "Encrypted",
                "Unencrypted"
                }
local f_enc = ProtoField.bool("ST_BLE.encryption", ".... X... Encryption", base.None, enc_tfs, 0, "Encryption")

local f_channel = ProtoField.uint8("ST_BLE.channel", "Channel", base.DEC)
local f_rssi = ProtoField.int8("ST_BLE.rssi", "RSSI (dBm)", base.DEC, nil, 0, "Received Signal Strength Indicator")
local f_ConnEvtCounter = ProtoField.uint16("ST_BLE.connevtcounter", "Connection event counter", base.DEC, nil, 0, "Connection event counter")
local f_Timestamp = ProtoField.uint16("ST_BLE.timestamp", "Timestamp (us)", base.DEC, nil, 0, "Timestamp in microseconds")
local f_BoardID = ProtoField.uint8("ST_BLE.boardID", "Board ID", base.DEC, nil, 0, "COM port number on Windows")
local f_TimeDiff = ProtoField.uint16("ST_BLE.timediff", "Time from previsous packet start (us)", base.DEC, nil, 0, "Time difference with previous packet start in microseconds")
local f_TimeDiff_ES = ProtoField.uint16("ST_BLE.timediff_es", "Time from previsous packet end (us)", base.DEC, nil, 0, "Time difference with previous packet end in microseconds")


ST_BLE.fields = {f_channel,f_rssi,f_ConnEvtCounter,f_direction,f_crcok,f_phy,f_enc,f_flags,f_Timestamp,f_TimeDiff,f_TimeDiff_ES,f_BoardID}

btle_dissector = Dissector.get("btle")

timestamps = {}
lengths = {}

function ST_BLE.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = ST_BLE.name

  -- compute the LL payload length
  _ENV.lengths[pinfo.number] = buffer(HEADER_LEN_BYTES+ACCESS_ADDRESS_LENGTH+1,1):uint()+ACCESS_ADDRESS_LENGTH+2

  local subtree = tree:add(ST_BLE, buffer(0,HEADER_LEN_BYTES), "STMicroelectronics BLE sniffer")
  
  local rssi = (-1)*(buffer(RSSI_INDEX, RSSI_LENGTH):uint())

  -- extract flag states
  local flags = buffer(FLAGS_INDEX, FLAGS_LENGTH):uint()
  local crcok = bit.band(flags, 2^(CRCOK_BIT_INDEX))
  local dir = bit.band(flags, 2^(DIRECTION_BIT_INDEX))
  local phy = bit.band(flags, 2^(PHY_BIT_INDEX))
  local enc = bit.band(flags, 2^(ENC_BIT_INDEX))

  subtree:add(f_BoardID,buffer(BOARDID_INDEX,BOARDID_LENGTH))
  subtree:add(f_rssi,buffer(RSSI_INDEX,RSSI_LENGTH),rssi)
  subtree:add(f_channel,buffer(CHANNEL_INDEX,CHANNEL_LENGTH))

  subtree:add_le(f_ConnEvtCounter,buffer(CONNECTION_COUNTER_INDEX,CONNECTION_COUNTER_LENGTH))

  -- add timestamp to subtree and store the timestamp in an array for difference computation
  local timestamp = (buffer(TIMESTAMP_INDEX, TIMESTAMP_LENGTH):uint())
  subtree:add(f_Timestamp,buffer(TIMESTAMP_INDEX,TIMESTAMP_LENGTH),timestamp)
  timestamps[pinfo.number] = timestamp

  -- for each packets (except the first one) calculate and add to subtree the timestamp differences
  if pinfo.number > 1 then
    local timediff = timestamp - _ENV.timestamps[pinfo.number - 1]
    subtree:add_le(f_TimeDiff,buffer(TIMESTAMP_INDEX,TIMESTAMP_LENGTH),timediff)
    local timediff_es = timestamp - _ENV.timestamps[pinfo.number - 1] - _ENV.lengths[pinfo.number - 1]
    subtree:add_le(f_TimeDiff_ES,buffer(TIMESTAMP_INDEX,TIMESTAMP_LENGTH),timediff_es)
  end

  local flags_item = subtree:add(f_flags, buffer(FLAGS_INDEX, FLAGS_LENGTH))
  flags_item:add(f_crcok, buffer(FLAGS_INDEX, FLAGS_LENGTH), crcok > 0)

  --if not an adv pdu display direction
  local adv_aa = 0x8e89bed6
  local aa = buffer(HEADER_LEN_BYTES, 4):le_uint()
  if aa == adv_aa then
    dir=3
  elseif dir==0 then
    dir=1
  end

  flags_item:add(f_direction, buffer(FLAGS_INDEX, FLAGS_LENGTH), dir)
  flags_item:add(f_phy, buffer(FLAGS_INDEX, FLAGS_LENGTH), phy > 0)
  flags_item:add(f_enc, buffer(FLAGS_INDEX, FLAGS_LENGTH), enc > 0)

  --here it would be needed to add a context parameter so that the btle dissector know the direction but it seems impossible
  --for now the trick is to add the direction col pointing to custom st_ble.direction field
  btle_dissector:call(buffer:range(HEADER_LEN_BYTES,length-HEADER_LEN_BYTES):tvb(),pinfo,tree)

  return length
end

local wtap_encap_table = DissectorTable.get("wtap_encap")
wtap_encap_table:add(wtap.USER1, ST_BLE)