-- source code of the implemented wireshark dissector
-- boilerplate code from: 

isa_protocol = Proto("ISApro",  "ISA Protocol")

message_length = ProtoField.int64("isa_protocol.message_length", "Length of message", base.DEC)
message_state = ProtoField.string("isa_protocol.message_state", "State", base.ASCII)
message_sender = ProtoField.string("isa_protocol.message_sender", "Sender", base.ASCII)
message_command = ProtoField.string("isa_protocol.message_command", "Command", base.ASCII)
-- message_args =

isa_protocol.fields = {message_state, message_length, message_sender, message_command}

function isa_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = isa_protocol.name
  
  local subtree = tree:add(isa_protocol, buffer(), "ISA Protocol Data")
  local snd = buffer(0,3):string()
  local sender = get_sender(snd)
  local command = get_command(snd)
  local state = get_state(snd)

  message_state = "State: " .. state
  message_length = "Length of message: " .. length .. " bytes"
  message_sender = "Message sender: " .. sender
  message_command = "Message command: " .. command

  if sender == "server" then subtree:add_le(message_state, buffer(0,3)) end

  subtree:add_le(message_length, buffer(0,4)) 
  
  subtree:add_le(message_sender, buffer(0,3));
  
  if sender == "client" then subtree:add_le(message_command, buffer(0,3)) end

  local information = "Unknown"
  if sender == "server" then pinfo.cols.info = state .. ": response from server" 
    elseif sender == "client" then pinfo.cols.info = "Command requested by client: " .. command
    end
end

function get_state(st)
  local state = "Unknown"
  if st == "(ok" then state = "SUCCESS"
  elseif st == "(er" then state = "ERROR"
  end
  return state
end

function get_sender(snd)
  local sender = "Unknown"

  if snd == "(ok" then sender = "server"
  elseif snd == "(er" then sender = "server"
  else sender = "client" end

  return sender
end 

function get_command(cmd)
  local command = "Unknown"
  if cmd == "(lo" then command = "login"
  elseif cmd == "(re" then command = "register"
  elseif cmd == "(se" then command = "send"
  elseif cmd == "(fe" then command = "fetch"
  elseif cmd == "(li" then command = "list"
  end
  return command
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(32323, isa_protocol)
