-- ISApro protocol dissection
-- Author: Sabina Gulcikova <xgulci00@stud.fit.vutbr.cz>

-- boilerplate code from: https://mika-s.github.io/wireshark/lua/dissector/2017/11/04/creating-a-wireshark-dissector-in-lua-1.html

isa_protocol = Proto("ISApro",  "ISA Protocol")

message_length = ProtoField.int64("isa_protocol.message_length", "Length of message", base.DEC)
message_state = ProtoField.string("isa_protocol.message_state", "State", base.ASCII)
message_sender = ProtoField.string("isa_protocol.message_sender", "Sender", base.ASCII)
message_command = ProtoField.string("isa_protocol.message_command", "Command", base.ASCII)
err_detail = ProtoField.string("isa_protocol.err_detail", "Error detail", base.ASCII)
operands_number = ProtoField.int64("isa_protocol.operands_number", "Number of operands", base.DEC)
-- message_args =

isa_protocol.fields = {message_state, message_length, message_sender, message_command, err_detail}

function isa_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end
  local max = length - 2 - 6
  pinfo.cols.protocol = isa_protocol.name
  
  local subtree = tree:add(isa_protocol, buffer(), "ISA Protocol Data")
  local snd = buffer(0,3):string()
  local detail = buffer(6, max):string()
  local sender = get_sender(snd)
  local command = get_command(snd)
  local state = get_state(snd)
  local num_of_args = get_args_num(sender, command)

  message_state = "State: " .. state
  message_length = "Length of message: " .. length .. " bytes"
  message_sender = "Message sender: " .. sender
  message_command = "Message command: " .. command
  error_detail = "Error detail: " .. detail
  operands_number = "Number of required operands: " .. num_of_args


  if sender == "server" then subtree:add_le(message_state, buffer(0,3)) end

  subtree:add_le(message_length, buffer(0,4)) 
  
  subtree:add_le(message_sender, buffer(0,3));
  
  if sender == "client" then subtree:add_le(message_command, buffer(0,3)) end

  if state == "ERROR" then subtree:add_le(error_detail, buffer(0,3)) end

  if sender == "client" then subtree:add_le(operands_number, buffer(0,3)) end 

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

function get_args_num(snd, cmd)
  local number = 0
  if snd == "client" then
    if cmd == "register" then number = 2
    elseif cmd == "login" then number = 2
    elseif cmd == "send" then number = 3
    elseif cmd == "fetch" then number = 1 
    end 
  end

  return number
end


local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(32323, isa_protocol)
