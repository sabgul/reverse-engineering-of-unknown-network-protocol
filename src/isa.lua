-- ISApro protocol dissection
-- Author: Sabina Gulcikova <xgulci00@stud.fit.vutbr.cz>

-- boilerplate code from: https://mika-s.github.io/wireshark/lua/dissector/2017/11/04/creating-a-wireshark-dissector-in-lua-1.html

isa_protocol = Proto("ISApro",  "ISA Protocol")
args = Proto("args", "arguments")

message_length = ProtoField.int64("isa_protocol.message_length", "Length of message", base.DEC)
message_state = ProtoField.string("isa_protocol.message_state", "State", base.ASCII)
message_sender = ProtoField.string("isa_protocol.message_sender", "Sender", base.ASCII)
message_command = ProtoField.string("isa_protocol.message_command", "Command", base.ASCII)
err_detail = ProtoField.string("isa_protocol.err_detail", "Error detail", base.ASCII)
operands_number = ProtoField.int64("isa_protocol.operands_number", "Number of operands", base.DEC)
login = ProtoField.string("args.login", "Login", base.ASCII)
session_hash_message = ProtoField.string("args.hash", "Session hash", base.ASCII)
no_args_available = ProtoField.string("args.noargs", "No arguments", base.ASCII)
server_message_command = ProtoField.string("args.servermessage", "Server message", base.ASCII)
dump = ProtoField.string("args.messageDump", "Raw message", base.ASCII)

isa_protocol.fields = {message_state, message_length, message_sender, message_command, err_detail, server_message_command}
args.fields = {login_operand, password_hash, send_subject_message, send_body_message, fetch_id_message, session_hash_message, dump}

function isa_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end
  local max = length - 2 - 6
  pinfo.cols.protocol = isa_protocol.name
  
  local subtree = tree:add(isa_protocol, buffer(), "ISA Protocol Data")
  local snd = buffer(0,5):string()
  local detail = buffer(6, max):string()
  local sender = get_sender(snd)
  local command = get_command(snd)
  local state = get_state(snd)
  local num_of_args = get_args_num(sender, command)
  local message = buffer(0,length):string()
  local login = get_login(command, message)
  local password_hash = get_passwd_hash(message) 
  local server_command = buffer(0,6):string()
  serv_command = get_serv_command(server_command)

  server_message_command = "Command: " .. serv_command

  sesh_hash = get_session_hash(message)
  session_hash_message = "Session hash: " .. sesh_hash

  if command == "fetch" then 
    fetch_id = get_fetch_id(message)
    fetch_id_message = "Id: " .. fetch_id

    server_login = get_ser_fetch_login(message)
    ser_fetch_login_message = "Fetched recipient: " .. server_login
  end 

  if command == "send" then
    send_subject = get_subject(message)
    send_body = get_body(message)
    send_subject_message = "Subject: " .. send_subject
    send_body_message = "Body: " .. send_body
  end

  message_state = "State: " .. state
  message_length = "Length of message: " .. length .. " bytes"
  message_sender = "Message sender: " .. sender
  message_command = "Message command: " .. command
  error_detail = "Error detail: " .. detail
  operands_number = "Number of required operands: " .. num_of_args
  dump = "ASCII dump: " .. message

  login_operand = "Login: " .. login
  password_hash = "Password hash: " .. password_hash
  no_args_available = "No operands"
  
  if sender == "server" then subtree:add_le(message_state, buffer(0,3)) end
  subtree:add_le(message_length, buffer(0,4)) 
  subtree:add_le(message_sender, buffer(0,3))
  subtree:add_le(dump, buffer(0,3))
  if sender == "client" then subtree:add_le(message_command, buffer(0,3)) end
  if state == "ERROR" then subtree:add_le(error_detail, buffer(0,3)) end
  if sender == "client" then subtree:add_le(operands_number, buffer(0,3)) end 
  local information = "Unknown"
  if sender == "server" then pinfo.cols.info = state .. ": response from server" 
    elseif sender == "client" then pinfo.cols.info = "Command requested by client: " .. command
  end 

  if sender == "server" and state == "SUCCESS" then subtree:add_le(server_message_command, buffer(0,4)) end
 
  -- Displaying subtree of operands
  if sender == "client" then
    local subtreeArgs = subtree:add(args, buffer(), "Sent operands")
    if command == "register" then 
      subtreeArgs:add_le(login_operand, buffer(0,4))
      subtreeArgs:add_le(password_hash, buffer(0,4)) 
    elseif command == "login" then 
      subtreeArgs:add_le(login_operand, buffer(0,4)) 
      subtreeArgs:add_le(password_hash, buffer(0,4))
    elseif command == "send" then 
      subtreeArgs:add_le(session_hash_message, buffer(0,4))
      subtreeArgs:add_le(login_operand, buffer(0,4))
      subtreeArgs:add_le(send_subject_message, buffer(0,4))
      subtreeArgs:add_le(send_body_message, buffer(0,4))
    elseif command == "fetch" then  
      subtreeArgs:add_le(session_hash_message, buffer(0,4))
      subtreeArgs:add_le(fetch_id_message, buffer(0,4))
    elseif command == "list" then 
      subtreeArgs:add_le(session_hash_message, buffer(0,4))
    elseif command == "logout" then 
      subtreeArgs:add_le(session_hash_message, buffer(0,4))
    end
  end 
end

-- ----------------- -- Other functions
function get_state(st)
  local state = "Unknown"
  if st == "(ok \"" then state = "SUCCESS"
  elseif st == "(ok (" then state = "SUCCESS"
  elseif st == "(err " then state = "ERROR"
  end
  return state
end

function get_sender(snd)
  local sender = "Unknown"

  if snd == "(ok \"" then sender = "server"
  elseif snd == "(ok (" then sender = "server"
  elseif snd == "(err " then sender = "server"
  else sender = "client" end

  return sender
end 

function get_command(cmd)
  local command = "Unknown"
  if cmd == "(logi" then command = "login"
  elseif cmd == "(regi" then command = "register"
  elseif cmd == "(send" then command = "send"
  elseif cmd == "(fetc" then command = "fetch"
  elseif cmd == "(list" then command = "list"
  elseif cmd == "(logo" then command = "logout"
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

function get_login(command, message)
  if command == "login" then
    login = string.match(message, '%"(.+)%"')
    login = string.gsub(login, '%"%s%"(.+)', '')
  elseif command == "register" then
    login = string.match(message, '%"(.+)%"')
    login = string.gsub(login, '%"%s%"(.+)', '')
  elseif command == "send" then
    login = string.match(message, '^(.+)%s%"(.+)%"%s%"')
    login = string.gsub(login, '^(.+)%s%"(.+)%"%s%"','')
    login = string.gsub(login, '%"$', '')
  end

  return login
end 

function get_passwd_hash(message)
  pass_hash = string.gsub(message, '^(.+)%s(.+)%s%"', '')
  pass_hash = string.match(pass_hash, '^(.+)%"')

  return pass_hash
end

function get_fetch_id(message)
  id = string.gsub(message, '^(.+)%s%"(.+)%"%s', '')
  id = string.match(id, '(%d+)')
  return id
end

function get_session_hash(message)
  hash = string.match(message, '%"(.+)%"')
  hash = string.gsub(hash, '%"%s%"(.+)', '')
  return hash
end 

function get_subject(message)
  subject = string.match(message, '%s%"(.+)%"%)$')
  subject = string.match(subject, '%"%s%"(.+)%"%s')
  subject = string.gsub(subject, '^(.+)%"%s%"', '')
  return subject
end 

function get_body(message)
  body = string.gsub(message, '^(.+)%s%"', '')
  body = string.gsub(body, '%"%)$', '')
  return body
end

function get_ser_fetch_login(command)
  login = "unknown"
  return login
end

function get_serv_command(cmd)
  command = "Unknown"
  if cmd == "(ok \"r" then
    command = "register"
  elseif cmd == "(ok \"u" then 
    command = "login"
  elseif cmd == "(ok \"m" then
    command = "send"
  elseif cmd == "(ok (\"" then
    command = "fetch"
  elseif cmd == "(ok ((" then
    command = "list"
  elseif cmd == "(ok \"l" then
    command = "logout"
  end

  return command
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(32323, isa_protocol)
