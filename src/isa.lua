-- source code of the implemented wireshark dissector

isa_protocol = Proto("ISAproto",  "ISA Protocol")

isa_protocol.fields = {}

function isa_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = isa_protocol.name

  local subtree = tree:add(isa_protocol, buffer(), "ISA Protocol Data")
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(32323, isa_protocol)
