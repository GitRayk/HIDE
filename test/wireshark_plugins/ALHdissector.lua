do
    --定义协议名称 my_protocol，将在 details 中显示
    local p_ALH = Proto("Address_Label","Address Label")
    --协议的各个字段
    local f_nhdr = ProtoField.uint8("ALH.nhdr","NextHeader", base.DEC)
    local f_length = ProtoField.uint16("ALH.len", "Length", base.DEC)
    local f_reserved = ProtoField.uint8("ALH.reserved", "Reserved", base.HEX)
    local f_ts = ProtoField.uint32("ALH.ts", "Timestamp", base.HEX)
    local f_sn = ProtoField.uint32("ALH.sn", "Sequence", base.HEX)
    local f_eea = ProtoField.uint64("ALH.eea", "Extra Encrypted Address", base.HEX)
    local f_ipc = ProtoField.string("ALH.ipc", "Integrity Protection Code", base.ASCII)

    --将所有的协议字段 ProtoField 添加到 Proto 中去
    p_ALH.fields = {f_nhdr, f_length, f_reserved, f_ts, f_sn, f_eea, f_ipc}
    
    --dissector 接受三个参数，分别标识包中的数据、包信息、解析树
    local function ALH_dissector(buf,pinfo,root)
        --从 buf 中取出需要在 wireshark 中展示的 field 信息
        --buf(x, n) 表示从第 x 字节开始连续取出 n 个字节数据
        local v_nhdr = buf(0, 1)
        local v_length = buf(1, 2)
        local v_reserved = buf(3, 1)
        local v_ts = buf(4, 4)
        local v_sn = buf(8, 4)
        local v_eea = buf(12, 8)
        local v_ipc = buf(20, 32)
        
        --将要显示的数据添加到解析树上
        local alh_node = root:add(p_ALH, buf(0, 52))
        alh_node:add(f_nhdr, v_nhdr)
        alh_node:add(f_length, v_length)
        alh_node:add(f_reserved, v_reserved)
        alh_node:add(f_ts, v_ts)
        alh_node:add(f_sn, v_sn)
        alh_node:add(f_eea, v_eea)
        alh_node:add(f_ipc, v_ipc)

        --对扩展报头后面的传输层数据重新调用对应的 dissector
        local next_protocol = buf(0, 1):uint()
        if next_protocol == 6 then
            Dissector.get("tcp"):call(buf(52):tvb(), pinfo, root)
        elseif next_protocol == 17 then
            Dissector.get("udp"):call(buf(52):tvb(), pinfo, root)
        elseif next_protocol == 58 then
            Dissector.get("icmpv6"):call(buf(52):tvb(), pinfo, root)
        end
        
        return true
    end
    
    function p_ALH.dissector(buf,pinfo,root) 
        ALH_dissector(buf,pinfo,root)
    end
    
    --将协议解析器添加到 DissectorTable 中去，并且当 ip 的 protocol 字段(IPv6下的 next header 字段)对应的值/pattern 是 146（地址标签）时触发该 Dissector
    DissectorTable.get("ip.proto"):add(146, p_ALH)
end