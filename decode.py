#!/usr/bin/env python3

import struct
from uvscada.util import hexdump

vars = {}

MAX_SIZE = 4096

def unpack8(buff, name=None, verbose=True):
    ret = buff[0]
    del buff[0]
    if name:
        verbose and print("% -12s: % 12u, 0x%02X" % (name, ret, ret))
        vars[name] = ret
    return ret

def unpackb16(buff, name=None, verbose=True):
    ret0 = buff[0]
    ret1 = buff[1]
    del buff[0:2]
    ret = (ret0 << 8) | ret1
    if name:
        verbose and print("% -12s: % 12u, 0x%04X" % (name, ret, ret))
        vars[name] = ret
    return ret

def unpackl16(buff, name=None, verbose=True):
    ret0 = buff[0]
    ret1 = buff[1]
    del buff[0:2]
    ret = (ret1 << 8) | ret0
    if name:
        verbose and print("% -12s: % 12u, 0x%04X" % (name, ret, ret))
        vars[name] = ret
    return ret

def unpack32(buff, name=None, verbose=True):
    ret0 = buff[0]
    ret1 = buff[1]
    ret2 = buff[2]
    ret3 = buff[3]
    del buff[0:4]
    ret = (ret0 << 24) | (ret1 << 16) | (ret2 << 8) | ret3
    if name:
        verbose and print("% -12s: % 12u, 0x%08X" % (name, ret, ret))
        vars[name] = ret
    return ret

def unpackb32(buff, name=None, verbose=True):
    ret0 = buff[0]
    ret1 = buff[1]
    ret2 = buff[2]
    ret3 = buff[3]
    del buff[0:4]
    ret = (ret0 << 24) | (ret1 << 16) | (ret2 << 8) | ret3
    if name:
        verbose and print("% -12s: % 12u, 0x%08X" % (name, ret, ret))
        vars[name] = ret
    return ret

def unpackl32(buff, name=None, verbose=True):
    ret0 = buff[0]
    ret1 = buff[1]
    ret2 = buff[2]
    ret3 = buff[3]
    del buff[0:4]
    ret = (ret3 << 24) | (ret2 << 16) | (ret1 << 8) | ret0
    if name:
        verbose and print("% -12s: % 12u, 0x%08X" % (name, ret, ret))
        vars[name] = ret
    return ret

def parse_header(buff):
    """
    Tag: A single byte field set to 0xD1
    Length: a two byte field in big endian format containing the overall length of the IVT,
    in bytes, including the header. (the length is fixed and must have a value of
    32 bytes)
    Version: A single byte field set to 0x40 or 0x41
    """
    assert unpack8(buff, "tag") == 0xD1
    assert unpackb16(buff, "length") == 32
    assert unpack8(buff, "version") in (0x40, 0x41)

def parse_boot_data(buff):
    # The DCD header is 4 B with the following format:
    print("Boot data")
    boot_data_rel = vars["boot_data"] - vars["self"]
    print("Boot data rel offset: 0x%08X" % (boot_data_rel,))
    buff = buff[boot_data_rel:]
    start = unpackl32(buff, "bd_start")
    if 0x10000000 <= start <= 0xFFFFFFFF:
        MB = (start - 0x10000000) / 1024 / 1024
        print("  start is in DDR, off=%u MB" % (MB,)) 
    unpackl32(buff, "bd_length")
    plugin = unpackb32(buff, "bd_plugin")
    if plugin:
        print("FIXME: parse plugin")


def parse_dcd(buff):
    # The DCD header is 4 B with the following format:
    print("DCD")
    """
    Tag: A single-byte field set to 0xD2
    Length: a two-byte field in the big-endian format containing the overall length of the DCD
    (in bytes) including the header
    Version: A single-byte field set to 0x41
    """
    dcd_rel = vars["dcd"] - vars["self"]
    print("DCD rel offset: 0x%08X" % (dcd_rel,))
    buff = buff[dcd_rel:]
    assert unpack8(buff, "dcd_tag") == 0xD2
    # The maximum size of the DCD is limited to 1768 B.
    dcd_length = unpackb16(buff, "dcd_length")
    assert dcd_length <= 1768
    # "Version: A single byte field set to 0x40 or 0x41"
    assert unpack8(buff, "version") in (0x40, 0x41)
    end_address = dcd_rel + dcd_length - 1
    assert end_address < MAX_SIZE

    """
    If any of the target addresses do not lie within the allowed
    region, none of the values are written. The list of allowable
    blocks and target addresses for the chip are provided below.
    """
    legal_addrs = {
        "IOMUX Control (IOMUXC) registers": (0x020E0000, 0x020E3FFF),
        "CCM register set": (0x020C4000, 0x020C7FFF),
        "ANADIG registers": (0x020C8000, 0x020C8FFF),
        "MMDC register set": (0x021B0000, 0x021B7FFF),
        "IRAM free space": (0x00907000, 0x00937FF0),
        "EIM memory": (0x08000000, 0x0FFEFFFF),
        "EIM registers": (0x021B8000, 0x021BBFFF),
        "DDR": (0x10000000, 0xFFFFFFFF),
        }

    def dcd_addr_range(addr):
        # Table 8-31. Valid DCD address ranges
        for k, (al, ah) in legal_addrs.items():
            if al <= addr <= ah:
                return k
        return None

    def legal_dcd_addr(addr):
        assert dcd_addr_range(addr)

    if 0:
        for i in range(16):
            print(unpack8(buff, "op_tag"))
        return
    # print(unpack8(buff, "op_tag", True))

    buffi = 4
    entryi = 0
    while buffi < dcd_length:
        # Table 8-28. Write data command format
        # 8.6.2.2 Check data command
        # 8.6.2.3 NOP command
        # 8.6.2.4 Unlock command
        tag = unpack8(buff, "op_tag", False)
        length = unpackb16(buff, "op_length", False)
        param = unpack8(buff, "op_param", False)
        # Already consumed a word
        op_buff = buff[0:length - 4]
        buff = buff[len(op_buff):]
        def print_ent(op):
            print("CMD % 4u %s, length=%u / 0x%04x, param=%u" % (entryi, op, length, length, param))
        if tag == 0xB2:
            print_ent("Unlock")
        elif tag == 0xC0:
            print_ent("NOP")
            assert length == 4
        elif tag == 0xCC:
            print_ent("Write")

            bytes_ = param & 0x7
            print("  Bytes: %u" % bytes_)
            assert bytes_ in (1, 2, 4)
            data_mask = bool(param & (1 << 3))
            print("  data_mask", data_mask)
            data_set = bool(param & (1 << 4))
            print("  data_set", data_set)

            assert len(op_buff) % 8 == 0
            print("  Addr/mask pairs")
            for opi in range(len(op_buff) // 8):
                address = unpackb32(op_buff)
                val_mask = unpackb32(op_buff)
                segment = dcd_addr_range(address)
                print("    % 4u, addr 0x%08X, val_mask 0x%08X, in %s" % (opi, address, val_mask, segment))
                assert segment
        elif tag == 0xCF:
            print_ent("Check data")
        else:
            print("fail")
            hexdump(op_buff)
            assert 0, tag
    
        entryi += 1
        buffi += length

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="print info")
    parser.add_argument("fn")
    args = parser.parse_args()

    f = open(args.fn, "rb")
    buff_raw = bytearray(f.read())
    buff = bytearray(buff_raw)[0:0x20]

    # The IVT has the following format where each entry is a 32-bit word:
    parse_header(buff)
    unpackl32(buff, "entry")
    # entry: Absolute address of the first instruction to execute from the image
    assert unpackl32(buff, "reserved1") == 0
    # dcd: Absolute address of the image DCD. The DCD is optional so this field may be set to NULL if no DCD is required.
    dcd = unpackl32(buff, "dcd")
    # boot data: Absolute address of the boot data
    unpackl32(buff, "boot_data")
    # self: Absolute address of the IVT. Used internally by the ROM.
    unpackl32(buff, "self")
    # csf: Absolute address of the Command Sequence File (CSF) used by the HAB library
    # This field must be set to NULL when not performing a secure boot
    csf = unpackl32(buff, "csf")
    assert unpackl32(buff, "reserved2") == 0
    assert len(buff) == 0, len(buff)

    entry_rel = vars["entry"] - vars["self"]
    print("entry_rel", "0x%08X" % entry_rel)

    print("")
    parse_boot_data(bytearray(buff_raw))

    if dcd:
        print("")
        parse_dcd(bytearray(buff_raw))
    if csf:
        print("")
        print("fixme: parse csf")

if __name__ == "__main__":
    main()
