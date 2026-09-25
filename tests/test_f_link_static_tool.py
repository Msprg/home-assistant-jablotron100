import struct

from f_link_static_tool import (
    PEImage,
    containing_idc_function,
    describe_vmt_slots,
    parse_delphi_class,
    parse_idc_functions,
)


def put_u16(data, offset, value):
    struct.pack_into("<H", data, offset, value)


def put_u32(data, offset, value):
    struct.pack_into("<I", data, offset, value)


def make_test_pe(path):
    data = bytearray(0x800)
    put_u32(data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    put_u16(data, 0x86, 1)
    put_u16(data, 0x94, 0xE0)
    put_u16(data, 0x98, 0x10B)
    put_u32(data, 0x98 + 28, 0x400000)
    section = 0x98 + 0xE0
    data[section : section + 8] = b".data\0\0\0"
    put_u32(data, section + 8, 0x1000)
    put_u32(data, section + 12, 0x1000)
    put_u32(data, section + 16, 0x600)
    put_u32(data, section + 20, 0x200)

    def off(va):
        return 0x200 + va - 0x401000

    rtti, type_info, vmt, table, metadata = 0x401100, 0x401104, 0x401300, 0x401380, 0x4013A0
    put_u32(data, off(rtti), type_info)
    data[off(type_info)] = 7
    data[off(type_info + 1) : off(type_info + 1) + 6] = b"\x05TTest"
    put_u32(data, off(type_info + 7), vmt)
    put_u32(data, off(type_info + 11), 0x401050)
    put_u32(data, off(vmt - 64), table)
    put_u32(data, off(vmt - 68), vmt + 8)
    put_u32(data, off(vmt - 52), 0x24)
    put_u32(data, off(vmt - 48), 0x401040)
    put_u32(data, off(0x401040), 0x401200)
    put_u32(data, off(0x401200), 0x401510)
    put_u32(data, off(0x401204), 0x401520)
    put_u32(data, off(vmt), 0x401510)
    put_u32(data, off(vmt + 4), 0x401530)
    field_table = vmt + 8
    put_u16(data, off(field_table + 4), 0)
    put_u16(data, off(field_table + 6), 1)
    data[off(field_table + 8)] = 0
    put_u32(data, off(field_table + 9), type_info)
    put_u32(data, off(field_table + 13), 0x20)
    data[off(field_table + 17) : off(field_table + 17) + 7] = b"\x06FValue"
    put_u16(data, off(field_table + 24), 2)
    put_u16(data, off(table), 0)
    put_u16(data, off(table + 2), 1)
    put_u32(data, off(table + 4), metadata)
    put_u32(data, off(table + 8), 3)
    put_u16(data, off(metadata), 14)
    put_u32(data, off(metadata + 2), 0x401500)
    data[off(metadata + 6) : off(metadata + 6) + 7] = b"\x06Create"
    path.write_bytes(data)
    return rtti


def test_parse_delphi_class_from_pe(tmp_path):
    path = tmp_path / "sample.exe"
    rtti = make_test_pe(path)
    parsed = parse_delphi_class(PEImage(path), rtti)
    assert parsed.name == "TTest"
    assert parsed.vmt == 0x401300
    assert parsed.instance_size == 0x24
    assert parsed.parent_rtti == 0x401050
    assert parsed.parent_vmt_cell == 0x401040
    assert parsed.parent_vmt == 0x401200
    assert parsed.field_table == 0x401308
    assert parsed.vmt_end == 0x401308
    assert parsed.vmt_slot_count == 2
    assert [(field.name, field.offset) for field in parsed.fields] == [("FValue", 0x20)]
    assert [(method.name, method.code) for method in parsed.methods] == [("Create", 0x401500)]

    # Delphi parent links use direct TypeInfo VAs rather than the pointer-cell
    # convention used by the component map's top-level RTTI anchors.
    parsed_from_type_info = parse_delphi_class(PEImage(path), 0x401104)
    assert parsed_from_type_info.name == "TTest"
    assert parsed_from_type_info.type_info == 0x401104
    assert parsed_from_type_info.vmt == 0x401300

    slots = describe_vmt_slots(PEImage(path), parsed, 2)
    assert slots == (
        {
            "offset": 0,
            "code": 0x401510,
            "parent_code": 0x401510,
            "added": False,
            "overridden": False,
        },
        {
            "offset": 4,
            "code": 0x401530,
            "parent_code": 0x401520,
            "added": False,
            "overridden": True,
        },
    )


def test_idc_function_ranges_are_half_open():
    functions = parse_idc_functions(
        "MakeFunction(0x401000, 0x401020);\nMakeFunction(0x402000, -1);"
    )
    assert containing_idc_function(functions, 0x401010) == (0x401000, 0x401020)
    assert containing_idc_function(functions, 0x401020) is None
    assert containing_idc_function(functions, 0x402000) is None
