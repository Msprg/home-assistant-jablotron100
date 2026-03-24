from __future__ import annotations

from struct import pack

import msgpack

from jablotron_re_tools import (
    _cluster_runs,
    _extract_export_root_fields,
    _find_fat_root_entry,
    _follow_fat16_chain,
    _parse_fat_geometry,
)


def test_extract_export_root_fields_uses_first_msgpack_object() -> None:
    blob = msgpack.packb({2: {0: 100, 1: 50, 2: 6, 3: 20, 13: "VO 66"}}, use_bin_type=True)
    blob += b"*****this*is*the*end*****\x00opaque-tail"
    root_fields = _extract_export_root_fields(blob)
    assert root_fields[2][3] == 20
    assert root_fields[2][13] == "VO 66"


def test_parse_fat_helpers_for_export_cfg() -> None:
    boot = bytearray(512)
    boot[11:13] = pack("<H", 512)
    boot[13] = 32
    boot[14:16] = pack("<H", 1)
    boot[16] = 1
    boot[17:19] = pack("<H", 128)
    boot[22:24] = pack("<H", 25)
    geometry = _parse_fat_geometry(bytes(boot))
    assert geometry["root_dir_start_sector"] == 26
    assert geometry["data_start_sector"] == 34

    root = bytearray(32 * 4)
    root[0:11] = b"EXPORT  CFG"
    root[11] = 0x22
    root[26:28] = pack("<H", 2)
    root[28:32] = pack("<I", 1048576)
    start_cluster, file_size = _find_fat_root_entry(bytes(root), b"EXPORT  CFG") or (0, 0)
    assert start_cluster == 2
    assert file_size == 1048576


def test_follow_fat16_chain_and_cluster_runs() -> None:
    fat = bytearray(512)
    fat[4:6] = pack("<H", 3)
    fat[6:8] = pack("<H", 4)
    fat[8:10] = pack("<H", 0xFFFF)
    clusters = _follow_fat16_chain(fat=bytes(fat), start_cluster=2, max_clusters=8)
    assert clusters == [2, 3, 4]
    assert _cluster_runs(clusters) == [(2, 3)]
    assert _cluster_runs([2, 3, 7, 8, 10]) == [(2, 2), (7, 2), (10, 1)]
