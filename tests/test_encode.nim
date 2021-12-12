import unittest
from strutils import repeat, parseHexStr, replace, toHex, toLowerAscii, toUpperAscii
import faststreams

import nimhpack/decode
import nimhpack/table
import nimhpack/encode

proc pair(name, val : string) : Headerfield =
    Headerfield(name: name, value: val)

suite "encoder table size update":
    type
        tc = object
            size1, size2: uint32
            wantHex: string
    let testcases = @[
        tc(size1: 2048, size2: 4096, wantHex: "3FE10F 3FE11F 82"),
        tc(size1: 16384, size2: 2048, wantHex: "3FE10F 82"),
    ]
    for i, testcase in testcases:
        test "test case " & $(i+1):
            var buf = memoryOutput()
            let enc = newEncoder(buf)
            enc.setMaxDynamicTableSize(testcase.size1)
            enc.setMaxDynamicTableSize(testcase.size2)
            enc.writeField(pair(":method", "GET"))

            let want = testcase.wantHex.replace(" ")
            let s = buf.getOutput(string)
            check(s.toHex == want)

suite "encoder write field":
    type
        tc = object
            header_fields: seq[Headerfield]
    let testcases = @[
        tc(header_fields: @[
            pair(":method", "GET"),
            pair(":scheme", "http"),
            pair(":path", "/"),
            pair(":authority", "www.example.com"),
        ]),
        tc(header_fields: @[
            pair(":method", "GET"),
            pair(":scheme", "http"),
            pair(":path", "/"),
            pair(":authority", "www.example.com"),
            pair("cache-control", "no-cache"),
        ]),
        tc(header_fields: @[
            pair(":method", "GET"),
            pair(":scheme", "https"),
            pair(":path", "/index.html"),
            pair(":authority", "www.example.com"),
            pair("custom-key", "custom-value"),
        ]),
    ]
    var buf = memoryOutput()
    var enc = newEncoder(buf)
    var got: seq[Headerfield]
    var d = newDecoder(4 shl 10, proc(h: Headerfield) = got.add h)
    for i, testcase in testcases:
        test "test case " & $(i+1):
            got = got[0..<0]
            buf.recycleBuffers(nil)
            for header_field in testcase.header_fields:
                enc.writeField(header_field)
            let k = buf.getOutput
            d.write(k)
            check(got == testcase.header_fields)

suite "encoder search table":
    type
        tc = object
            hf: Headerfield
            wantI: uint64
            wantMatch: bool
    let enc = newEncoder(nil)
    enc.dynTab.add(pair("foo", "bar"))
    enc.dynTab.add(pair("blake", "miz"))
    enc.dynTab.add(pair(":method", "GET"))
    let testcases = @[
        # Name and Value match
        tc(hf: pair("foo", "bar"), wantI: uint64(staticTable.len()) + 3, wantMatch: true),
        tc(hf: pair("blake", "miz"), wantI: uint64(staticTable.len()) + 2, wantMatch: true),
        tc(hf: pair(":method", "GET"), wantI: 2, wantMatch: true),

        # Only name match because Sensitive == true. This is allowed to match
        # any ":method" entry. The current implementation uses the last entry
        # added in newStaticTable.
        tc(hf: HeaderField(name: ":method", value: "GET", sensitive: true), wantI: 3, wantMatch: false),

        # Only Name matches
        tc(hf: pair("foo", "..."), wantI: uint64(staticTable.len()) + 3, wantMatch: false),
        tc(hf: pair("blake", "..."), wantI: uint64(staticTable.len()) + 2, wantMatch: false),

        # As before, this is allowed to match any ":method" entry.
        tc(hf: pair(":method", "..."), wantI: 3, wantMatch: false),

        # None match
        tc(hf: pair("foo-", "bar"), wantI: 0, wantMatch: false),
    ]
    for i, testcase in testcases:
        test "test case " & $(i+1):
            let (i, matched) = enc.searchTable(testcase.hf)
            check(i == testcase.wantI or matched == testcase.wantMatch)

suite "append var int":
    type
        tc = object
            n: byte
            i: uint64
            want: seq[byte]
    let testcases = @[
        # Fits in a byte:
        tc(n: 1, i: 0, want: @[0'u8]),
        tc(n: 2, i: 2, want: @[2'u8]),
        tc(n: 3, i: 6, want: @[6'u8]),
        tc(n: 4, i: 14, want: @[14'u8]),
        tc(n: 5, i: 30, want: @[30'u8]),
        tc(n: 6, i: 62, want: @[62'u8]),
        tc(n: 7, i: 126, want: @[126'u8]),
        tc(n: 8, i: 254, want: @[254'u8]),
        # Multiple bytes:
        tc(n: 5, i: 1337, want: @[31'u8, 154, 10]),
    ]
    for i, testcase in testcases:
        test "test case " & $(i+1):
            var g : seq[byte] = @[]
            appendVarInt(g, testcase.n, testcase.i)
            check(g == testcase.want)

suite "append hpack string":
    type
        tc = (string, string)
    let testcases: seq[tc] = @[
        ("www.example.com", "8C F1E3 C2E5 F23A 6BA0 AB90 F4FF"),
        ("a", "01 61"),
        ("", "00"),
    ]
    for i, testcase in testcases:
        test "test case " & $(i+1):
            let want = replace(testcase[1], " ")
            var g: seq[byte]
            appendHpackString(g, testcase[0])
            check(cast[string](g).toHex == want)
    
suite "append indexed":
    let testcases: seq[(uint64, string)] = @[
        (1'u64, "81"),
        (126'u64, "FE"),
        (127'u64, "FF00"),
        (128'u64, "FF01"),
    ]
    for i, testcase in testcases:
        test "test case " & $(i+1):
            let want = replace(testcase[1], " ")
            var g: seq[byte]
            appendIndexed(g, testcase[0])
            check(cast[string](g).toHex == want)

suite "append new name":
    let testcases: seq[(Headerfield, bool, string)] = @[
        (HeaderField(name: "custom-key", value: "custom-value", sensitive: false), true, "40 88 25a8 49e9 5ba9 7d7f 89 25a8 49e9 5bb8 e8b4 bf"),
        (HeaderField(name: "custom-key", value: "custom-value", sensitive: false), false, "00 88 25a8 49e9 5ba9 7d7f 89 25a8 49e9 5bb8 e8b4 bf"),
        (HeaderField(name: "custom-key", value: "custom-value", sensitive: true), true, "10 88 25a8 49e9 5ba9 7d7f 89 25a8 49e9 5bb8 e8b4 bf"),
        (HeaderField(name: "custom-key", value: "custom-value", sensitive: true), false, "10 88 25a8 49e9 5ba9 7d7f 89 25a8 49e9 5bb8 e8b4 bf"),
    ]
    for i, testcase in testcases:
        test "test case " & $(i+1):
            let want = replace(testcase[2], " ").toUpperAscii
            var g: seq[byte]
            appendNewName(g, testcase[0], testcase[1])
            check(cast[string](g).toHex == want)

suite "append indexed name":
    let testcases: seq[(Headerfield, uint64, bool, string)] = @[
        (HeaderField(name: ":status", value: "302", sensitive: false), 8'u64, true, "48 82 6402"),
        (HeaderField(name: ":status", value: "302", sensitive: false), 8'u64, false, "08 82 6402"),
        (HeaderField(name: ":status", value: "302", sensitive: true), 8'u64, true, "18 82 6402"),
        (HeaderField(name: ":status", value: "302", sensitive: true), 8'u64, false, "18 82 6402"),
    ]
    for i, testcase in testcases:
        test "test case " & $(i+1):
            let want = replace(testcase[3], " ").toUpperAscii
            var g: seq[byte]
            appendIndexedName(g, testcase[0], testcase[1], testcase[2])
            check(cast[string](g).toHex == want)

suite "append table size":
    let testcases: seq[(uint32, string)] = @[
        (30'u32, "3e"),
        (31'u32, "3f00"),
        (32'u32, "3f01"),
    ]
    for i, testcase in testcases:
        test "test case " & $(i+1):
            let want = replace(testcase[1], " ").toUpperAscii
            var g: seq[byte]
            appendTableSize(g, testcase[0])
            check(cast[string](g).toHex == want)

suite "encoder set max dynamic table size":
    let testcases: seq[(uint32, bool, uint32, uint32)] = @[
        (2048'u32, true, 2048'u32, 2048'u32),
        (16384'u32, true, 2048'u32, 4096'u32),
    ]
    var buf = memoryOutput()
    let enc = newEncoder(buf)
    for i, testcase in testcases:
        test "test case " & $(i+1):
            enc.setMaxDynamicTableSize(testcase[0])
            check(enc.tableSizeUpdate == testcase[1])
            check(enc.minSize == testcase[2])
            check(enc.dynTab.maxSize == testcase[3])

test "encoder set max dynamic table size limit":
    let enc = newEncoder(nil)
    enc.setMaxDynamicTableSizeLimit(4095)
    check(enc.dynTab.maxSize == uint32(4095))
    check(enc.maxSizeLimit == uint32(4095))
    check(enc.tableSizeUpdate == true)

    enc.setMaxDynamicTableSize(16384)
    check(enc.dynTab.maxSize == uint32(4095))

    enc.setMaxDynamicTableSizeLimit(8192)
    check(enc.dynTab.maxSize == uint32(4095))
    check(enc.maxSizeLimit == uint32(8192))
