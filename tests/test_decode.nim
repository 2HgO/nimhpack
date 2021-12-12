import unittest
import random
from strutils import repeat, parseHexStr, replace, toHex, toLowerAscii
import faststreams

import nimhpack/errors
import nimhpack/huffman
import nimhpack/encode
import nimhpack/table
import nimhpack/decode

randomize()

type
    encAndWant = object
        enc : seq[byte]
        want : seq[Headerfield]
        wantDynTab : seq[Headerfield]
        wantDynSize : uint32

proc mustAt(d : Decoder, idx : int) : HeaderField =
    var (hf, ok) = d.at(idx.uint64)
    if not ok: raise newException(IndexDefect, "bogus index " & $idx)
    return hf

proc pair(name, val : string) : Headerfield =
    Headerfield(name: name, value: val)

proc reverseCopy(d : dynamicTable) : seq[Headerfield] =
    var t = newSeq[Headerfield](len(d.table.ents))
    for i in 0..<d.table.ents.len(): t[i] = d.table.ents[len(d.table.ents)-1-i]
    return t

proc dehex(c : string) : seq[byte] =
    var s = c
    s = replace(s, " ")
    s = replace(s, "\n")
    return cast[seq[byte]](parseHexStr(s))

proc testDecodeSeries(d : Decoder, step : encAndWant) =
    var hf = d.decodeFull(step.enc)
    check(hf == step.want)
    var g = d.dynTab.reverseCopy()
    check(g == step.wantDynTab)
    check(d.dynTab.size == step.wantDynSize)


suite "testing dynamicTable type in hpack module":
    setup:
        var d = newDecoder(4096, nil) 
    test "`at` procedure":
        check(d.mustAt(2) == pair(":method", "GET"))  
        d.dynTab.add(pair("foo", "bar"))
        d.dynTab.add(pair("blake", "miz"))    
        check(d.mustAt(staticTable.len() + 1) == pair("blake", "miz"))
        check(d.mustAt(staticTable.len() + 2) == pair("foo", "bar"))
        check(d.mustAt(3) == pair(":method", "POST"))
        expect(IndexDefect):
            discard d.mustAt(staticTable.len() + 4)

    test "size evict":
        check(d.dynTab.size == 0'u32)
        d.dynTab.add(pair("blake", "eats pizza"))
        check(d.dynTab.size == 47'u32)
        d.dynTab.add(pair("foo", "bar"))
        check(d.dynTab.size == 85'u32)
        d.dynTab.setMaxSize(15 + 32 + 1)
        check(d.dynTab.size == 38'u32)
        check(d.mustAt(staticTable.len() + 1) == pair("foo", "bar"))
        d.dynTab.add(pair("long", repeat("x", 500)))
        check(d.dynTab.size == 0'u32)

suite "testing Decoder type in hpack module":
    type
        testcase = object
            name : string
            `in` : seq[byte]
            want : seq[Headerfield]
            wantDynTab : seq[Headerfield]
    let tests = @[
        testcase(
          name : "C.2.1",
          `in`: dehex("400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572"),
          want: @[pair("custom-key", "custom-header")],
          wantDynTab: @[pair("custom-key", "custom-header")]
        ),
        testcase(
          name : "C.2.2",
          `in`: dehex("040c 2f73 616d 706c 652f 7061 7468"),
          want: @[pair(":path", "/sample/path")],
          wantDynTab: @[]
        ),
        testcase(
          name : "C.2.3",
          `in`: dehex("1008 7061 7373 776f 7264 0673 6563 7265 74"),
          want: @[Headerfield(name : "password", value : "secret", sensitive : true)],
          wantDynTab: @[]
        ),
        testcase(
          name : "C.2.4",
          `in`: @[130'u8],
          want: @[pair(":method", "GET")],
          wantDynTab: @[]
        ),
    ]
    setup:
        var d = newDecoder(4096, nil)
    for i in tests:
        test i.name:
            var hf = d.decodeFull(i.`in`)
            check(hf == i.want)
            var g = d.dynTab.reverseCopy()
            check(g == i.wantDynTab)
  
suite "testing decode c3 (no huffman)":
    var d = newDecoder(4096, nil)
    var tests = @[
        encAndWant(
            enc : dehex("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d"),
            want : @[
                pair(":method", "GET"),
                pair(":scheme", "http"),
                pair(":path", "/"),
                pair(":authority", "www.example.com"),
            ],
            wantDynTab : @[
                pair(":authority", "www.example.com"),
            ],
            wantDynSize : 57,
        ),
        encAndWant(
            enc : dehex("8286 84be 5808 6e6f 2d63 6163 6865"),
            want : @[
                pair(":method", "GET"),
                pair(":scheme", "http"),
                pair(":path", "/"),
                pair(":authority", "www.example.com"),
                pair("cache-control", "no-cache"),
            ],
            wantDynTab : @[
                pair("cache-control", "no-cache"),
                pair(":authority", "www.example.com"),
            ],
            wantDynSize : 110,
        ),
        encAndWant(
            enc : dehex("8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65"),
            want : @[
                pair(":method", "GET"),
                pair(":scheme", "https"),
                pair(":path", "/index.html"),
                pair(":authority", "www.example.com"),
                pair("custom-key", "custom-value"),
            ],
            wantDynTab : @[
                pair("custom-key", "custom-value"),
                pair("cache-control", "no-cache"),
                pair(":authority", "www.example.com"),
            ],
            wantDynSize : 164,
        ),
    ]
    for i, tt in tests.pairs:
        test "test case " & $(i+1):
            testDecodeSeries(d, tt)

suite "testing decode c4 (huffman)":
    var d = newDecoder(4096, nil)
    var tests = @[
        encAndWant(
            enc : dehex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff"),
            want : @[
              pair(":method", "GET"),
              pair(":scheme", "http"),
              pair(":path", "/"),
              pair(":authority", "www.example.com"),
            ],
            wantDynTab : @[
              pair(":authority", "www.example.com"),
            ],
            wantDynSize : 57,
        ),
        encAndWant(
            enc : dehex("8286 84be 5886 a8eb 1064 9cbf"),
            want : @[
                pair(":method", "GET"),
                pair(":scheme", "http"),
                pair(":path", "/"),
                pair(":authority", "www.example.com"),
                pair("cache-control", "no-cache"),
            ],
            wantDynTab : @[
                pair("cache-control", "no-cache"),
                pair(":authority", "www.example.com"),
            ],
            wantDynSize : 110,
        ),
        encAndWant(
            enc : dehex("8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf"),
            want : @[
                pair(":method", "GET"),
                pair(":scheme", "https"),
                pair(":path", "/index.html"),
                pair(":authority", "www.example.com"),
                pair("custom-key", "custom-value"),
            ],
            wantDynTab : @[
                pair("custom-key", "custom-value"),
                pair("cache-control", "no-cache"),
                pair(":authority", "www.example.com"),
            ],
            wantDynSize : 164,
        ),
    ]
    for i, tt in tests.pairs:
        test "test case " & $(i+1):
            testDecodeSeries(d, tt)

suite "testing decode c5 response (no huffman)":
    var d = newDecoder(256, nil)
    var tests = @[
        encAndWant(
            enc : dehex("""4803 3330 3258 0770 7269 7661 7465 611d
4d6f 6e2c 2032 3120 4f63 7420 3230 3133
2032 303a 3133 3a32 3120 474d 546e 1768
7474 7073 3a2f 2f77 7777 2e65 7861 6d70
6c65 2e63 6f6d"""),
            want : @[
                pair(":status", "302"),
                pair("cache-control", "private"),
                pair("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                pair("location", "https://www.example.com"),
            ],
            wantDynTab : @[
                pair("location", "https://www.example.com"),
                pair("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                pair("cache-control", "private"),
                pair(":status", "302"),
            ],
            wantDynSize : 222,
        ),
        encAndWant(
            enc : dehex("""4803 3330 37c1 c0bf"""),
            want : @[
                pair(":status", "307"),
                pair("cache-control", "private"),
                pair("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                pair("location", "https://www.example.com"),
            ],
            wantDynTab : @[
                pair(":status", "307"),
                pair("location", "https://www.example.com"),
                pair("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                pair("cache-control", "private"),
            ],
            wantDynSize : 222,
        ),
        encAndWant(
            enc : dehex("""88c1 611d 4d6f 6e2c 2032 3120 4f63 7420
3230 3133 2032 303a 3133 3a32 3220 474d
54c0 5a04 677a 6970 7738 666f 6f3d 4153
444a 4b48 514b 425a 584f 5157 454f 5049
5541 5851 5745 4f49 553b 206d 6178 2d61
6765 3d33 3630 303b 2076 6572 7369 6f6e
3d31"""),
            want : @[
                pair(":status", "200"),
                pair("cache-control", "private"),
                pair("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
                pair("location", "https://www.example.com"),
                pair("content-encoding", "gzip"),
                pair("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"),
            ],
            wantDynTab : @[
                pair("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"),
                pair("content-encoding", "gzip"),
                pair("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
            ],
            wantDynSize : 215,
        ),
    ]
    for i, tt in tests.pairs:
        test "test case " & $(i+1):
            testDecodeSeries(d, tt)

suite "testing decode c6 response (huffman)":
    var d = newDecoder(256, nil)
    var tests = @[
        encAndWant(
            enc : dehex("""4882 6402 5885 aec3 771a 4b61 96d0 7abe
9410 54d4 44a8 2005 9504 0b81 66e0 82a6
2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8
e9ae 82ae 43d3"""),
            want : @[
                pair(":status", "302"),
                pair("cache-control", "private"),
                pair("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                pair("location", "https://www.example.com"),
            ],
            wantDynTab : @[
                pair("location", "https://www.example.com"),
                pair("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                pair("cache-control", "private"),
                pair(":status", "302"),
            ],
            wantDynSize : 222,
        ),
        encAndWant(
            enc : dehex("""4883 640e ffc1 c0bf"""),
            want : @[
                pair(":status", "307"),
                pair("cache-control", "private"),
                pair("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                pair("location", "https://www.example.com"),
            ],
            wantDynTab : @[
                pair(":status", "307"),
                pair("location", "https://www.example.com"),
                pair("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                pair("cache-control", "private"),
            ],
            wantDynSize : 222,
        ),
        encAndWant(
            enc : dehex("""88c1 6196 d07a be94 1054 d444 a820 0595
040b 8166 e084 a62d 1bff c05a 839b d9ab
77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b
3960 d5af 2708 7f36 72c1 ab27 0fb5 291f
9587 3160 65c0 03ed 4ee5 b106 3d50 07"""),
            want : @[
                pair(":status", "200"),
                pair("cache-control", "private"),
                pair("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
                pair("location", "https://www.example.com"),
                pair("content-encoding", "gzip"),
                pair("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"),
            ],
            wantDynTab : @[
                pair("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"),
                pair("content-encoding", "gzip"),
                pair("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
            ],
            wantDynSize : 215,
        ),
    ]
    for i, tt in tests.pairs:
        test "test case " & $(i+1):
            testDecodeSeries(d, tt)

suite "testing huffman decode excess padding":
    var testcases : seq[seq[byte]] = @[
        @[0xff'u8],
        @[0x1f'u8, 0xff],
        @[0x1f'u8, 0xff, 0xff],
        @[0x1f'u8, 0xff, 0xff, 0xff],
        @[0xff'u8, 0x9f, 0xff, 0xff, 0xff],
        @['R'.uint8, 0xbc, '0'.uint8, 0xff, 0xff, 0xff, 0xff]
    ]
    setup:
        var b = memoryOutput()
    for i, tt in testcases.pairs:
        test "test case: " & $(i+1):
            expect(InvalidHuffmanError):
                discard huffmanDecode(b, tt)

test "testing huffman decode EOS":
    var b = memoryOutput()
    var `in` = @[0xff'u8, 0xff, 0xff, 0xff, 0xfc]
    expect(InvalidHuffmanError):
        discard huffmanDecode(b, `in`)

test "testing huffman decode max length on trailing byte":
    var `in` = @[0x00'u8, 0x01]
    var b = memoryOutput()
    expect(StringLengthError):
        huffmanDecode(b, 2, `in`)

test "testing huffman decode corrupted padding":
    var `in` = @[0x01'u8]
    var b = memoryOutput()
    expect(InvalidHuffmanError):
        huffmanDecode(b, 2, `in`)

suite "testing huffman decode":
    type testcase = object
        inHex, want : string
    var testcases = @[
        testcase(
            inHex : "f1e3 c2e5 f23a 6ba0 ab90 f4ff", want : "www.example.com"
        ),
        testcase(
            inHex : "a8eb 1064 9cbf", want : "no-cache"
        ),
        testcase(
            inHex : "25a8 49e9 5ba9 7d7f", want : "custom-key"
        ),
        testcase(
            inHex : "25a8 49e9 5bb8 e8b4 bf", want : "custom-value"
        ),
        testcase(
            inHex : "6402", want : "302"
        ),
        testcase(
            inHex : "aec3 771a 4b", want : "private"
        ),
        testcase(
            inHex : "d07a be94 1054 d444 a820 0595 040b 8166 e082 a62d 1bff", want : "Mon, 21 Oct 2013 20:13:21 GMT"
        ),
        testcase(
            inHex : "9d29 ad17 1863 c78f 0b97 c8e9 ae82 ae43 d3", want : "https://www.example.com"
        ),
        testcase(
            inHex : "9bd9 ab", want : "gzip"
        ),
        testcase(
            inHex : "94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f 9587 3160 65c0 03ed 4ee5 b106 3d50 07",
            want : "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"
        ),
    ]
    setup:
        var b = memoryOutput()
    for i, tt in testcases.pairs:
        test "test case: " & $(i+1):
            var s = parseHexStr(replace(tt.inHex, " "))
            discard huffmanDecode(b, cast[seq[byte]](s))
            check(b.getOutput(string) == tt.want)

suite "testing append huffman string":
    type testcase = object
        `in`, want : string
    var testcases = @[
        testcase(
            want : "f1e3 c2e5 f23a 6ba0 ab90 f4ff", `in` : "www.example.com"
        ),
        testcase(
            want : "a8eb 1064 9cbf", `in` : "no-cache"
        ),
        testcase(
            want : "25a8 49e9 5ba9 7d7f", `in` : "custom-key"
        ),
        testcase(
            want : "25a8 49e9 5bb8 e8b4 bf", `in` : "custom-value"
        ),
        testcase(
            want : "6402", `in` : "302"
        ),
        testcase(
            want : "aec3 771a 4b", `in` : "private"
        ),
        testcase(
            want : "d07a be94 1054 d444 a820 0595 040b 8166 e082 a62d 1bff", `in` : "Mon, 21 Oct 2013 20:13:21 GMT"
        ),
        testcase(
            want : "9d29 ad17 1863 c78f 0b97 c8e9 ae82 ae43 d3", `in` : "https://www.example.com"
        ),
        testcase(
            want : "9bd9 ab", `in` : "gzip"
        ),
        testcase(
            want : "94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f 9587 3160 65c0 03ed 4ee5 b106 3d50 07",
            `in` : "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"
        ),
    ]
    setup:
        var b : seq[byte] = @[]
    for i, tt in testcases.pairs:
        test "test case: " & $(i+1):
            var s = replace(tt.want, " ")
            appendHuffmanString(b, tt.`in`)
            check(toLowerAscii(toHex(cast[string](b))) == s)

test "testing huffman max string length":
    var msg = "Some string"
    var store : seq[byte] = @[]
    appendHuffmanString(store, msg)
    var testgood = proc(max : int) = 
        var s = memoryOutput()
        huffmanDecode(s, max, store)
        check(s.getOutput(string) == msg)
    testgood(0)
    testgood(msg.len())
    testgood(msg.len() + 1)
    var s = memoryOutput()
    expect(StringLengthError):
        huffmanDecode(s, msg.len()-1, store)

test "testing huffman roundtrip stress":
    let len = 50
    var input = newSeq[byte](len)
    var output = memoryOutput()
    var huff : seq[byte] = @[]
    var n = 5000
    var encSize : int64
    for i in 0..<n:
        for l in 0..<input.len():
            input[l] = rand(256).byte
        appendHuffmanString(huff, cast[string](input))
        defer: huff = @[]
        encSize += len(huff).int64
        huffmanDecode(output, 0, huff)
        check(output.getOutput == input)
        output.recycleBuffers(nil)

test "testing huffman decode fuzz":
    var len = 50
    var buf = memoryOutput()
    var zbuf = memoryOutput()
    var n = 5000
    var numfail = 0
    for i in 0..<n:
        defer:
            zbuf.recycleBuffers(nil)
        if i == 0:
            for i in "00\x91\xff\xff\xff\xff\xc8": zbuf.write(i.byte)
        else:
            for l in 0..<len: zbuf.write(rand(256).byte)
        defer:
            buf.recycleBuffers(nil)
        try:
            huffmanDecode(buf, 0, zbuf.getOutput())
        except InvalidHuffmanError:
            inc(numfail)
        except:
            check(false)
    check(numfail >= 1)

suite "testing read var int":
    type 
        res = object
            i : uint64
            consumed : int
            err : ref Exception
        testcase = object
            n : byte
            p : seq[byte]
            want : res
    var needmore : ref NeedMoreError
    new(needmore)
    needmore.msg = "need more data"
    var varintoverflow : ref DecodeError
    new(varintoverflow)
    varintoverflow.msg = "decoding error: varint integer overflow"
    var testcases = @[
        # Fits in a byte:
        testcase(n : 1.byte, p : @[0'u8], want : res(i : 0, consumed : 1)),
        testcase(n : 2.byte, p : @[2'u8], want : res(i : 2, consumed : 1)),
        testcase(n : 3.byte, p : @[6'u8], want : res(i : 6, consumed : 1)),
        testcase(n : 4.byte, p : @[14'u8], want : res(i : 14, consumed : 1)),
        testcase(n : 5.byte, p : @[30'u8], want : res(i : 30, consumed : 1)),
        testcase(n : 6.byte, p : @[62'u8], want : res(i : 62, consumed : 1)),
        testcase(n : 7.byte, p : @[126'u8], want : res(i : 126, consumed : 1)),
        testcase(n : 8.byte, p : @[254'u8], want : res(i : 254, consumed : 1)),
        # Doesn't fit in a byte:
        testcase(n : 1.byte, p : @[1'u8], want : res(i : 0, consumed : 0, err : needMore)),
        testcase(n : 2.byte, p : @[3'u8], want : res(i : 0, consumed : 0, err : needMore)),
        testcase(n : 3.byte, p : @[7'u8], want : res(i : 0, consumed : 0, err : needMore)),
        testcase(n : 4.byte, p : @[15'u8], want : res(i : 0, consumed : 0, err : needMore)),
        testcase(n : 5.byte, p : @[31'u8], want : res(i : 0, consumed : 0, err : needMore)),
        testcase(n : 6.byte, p : @[63'u8], want : res(i : 0, consumed : 0, err : needMore)),
        testcase(n : 7.byte, p : @[127'u8], want : res(i : 0, consumed : 0, err : needMore)),
        testcase(n : 8.byte, p : @[255'u8], want : res(i : 0, consumed : 0, err : needMore)),
        # Ignoring top bits:
        testcase(n : 5.byte, p : @[255'u8, 154, 10], want : res(i : 1337, consumed : 3)), # high dummy three bits: 111
        testcase(n : 5.byte, p : @[159'u8, 154, 10], want : res(i : 1337, consumed : 3)), # high dummy three bits: 100
        testcase(n : 5.byte, p : @[191'u8, 154, 10], want : res(i : 1337, consumed : 3)), # high dummy three bits: 101
        # Extra byte:
        testcase(n : 5.byte, p : @[191'u8, 154, 10, 2], want : res(i : 1337, consumed : 3)), # extra byte
        # Short a byte:
        testcase(n : 5.byte, p : @[191'u8, 154], want : res(i : 0, consumed: 0, err : needMore)),
        # integer overflow:
        testcase(n : 1.byte, p : @[255'u8, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128], want : res(i : 0, consumed : 0, err : varintoverflow))
    ]
    for i, tt in testcases.pairs:
        test "test case: " & $(i+1):
            try:
                var (j, remain) = readVarInt(tt.n, tt.p)
                var consumed = len(tt.p) - len(remain)
                check(tt.want.i == j)
                check(tt.want.consumed == consumed)
            # finally: discard
            except:
                check(tt.want.err.name == getCurrentException().name)
                check(tt.want.err.msg == getCurrentExceptionMsg())

test "testing huffman fuzz crash":
    expect(InvalidHuffmanError):
        discard huffmanDecodeToString(cast[seq[byte]]("00\x91\xff\xff\xff\xff\xc8"))

test "testing emit enabled":
    var s = memoryOutput()
    var enc = newEncoder(s)
    enc.writeField(Headerfield(name : "foo", value : "bar"))
    enc.writeField(Headerfield(name : "foo", value : "bar"))
    var numCallback = 0
    var dec : Decoder
    dec = newDecoder(8 shl 20, proc(_ : Headerfield) =
        inc(numCallback)
        dec.setEmitEnabled(false)
    )
    check(dec.checkEmitEnabled())
    dec.write(s.getOutput)
    check(numCallback == 1)
    check(not dec.checkEmitEnabled())

test "testing save buf limit":
    let maxStr = 1 shl 10
    var got : seq[Headerfield]
    var dec = newDecoder(4096, proc(hf : Headerfield) =
        got.add(hf)
    )
    dec.setMaxStringLength(maxStr)
    var frag : seq[byte]
    frag.add(encodeTypeByte(false, false))
    appendVarInt(frag, 7, 3)
    for c in "foo": frag.add(c.byte)
    appendVarInt(frag, 7, 3)
    for c in "bar": frag.add(c.byte)
    dec.write(frag)
    
    var want = @[pair("foo", "bar")]
    check(got == want)
    
    frag = frag[0..<0]
    frag.add(encodeTypeByte(false, false))
    appendVarInt(frag, 7, uint64(maxStr*3))
    for c in newSeq[byte](maxStr*3): frag.add(c.byte)
    
    expect(StringLengthError):
        discard dec.write(frag)

test "dynamic size update":
    var b = memoryOutput()
    defer: b.close()
    var enc = newEncoder(b)
    enc.setMaxDynamicTableSize(255)
    enc.writeField(pair("foo", "bar"))
    
    var dec = newDecoder(4096, func(_ : Headerfield) = discard)
    var data: seq[byte] = b.getOutput
    dec.write(data)
    dec.close()
    
    dec.write(data)
    
    expect(DecodeError):
        discard dec.write(data)
