import faststreams

from table import huffmanCodes, huffmanCodeLen
from errors import raiseHuffmanError, raiseStringLengthError

type
    node = ref object
        children : ref array[256, node]
        codeLen : uint8
        sym : byte

proc huffmanDecode*(w : OutputStream, v : seq[byte]) : int
proc huffmanDecodeToString*(v : seq[byte]) : string
proc huffmanDecode*(buf : OutputStream, maxLen : int, v : seq[byte])
proc newInternalNode() : node {.inline.}
proc addDecoderNode(sym : byte, code : uint32, codeLen : uint8)
proc getRootHuffmanNode() : node
proc buildRootHuffmanNode()
proc appendHuffmanString*(dst : var seq[byte], s : string)
proc huffmanEncodeLength*(s : string) : uint64
proc appendByteToHuffmanCode(dst : var seq[byte], rembits : uint8, c : byte) : uint8

func `==`*(a, b: node) : bool {.error: "cannot compare two nodes".}

var lazyRootHuffmanNode : node

proc huffmanDecode*(w : OutputStream, v : seq[byte]) : int =
    var buf : OutputStream = memoryOutput()
    defer: buf.close()
    var init = w.pos
    huffmanDecode(buf, 0, v)
    w.write(buf.getOutput())
    return w.pos - init

proc huffmanDecodeToString*(v : seq[byte]) : string =
    var buf : OutputStream = memoryOutput()
    defer: buf.close()

    huffmanDecode(buf, 0, v)
    result = buf.getOutput(string)
    return

proc huffmanDecode*(buf : OutputStream, maxLen : int, v : seq[byte]) =
    var root = getRootHuffmanNode()
    var n = root
    var (cur, cbits, sbits) = (0'u, 0'u8, 0'u8)
    for b in v:
        cur = (cur shl 8) or b.uint
        cbits += 8
        sbits += 8
        while cbits >= 8:
            var idx = byte(cur shr (cbits - 8))
            n = n.children[idx]
            if n.isNil: raiseHuffmanError()
            if n.children.isNil:
                if maxLen != 0 and buf.pos == maxLen: raiseStringLengthError()
                buf.write(n.sym)
                cbits -= n.codeLen
                n = root
                sbits = cbits
            else:
                cbits -= 8
    while cbits > 0:
        n = n.children[byte(cur shl (8 - cbits))]
        if n.isNil: raiseHuffmanError()
        if not n.children.isNil or n.codeLen > cbits: break
        if maxLen != 0 and buf.pos == maxLen: raiseStringLengthError()
        buf.write(n.sym)
        cbits -= n.codeLen
        n = root
        sbits = cbits
    if sbits > 7: raiseHuffmanError()
    let mask = uint((1 shl cbits) - 1)
    if (cur and mask) != mask: raiseHuffmanError()

proc newInternalNode() : node =
    node(children : new array[256, node])

proc addDecoderNode(sym : byte, code : uint32, codeLen : uint8) =
    var cl = codeLen
    var cur = lazyRootHuffmanNode
    while cl > 8'u8:
        cl = cl - 8'u8
        let i = (code shr cl).uint8
        if cur.children[i].isNil: cur.children[i] = newInternalNode()
        cur = cur.children[i]
    let shift = 8 - cl
    let (start, `end`) = (((code shl shift).uint8).int, (1 shl shift).int)
    for i in start..<(start+`end`):
        cur.children[i] = node(sym : sym, codeLen : cl)

proc buildRootHuffmanNode() =
    static: assert len(huffmanCodes) == 256, "unexpected size"
    lazyRootHuffmanNode = newInternalNode()
    for i, code in huffmanCodes.pairs:
        addDecoderNode(byte(i), code, huffmanCodeLen[i])

proc getRootHuffmanNode() : node =
    once:
        buildRootHuffmanNode()
    return lazyRootHuffmanNode

proc appendHuffmanString*(dst : var seq[byte], s : string) =
    var rembits = 8'u8
    for i in 0..<s.len():
        if rembits == 8: dst.add(0)
        rembits = appendByteToHuffmanCode(dst, rembits, s[i].byte)
    if rembits < 8:
        var code = 0x3fffffff'u32
        var nbits = 30'u8
        var t = uint8(code shr (nbits - rembits))
        dst[high(dst)] = dst[high(dst)] or t

proc huffmanEncodeLength*(s : string) : uint64 =
    var n = 0'u64
    for i in 0..<len(s):
        n += uint64(huffmanCodeLen[s[i].uint8])
    return uint64((n + 7).float64 / 8)

proc appendByteToHuffmanCode(dst : var seq[byte], rembits : uint8, c : byte) : uint8 =
    var r = rembits
    var code = huffmanCodes[c]
    var nbits = huffmanCodeLen[c]
    while true:
        if r > nbits:
            var t = uint8(code shl (r - nbits))
            dst[high(dst)] = dst[high(dst)] or t
            r -= nbits
            break
        var t = uint8(code shr (nbits - r))
        dst[high(dst)] = dst[high(dst)] or t
        nbits -= r
        r = 8'u8
        if nbits == 0: break
        dst.add(0)
    return r
