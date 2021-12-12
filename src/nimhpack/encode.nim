import faststreams

from huffman import appendHuffmanString, huffmanEncodeLength
from table import Headerfield, add, dynamicTable, len, newHeaderFieldTable, search, setMaxSize, size, staticTable

const
    uint32max = high(uint32)
    initialHeaderTableSize = 4096

type
    Encoder* = ref EncoderObj
    EncoderObj = object
        dynTab* : dynamicTable
        minSize : uint32
        maxSizeLimit : uint32
        tableSizeUpdate : bool
        w : OutputStream
        buf : seq[byte]

proc minSize*(e: Encoder) : uint32 {.inline.} = e.minSize
proc maxSizeLimit*(e: Encoder) : uint32 {.inline.} = e.maxSizeLimit
proc tableSizeUpdate*(e: Encoder) : bool {.inline.} = e.tableSizeUpdate
proc buf*(e: Encoder) : lent seq[byte] {.inline.} = e.buf

proc newEncoder*(w : OutputStream) : Encoder =
    var e = Encoder(
        minSize: uint32max,
        maxSizeLimit: initialHeaderTableSize,
        tableSizeUpdate : false,
        w : w,
    )
    e.dynTab.table = newHeaderFieldTable()
    e.dynTab.setMaxSize(initialHeaderTableSize)
    return e

proc writeField*(e : Encoder, hf : Headerfield)
proc searchTable*(e : Encoder, hf : Headerfield) : (uint64, bool)
proc setMaxDynamicTableSize*(e : Encoder, v : uint32)
proc setMaxDynamicTableSizeLimit*(e : Encoder, v : uint32)
proc shouldIndex(e : Encoder, hf : Headerfield) : bool {.inline.}
proc appendIndexed*(dst : var seq[byte], i : uint64)
proc appendNewName*(dst : var seq[byte], hf : Headerfield, indexing : bool)
proc appendIndexedName*(dst : var seq[byte], hf : Headerfield, i : uint64, indexing : bool)
proc appendTableSize*(dst : var seq[byte], v : uint32)
proc appendVarInt*(dst : var seq[byte], n : byte, i : uint64)
proc appendHpackString*(dst : var seq[byte], s : string)
proc encodeTypeByte*(indexing, sensitive : bool) : byte

proc writeField*(e : Encoder, hf : Headerfield) =
    e.buf = e.buf[0..<0]
    if e.tableSizeUpdate:
        e.tableSizeUpdate = false
        if e.minSize < e.dynTab.maxSize:
            appendTableSize(e.buf, e.minSize)
        e.minSize = uint32max
        appendTableSize(e.buf, e.dynTab.maxSize)
    var (idx, nameValueMatch) = e.searchTable(hf)
    if nameValueMatch:
        appendIndexed(e.buf, idx)
    else:
        var indexing = e.shouldIndex(hf)
        if indexing: e.dynTab.add(hf)
        if idx == 0:
            appendNewName(e.buf, hf, indexing)
        else:
            appendIndexedName(e.buf, hf, idx, indexing)
    var init = e.w.pos
    e.w.write(e.buf)
    if e.w.pos - init != e.buf.len(): raise newException(IOError, "short write")

proc searchTable*(e : Encoder, hf : Headerfield) : (uint64, bool) =
    var (i, nameValueMatch) = staticTable.search(hf)
    if nameValueMatch: return (i, nameValueMatch)
    var j : uint64
    (j, nameValueMatch) = e.dynTab.table.search(hf)
    if nameValueMatch or (i == 0 and j != 0): return (j + uint64(staticTable.len()), nameValueMatch)
    return (i, false)

proc setMaxDynamicTableSize*(e : Encoder, v : uint32) =
    var t = v
    if t > e.maxSizeLimit:
        t = e.maxSizeLimit
    if t < e.minSize:
        e.minSize = t
    e.tableSizeUpdate = true
    e.dynTab.setMaxSize(t)

proc setMaxDynamicTableSizeLimit*(e : Encoder, v : uint32) =
    e.maxSizeLimit = v
    if e.dynTab.maxSize > v:
        e.tableSizeUpdate = true
        e.dynTab.setMaxSize(v)

proc shouldIndex(e : Encoder, hf : Headerfield) : bool {.inline.} =
  result = (not hf.sensitive) and hf.size() <= e.dynTab.maxSize

proc appendIndexed(dst : var seq[byte], i : uint64) =
    var fst = len(dst)
    appendVarInt(dst, 7, i)
    dst[fst] = dst[fst] or 0x80

proc appendNewName*(dst : var seq[byte], hf : Headerfield, indexing : bool) =
    dst.add(encodeTypeByte(indexing, hf.sensitive))
    appendHpackString(dst, hf.name)
    appendHpackString(dst, hf.value)

proc appendIndexedName*(dst : var seq[byte], hf : Headerfield, i : uint64, indexing : bool) =
    var fst = len(dst)
    var n : byte = if indexing: 6 else: 4
    appendVarInt(dst, n, i)
    dst[fst] = dst[fst] or encodeTypeByte(indexing, hf.sensitive)
    appendHpackString(dst, hf.value)

proc appendTableSize*(dst : var seq[byte], v : uint32) =
    var fst = len(dst)
    appendVarInt(dst, 5, v.uint64)
    dst[fst] = dst[fst] or 0x20

proc appendVarInt*(dst : var seq[byte], n : byte, i : uint64) =
    var k = uint64((1 shl n) - 1)
    if i < k:
        dst.add(i.byte)
        return
    dst.add(k.byte)
    var j = i - k

    while j >= 128:
        dst.add(byte(0x80 or (j and 0x7f)))
        j = j shr 7
    dst.add(j.byte)

proc appendHpackString*(dst : var seq[byte], s : string) =
    var huffmanLength = huffmanEncodeLength(s)
    if huffmanLength < s.len().uint64:
        var fst = len(dst)
        appendVarInt(dst, 7, huffmanLength)
        appendHuffmanString(dst, s)
        dst[fst] = dst[fst] or 0x80
    else:
        appendVarInt(dst, 7, s.len().uint64)
        dst.add(cast[seq[byte]](s))

proc encodeTypeByte(indexing, sensitive : bool) : byte =
    if sensitive: return 0x10
    elif indexing: return 0x40
    else: return 0
