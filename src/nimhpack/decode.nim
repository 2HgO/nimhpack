import faststreams

from errors import NeedMoreError, raiseDecodeError, raiseIndexError, raiseNeedMoreError, raiseStringLengthError, StringLengthError
from huffman import huffmanDecode
from table import Headerfield, add, dynamicTable, len, newHeaderFieldTable, setMaxSize, size, staticTable

type
    Decoder* = ref DecoderObj
    DecoderObj = object
        dynTab* : dynamicTable
        emit : proc(hf : Headerfield)
        emitEnabled : bool
        maxStrLen : int
        buf : seq[byte]
        saveBuf : OutputStream
        firstField : bool
    indexType = enum
        indexedTrue=0
        indexedFalse=1
        indexedNever=2


# proc dynTab*(d: Decoder) : lent dynamicTable {.inline.} = d.dynTab
proc emit*(d: Decoder) : proc(hf : Headerfield) = d.emit
proc emitEnabled*(d: Decoder) : bool {.inline.} = d.emitEnabled
proc maxStrLen*(d: Decoder) : int {.inline.} = d.maxStrLen
proc buf*(d: Decoder) : lent seq[byte] {.inline.} = d.buf
proc firstField*(d: Decoder) : bool {.inline.} = d.firstField

func indexed(i : indexType) : bool {.inline.} = result = i == indexedTrue
func sensitive(i : indexType) : bool {.inline.} = result =  i == indexedNever

proc newDecoder*(maxDynamicTableSize : uint32, emitFunc : proc(hf : HeaderField)) : Decoder =
    var d = Decoder(
        emit : emitFunc,
        emitEnabled : true,
        firstField : true,
        saveBuf : memoryOutput()
    )
    d.dynTab.table = newHeaderFieldTable()
    d.dynTab.allowedMaxSize = maxDynamicTableSize
    d.dynTab.setMaxSize(maxDynamicTableSize)
    return d

proc decodeFull*(d : Decoder, p : seq[byte]) : seq[Headerfield]
proc close*(d : Decoder)
proc write*(d : Decoder, p : seq[byte]) : int {.discardable.}
proc parseHeaderFieldRepr(d : Decoder)
proc parseFieldIndexed(d : Decoder)
proc parseFieldLiteral(d : Decoder, n : uint8, it : indexType)
proc callEmit(d : Decoder, hf : Headerfield)
proc parseDynamicTableSizeUpdate(d : Decoder)
proc readString(d : Decoder, p : seq[byte], wantStr : bool) : (string, seq[byte])

proc readVarInt*(n : byte, p : seq[byte]) : (uint64, seq[byte])

proc setMaxStringLength*(d : Decoder, n : int) {.inline.} =
    d.maxStrLen = n
proc setEmitFunc*(d : Decoder, emitFunc : proc(hf : HeaderField)) {.inline.} =
    d.emit = emitFunc
proc setEmitEnabled*(d : Decoder, v : bool) {.inline.} =
    d.emitEnabled = v
proc checkEmitEnabled*(d : Decoder) : bool {.inline.} =
    result = d.emitEnabled
proc setMaxDynamicTableSize*(d : Decoder, v : uint32) {.inline.} =
    d.dynTab.setMaxSize(v)
proc setAllowedMaxDynamicTableSize*(d : Decoder, v : uint32) {.inline.} =
    d.dynTab.allowedMaxSize = v

proc maxTableIndex(d : Decoder) : int {.inline.} =
    result = d.dynTab.table.len() + staticTable.len()

proc at*(d : Decoder, i : uint64) : (Headerfield, bool) =
    if i == 0: return
    if i <= staticTable.len().uint64: return (staticTable.ents[i-1], true)
    if i > d.maxTableIndex().uint64: return
    var dt = d.dynTab.table
    result = (dt.ents[dt.len()-(int(i)-staticTable.len())], true)

proc decodeFull*(d : Decoder, p : seq[byte]) : seq[Headerfield] =
    var hf : seq[Headerfield]
    var saveFunc = d.emit
    defer:
        d.emit = saveFunc
    d.emit = proc(f : Headerfield) = hf.add(f)
    d.write(p)
    d.close()
    return hf

proc close*(d : Decoder) =
    if d.saveBuf.pos != 0:
        d.saveBuf.recycleBuffers(nil)
        raiseDecodeError("truncated headers")
    d.firstField = true

proc write*(d : Decoder, p : seq[byte]) : int {.discardable.} =
    if len(p) == 0: return
    if d.saveBuf.pos == 0:
        d.buf = p
    else:
        d.saveBuf.write(p)
        d.buf = d.saveBuf.getOutput()
    while d.buf.len() > 0:
        try:
            d.parseHeaderFieldRepr()
            d.firstField = false
        except NeedMoreError:
            const varIntOverhead = 8
            if (d.maxStrLen != 0) and (d.buf.len().int64 > 2*(d.maxStrLen.int64 + varIntOverhead)): raiseStringLengthError()
            for i in d.buf: d.saveBuf.write(i)
            return len(p)
        except StringLengthError:
            raise
        except:
            d.firstField = false
            result = len(p)
            raise
    result = len(p)
  
proc parseHeaderFieldRepr(d : Decoder) =
    var b = d.buf[0]
    if (b and 128) != 0: d.parseFieldIndexed()
    elif (b and 192) == 64: d.parseFieldLiteral(6, indexedTrue)
    elif (b and 240) == 0: d.parseFieldLiteral(4, indexedFalse)
    elif (b and 240) == 16: d.parseFieldLiteral(4, indexedNever)
    elif (b and 224) == 32: d.parseDynamicTableSizeUpdate()
    else: raiseDecodeError("invalid encoding")

proc parseFieldIndexed(d : Decoder) =
    var b = d.buf
    var idx : uint64
    (idx, b) = readVarInt(7, b)
    var (hf, ok) = d.at(idx)
    if not ok: raiseIndexError(idx.int)
    d.buf = b
    d.callEmit(Headerfield(name: hf.name, value: hf.value))

proc parseFieldLiteral(d : Decoder, n : uint8, it : indexType) =
    var b = d.buf
    var idx : uint64
    (idx, b) = readVarInt(n, b)
    var hf : Headerfield
    var wantStr = d.emitEnabled or it.indexed()
    if idx > 0:
        var (ihf, ok) = d.at(idx)
        if not ok: raiseIndexError(idx.int)
        hf.name = ihf.name
    else:
        (hf.name, b) = d.readString(b, wantStr)
    (hf.value, b) = d.readString(b, wantStr)
    d.buf = b
    if it.indexed(): d.dynTab.add(hf)
    hf.sensitive = it.sensitive
    d.callEmit(hf)

proc callEmit(d : Decoder, hf : Headerfield) =
    if d.maxStrLen != 0:
        if (hf.name.len() > d.maxStrLen) or (hf.value.len() > d.maxStrLen): raiseStringLengthError()
    if d.emitEnabled: d.emit(hf)

proc parseDynamicTableSizeUpdate(d : Decoder) =
    if (not d.firstField) and (d.dynTab.size > 0): raiseDecodeError("dynamic table size update MUST occur at the beginning of a header block")
    var b = d.buf
    var size : uint64
    (size, b) = readVarInt(5, b)
    if size > d.dynTab.allowedMaxSize.uint64: raiseDecodeError("dynamic table size update too large")
    d.dynTab.setMaxSize(size.uint32)
    d.buf = b

proc readString(d : Decoder, p : seq[byte], wantStr : bool) : (string, seq[byte]) =
    var copy = p
    var strLen : uint64
    var s : string
    if p.len() == 0: raiseNeedMoreError()
    var isHuff = (p[0] and 128) != 0
  
    (strLen, copy) = readVarInt(7, copy)
    if (d.maxStrLen != 0) and (strLen > d.maxStrLen.uint64): raiseStringLengthError()
    if copy.len().uint64 < strLen: raiseNeedMoreError()
    if not isHuff:
        if wantStr:
            s = cast[string](copy[0..<strLen])
        return (s, copy[strLen..^1])
    if wantStr:
        var b : OutputStream = memoryOutput()
        defer: b.close()
        huffmanDecode(b, d.maxStrLen, copy[0..<strLen])
        s = b.getOutput(string)
    return (s, copy[strLen..^1])

proc readVarInt*(n : byte, p : seq[byte]) : (uint64, seq[byte]) =
    if (n < 1) or (n > 8): raise newException(ValueError, "bad n")
    if p.len() == 0: raiseNeedMoreError()
    var i = p[0].uint64
    if n < 8:
        i = i and ((1 shl n.uint64) - 1).uint64
    if i < ((1 shl n.uint64) - 1).uint64:
        return (i, p[1..^1])
    var copy = p[1..^1]
    var m : uint64
    while copy.len() > 0:
        var b = copy[0]
        copy = copy[1..^1]
        i = i + ((b and 127).uint64 shl m)
        if (b and 128) == 0:
            return (i, copy)
        m += 7
        if m >= 63:
            result = (0'u64, p)
            raiseDecodeError("varint integer overflow")
    raiseNeedMoreError()
