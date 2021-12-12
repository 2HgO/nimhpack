from hashes import Hash, hash, `!&`
from strformat import fmt
from tables import Table, initTable, del, hasKey, getOrDefault, `[]`, `[]=`

type
    Headerfield* = object
        name* : string
        value* : string
        sensitive* : bool
    pairNameValue* = object
        name : string
        value : string
    headerFieldTable* = ref object
        ents* : seq[Headerfield]
        evictCount : uint64
        byName : Table[string, uint64]
        byNameValue : Table[pairNameValue, uint64]
    dynamicTable* = object
        table* : headerFieldTable
        size* : uint32
        maxSize* : uint32
        allowedMaxSize* : uint32


proc evictCount*(h: headerFieldTable) : uint64 {.inline.} = h.evictCount
proc byName*(h: headerFieldTable) : Table[string, uint64] {.inline.} = h.byName
proc byNameValue*(h: headerFieldTable) : Table[pairNameValue, uint64] {.inline.} = h.byNameValue

proc newStaticTable() : headerFieldTable

proc isPseudo*(hf : Headerfield) : bool
proc `$`*(hf : Headerfield) : string
proc size*(hf : Headerfield) : uint32

func newHeaderFieldTable*() : headerFieldTable
func addEntry*(h : headerFieldTable, hf : Headerfield)
func evictOldest*(h : headerFieldTable, n : int)
proc search*(h : headerFieldTable, hf : Headerfield) : (uint64, bool)
proc idToIndex(h : headerFieldTable, id : uint64) : uint64

proc setMaxSize*(dt : var dynamicTable, v : uint32)
proc add*(dt : var dynamicTable, hf : Headerfield)
proc evict*(dt : var dynamicTable)

const
    staticTableEntries : array[61, Headerfield] = [
        Headerfield(name: ":authority", value: ""),
        Headerfield(name: ":method", value: "GET"),
        Headerfield(name: ":method", value: "POST"),
        Headerfield(name: ":path", value: "/"),
        Headerfield(name: ":path", value: "/index.html"),
        Headerfield(name: ":scheme", value: "http"),
        Headerfield(name: ":scheme", value: "https"),
        Headerfield(name: ":status", value: "200"),
        Headerfield(name: ":status", value: "204"),
        Headerfield(name: ":status", value: "206"),
        Headerfield(name: ":status", value: "304"),
        Headerfield(name: ":status", value: "400"),
        Headerfield(name: ":status", value: "404"),
        Headerfield(name: ":status", value: "500"),
        Headerfield(name: "accept-charset", value: ""),
        Headerfield(name: "accept-encoding", value: "gzip, deflate"),
        Headerfield(name: "accept-language", value: ""),
        Headerfield(name: "accept-ranges", value: ""),
        Headerfield(name: "accept", value: ""),
        Headerfield(name: "access-control-allow-origin", value: ""),
        Headerfield(name: "age", value: ""),
        Headerfield(name: "allow", value: ""),
        Headerfield(name: "authorization", value: ""),
        Headerfield(name: "cache-control", value: ""),
        Headerfield(name: "content-disposition", value: ""),
        Headerfield(name: "content-encoding", value: ""),
        Headerfield(name: "content-language", value: ""),
        Headerfield(name: "content-length", value: ""),
        Headerfield(name: "content-location", value: ""),
        Headerfield(name: "content-range", value: ""),
        Headerfield(name: "content-type", value: ""),
        Headerfield(name: "cookie", value: ""),
        Headerfield(name: "date", value: ""),
        Headerfield(name: "etag", value: ""),
        Headerfield(name: "expect", value: ""),
        Headerfield(name: "expires", value: ""),
        Headerfield(name: "from", value: ""),
        Headerfield(name: "host", value: ""),
        Headerfield(name: "if-match", value: ""),
        Headerfield(name: "if-modified-since", value: ""),
        Headerfield(name: "if-none-match", value: ""),
        Headerfield(name: "if-range", value: ""),
        Headerfield(name: "if-unmodified-since", value: ""),
        Headerfield(name: "last-modified", value: ""),
        Headerfield(name: "link", value: ""),
        Headerfield(name: "location", value: ""),
        Headerfield(name: "max-forwards", value: ""),
        Headerfield(name: "proxy-authenticate", value: ""),
        Headerfield(name: "proxy-authorization", value: ""),
        Headerfield(name: "range", value: ""),
        Headerfield(name: "referer", value: ""),
        Headerfield(name: "refresh", value: ""),
        Headerfield(name: "retry-after", value: ""),
        Headerfield(name: "server", value: ""),
        Headerfield(name: "set-cookie", value: ""),
        Headerfield(name: "strict-transport-security", value: ""),
        Headerfield(name: "transfer-encoding", value: ""),
        Headerfield(name: "user-agent", value: ""),
        Headerfield(name: "vary", value: ""),
        Headerfield(name: "via", value: ""),
        Headerfield(name: "www-authenticate", value: "")
    ]

    huffmanCodes* : array[256, uint32] = [
        0x1ff8'u32,
        0x7fffd8,
        0xfffffe2,
        0xfffffe3,
        0xfffffe4,
        0xfffffe5,
        0xfffffe6,
        0xfffffe7,
        0xfffffe8,
        0xffffea,
        0x3ffffffc,
        0xfffffe9,
        0xfffffea,
        0x3ffffffd,
        0xfffffeb,
        0xfffffec,
        0xfffffed,
        0xfffffee,
        0xfffffef,
        0xffffff0,
        0xffffff1,
        0xffffff2,
        0x3ffffffe,
        0xffffff3,
        0xffffff4,
        0xffffff5,
        0xffffff6,
        0xffffff7,
        0xffffff8,
        0xffffff9,
        0xffffffa,
        0xffffffb,
        0x14,
        0x3f8,
        0x3f9,
        0xffa,
        0x1ff9,
        0x15,
        0xf8,
        0x7fa,
        0x3fa,
        0x3fb,
        0xf9,
        0x7fb,
        0xfa,
        0x16,
        0x17,
        0x18,
        0x0,
        0x1,
        0x2,
        0x19,
        0x1a,
        0x1b,
        0x1c,
        0x1d,
        0x1e,
        0x1f,
        0x5c,
        0xfb,
        0x7ffc,
        0x20,
        0xffb,
        0x3fc,
        0x1ffa,
        0x21,
        0x5d,
        0x5e,
        0x5f,
        0x60,
        0x61,
        0x62,
        0x63,
        0x64,
        0x65,
        0x66,
        0x67,
        0x68,
        0x69,
        0x6a,
        0x6b,
        0x6c,
        0x6d,
        0x6e,
        0x6f,
        0x70,
        0x71,
        0x72,
        0xfc,
        0x73,
        0xfd,
        0x1ffb,
        0x7fff0,
        0x1ffc,
        0x3ffc,
        0x22,
        0x7ffd,
        0x3,
        0x23,
        0x4,
        0x24,
        0x5,
        0x25,
        0x26,
        0x27,
        0x6,
        0x74,
        0x75,
        0x28,
        0x29,
        0x2a,
        0x7,
        0x2b,
        0x76,
        0x2c,
        0x8,
        0x9,
        0x2d,
        0x77,
        0x78,
        0x79,
        0x7a,
        0x7b,
        0x7ffe,
        0x7fc,
        0x3ffd,
        0x1ffd,
        0xffffffc,
        0xfffe6,
        0x3fffd2,
        0xfffe7,
        0xfffe8,
        0x3fffd3,
        0x3fffd4,
        0x3fffd5,
        0x7fffd9,
        0x3fffd6,
        0x7fffda,
        0x7fffdb,
        0x7fffdc,
        0x7fffdd,
        0x7fffde,
        0xffffeb,
        0x7fffdf,
        0xffffec,
        0xffffed,
        0x3fffd7,
        0x7fffe0,
        0xffffee,
        0x7fffe1,
        0x7fffe2,
        0x7fffe3,
        0x7fffe4,
        0x1fffdc,
        0x3fffd8,
        0x7fffe5,
        0x3fffd9,
        0x7fffe6,
        0x7fffe7,
        0xffffef,
        0x3fffda,
        0x1fffdd,
        0xfffe9,
        0x3fffdb,
        0x3fffdc,
        0x7fffe8,
        0x7fffe9,
        0x1fffde,
        0x7fffea,
        0x3fffdd,
        0x3fffde,
        0xfffff0,
        0x1fffdf,
        0x3fffdf,
        0x7fffeb,
        0x7fffec,
        0x1fffe0,
        0x1fffe1,
        0x3fffe0,
        0x1fffe2,
        0x7fffed,
        0x3fffe1,
        0x7fffee,
        0x7fffef,
        0xfffea,
        0x3fffe2,
        0x3fffe3,
        0x3fffe4,
        0x7ffff0,
        0x3fffe5,
        0x3fffe6,
        0x7ffff1,
        0x3ffffe0,
        0x3ffffe1,
        0xfffeb,
        0x7fff1,
        0x3fffe7,
        0x7ffff2,
        0x3fffe8,
        0x1ffffec,
        0x3ffffe2,
        0x3ffffe3,
        0x3ffffe4,
        0x7ffffde,
        0x7ffffdf,
        0x3ffffe5,
        0xfffff1,
        0x1ffffed,
        0x7fff2,
        0x1fffe3,
        0x3ffffe6,
        0x7ffffe0,
        0x7ffffe1,
        0x3ffffe7,
        0x7ffffe2,
        0xfffff2,
        0x1fffe4,
        0x1fffe5,
        0x3ffffe8,
        0x3ffffe9,
        0xffffffd,
        0x7ffffe3,
        0x7ffffe4,
        0x7ffffe5,
        0xfffec,
        0xfffff3,
        0xfffed,
        0x1fffe6,
        0x3fffe9,
        0x1fffe7,
        0x1fffe8,
        0x7ffff3,
        0x3fffea,
        0x3fffeb,
        0x1ffffee,
        0x1ffffef,
        0xfffff4,
        0xfffff5,
        0x3ffffea,
        0x7ffff4,
        0x3ffffeb,
        0x7ffffe6,
        0x3ffffec,
        0x3ffffed,
        0x7ffffe7,
        0x7ffffe8,
        0x7ffffe9,
        0x7ffffea,
        0x7ffffeb,
        0xffffffe,
        0x7ffffec,
        0x7ffffed,
        0x7ffffee,
        0x7ffffef,
        0x7fffff0,
        0x3ffffee,
    ]

    huffmanCodeLen* : array[256, uint8] = [
        13'u8, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
        28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
        6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
        5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
        13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
        15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
        6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
        20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
        24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
        22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
        21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
        26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
        19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
        20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
        26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26
    ]

var staticTable* = newStaticTable()

proc newStaticTable() : headerFieldTable =
    result = newHeaderFieldTable()
    for entry in staticTableEntries:
        result.addEntry(entry)

proc isPseudo*(hf : Headerfield) : bool =
    return hf.name.len() != 0 and hf.name[0] != ':'

proc `$`*(hf : Headerfield) : string =
    var suffix = if hf.sensitive: "(sensitive)" else: ""
    return fmt("header field {hf.name} = {hf.value}{suffix}")

proc size*(hf : Headerfield) : uint32 =
    return uint32(hf.name.len() + hf.value.len() + 32)

proc hash(p : pairNameValue) : Hash =
    result = p.name.hash !& p.value.hash
    result = result !& 2

func newHeaderFieldTable*() : headerFieldTable =
    headerFieldTable(byName: initTable[string, uint64](), byNamevalue: initTable[pairNameValue, uint64]())

func len*(h : headerFieldTable) : int {.inline.} =
    h.ents.len()

func addEntry*(h : headerFieldTable, hf : Headerfield) =
    let id = h.len().uint64 + h.evictCount + 1
    h.byName[hf.name] = id
    h.byNameValue[pairNameValue(name: hf.name, value: hf.value)] = id
    h.ents.add(hf)

func evictOldest*(h : headerFieldTable, n : int) =
    if n > h.len(): raise newException(IndexDefect, fmt("evictOldest({n}) on table with {h.len()} entries"))
    for k in 0..<n:
        let hf = h.ents[k]
        let id = h.evictCount + k.uint64 + 1
        if h.byName.getOrDefault(hf.name) == id:
            h.byName.del(hf.name)
        let p = pairNameValue(name: hf.name, value: hf.value)
        if h.byNameValue.getOrDefault(p) == id:
            h.byNameValue.del(p)
    h.ents = h.ents[n..^1]
    if h.evictCount+n.uint64 < h.evictCount: raise newException(IndexDefect, fmt("evictCount overflow"))
    h.evictCount += n.uint64

proc search*(h : headerFieldTable, hf : Headerfield) : (uint64, bool) =
    if not hf.sensitive:
        let id = h.byNameValue.getOrDefault(pairNameValue(name: hf.name, value: hf.value))
        if id != 0'u64:
            return (h.idToIndex(id), true)
    let id = h.byName.getOrDefault(hf.name)
    if id != 0'u64:
        return (h.idToIndex(id), false)
    return (0'u64, false)

proc idToIndex(h : headerFieldTable, id : uint64) : uint64 =
    if id <= h.evictCount: raise newException(IndexDefect, fmt("id ({id}) <= evictCount {h.evictCount}"))
    let k = id - h.evictCount - 1
    if h != staticTable: return h.len().uint64 - k
    return k+1

proc setMaxSize*(dt : var dynamicTable, v : uint32) =
    dt.maxSize = v
    dt.evict()

proc add*(dt : var dynamicTable, hf : Headerfield) =
    dt.table.addEntry(hf)
    dt.size += hf.size()
    dt.evict()

proc evict*(dt : var dynamicTable) =
    var n : int
    while (dt.size > dt.maxSize) and (n < dt.table.len()):
        dt.size -= dt.table.ents[n].size()
        inc(n)
    dt.table.evictOldest(n)
