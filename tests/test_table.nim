import unittest

from tables import len

import nimhpack/table

proc pair(name, val : string) : Headerfield =
    Headerfield(name: name, value: val)

suite "testing header field table":
    var table = newHeaderFieldTable()
    table.addEntry(pair("key1", "value1-1"))
    table.addEntry(pair("key2", "value2-1"))
    table.addEntry(pair("key1", "value1-2"))
    table.addEntry(pair("key3", "value3-1"))
    table.addEntry(pair("key4", "value4-1"))
    table.addEntry(pair("key2", "value2-2"))
    type
        testcase = object
            f : Headerfield
            beforeWantStaticI : uint64
            beforeWantMatch : bool
            afterWantStaticI : uint64
            afterWantMatch : bool
    
    var testcases = @[
        testcase(f:pair("key1", "value1-1"), beforeWantStaticI : 1, beforeWantMatch : true, afterWantStaticI : 0, afterWantMatch : false),
        testcase(f:pair("key1", "value1-2"), beforeWantStaticI : 3, beforeWantMatch : true, afterWantStaticI : 0, afterWantMatch : false),
        testcase(f:pair("key1", "value1-3"), beforeWantStaticI : 3, beforeWantMatch : false, afterWantStaticI : 0, afterWantMatch : false),
        testcase(f:pair("key2", "value2-1"), beforeWantStaticI : 2, beforeWantMatch : true, afterWantStaticI : 3, afterWantMatch : false),
        testcase(f:pair("key2", "value2-2"), beforeWantStaticI : 6, beforeWantMatch : true, afterWantStaticI : 3, afterWantMatch : true),
        testcase(f:pair("key2", "value2-3"), beforeWantStaticI : 6, beforeWantMatch : false, afterWantStaticI : 3, afterWantMatch : false),
        testcase(f:pair("key4", "value4-1"), beforeWantStaticI : 5, beforeWantMatch : true, afterWantStaticI : 2, afterWantMatch : true),
        testcase(f:Headerfield(name:"key4", value:"value4-1", sensitive:true), beforeWantStaticI : 5, beforeWantMatch : false, afterWantStaticI : 2, afterWantMatch : false),
        testcase(f:pair("key5", "value5-x"), beforeWantStaticI : 0, beforeWantMatch : false, afterWantStaticI : 0, afterWantMatch : false),
    ]
    var staticToDynamic = proc(i : uint64) : uint64 =
        if i == 0: return
        return table.len().uint64 - i + 1
    var searchStatic = proc(f : Headerfield) : (uint64, bool) =
        var old = staticTable
        staticTable = table
        defer: staticTable = old
        return staticTable.search(f)
    var searchDynamic = proc(f : Headerfield) : (uint64, bool) =
        return table.search(f)

    for i, t in testcases.pairs:
        test "test case (before): " & $(i+1):
            var (g, gm) = searchStatic(t.f)
            check(g == t.beforeWantStaticI)
            check(gm == t.beforeWantMatch)
            (g, gm) = searchDynamic(t.f)
            check(g == staticToDynamic(t.beforeWantStaticI))
            check(gm == t.beforeWantMatch)
  
    table.evictOldest(3)
    for i, t in testcases.pairs:
        test "test case (after): " & $(i+1):
            var (g, gm) = searchStatic(t.f)
            check(g == t.afterWantStaticI)
            check(gm == t.afterWantMatch)
            (g, gm) = searchDynamic(t.f)
            check(g == staticToDynamic(t.afterWantStaticI))
            check(gm == t.afterWantMatch)

test "testing header field table lookup eviction":
    var table = newHeaderFieldTable()
    table.addEntry(pair("key1", "value1-1"))
    table.addEntry(pair("key2", "value2-1"))
    table.addEntry(pair("key1", "value1-2"))
    table.addEntry(pair("key3", "value3-1"))
    table.addEntry(pair("key4", "value4-1"))
    table.addEntry(pair("key2", "value2-2"))

    table.evictOldest(table.len())

    check(table.len() == 0)
    check(table.byName.len() == 0)
    check(table.byNameValue.len() == 0)
