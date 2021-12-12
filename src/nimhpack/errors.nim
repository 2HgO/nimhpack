type
    DecodeError* = object of CatchableError
    InvalidIndexError* = ref object of DecodeError
        idx : int
    InvalidHuffmanError* = object of CatchableError
    NeedMoreError* = object of CatchableError
    StringLengthError* = object of CatchableError

template raiseDecodeError*(e : string) =
    raise newException(DecodeError, "decoding error: " & e)
template raiseIndexError*(i : int) =
    raise InvalidIndexError(idx : i, msg : "decoding error: invalid indexed representation index " & $i)
template raiseHuffmanError*() =
    raise newException(InvalidHuffmanError, "hpack: invalid Huffman-encoded data")
template raiseStringLengthError*() =
    raise newException(StringLengthError, "hpack: string too long")
template raiseNeedMoreError*() =
    raise newException(NeedMoreError, "need more data")
