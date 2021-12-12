import nimhpack/encode
export
    encode.Encoder,
    encode.newEncoder,
    encode.setMaxDynamicTableSize,
    encode.setMaxDynamicTableSizeLimit

import nimhpack/table
export
    table.Headerfield,
    table.isPseudo,
    table.size,
    table.`$`

import nimhpack/errors
export errors

import nimhpack/decode
export
    decode.Decoder,
    decode.newDecoder,
    decode.close,
    decode.decodeFull,
    decode.emitEnabled,
    decode.setAllowedMaxDynamicTableSize,
    decode.setEmitEnabled,
    decode.setEmitFunc,
    decode.setMaxDynamicTableSize,
    decode.setMaxStringLength,
    decode.write

import nimhpack/huffman
export
    huffman.appendHuffmanString,
    huffman.huffmanDecode,
    huffman.huffmanDecodeToString,
    huffman.huffmanEncodeLength

import faststreams
export
    faststreams.getOutput,
    faststreams.memoryOutput,
    faststreams.recycleBuffers,
    faststreams.initPageBuffers,
    faststreams.close,
    faststreams.flush,
    faststreams.pos

# TODO: add comments and documentation
