#ifndef VPK_HEADER_H
#define VPK_HEADER_H

#include <cstdint>

#pragma pack(push, 1)

struct VPKHeaderV1 {
    uint32_t signature;
    uint32_t version;
    uint32_t tree_length;
};

struct VPKHeaderV2 : VPKHeaderV1 {
    uint32_t embed_chunk_length;
    uint32_t chunk_hashes_length;
    uint32_t self_hashes_length;
    uint32_t signature_length;
};

struct VPKEntryMetadata {
    uint32_t crc32;
    uint16_t preload_length;
    uint16_t archive_index;
    uint32_t archive_offset;
    uint32_t file_length;
    uint16_t suffix;
};

#pragma pack(pop)

#endif // VPK_HEADER_H
