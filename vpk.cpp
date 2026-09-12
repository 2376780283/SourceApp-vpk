#include "vpk.hpp"
#include <stdexcept>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <cstring>

namespace vpk {

// ==================== CRC32 ====================

uint32_t calculate_crc32(const uint8_t* data, size_t length, uint32_t crc) {
    static std::vector<uint32_t> table;
    if (table.empty()) {
        table.resize(256);
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int j = 0; j < 8; ++j) {
                if (c & 1) c = 0xedb88320L ^ (c >> 1);
                else c >>= 1;
            }
            table[i] = c;
        }
    }
    crc = ~crc;
    for (size_t i = 0; i < length; ++i) {
        crc = table[(crc ^ data[i]) & 0xff] ^ (crc >> 8);
    }
    return ~crc;
}

// ==================== MD5 ====================

struct MD5Context {
    uint32_t state[4];
    uint32_t count[2];
    uint8_t buffer[64];
};

static void md5_transform(uint32_t state[4], const uint8_t block[64]);

static void md5_init(MD5Context* ctx) {
    ctx->count[0] = ctx->count[1] = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
}

static void md5_update(MD5Context* ctx, const uint8_t* input, size_t length) {
    size_t i, index, partLen;
    index = (size_t)((ctx->count[0] >> 3) & 0x3F);
    partLen = 64 - index;
    ctx->count[0] += (uint32_t)(length << 3);
    if (ctx->count[0] < (length << 3)) ctx->count[1]++;
    ctx->count[1] += (uint32_t)(length >> 29);

    if (length >= partLen) {
        std::memcpy(&ctx->buffer[index], input, partLen);
        md5_transform(ctx->state, ctx->buffer);
        for (i = partLen; i + 63 < length; i += 64) {
            md5_transform(ctx->state, &input[i]);
        }
        index = 0;
    } else {
        i = 0;
    }
    std::memcpy(&ctx->buffer[index], &input[i], length - i);
}

static void md5_final(uint8_t digest[16], MD5Context* ctx) {
    uint8_t bits[8];
    size_t index, padLen;
    static const uint8_t padding[64] = { 0x80 };

    for (int i = 0; i < 8; ++i) {
        bits[i] = (uint8_t)((ctx->count[i >> 2] >> ((i & 3) << 3)) & 0xFF);
    }
    index = (size_t)((ctx->count[0] >> 3) & 0x3f);
    padLen = (index < 56) ? (56 - index) : (120 - index);
    md5_update(ctx, padding, padLen);
    md5_update(ctx, bits, 8);
    for (int i = 0; i < 16; ++i) {
        digest[i] = (uint8_t)((ctx->state[i >> 2] >> ((i & 3) << 3)) & 0xFF);
    }
}

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define FF(a, b, c, d, x, s, ac) { (a) += F((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTATE_LEFT((a), (s)); (a) += (b); }
#define GG(a, b, c, d, x, s, ac) { (a) += G((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTATE_LEFT((a), (s)); (a) += (b); }
#define HH(a, b, c, d, x, s, ac) { (a) += H((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTATE_LEFT((a), (s)); (a) += (b); }
#define II(a, b, c, d, x, s, ac) { (a) += I((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTATE_LEFT((a), (s)); (a) += (b); }

static void md5_transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t x[16];
    for (int i = 0; i < 16; ++i) {
        x[i] = block[i * 4] | (block[i * 4 + 1] << 8) | (block[i * 4 + 2] << 16) | (block[i * 4 + 3] << 24);
    }
    FF(a, b, c, d, x[ 0],  7, 0xd76aa478); FF(d, a, b, c, x[ 1], 12, 0xe8c7b756);
    FF(c, d, a, b, x[ 2], 17, 0x242070db); FF(b, c, d, a, x[ 3], 22, 0xc1bdceee);
    FF(a, b, c, d, x[ 4],  7, 0xf57c0faf); FF(d, a, b, c, x[ 5], 12, 0x4787c62a);
    FF(c, d, a, b, x[ 6], 17, 0xa8304613); FF(b, c, d, a, x[ 7], 22, 0xfd469501);
    FF(a, b, c, d, x[ 8],  7, 0x698098d8); FF(d, a, b, c, x[ 9], 12, 0x8b44f7af);
    FF(c, d, a, b, x[10], 17, 0xffff5bb1); FF(b, c, d, a, x[11], 22, 0x895cd7be);
    FF(a, b, c, d, x[12],  7, 0x6b901122); FF(d, a, b, c, x[13], 12, 0xfd987193);
    FF(c, d, a, b, x[14], 17, 0xa679438e); FF(b, c, d, a, x[15], 22, 0x49b40821);
    GG(a, b, c, d, x[ 1],  5, 0xf61e2562); GG(d, a, b, c, x[ 6],  9, 0xc040b340);
    GG(c, d, a, b, x[11], 14, 0x265e5a51); GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa);
    GG(a, b, c, d, x[ 5],  5, 0xd62f105d); GG(d, a, b, c, x[10],  9, 0x02441453);
    GG(c, d, a, b, x[15], 14, 0xd8a1e681); GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8);
    GG(a, b, c, d, x[ 9],  5, 0x21e1cde6); GG(d, a, b, c, x[14],  9, 0xc33707d6);
    GG(c, d, a, b, x[ 3], 14, 0xf4d50d87); GG(b, c, d, a, x[ 8], 20, 0x455a14ed);
    GG(a, b, c, d, x[13],  5, 0xa9e3e905); GG(d, a, b, c, x[ 2],  9, 0xfcefa3f8);
    GG(c, d, a, b, x[ 7], 14, 0x676f02d9); GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);
    HH(a, b, c, d, x[ 5],  4, 0xfffa3942); HH(d, a, b, c, x[ 8], 11, 0x8771f681);
    HH(c, d, a, b, x[11], 16, 0x6d9d6122); HH(b, c, d, a, x[14], 23, 0xfde5380c);
    HH(a, b, c, d, x[ 1],  4, 0xa4beea44); HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9);
    HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60); HH(b, c, d, a, x[10], 23, 0xbebfbc70);
    HH(a, b, c, d, x[13],  4, 0x289b7ec6); HH(d, a, b, c, x[ 0], 11, 0xeaa127fa);
    HH(c, d, a, b, x[ 3], 16, 0xd4ef3085); HH(b, c, d, a, x[ 6], 23, 0x04881d05);
    HH(a, b, c, d, x[ 9],  4, 0xd9d4d039); HH(d, a, b, c, x[12], 11, 0x6d9d6122);
    HH(c, d, a, b, x[15], 16, 0x1fa27cf8); HH(b, c, d, a, x[ 2], 23, 0xc4ac5665);
    II(a, b, c, d, x[ 0],  6, 0xf4292244); II(d, a, b, c, x[ 7], 10, 0x432aff97);
    II(c, d, a, b, x[14], 15, 0xab9423a7); II(b, c, d, a, x[ 5], 21, 0xfc93a039);
    II(a, b, c, d, x[12],  6, 0x655b59c3); II(d, a, b, c, x[ 3], 10, 0x8f0ccc92);
    II(c, d, a, b, x[10], 15, 0xffeff47d); II(b, c, d, a, x[ 1], 21, 0x85845dd1);
    II(a, b, c, d, x[ 8],  6, 0x6fa87e4f); II(d, a, b, c, x[15], 10, 0xfe2ce6e0);
    II(c, d, a, b, x[ 6], 15, 0xa3014314); II(b, c, d, a, x[13], 21, 0x4e0811a1);
    II(a, b, c, d, x[ 4],  6, 0xf7537e82); II(d, a, b, c, x[11], 10, 0xbd3af235);
    II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb); II(b, c, d, a, x[ 9], 21, 0xeb86d391);
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

#undef F
#undef G
#undef H
#undef I
#undef ROTATE_LEFT
#undef FF
#undef GG
#undef HH
#undef II

// ==================== VPK 读取 ====================

VPK::VPK(const std::filesystem::path& vpk_path) : vpk_path_(vpk_path) {
    read_header();
    read_index();
}

std::string VPK::read_cstring(std::ifstream& f) {
    std::string str;
    char c;
    while (f.get(c) && c != '\0') {
        str += c;
    }
    return str;
}

void VPK::read_header() {
    std::ifstream f(vpk_path_, std::ios::binary);
    if (!f.is_open()) throw std::runtime_error("Could not open VPK");

    f.read(reinterpret_cast<char*>(&header_v1_), sizeof(header_v1_));
    if (header_v1_.signature != 0x55aa1234) {
        throw std::runtime_error("Invalid VPK signature");
    }

    if (header_v1_.version == 2) {
        f.seekg(0, std::ios::beg);
        f.read(reinterpret_cast<char*>(&header_v2_), sizeof(header_v2_));
        header_length_ = sizeof(VPKHeaderV2);
    } else if (header_v1_.version == 1) {
        header_length_ = sizeof(VPKHeaderV1);
    } else if (header_v1_.version == 0) {
        header_length_ = 0;
        header_v1_.tree_length = static_cast<uint32_t>(std::filesystem::file_size(vpk_path_));
    } else {
        throw std::runtime_error("Unsupported VPK version");
    }
}

void VPK::read_index() {
    std::ifstream f(vpk_path_, std::ios::binary);
    f.seekg(header_length_, std::ios::beg);

    while (true) {
        std::string ext = read_cstring(f);
        if (ext.empty()) break;

        while (true) {
            std::string path = read_cstring(f);
            if (path.empty()) break;

            while (true) {
                std::string name = read_cstring(f);
                if (name.empty()) break;

                VPKEntryMetadata meta;
                f.read(reinterpret_cast<char*>(&meta), sizeof(meta));
                
                std::vector<uint8_t> preload_data;
                if (meta.preload_length > 0) {
                    preload_data.resize(meta.preload_length);
                    f.read(reinterpret_cast<char*>(preload_data.data()), meta.preload_length);
                }

                std::string full_path;
                if (path != " ") {
                    full_path = path + "/" + name;
                } else {
                    full_path = name;
                }
                if (ext != " ") {
                    full_path += "." + ext;
                }
                std::replace(full_path.begin(), full_path.end(), '\\', '/');

                tree_[full_path] = {meta, preload_data};
            }
        }
    }
}

void VPK::list() const {
    for (const auto& [path, meta] : tree_) {
        std::cout << path << std::endl;
    }
}

std::unique_ptr<VPKFile> VPK::get_file(const std::string& path) {
    auto it = tree_.find(path);
    if (it == tree_.end()) {
        throw std::runtime_error("File not found in VPK: " + path);
    }
    return std::make_unique<VPKFile>(vpk_path_, it->second.first, path, it->second.second, header_length_, header_v1_.tree_length);
}

// ==================== VPKFile ====================

VPKFile::VPKFile(const std::filesystem::path& vpk_path,
                 const VPKEntryMetadata& meta,
                 const std::string& path,
                 const std::vector<uint8_t>& preload_data,
                 uint32_t header_length,
                 uint32_t tree_length)
    : vpk_path_(vpk_path), meta_(meta), preload_data_(preload_data), internal_path_(path),
      header_length_(header_length), tree_length_(tree_length), current_pos_(0) {

    std::filesystem::path archive_path = vpk_path;

    if (meta_.archive_index != VPKFILENUMBER_EMBEDDED_IN_DIR_FILE) {
        std::string filename = vpk_path.filename().string();
        size_t dir_pos = filename.find("_dir");
        if (dir_pos != std::string::npos) {
            std::stringstream ss;
            ss << filename.substr(0, dir_pos) << "_"
               << std::setw(3) << std::setfill('0') << meta_.archive_index << ".vpk";
            archive_path = vpk_path.parent_path() / ss.str();
        }
        data_offset_ = meta_.archive_offset;
    } else {
        data_offset_ = header_length_ + tree_length_ + meta_.archive_offset;
    }

    fp_.open(archive_path, std::ios::binary);
    if (!fp_.is_open()) {
        throw std::runtime_error("Could not open archive: " + archive_path.string());
    }
    fp_.seekg(data_offset_, std::ios::beg);
}

void VPKFile::seek(std::streampos pos) {
    current_pos_ = pos;
    std::streampos file_pos = data_offset_;
    if (pos > static_cast<std::streamoff>(meta_.preload_length)) {
        file_pos += (pos - static_cast<std::streamoff>(meta_.preload_length));
    }
    fp_.clear();
    fp_.seekg(file_pos, std::ios::beg);
}

size_t VPKFile::read(uint8_t* buffer, size_t length) {
    if (current_pos_ >= meta_.preload_length + meta_.file_length) return 0;

    size_t total_read = 0;

    if (current_pos_ < meta_.preload_length) {
        size_t to_read = std::min(length, (size_t)meta_.preload_length - (size_t)current_pos_);
        std::memcpy(buffer, preload_data_.data() + (size_t)current_pos_, to_read);
        current_pos_ += to_read;
        total_read += to_read;
        length -= to_read;
        buffer += to_read;
    }

    if (length > 0) {
        size_t file_offset = (size_t)current_pos_ - meta_.preload_length;
        fp_.clear();
        fp_.seekg(static_cast<std::streamoff>(data_offset_) + static_cast<std::streamoff>(file_offset), std::ios::beg);
        size_t to_read = std::min(length, (size_t)meta_.file_length - file_offset);
        fp_.read(reinterpret_cast<char*>(buffer), to_read);
        size_t r = fp_.gcount();
        current_pos_ += r;
        total_read += r;
    }
    return total_read;
}

bool VPKFile::verify() {
    fp_.clear();
    fp_.seekg(data_offset_, std::ios::beg);
    uint32_t crc = 0;
    uint8_t buf[8192];
    size_t rem = meta_.file_length;
    while (rem > 0) {
        size_t r = std::min(rem, sizeof(buf));
        fp_.read(reinterpret_cast<char*>(buf), r);
        size_t gcount = fp_.gcount();
        if (gcount == 0) break;
        crc = calculate_crc32(buf, gcount, crc);
        rem -= gcount;
    }
    return crc == meta_.crc32;
}

void VPKFile::save(const std::filesystem::path& op) {
    std::filesystem::create_directories(op.parent_path());
    std::ofstream out(op, std::ios::binary);
    if (!out.is_open()) throw std::runtime_error("Could not create output file: " + op.string());
    

    if (meta_.preload_length > 0 && !preload_data_.empty()) {
        out.write(reinterpret_cast<const char*>(preload_data_.data()), meta_.preload_length);
    }

    fp_.clear(); 
    fp_.seekg(data_offset_, std::ios::beg);
    uint8_t buf[8192];
    size_t rem = meta_.file_length;
    while (rem > 0) {
        size_t r = std::min(rem, sizeof(buf));
        fp_.read(reinterpret_cast<char*>(buf), r);
        size_t gcount = fp_.gcount();
        if (gcount == 0) break;
        out.write(reinterpret_cast<const char*>(buf), gcount);
        rem -= gcount;
    }
}

// ==================== VPKWriter ====================

VPKWriter::VPKWriter(const std::filesystem::path& input_dir, bool enable_chunking) 
    : input_dir_(input_dir), enable_chunking_(enable_chunking) {
    read_dir(input_dir);
    calculate_tree_length();
}

void VPKWriter::read_dir(const std::filesystem::path& dir) {
    for (const auto& entry : std::filesystem::recursive_directory_iterator(dir)) {
        if (!entry.is_regular_file()) continue;
        std::filesystem::path full = entry.path();
        std::filesystem::path rel = std::filesystem::relative(full, input_dir_);
        
        std::string ext = full.extension().string();
        if (!ext.empty() && ext[0] == '.') ext = ext.substr(1);
        if (ext.empty()) ext = " "; 

        std::string filename = full.stem().string();
        if (filename.empty()) filename = " ";

        std::string parent = rel.has_parent_path() ? rel.parent_path().string() : " ";
        std::replace(parent.begin(), parent.end(), '\\', '/');
        tree_[ext][parent][filename] = VPKFileSource{full, 0};
    }
}

void VPKWriter::calculate_tree_length() {
    tree_length_ = 0;
    for (const auto& [ext, paths] : tree_) {
        tree_length_ += ext.size() + 1;
        for (const auto& [relpath, files] : paths) {
            tree_length_ += relpath.size() + 1;
            for (const auto& [fname, info] : files) {
                tree_length_ += fname.size() + 1 + 18;
            }
            tree_length_ += 1;
        }
        tree_length_ += 1;
    }
    tree_length_ += 1;
}

void VPKWriter::save(const std::filesystem::path& out_path) {
    save_internal(out_path, enable_chunking_);
}

void VPKWriter::save_single(const std::filesystem::path& out_path) {
    save_internal(out_path, false);
}

void VPKWriter::save_internal(const std::filesystem::path& out_path, bool use_chunks) {
    std::filesystem::path dir_path = out_path;
    if (use_chunks) {
        std::string stem = dir_path.stem().string();
        if (stem.find("_dir") == std::string::npos) dir_path.replace_filename(stem + "_dir.vpk");
    } else {
        dir_path.replace_extension(".vpk");
    }

    std::ofstream dir_file(dir_path, std::ios::binary | std::ios::trunc);
    if (!dir_file.is_open()) throw std::runtime_error("Could not create VPK file: " + dir_path.string());

    VPKHeaderV2 header = {0x55aa1234, 2, static_cast<uint32_t>(tree_length_), 0, 0, 48, 0};
    dir_file.write(reinterpret_cast<const char*>(&header), sizeof(header));

    for (auto& [ext, paths] : tree_) {
        dir_file.write(ext.c_str(), ext.size() + 1);
        for (auto& [relpath, files] : paths) {
            dir_file.write(relpath.c_str(), relpath.size() + 1);
            for (auto& [fname, info] : files) {
                dir_file.write(fname.c_str(), fname.size() + 1);
                info.meta_pos = dir_file.tellp();
                
               
                uint8_t dummy[18] = {0}; 
                dir_file.write(reinterpret_cast<const char*>(dummy), 18);
            }
            dir_file.put('\0');
        }
        dir_file.put('\0');
    }
    dir_file.put('\0');

    uint16_t archive_index = 0;
    size_t current_chunk_size = 0;
    std::ofstream data_fp;
    std::string base = dir_path.stem().string();
    if (use_chunks && base.find("_dir") != std::string::npos) base = base.substr(0, base.find("_dir"));
    
    auto open_new_chunk = [&](uint16_t idx) {
        if (data_fp.is_open()) data_fp.close();
        std::stringstream ss; ss << base << "_" << std::setw(3) << std::setfill('0') << idx << ".vpk";
        data_fp.open(dir_path.parent_path() / ss.str(), std::ios::binary | std::ios::trunc);
    };
    
    // 如果使用分卷，则开启独立 chunk 文件；如果为单文件 VPK，则绝对不双开文件流，直接追加写入 dir_file 保证数据连续
    if (use_chunks) open_new_chunk(archive_index);

    struct FileEntry { VPKFileSource* info; uint32_t crc32; uint32_t file_len; uint16_t archive_idx; uint32_t archive_off; };
    std::vector<FileEntry> entries;

    for (auto& [ext, paths] : tree_) {
        for (auto& [relpath, files] : paths) {
            for (auto& [fname, info] : files) {
                std::ifstream src(info.src_path, std::ios::binary);
                src.seekg(0, std::ios::end); size_t flen = src.tellg(); src.seekg(0, std::ios::beg);
                uint32_t crc = 0; uint8_t buf[8192];
                while (src.read(reinterpret_cast<char*>(buf), sizeof(buf)) || src.gcount() > 0) crc = calculate_crc32(buf, src.gcount(), crc);
                entries.push_back({&info, crc, static_cast<uint32_t>(flen), 0, 0});
            }
        }
    }

    size_t embed_offset = 0;
    for (auto& e : entries) {
        if (e.file_len == 0) { e.archive_idx = VPKFILENUMBER_EMBEDDED_IN_DIR_FILE; continue; }
        if (use_chunks) {
            if (current_chunk_size > 0 && current_chunk_size + e.file_len > k_nVPKDefaultChunkSize) {
                archive_index++; current_chunk_size = 0; open_new_chunk(archive_index);
            }
            e.archive_idx = archive_index; e.archive_off = static_cast<uint32_t>(data_fp.tellp());
            std::ifstream src(e.info->src_path, std::ios::binary);
            uint8_t buf[8192];
            while (src.read(reinterpret_cast<char*>(buf), sizeof(buf)) || src.gcount() > 0) data_fp.write(reinterpret_cast<const char*>(buf), src.gcount());
            current_chunk_size += e.file_len;
        } else {
            e.archive_idx = VPKFILENUMBER_EMBEDDED_IN_DIR_FILE; 
            e.archive_off = static_cast<uint32_t>(embed_offset);
            std::ifstream src(e.info->src_path, std::ios::binary);
            uint8_t buf[8192];
            while (src.read(reinterpret_cast<char*>(buf), sizeof(buf)) || src.gcount() > 0) {
                dir_file.write(reinterpret_cast<const char*>(buf), src.gcount());
            }
            embed_offset += e.file_len;
        }
    }
    if (data_fp.is_open()) data_fp.close();

    for (const auto& e : entries) {
        dir_file.seekp(e.info->meta_pos);
        uint16_t preload_len = 0; uint16_t suffix = 0xffff;
        dir_file.write(reinterpret_cast<const char*>(&e.crc32), 4);
        dir_file.write(reinterpret_cast<const char*>(&preload_len), 2);
        dir_file.write(reinterpret_cast<const char*>(&e.archive_idx), 2);
        dir_file.write(reinterpret_cast<const char*>(&e.archive_off), 4);
        dir_file.write(reinterpret_cast<const char*>(&e.file_len), 4);
        dir_file.write(reinterpret_cast<const char*>(&suffix), 2);
    }
    
    size_t embed_chunk_length = use_chunks ? 0 : embed_offset;
    dir_file.seekp(sizeof(VPKHeaderV1));
    dir_file.write(reinterpret_cast<const char*>(&embed_chunk_length), 4);
    dir_file.flush(); 
    dir_file.close(); // 先关闭，准备重新以读方式打开并计算校验和

    // --- 符合标准的 MD5 实现 ---
    std::ifstream check_file(dir_path, std::ios::binary);
    MD5Context tree_ctx, chunk_hashes_ctx, file_ctx;
    md5_init(&tree_ctx); md5_init(&chunk_hashes_ctx); md5_init(&file_ctx);
    
    std::vector<uint8_t> buf(8192);
    check_file.read(reinterpret_cast<char*>(buf.data()), sizeof(VPKHeaderV2));
    md5_update(&file_ctx, buf.data(), sizeof(VPKHeaderV2));
    
    size_t tree_rem = tree_length_;
    while (tree_rem > 0) {
        size_t r = std::min(tree_rem, buf.size());
        check_file.read(reinterpret_cast<char*>(buf.data()), r);
        md5_update(&tree_ctx, buf.data(), r);
        md5_update(&file_ctx, buf.data(), r);
        tree_rem -= r;
    }
    
    if (!use_chunks && embed_chunk_length > 0) {
        check_file.seekg(embed_chunk_length, std::ios::cur);
    }
    
    uint8_t t_digest[16], c_digest[16], f_digest[16];
    MD5Context t_ctx = tree_ctx, c_ctx = chunk_hashes_ctx;
    md5_final(t_digest, &t_ctx); 
    md5_final(c_digest, &c_ctx);
    
    md5_update(&file_ctx, t_digest, 16);
    md5_update(&file_ctx, c_digest, 16);
    md5_final(f_digest, &file_ctx);
    check_file.close();

    std::ofstream final_file(dir_path, std::ios::binary | std::ios::app);
    final_file.write(reinterpret_cast<const char*>(t_digest), 16);
    final_file.write(reinterpret_cast<const char*>(c_digest), 16);
    final_file.write(reinterpret_cast<const char*>(f_digest), 16);
    final_file.close();
}

} // namespace vpk