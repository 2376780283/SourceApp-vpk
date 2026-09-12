#ifndef VPK_HPP
#define VPK_HPP

#include <string>
#include <vector>
#include <filesystem>
#include <memory>
#include <iostream>
#include <fstream>
#include <map>
#include <cstdint>
#include "vpk_header.h"

namespace vpk {

// VPK 默认分卷大小: 200MB (与官方一致)
constexpr uint32_t k_nVPKDefaultChunkSize = 200 * 1024 * 1024;
// 嵌入 dir 文件的特殊 archive index
constexpr uint16_t VPKFILENUMBER_EMBEDDED_IN_DIR_FILE = 0x7fff;

// CRC32 计算
uint32_t calculate_crc32(const uint8_t* data, size_t length, uint32_t crc = 0);

// 表示 VPK 中单个文件的数据来源信息
struct VPKFileSource {
    std::filesystem::path src_path;     // 源文件路径
    std::streampos meta_pos;            // 在 dir 文件中元数据的位置
};

// 解压时使用的文件句柄
class VPKFile {
public:
    VPKFile(const std::filesystem::path& vpk_path,
            const VPKEntryMetadata& meta,
            const std::string& path,
            const std::vector<uint8_t>& preload_data,
            uint32_t header_length,
            uint32_t tree_length);

    size_t read(uint8_t* buffer, size_t length);
    void seek(std::streampos pos);
    bool verify();
    void save(const std::filesystem::path& output_path);

private:
    std::filesystem::path vpk_path_;
    VPKEntryMetadata meta_;
    std::vector<uint8_t> preload_data_;
    std::string internal_path_;
    std::ifstream fp_;
    uint32_t header_length_;
    uint32_t tree_length_;
    std::streampos data_offset_;
    std::streampos current_pos_;
};

// VPK 打包器
class VPKWriter {
public:
    explicit VPKWriter(const std::filesystem::path& input_dir, bool enable_chunking = true);
    void save(const std::filesystem::path& output_path);
    void save_single(const std::filesystem::path& output_path);

private:
    void read_dir(const std::filesystem::path& dir);
    void calculate_tree_length();
    void save_internal(const std::filesystem::path& out_path, bool use_chunks);

    std::filesystem::path input_dir_;
    bool enable_chunking_;
    // ext -> relpath -> filename -> info
    std::map<std::string, std::map<std::string, std::map<std::string, VPKFileSource>>> tree_;
    size_t tree_length_ = 0;
};

// VPK 读取器
class VPK {
public:
    explicit VPK(const std::filesystem::path& vpk_path);

    void read_header();
    void read_index();

    static std::string read_cstring(std::ifstream& f);

    void list() const;
    std::unique_ptr<VPKFile> get_file(const std::string& path);

    const std::map<std::string, std::pair<VPKEntryMetadata, std::vector<uint8_t>>>& get_tree() const { return tree_; }
    uint32_t version() const { return header_v1_.version; }
    uint32_t header_length() const { return header_length_; }
    uint32_t tree_length() const { return header_v1_.tree_length; }

private:
    std::filesystem::path vpk_path_;
    VPKHeaderV1 header_v1_;
    VPKHeaderV2 header_v2_;
    uint32_t header_length_ = 12;
    // Index mapping: full path -> {metadata, preload_data}
    std::map<std::string, std::pair<VPKEntryMetadata, std::vector<uint8_t>>> tree_;
};

} // namespace vpk

#endif // VPK_HPP
