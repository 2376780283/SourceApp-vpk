// ========================================================
//
//   zzhlife / Pixel Z
//
// ========================================================


#include "vpk.hpp"
#include <iostream>
#include <string>

static void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " <vpk_file>              - Show VPK info\n"
              << "       " << prog << " <vpk_file> -l         - List contents\n"
              << "       " << prog << " <vpk_file> -t         - Verify CRC32 of all files\n"
              << "       " << prog << " <vpk_file> -x <dir>   - Extract all files to directory\n"
              << "       " << prog << " <dir> -c <vpk_file>   - Create VPK from directory\n"
              << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string arg1 = argv[1];
    std::string command;
    std::string out_val;

    // 解析参数: 支持两种形式
    // 1. vpk_cli <vpk_file> [command] [out]
    // 2. vpk_cli <dir> -c <vpk_file>
    std::string path = arg1;

    if (argc >= 3) {
        command = argv[2];
        if (argc >= 4) {
            out_val = argv[3];
        }
    }

    // 处理 -c 命令的另一种参数顺序: <dir> -c <out>
    // 也支持: vpk_cli -c <dir> <out>
    if (arg1 == "-c" && argc >= 4) {
        command = "-c";
        path = argv[2];
        out_val = argv[3];
    }

    try {
        if (command == "-c") {
            if (out_val.empty()) {
                std::cerr << "Error: Output VPK file not specified for -c" << std::endl;
                return 1;
            }

            std::filesystem::path out_path = out_val;
            std::string stem = out_path.stem().string();
            if (stem.find("_dir") == std::string::npos) {
                stem += "_dir";
                out_path.replace_filename(stem + ".vpk");
            }

            std::cout << "Creating VPK from: " << path << std::endl;
            std::cout << "Output: " << out_path.string() << std::endl;

            vpk::VPKWriter writer(path);
            writer.save(out_path);

            std::cout << "Done." << std::endl;
        } else {
            // 读取模式
            vpk::VPK pak(path);

            if (command == "-l") {
                pak.list();
            } else if (command == "-t") {
                size_t ok_count = 0;
                size_t fail_count = 0;
                for (const auto& [fpath, meta] : pak.get_tree()) {
                    auto vpk_file = pak.get_file(fpath);
                    if (vpk_file->verify()) {
                        ok_count++;
                    } else {
                        std::cout << "FAILED: " << fpath << std::endl;
                        fail_count++;
                    }
                }
                std::cout << "Verification complete: " << ok_count << " OK, " << fail_count << " FAILED" << std::endl;
            } else if (command == "-x" && !out_val.empty()) {
                std::cout << "Extracting files to: " << out_val << std::endl;
                size_t count = 0;
                for (const auto& [fpath, meta] : pak.get_tree()) {
                    auto vpk_file = pak.get_file(fpath);
                    vpk_file->save(std::filesystem::path(out_val) / fpath);
                    count++;
                }
                std::cout << "Extracted " << count << " files." << std::endl;
            } else {
                // 显示信息 ???
                std::cout << "VPK File:    " << path << std::endl;
                std::cout << "Version:     " << pak.version() << std::endl;
                std::cout << "Header size: " << pak.header_length() << std::endl;
                std::cout << "Tree size:   " << pak.tree_length() << std::endl;
                std::cout << "Files:       " << pak.get_tree().size() << std::endl;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
