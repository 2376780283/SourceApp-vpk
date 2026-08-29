# VPK CLI

> 由 Pixel Z / ZZHLife 开发的vpk工具 SourceApp 使用

- 主要针对 linux Android termux

---

# VPK CLI Usage Guide

The C++ VPK CLI tool (`vpk_cli`) is a high-performance utility for managing Valve Pak (VPK) files. It is located at `SourceLauncher-Thirdparty/tools/cpp/vpk-cli/`.

## Usage
```bash
./vpk_cli <vpk_file> [command] [args]
```

## Commands

| Command | Description |
| :--- | :--- |
| **None** | Displays basic VPK header information. |
| `-l` | Lists all file paths contained within the VPK archive. |
| `-x <dir>` | Extracts all files from the VPK archive into the specified directory. |
| `-t` | Verifies the integrity of all files in the VPK by checking CRC32 checksums. |
| `-c <dir>` | Creates a new VPK archive from the specified input directory. |

## Examples

### 1. View VPK Information
```bash
./vpk_cli game_assets.vpk
```

### 2. List Files
```bash
./vpk_cli game_assets.vpk -l
```

### 3. Extract All Files
```bash
./vpk_cli game_assets.vpk -x ./output_directory
```

### 4. Verify Integrity
```bash
./vpk_cli game_assets.vpk -t
```

### 5. Create VPK from Directory
```bash
./vpk_cli ./my_assets_folder -c new_assets.vpk
```

---

## Build
```bash
mkdir build && cd build && cmake .. && make -j4
```
