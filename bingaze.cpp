/*
 * NullSec BinGaze - Hardened Binary Analysis Toolkit
 * Language: C++20 (Modern Systems Programming)
 * Author: bad-antics
 * License: NullSec Proprietary
 * Security Level: Maximum Hardening
 *
 * Security Features:
 * - RAII resource management
 * - Bounds-checked containers (std::span, std::array)
 * - Smart pointers for memory safety
 * - Input validation on all operations
 * - AddressSanitizer compatible
 * - Stack protection enabled
 * - Defense-in-depth architecture
 */

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace NullSec {

// ==========================================================================
// Version and Banner
// ==========================================================================

constexpr std::string_view VERSION = "2.0.0";

constexpr std::string_view BANNER = R"(
██████╗ ██╗███╗   ██╗ ██████╗  █████╗ ███████╗███████╗
██╔══██╗██║████╗  ██║██╔════╝ ██╔══██╗╚══███╔╝██╔════╝
██████╔╝██║██╔██╗ ██║██║  ███╗███████║  ███╔╝ █████╗  
██╔══██╗██║██║╚██╗██║██║   ██║██╔══██║ ███╔╝  ██╔══╝  
██████╔╝██║██║ ╚████║╚██████╔╝██║  ██║███████╗███████╗
╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝
              bad-antics • Binary Analysis
═══════════════════════════════════════════════════════
)";

// ==========================================================================
// Security Constants
// ==========================================================================

constexpr size_t MAX_FILE_SIZE = 100 * 1024 * 1024;  // 100MB
constexpr size_t MAX_PATH_LENGTH = 4096;
constexpr size_t MAX_SECTIONS = 256;
constexpr size_t MAX_SYMBOLS = 1000000;

// ==========================================================================
// Error Handling
// ==========================================================================

enum class ErrorCode {
    Success = 0,
    FileNotFound,
    FileTooLarge,
    InvalidFormat,
    ParseError,
    ValidationError,
    PermissionDenied,
    OutOfMemory
};

class BinGazeError : public std::exception {
public:
    explicit BinGazeError(ErrorCode code, std::string message)
        : code_(code), message_(std::move(message)) {}

    [[nodiscard]] const char* what() const noexcept override {
        return message_.c_str();
    }

    [[nodiscard]] ErrorCode code() const noexcept { return code_; }

private:
    ErrorCode code_;
    std::string message_;
};

// ==========================================================================
// Secure Memory Operations
// ==========================================================================

/**
 * Securely zero memory to prevent data leakage.
 */
inline void secure_zero(void* ptr, size_t size) {
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (size--) {
        *p++ = 0;
    }
    std::atomic_thread_fence(std::memory_order_seq_cst);
}

/**
 * RAII wrapper for secure buffer management.
 */
class SecureBuffer {
public:
    explicit SecureBuffer(size_t size) : data_(size, 0) {}
    
    SecureBuffer(const std::vector<uint8_t>& data) : data_(data) {}
    
    ~SecureBuffer() {
        secure_zero(data_.data(), data_.size());
    }

    // Disable copy to prevent sensitive data duplication
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    // Allow move
    SecureBuffer(SecureBuffer&& other) noexcept : data_(std::move(other.data_)) {}
    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            secure_zero(data_.data(), data_.size());
            data_ = std::move(other.data_);
        }
        return *this;
    }

    [[nodiscard]] std::span<uint8_t> data() noexcept { return data_; }
    [[nodiscard]] std::span<const uint8_t> data() const noexcept { return data_; }
    [[nodiscard]] size_t size() const noexcept { return data_.size(); }
    [[nodiscard]] bool empty() const noexcept { return data_.empty(); }

private:
    std::vector<uint8_t> data_;
};

// ==========================================================================
// Input Validation
// ==========================================================================

/**
 * Validate file path for safety.
 */
[[nodiscard]] std::filesystem::path validate_path(const std::string& path) {
    if (path.length() > MAX_PATH_LENGTH) {
        throw BinGazeError(ErrorCode::ValidationError, "Path too long");
    }

    // Check for null bytes
    if (path.find('\0') != std::string::npos) {
        throw BinGazeError(ErrorCode::ValidationError, "Null byte in path");
    }

    // Check for path traversal
    if (path.find("..") != std::string::npos) {
        throw BinGazeError(ErrorCode::ValidationError, "Path traversal detected");
    }

    std::filesystem::path fs_path(path);
    
    if (!std::filesystem::exists(fs_path)) {
        throw BinGazeError(ErrorCode::FileNotFound, "File not found: " + path);
    }

    auto file_size = std::filesystem::file_size(fs_path);
    if (file_size > MAX_FILE_SIZE) {
        throw BinGazeError(ErrorCode::FileTooLarge, 
            "File too large: " + std::to_string(file_size) + " bytes");
    }

    return fs_path;
}

// ==========================================================================
// ELF Structures (64-bit)
// ==========================================================================

#pragma pack(push, 1)

struct Elf64_Ehdr {
    std::array<uint8_t, 16> e_ident;
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Elf64_Shdr {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
};

struct Elf64_Phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

struct Elf64_Sym {
    uint32_t st_name;
    uint8_t st_info;
    uint8_t st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
};

#pragma pack(pop)

// ELF Constants
constexpr std::array<uint8_t, 4> ELF_MAGIC = {0x7f, 'E', 'L', 'F'};

// ==========================================================================
// Binary Analysis Classes
// ==========================================================================

/**
 * Section information with security metadata.
 */
struct Section {
    std::string name;
    uint32_t type;
    uint64_t flags;
    uint64_t address;
    uint64_t offset;
    uint64_t size;
    double entropy;
    bool is_executable;
    bool is_writable;
};

/**
 * Symbol information.
 */
struct Symbol {
    std::string name;
    uint64_t address;
    uint64_t size;
    uint8_t type;
    uint8_t bind;
};

/**
 * Security assessment result.
 */
struct SecurityAssessment {
    bool has_nx_stack;
    bool has_pie;
    bool has_relro;
    bool has_canary;
    bool has_fortify;
    bool has_rwx_segments;
    std::vector<std::string> warnings;
    std::vector<std::string> recommendations;
};

/**
 * Main ELF analyzer class.
 */
class ElfAnalyzer {
public:
    explicit ElfAnalyzer(const std::filesystem::path& path) : path_(path) {
        load_file();
        parse_header();
        parse_sections();
        parse_segments();
    }

    [[nodiscard]] const Elf64_Ehdr& header() const { return header_; }
    [[nodiscard]] const std::vector<Section>& sections() const { return sections_; }
    [[nodiscard]] std::vector<Symbol> symbols() const { return parse_symbols(); }
    [[nodiscard]] SecurityAssessment assess_security() const;

    void print_info() const;
    void print_sections() const;
    void print_segments() const;
    void print_security() const;

private:
    void load_file();
    void parse_header();
    void parse_sections();
    void parse_segments();
    [[nodiscard]] std::vector<Symbol> parse_symbols() const;
    [[nodiscard]] double calculate_entropy(std::span<const uint8_t> data) const;
    [[nodiscard]] std::string get_section_name(uint32_t offset) const;

    std::filesystem::path path_;
    SecureBuffer buffer_{0};
    Elf64_Ehdr header_{};
    std::vector<Section> sections_;
    std::vector<Elf64_Phdr> segments_;
    size_t shstrtab_offset_ = 0;
};

void ElfAnalyzer::load_file() {
    std::ifstream file(path_, std::ios::binary);
    if (!file) {
        throw BinGazeError(ErrorCode::FileNotFound, "Cannot open file");
    }

    file.seekg(0, std::ios::end);
    auto size = static_cast<size_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    if (size > MAX_FILE_SIZE) {
        throw BinGazeError(ErrorCode::FileTooLarge, "File exceeds size limit");
    }

    std::vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(size));

    buffer_ = SecureBuffer(std::move(data));
}

void ElfAnalyzer::parse_header() {
    if (buffer_.size() < sizeof(Elf64_Ehdr)) {
        throw BinGazeError(ErrorCode::InvalidFormat, "File too small for ELF header");
    }

    auto data = buffer_.data();
    
    // Verify magic
    if (!std::equal(ELF_MAGIC.begin(), ELF_MAGIC.end(), data.begin())) {
        throw BinGazeError(ErrorCode::InvalidFormat, "Invalid ELF magic");
    }

    // Bounds-checked copy
    std::memcpy(&header_, data.data(), sizeof(Elf64_Ehdr));

    // Validate header values
    if (header_.e_shoff >= buffer_.size()) {
        throw BinGazeError(ErrorCode::ParseError, "Invalid section header offset");
    }

    if (header_.e_shnum > MAX_SECTIONS) {
        throw BinGazeError(ErrorCode::ParseError, "Too many sections");
    }
}

void ElfAnalyzer::parse_sections() {
    if (header_.e_shnum == 0) return;

    size_t sh_offset = header_.e_shoff;
    size_t sh_size = header_.e_shentsize;

    // Bounds check
    if (sh_offset + (header_.e_shnum * sh_size) > buffer_.size()) {
        throw BinGazeError(ErrorCode::ParseError, "Section headers exceed file bounds");
    }

    // Get string table offset
    if (header_.e_shstrndx < header_.e_shnum) {
        size_t strtab_hdr_offset = sh_offset + (header_.e_shstrndx * sh_size);
        Elf64_Shdr strtab_hdr;
        std::memcpy(&strtab_hdr, buffer_.data().data() + strtab_hdr_offset, sizeof(Elf64_Shdr));
        shstrtab_offset_ = strtab_hdr.sh_offset;
    }

    // Parse each section
    for (uint16_t i = 0; i < header_.e_shnum; ++i) {
        size_t offset = sh_offset + (i * sh_size);
        Elf64_Shdr shdr;
        std::memcpy(&shdr, buffer_.data().data() + offset, sizeof(Elf64_Shdr));

        Section section;
        section.name = get_section_name(shdr.sh_name);
        section.type = shdr.sh_type;
        section.flags = shdr.sh_flags;
        section.address = shdr.sh_addr;
        section.offset = shdr.sh_offset;
        section.size = shdr.sh_size;
        section.is_executable = (shdr.sh_flags & 0x4) != 0;  // SHF_EXECINSTR
        section.is_writable = (shdr.sh_flags & 0x1) != 0;    // SHF_WRITE

        // Calculate entropy for sections with content
        if (shdr.sh_type != 8 && shdr.sh_size > 0 && 
            shdr.sh_offset + shdr.sh_size <= buffer_.size()) {
            auto section_data = buffer_.data().subspan(shdr.sh_offset, shdr.sh_size);
            section.entropy = calculate_entropy(section_data);
        } else {
            section.entropy = 0.0;
        }

        sections_.push_back(std::move(section));
    }
}

void ElfAnalyzer::parse_segments() {
    if (header_.e_phnum == 0) return;

    size_t ph_offset = header_.e_phoff;
    size_t ph_size = header_.e_phentsize;

    if (ph_offset + (header_.e_phnum * ph_size) > buffer_.size()) {
        throw BinGazeError(ErrorCode::ParseError, "Program headers exceed file bounds");
    }

    for (uint16_t i = 0; i < header_.e_phnum; ++i) {
        size_t offset = ph_offset + (i * ph_size);
        Elf64_Phdr phdr;
        std::memcpy(&phdr, buffer_.data().data() + offset, sizeof(Elf64_Phdr));
        segments_.push_back(phdr);
    }
}

std::string ElfAnalyzer::get_section_name(uint32_t offset) const {
    if (shstrtab_offset_ == 0 || shstrtab_offset_ + offset >= buffer_.size()) {
        return "";
    }

    const char* start = reinterpret_cast<const char*>(buffer_.data().data() + shstrtab_offset_ + offset);
    
    // Find null terminator safely
    size_t max_len = buffer_.size() - shstrtab_offset_ - offset;
    size_t len = 0;
    while (len < max_len && start[len] != '\0') {
        ++len;
    }

    return std::string(start, len);
}

double ElfAnalyzer::calculate_entropy(std::span<const uint8_t> data) const {
    if (data.empty()) return 0.0;

    std::array<size_t, 256> freq{};
    for (uint8_t byte : data) {
        ++freq[byte];
    }

    double entropy = 0.0;
    double size = static_cast<double>(data.size());

    for (size_t count : freq) {
        if (count > 0) {
            double p = static_cast<double>(count) / size;
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

std::vector<Symbol> ElfAnalyzer::parse_symbols() const {
    std::vector<Symbol> symbols;
    
    // Find symbol tables
    for (const auto& section : sections_) {
        if (section.type == 2 || section.type == 11) {  // SHT_SYMTAB or SHT_DYNSYM
            // Implementation would parse symbols here
            // Omitted for brevity but would follow same bounds-checking pattern
        }
    }

    return symbols;
}

SecurityAssessment ElfAnalyzer::assess_security() const {
    SecurityAssessment result{};
    
    // Check for PIE (Position Independent Executable)
    result.has_pie = (header_.e_type == 3);  // ET_DYN

    // Check segments for security features
    for (const auto& seg : segments_) {
        // PT_GNU_STACK
        if (seg.p_type == 0x6474e551) {
            result.has_nx_stack = !(seg.p_flags & 0x1);  // PF_X
        }
        // PT_GNU_RELRO
        if (seg.p_type == 0x6474e552) {
            result.has_relro = true;
        }
        // Check for RWX segments
        if ((seg.p_flags & 0x7) == 0x7) {  // PF_R | PF_W | PF_X
            result.has_rwx_segments = true;
        }
    }

    // Check sections for stack canary
    for (const auto& section : sections_) {
        if (section.name == ".note.gnu.build-id") {
            // Build ID present
        }
        if (section.name.find("__stack_chk") != std::string::npos) {
            result.has_canary = true;
        }
    }

    // Generate warnings
    if (!result.has_nx_stack) {
        result.warnings.push_back("Executable stack detected (NX disabled)");
    }
    if (!result.has_pie) {
        result.warnings.push_back("Not compiled as PIE (ASLR limited)");
    }
    if (!result.has_relro) {
        result.warnings.push_back("RELRO not enabled");
    }
    if (result.has_rwx_segments) {
        result.warnings.push_back("RWX segment detected (dangerous)");
    }

    // Generate recommendations
    if (!result.has_pie) {
        result.recommendations.push_back("Compile with -fPIE -pie");
    }
    if (!result.has_canary) {
        result.recommendations.push_back("Compile with -fstack-protector-strong");
    }
    if (!result.has_relro) {
        result.recommendations.push_back("Link with -Wl,-z,relro,-z,now");
    }

    return result;
}

void ElfAnalyzer::print_info() const {
    std::cout << "\n[*] ELF Header Information\n";
    std::cout << "─────────────────────────────────────────\n";
    std::cout << "  Class:        " << (header_.e_ident[4] == 2 ? "64-bit" : "32-bit") << "\n";
    std::cout << "  Data:         " << (header_.e_ident[5] == 1 ? "Little Endian" : "Big Endian") << "\n";
    std::cout << "  Type:         " << header_.e_type << "\n";
    std::cout << "  Machine:      0x" << std::hex << header_.e_machine << std::dec << "\n";
    std::cout << "  Entry Point:  0x" << std::hex << header_.e_entry << std::dec << "\n";
    std::cout << "  Sections:     " << header_.e_shnum << "\n";
    std::cout << "  Segments:     " << header_.e_phnum << "\n";
}

void ElfAnalyzer::print_sections() const {
    std::cout << "\n[*] Sections (" << sections_.size() << ")\n";
    std::cout << "─────────────────────────────────────────────────────────────────────\n";
    std::cout << std::left << std::setw(20) << "Name" 
              << std::right << std::setw(12) << "Address"
              << std::setw(12) << "Size"
              << std::setw(8) << "Entropy"
              << std::setw(6) << "Flags"
              << "\n";
    std::cout << "─────────────────────────────────────────────────────────────────────\n";

    for (const auto& section : sections_) {
        std::string flags;
        if (section.is_executable) flags += "X";
        if (section.is_writable) flags += "W";
        if (section.flags & 0x2) flags += "A";  // SHF_ALLOC

        std::cout << std::left << std::setw(20) << section.name.substr(0, 19)
                  << std::right << "0x" << std::hex << std::setw(10) << section.address
                  << std::dec << std::setw(12) << section.size
                  << std::fixed << std::setprecision(2) << std::setw(8) << section.entropy
                  << std::setw(6) << flags
                  << "\n";

        // Highlight high entropy sections (possible packed/encrypted)
        if (section.entropy > 7.5 && section.size > 100) {
            std::cout << "     ⚠️  High entropy - possibly packed/encrypted\n";
        }
    }
}

void ElfAnalyzer::print_security() const {
    auto assessment = assess_security();

    std::cout << "\n[*] Security Assessment\n";
    std::cout << "─────────────────────────────────────────\n";
    
    auto check = [](bool v) { return v ? "✓" : "✗"; };
    
    std::cout << "  [" << check(assessment.has_nx_stack) << "] NX Stack (Non-Executable)\n";
    std::cout << "  [" << check(assessment.has_pie) << "] PIE (Position Independent)\n";
    std::cout << "  [" << check(assessment.has_relro) << "] RELRO (Read-Only Relocations)\n";
    std::cout << "  [" << check(assessment.has_canary) << "] Stack Canary\n";
    std::cout << "  [" << check(!assessment.has_rwx_segments) << "] No RWX Segments\n";

    if (!assessment.warnings.empty()) {
        std::cout << "\n⚠️  Warnings:\n";
        for (const auto& warning : assessment.warnings) {
            std::cout << "    • " << warning << "\n";
        }
    }

    if (!assessment.recommendations.empty()) {
        std::cout << "\n💡 Recommendations:\n";
        for (const auto& rec : assessment.recommendations) {
            std::cout << "    • " << rec << "\n";
        }
    }
}

// ==========================================================================
// CLI Interface
// ==========================================================================

void print_help() {
    std::cout << R"(
USAGE:
    bingaze [OPTIONS] <binary>

OPTIONS:
    -a, --all       Show all information
    -h, --header    Show ELF header
    -s, --sections  Show sections
    -S, --security  Security assessment
    -e, --entropy   Show entropy analysis
    --help          Show this help

EXAMPLES:
    bingaze -a /bin/ls
    bingaze -S /usr/bin/ssh
    bingaze -s --entropy ./my_binary
)";
}

}  // namespace NullSec

int main(int argc, char* argv[]) {
    std::cout << NullSec::BANNER << "v" << NullSec::VERSION << "\n";

    if (argc < 2) {
        NullSec::print_help();
        return 1;
    }

    bool show_all = false;
    bool show_header = false;
    bool show_sections = false;
    bool show_security = false;
    std::string binary_path;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--help") {
            NullSec::print_help();
            return 0;
        } else if (arg == "-a" || arg == "--all") {
            show_all = true;
        } else if (arg == "-h" || arg == "--header") {
            show_header = true;
        } else if (arg == "-s" || arg == "--sections") {
            show_sections = true;
        } else if (arg == "-S" || arg == "--security") {
            show_security = true;
        } else if (!arg.empty() && arg[0] != '-') {
            binary_path = arg;
        }
    }

    if (binary_path.empty()) {
        std::cerr << "[!] No binary specified\n";
        return 1;
    }

    try {
        auto path = NullSec::validate_path(binary_path);
        NullSec::ElfAnalyzer analyzer(path);

        if (show_all || show_header) {
            analyzer.print_info();
        }
        if (show_all || show_sections) {
            analyzer.print_sections();
        }
        if (show_all || show_security) {
            analyzer.print_security();
        }

        if (!show_all && !show_header && !show_sections && !show_security) {
            // Default: show all
            analyzer.print_info();
            analyzer.print_sections();
            analyzer.print_security();
        }

    } catch (const NullSec::BinGazeError& e) {
        std::cerr << "[!] Error: " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "[!] Unexpected error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
