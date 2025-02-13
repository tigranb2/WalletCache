#include <filesystem>

#include "fstreamfileio.hpp"
#include "utils.hpp"

FStreamFileIO::FStreamFileIO(const std::string &file_path) : FILE_PATH(file_path), TMP_FILE_PATH(file_path + ".tmp") {}

auto FStreamFileIO::Read(char *buf, int64_t stream_size) -> bool {
    return !!this->in_stream_.read(buf, stream_size); // Note: '!!' so that true indicates NO error
}

auto FStreamFileIO::WriteTemp(const char *buf, int64_t stream_size) -> bool {
    return !!this->out_stream_.write(buf, stream_size); // Note: '!!' so that true indicates NO error
}

auto FStreamFileIO::CommitTemp() -> int {
    if (!this->GetExists(false)) {
        if (rename(this->TMP_FILE_PATH.c_str(), this->FILE_PATH.c_str()) != 0) {
            this->Delete(true);
            return -1;
        }
        return 0;
    }

    const std::string bak_file_path = this->FILE_PATH + ".bak";
    if (rename(this->FILE_PATH.c_str(), bak_file_path.c_str()) != 0) {
        this->Delete(true);
        return -1;
    }

    if (rename(this->TMP_FILE_PATH.c_str(), this->FILE_PATH.c_str()) != 0) {
        rename(bak_file_path.c_str(), this->FILE_PATH.c_str());
        this->Delete(true);
        return -1;
    }

    if (!this->DeleteFile(bak_file_path)) {
        return -1;
    }

    return 0;
}

auto FStreamFileIO::OpenRead() -> int {
    try {
        this->in_stream_.open(this->FILE_PATH, std::ios::binary);
    } catch (...) {
        return -1;
    }

    return 0;
}

auto FStreamFileIO::OpenWriteTemp() -> int {
    try {
        this->out_stream_.open(this->TMP_FILE_PATH, std::ios::binary);
    } catch (...) {
        return -1;
    }

    return 0;
}

void FStreamFileIO::CloseRead() { this->in_stream_.close(); }

void FStreamFileIO::CloseWriteTemp() { this->out_stream_.close(); }

auto FStreamFileIO::GetPositionRead() -> int64_t { return this->in_stream_.tellg(); }

auto FStreamFileIO::GetPositionWriteTemp() -> int64_t { return this->out_stream_.tellp(); }

auto FStreamFileIO::GetSize(bool temp) -> uintmax_t {
    try {
        return temp ? std::filesystem::file_size(this->TMP_FILE_PATH) : std::filesystem::file_size(this->FILE_PATH);
    } catch (...) {
        return 0;
    }
}

auto FStreamFileIO::GetExists(bool temp) -> bool {
    return temp ? CheckFileExists(this->TMP_FILE_PATH) : CheckFileExists(this->FILE_PATH);
}

auto FStreamFileIO::Delete(bool temp) -> bool {
    return temp ? this->DeleteFile(this->TMP_FILE_PATH) : this->DeleteFile(this->FILE_PATH);
}

auto FStreamFileIO::DeleteFile(const std::string &path) -> bool { return std::filesystem::remove(path); }
