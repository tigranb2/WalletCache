#ifndef FSTREAMFILEIO_HPP
#define FSTREAMFILEIO_HPP

#include "ifileio.hpp"

#include <cstdint>
#include <fstream>
#include <ios>
#include <string>

class FStreamFileIO : public IFileIO {
  public:
    explicit FStreamFileIO(const std::string &file_path);
    ~FStreamFileIO() override = default;

    auto Read(char *buf, int64_t stream_size) -> bool override;
    auto WriteTemp(const char *buf, int64_t stream_size) -> bool override;
    auto CommitTemp() -> int override;

    auto OpenRead() -> int override;
    auto OpenWriteTemp() -> int override;

    void CloseRead() override;
    void CloseWriteTemp() override;

    auto GetPositionRead() -> int64_t override;
    auto GetPositionWriteTemp() -> int64_t override;

    auto GetSize(bool temp) -> uintmax_t override;
    auto GetExists(bool temp) -> bool override;
    auto Delete(bool temp) -> bool override;

  private:
    std::ifstream in_stream_;
    std::ofstream out_stream_;

    const std::string FILE_PATH;
    const std::string TMP_FILE_PATH;

    auto DeleteFile(const std::string &path) -> bool;
};

#endif // FSTREAMFILEIO_HPP
