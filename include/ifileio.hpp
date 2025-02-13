#ifndef IFILEIO_HPP
#define IFILEIO_HPP

#include <cstdint>
#include <ios>

class IFileIO {
  public:
    virtual ~IFileIO() = default;

    virtual auto Read(char *buf, int64_t stream_size) -> bool = 0;
    virtual auto WriteTemp(const char *buf, int64_t stream_size) -> bool = 0;
    virtual auto CommitTemp() -> int = 0;

    virtual auto OpenRead() -> int = 0;
    virtual auto OpenWriteTemp() -> int = 0;

    virtual void CloseRead() = 0;
    virtual void CloseWriteTemp() = 0;

    virtual auto GetPositionRead() -> int64_t = 0;
    virtual auto GetPositionWriteTemp() -> int64_t = 0;

    virtual auto GetSize(bool temp) -> uintmax_t = 0;
    virtual auto GetExists(bool temp) -> bool = 0;
    virtual auto Delete(bool temp) -> bool = 0; 
};

#endif // IFILEIO_HPP
