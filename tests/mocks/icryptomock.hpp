#include "icrypto.hpp"

#include <gmock/gmock.h>

class MockCrypto : public ICrypto {
  public:
    MOCK_METHOD(int, InitCrypto, (), (override));
    MOCK_METHOD(uint64_t, EncryptionAddedBytes, (), (const, override));
    MOCK_METHOD(uint64_t, EncryptionHeaderLen, (), (const, override));
    MOCK_METHOD(uint64_t, EncryptionKeyLen, (), (const, override));
    MOCK_METHOD(uint64_t, HashLen, (), (const, override));
    MOCK_METHOD(uint64_t, SaltLen, (), (const, override));
    MOCK_METHOD(int, DeriveEncryptionKey, (unsigned char *, size_t, const unsigned char *, const unsigned char *),
                (override));
    MOCK_METHOD(int, EncryptBuf,
                (unsigned char *, unsigned char *, const unsigned char *, uintmax_t, const unsigned char *),
                (override));
    MOCK_METHOD(int, HashPassword, (unsigned char *, const unsigned char *), (override));
    MOCK_METHOD(void, GenerateSalt, (unsigned char *), (override));
    MOCK_METHOD(int, DecryptBuf,
                (unsigned char *, uint64_t *, unsigned char *, unsigned char *, uintmax_t, const unsigned char *),
                (override));
    MOCK_METHOD(int, VerifyPasswordHash, (const unsigned char *, const unsigned char *), (override));
    MOCK_METHOD(void, Memzero, (void *, size_t), (override));
};
