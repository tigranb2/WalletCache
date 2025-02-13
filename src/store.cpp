#include "store.hpp"
#include "icrypto.hpp"
#include "utils.hpp"

#include <cstring>
#include <filesystem>
#include <utility>

Store::Store(std::shared_ptr<ICrypto> crypto, std::unique_ptr<IFileIO> fileio) {
    this->crypto_ = std::move(crypto);
    this->fileio_ = std::move(fileio);
}

Store::~Store() {
    for (CreditCard *card_ptr : this->cards_) {
        free(card_ptr);
    }

    this->cards_.clear();
}

auto Store::InitNewStore(unsigned char *password) -> int {
    unsigned char hash[this->crypto_->HashLen()];
    if (this->crypto_->HashPassword(hash, password) != 0) {
        return -1;
    }

    unsigned char salt[this->crypto_->SaltLen()];
    this->crypto_->GenerateSalt(salt);

    if (this->fileio_->OpenWriteTemp() != 0) {
        return -1;
    }
    if (this->WriteHeader(hash, salt) != 0) {
        this->fileio_->CloseWriteTemp();
        return -1;
    }
    this->fileio_->CloseWriteTemp();

    this->crypto_->Memzero(hash, this->crypto_->HashLen());
    return this->fileio_->CommitTemp();
}

auto Store::LoadStore(unsigned char *password) -> Store::LoadStoreStatus {
    unsigned char hash[this->crypto_->HashLen()];
    unsigned char salt[this->crypto_->SaltLen()];
    if (this->fileio_->OpenRead() != 0) {
        return LOAD_STORE_OPEN_ERR;
    }

    if (this->ReadHeader(hash, salt) != 0) {
        return LOAD_STORE_HEADER_READ_ERR;
    }

    if (this->crypto_->VerifyPasswordHash(hash, password) != 0) {
        return LOAD_STORE_PWD_VERIFY_ERR;
    }

    unsigned char encryption_key[this->crypto_->EncryptionKeyLen()];
    if (this->crypto_->DeriveEncryptionKey(encryption_key, this->crypto_->EncryptionKeyLen(), password, salt) != 0) {
        return LOAD_STORE_KEY_DERIVATION_ERR;
    }

    this->hashed_password_ = std::make_unique<unsigned char[]>(this->crypto_->HashLen());
    std::memcpy(this->hashed_password_.get(), hash, this->crypto_->HashLen());

    this->salt_ = std::make_unique<unsigned char[]>(this->crypto_->SaltLen());
    std::memcpy(this->salt_.get(), salt, this->crypto_->SaltLen());

    this->encryption_key_ = std::make_unique<unsigned char[]>(this->crypto_->EncryptionKeyLen());
    std::memcpy(this->encryption_key_.get(), encryption_key, this->crypto_->EncryptionKeyLen());

    uintmax_t store_size = this->fileio_->GetSize(false);
    if (store_size == 0) {
        return LOAD_STORE_DATA_READ_ERR;
    }
    uintmax_t data_size = store_size - this->crypto_->HashLen() - this->crypto_->SaltLen();
    if (data_size == 0) {
        return LOAD_STORE_VALID;
    }

    auto *decrypted_data = static_cast<unsigned char *>(malloc(data_size));
    uint64_t decrypted_size_actual;
    if (this->ReadData(decrypted_data, data_size, &decrypted_size_actual) != 0) {
        return LOAD_STORE_DATA_DECRYPT_ERR;
    }
    decrypted_data[decrypted_size_actual] = 0;

    this->LoadCards(decrypted_data);

    this->crypto_->Memzero(encryption_key, this->crypto_->EncryptionKeyLen());
    this->crypto_->Memzero(decrypted_data, data_size);
    free(decrypted_data);
    this->fileio_->CloseRead();

    return LOAD_STORE_VALID;
}

auto Store::SaveStore() -> Store::SaveStoreStatus {
    if (this->fileio_->OpenWriteTemp() != 0) {
        return SAVE_STORE_OPEN_ERR;
    }
    if (this->WriteHeader(this->hashed_password_.get(), this->salt_.get()) != 0) {
        this->fileio_->CloseWriteTemp();
        return SAVE_STORE_HEADER_ERR;
    }

    uintmax_t data_size = this->GetCardsSize();
    if (data_size != 0) {
        unsigned char data[data_size];
        this->CardsFormatted(data);
        if (this->WriteData(data, data_size) != 0) {
            return SAVE_STORE_WRITE_DATA_ERR;
        }
        this->crypto_->Memzero(data, data_size);
    }
    this->fileio_->CloseWriteTemp();

    if (this->fileio_->CommitTemp() != 0) {
        return SAVE_STORE_COMMIT_TEMP_ERR;
    }

    return SAVE_STORE_VALID;
}

void Store::AddCard(CreditCard *card) { this->cards_.push_back(card); }

auto Store::StoreExists(bool is_tmp) -> bool { return this->fileio_->GetExists(is_tmp); }

auto Store::DeleteStore(bool is_tmp) -> int { return this->fileio_->Delete(is_tmp) ? 0 : -1; }

auto Store::CardsDisplayString() -> std::string {
    std::string result;
    for (CreditCard *card : this->cards_) {
        result += card->GetName() + "\n";
    }
    return result;
}

auto Store::ReadHeader(unsigned char *hash, unsigned char *salt) -> int {
    if (this->fileio_->GetPositionRead() != 0) {
        return -1;
    }

    if (!this->fileio_->Read(reinterpret_cast<char *>(hash), this->crypto_->HashLen())) {
        return -1;
    }
    if (!this->fileio_->Read(reinterpret_cast<char *>(salt), this->crypto_->SaltLen())) {
        return -1;
    }

    if (this->fileio_->GetPositionRead() != (this->crypto_->HashLen() + this->crypto_->SaltLen())) {
        return -1;
    }

    return 0;
}

auto Store::ReadData(unsigned char *decrypted_data, uintmax_t data_size, uint64_t *decrypted_size_actual) -> int {
    unsigned char header[this->crypto_->EncryptionHeaderLen()];
    uintmax_t encrypted_data_size = data_size - this->crypto_->EncryptionHeaderLen();
    auto *encrypted_data = static_cast<unsigned char *>(malloc(encrypted_data_size));

    if (!this->fileio_->Read(reinterpret_cast<char *>(header), this->crypto_->EncryptionHeaderLen())) {
        free(encrypted_data);
        return -1;
    }
    if (!this->fileio_->Read(reinterpret_cast<char *>(encrypted_data), encrypted_data_size)) {
        free(encrypted_data);
        return -1;
    }

    if (this->crypto_->DecryptBuf(decrypted_data, decrypted_size_actual, header, encrypted_data, encrypted_data_size,
                                  this->encryption_key_.get()) != 0) {
        free(encrypted_data);
        return -1;
    }

    free(encrypted_data);
    return 0;
}

auto Store::WriteHeader(const unsigned char *hash, const unsigned char *salt) -> int {
    if (this->fileio_->GetPositionWriteTemp() != 0) {
        this->fileio_->CloseWriteTemp();
        return -1;
    }

    this->fileio_->WriteTemp(reinterpret_cast<const char *>(hash), this->crypto_->HashLen());
    this->fileio_->WriteTemp(reinterpret_cast<const char *>(salt), this->crypto_->SaltLen());
    if (this->fileio_->GetPositionWriteTemp() != (this->crypto_->HashLen() + this->crypto_->SaltLen())) {
        return -1;
    }

    return 0;
}

auto Store::WriteData(unsigned char *decrypted_data, uintmax_t decrypt_data_size) -> int {
    unsigned char header[this->crypto_->EncryptionHeaderLen()];
    uint64_t encrypted_len = decrypt_data_size + this->crypto_->EncryptionAddedBytes();
    auto *encrypted_data = static_cast<unsigned char *>(malloc(encrypted_len));
    if (encrypted_data == nullptr) {
        return -1;
    }

    if (this->crypto_->EncryptBuf(encrypted_data, header, decrypted_data, decrypt_data_size,
                                  this->encryption_key_.get()) != 0) {
        free(encrypted_data);
        return -1;
    }

    this->fileio_->WriteTemp(reinterpret_cast<const char *>(header), sizeof(header));
    this->fileio_->WriteTemp(reinterpret_cast<const char *>(encrypted_data), encrypted_len);

    if (this->fileio_->GetPositionWriteTemp() !=
        (this->crypto_->HashLen() + this->crypto_->SaltLen() + sizeof(header) + encrypted_len)) {
        free(encrypted_data);
        return -1;
    }

    free(encrypted_data);
    return 0;
}

auto Store::GetCardsSize() -> uintmax_t {
    uintmax_t total_size = 0;
    for (CreditCard *card_ptr : this->cards_) {
        total_size += card_ptr->FormatText().size();
    }
    return total_size;
}

auto Store::CardsFormatted(unsigned char *buf) -> uintmax_t {
    uintmax_t pos = 0;
    for (CreditCard *card_ptr : this->cards_) {
        std::string formatted_card = card_ptr->FormatText();
        size_t formatted_len = formatted_card.size();
        memcpy(buf + pos, formatted_card.c_str(), formatted_len);
        pos += formatted_len;
    }

    return pos;
}

void Store::LoadCards(unsigned char *data) {
    char *rest = nullptr;
    char *portion = strtok_r(reinterpret_cast<char *>(data), ";", &rest);

    while (portion != nullptr) {
        auto *card = static_cast<CreditCard *>(calloc(1, sizeof(CreditCard)));
        card->InitFromText(portion);
        this->AddCard(card);

        portion = strtok_r(nullptr, ";", &rest);
    }
}
