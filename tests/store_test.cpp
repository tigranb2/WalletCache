#include "icryptomock.hpp"
#include "sodiumcrypto.hpp"
#include "store.hpp"

#include <fstream>
#include <memory>

using std::make_unique;

class StoreTest : public ::testing::Test {
  protected:
    void SetUp() override {
        in_stream_ = std::make_unique<std::ifstream>(std::ifstream());
        out_stream_ = std::make_unique<std::ofstream>(std::ofstream());

        istream_buffer_ = in_stream_->rdbuf();
        ostream_buffer_ = out_stream_->rdbuf();

        in_stream_->rdbuf(input_stream_.rdbuf());
        out_stream_->rdbuf(output_stream_.rdbuf());

        auto crypto = std::make_shared<SodiumCrypto>(SodiumCrypto());
        store_ = Store(crypto, std::move(in_stream_), std::move(out_stream_));
    }

    void TearDown() override {
        in_stream_->rdbuf(istream_buffer_);
        out_stream_->rdbuf(ostream_buffer_);
    }

    Store store_;

    std::unique_ptr<std::ifstream> in_stream_;
    std::unique_ptr<std::ofstream> out_stream_;

    std::streambuf *istream_buffer_;
    std::streambuf *ostream_buffer_;

    std::stringstream input_stream_;
    std::stringstream output_stream_;
};

TEST_F()
