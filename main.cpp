#include "creditcard.hpp"
#include "fstreamfileio.hpp"
#include "sodiumcrypto.hpp"
#include "store.hpp"
#include "ui.hpp"
#include "utils.hpp"
#include "verification.hpp"

#include <cstring>
#include <iostream>

auto GetStorePath() -> std::string {
    std::string homepath = GetHomePath();
    if (homepath.empty()) {
        return "";
    }

    return GetFilePath(homepath, Store::STORE_FILE_NAME);
}

auto CheckProfileReplacement(UI ui, bool profile_exists, UI::StartMenuOption input) -> int {
    if (profile_exists && input == UI::OPT_START_NEW_PROFILE) {
        std::string msg = "Are you sure you want to create a new profile? This will "
                          "replace the existing profile.\n";
        if (!ui.PromptConfirmation(msg)) {
            return -1;
        }
    }
    return 0;
}

void HandlePasswordSetup(UI &ui, unsigned char *password) {
    std::string error_msg;
    std::string input_password;
    std::string input_confirm;

    NewPasswordStatus valid_password;
    do {
        ui.CreateProfileMenu(error_msg, input_password, input_confirm);

        valid_password = VerifyNewPassword(input_password, input_confirm);
        switch (valid_password) {
        case PASS_TOO_SHORT:
            error_msg = "Password should be at least " + std::to_string(MIN_PASSWORD_LENGTH) + " characters long.\n";
            break;
        case PASS_TOO_LONG:
            error_msg = "Password should be at most " + std::to_string(MAX_PASSWORD_LENGTH) + " characters long.\n";
            break;
        case PASS_NO_MATCH:
            error_msg = "Passwords do not match.\n";
            break;
        case PASS_VALID:
            break;
        }
    } while (valid_password != PASS_VALID);

    memcpy(password, input_password.c_str(), input_password.size());
    password[input_password.size()] = 0;

    input_password.clear();
    input_confirm.clear();
}

auto HandleNewProfile(Store &store, UI &ui, const std::shared_ptr<SodiumCrypto> &crypto, bool profile_exists) -> int {
    if (profile_exists) {
        store.DeleteStore(false);
    }

    unsigned char password[MAX_PASSWORD_LENGTH + 1];
    HandlePasswordSetup(ui, password);
    ui.DisplayHashing();

    int res = store.InitNewStore(password);
    crypto->Memzero(password, MAX_PASSWORD_LENGTH + 1);
    return res;
}

auto HandleLogin(Store &store, UI &ui) -> Store::LoadStoreStatus {
    std::string input_password;
    ui.PromptLogin(input_password);

    unsigned char password[MAX_PASSWORD_LENGTH + 1];
    memcpy(password, input_password.c_str(), input_password.size());
    password[input_password.size()] = 0;
    return store.LoadStore(password);
}

auto HandleCardsList(Store &store, UI &ui) -> int {
    std::string cards_string = store.CardsDisplayString();
    ui.CardsList(cards_string);
    return 0;
}

auto HandleCardAdd(Store &store, UI &ui) -> int {
    auto *card = static_cast<CreditCard *>(calloc(1, sizeof(CreditCard)));

    std::string card_name;
    std::string error_msg;
    while (true) {
        ui.PromptCardName(error_msg, card_name);
        if (card_name == "0") {
            return 1;
        }
        if (card->SetName(card_name) != 0) {
            error_msg = "ERR: Name should contain only letters and numbers!\n";
        } else {
            break;
        }
    }

    std::string card_number;
    error_msg = "";
    while (true) {
        ui.PromptCardNumber(error_msg, card_number);
        if (card_number == "0") {
            return 1;
        }
        if (card->SetCardNumber(card_number) != 0) {
            error_msg = "ERR: Invalid card number!\n";
        } else {
            break;
        }
    }

    std::string card_cvv;
    error_msg = "";
    while (true) {
        ui.PromptCardCvv(error_msg, card_cvv);
        if (card_cvv == "0") {
            return 1;
        }
        if (card->SetCvv(card_cvv) != 0) {
            error_msg = "ERR: Invalid card cvv!\n";
        } else {
            break;
        }
    }

    std::string card_month;
    error_msg = "";
    while (true) {
        ui.PromptCardMonth(error_msg, card_month);
        if (card_month == "0") {
            return 1;
        }
        if (card->SetMonth(card_month) != 0) {
            error_msg = "ERR: Invalid card month!\n";
        } else {
            break;
        }
    }

    std::string card_year;
    error_msg = "";
    while (true) {
        ui.PromptCardYear(error_msg, card_year);
        if (card->SetYear(card_year) != 0) {
            error_msg = "ERR: Invalid card year!\n";
        } else {
            break;
        }
    }

    store.AddCard(card);
    return 0;
}

auto main() -> int {
    std::string store_path = GetStorePath();
    if (store_path.empty()) {
        std::cerr << "Failed to determine path for data file.\n";
        return -1;
    }

    UI ui = UI();
    auto sodium_crypto = std::make_shared<SodiumCrypto>();
    auto fstream_fileio = std::make_unique<FStreamFileIO>(store_path);
    Store store(sodium_crypto, std::move(fstream_fileio));

    if (sodium_crypto->InitCrypto() == -1) {
        std::cerr << "Failed to init crypto.\n";
        return -1;
    }

    bool logged_in = false;
    std::string status_msg;
    while (!logged_in) {
        bool profile_exists = store.StoreExists(false);

        UI::StartMenuOption selection = ui.StartMenu(status_msg, profile_exists);
        if (CheckProfileReplacement(ui, profile_exists, selection) != 0) {
            continue;
        }

        switch (selection) {
        case UI::OPT_START_EXIT:
            return 0;
        case UI::OPT_START_NEW_PROFILE:
            if (HandleNewProfile(store, ui, sodium_crypto, profile_exists) != 0) {
                status_msg = "ERR: Failed to initialize store for new profile\n";
            } else {
                status_msg = "Successfully created new profile!\n";
            }
            break;
        case UI::OPT_START_LOGIN:
            switch (HandleLogin(store, ui)) {
            case Store::LOAD_STORE_VALID:
                logged_in = true;
                break;
            case Store::LOAD_STORE_OPEN_ERR:
                status_msg = "ERR: Login failed. Unable to load data file.\n";
                break;
            case Store::LOAD_STORE_HEADER_READ_ERR:
                status_msg = "ERR: Login failed. Unable to read data file.\n";
                break;
            case Store::LOAD_STORE_PWD_VERIFY_ERR:
                status_msg = "ERR: Login failed. Please ensure password is correct.\n";
                break;
            case Store::LOAD_STORE_KEY_DERIVATION_ERR:
                status_msg = "ERR: Failed to derive encryption key.\n";
                break;
            case Store::LOAD_STORE_DATA_READ_ERR:
                status_msg = "ERR: Failed to read data file.\n";
                break;
            case Store::LOAD_STORE_DATA_DECRYPT_ERR:
                status_msg = "ERR: Failed to decrypt data.\n";
                break;
            }
            break;
        }
    }

    status_msg = "";
    while (true) {
        UI::ProfileMenuOption selection = ui.ProfileMenu(status_msg);
        switch (selection) {
        case UI::OPT_PROFILE_EXIT:
            return 0;
        case UI::OPT_PROFILE_LIST:
            HandleCardsList(store, ui);
            break;
        case UI::OPT_PROFILE_ADD:
            HandleCardAdd(store, ui);
            switch (store.SaveStore()) {
            case Store::SAVE_STORE_VALID:
                status_msg = "New card added successfully!\n";
                break;
            case Store::SAVE_STORE_OPEN_ERR:
                status_msg = "Failed to open new file\n";
                break;
            case Store::SAVE_STORE_HEADER_ERR:
                status_msg = "Failed to write new header!\n";
            case Store::SAVE_STORE_WRITE_DATA_ERR:
                status_msg = "Failed to write new data\n";
                break;
            case Store::SAVE_STORE_COMMIT_TEMP_ERR:
                status_msg = "Failed to commit new data\n";
                break;
            }

            break;
        case UI::OPT_PROFILE_DEL:
            break;
        }
    }
}
