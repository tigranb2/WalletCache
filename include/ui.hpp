#ifndef UI_HPP
#define UI_HPP

#include <string>

struct UIStrings {
    static const inline std::string WELCOME = "Welcome to WalletCache\n\n";
    static const inline std::string SELECT_OPT = "Select an option below:\n";

    static const inline std::string START_MENU_EXIT = "[0]: EXIT\n";
    static const inline std::string START_MENU_CREATE_PROFILE = "[1]: CREATE NEW PROFILE\n";
    static const inline std::string START_MENU_LOGIN_PROFILE = "[2]: LOGIN TO EXISTING PROFILE\n";

    static const inline std::string CREATE_PROFILE_MENU_PASSWORD = "Enter a master password:\n";
    static const inline std::string CREATE_PROFILE_MENU_CONFIRM_PASSWORD = "Confirm your master password:\n";

    static const inline std::string PROFILE_MENU_EXIT = "[0]: EXIT\n";
    static const inline std::string PROFILE_MENU_LIST = "[1]: LIST\n";
    static const inline std::string PROFILE_MENU_ADD = "[2]: ADD\n";
    static const inline std::string PROFILE_MENU_DELETE = "[3]: DELETE\n";

    static const inline std::string HASHING = "\nHashing...\n";

    static const inline std::string CARD_CVV_PROMPT = "Enter card cvv (or 0 to cancel):\n";
    static const inline std::string CARD_MONTH_PROMPT = "Enter card expiration month [Ex: 10 for october] (or 0 to cancel):\n";
    static const inline std::string CARD_NAME_PROMPT = "Optional: enter a name for the card using only letters or numbers (or 0 "
                                         "to cancel):\n";
    static const inline std::string CARD_NUMBER_PROMPT = "Enter card number (or 0 to cancel):\n";
    static const inline std::string CARD_YEAR_PROMPT = "Enter card expiration year [Ex: 2025] (or 0 to cancel):\n";

    static const inline std::string PASSWORD_PROMPT = "Enter the profile master password:\n";

    static const inline std::string CONFIRMATION_CANCEL = "[0] CANCEL\n";
    static const inline std::string CONFIRMATION_CONFIRM = "[1] CONFIRM\n";

    static const inline std::string REQUEST_VALID_INPUT = "Please input a number corresponding to available options.\n";
};

class UI {
    friend class UITest;

  public:
    enum StartMenuOption {
        OPT_START_EXIT = 0,
        OPT_START_NEW_PROFILE,
        OPT_START_LOGIN,
    };
    enum ProfileMenuOption {
        OPT_PROFILE_EXIT = 0,
        OPT_PROFILE_LIST,
        OPT_PROFILE_ADD,
        OPT_PROFILE_DEL,
    };

    auto StartMenu(const std::string &status_msg, bool profile_exists) -> StartMenuOption;
    void CreateProfileMenu(const std::string &status_msg, std::string &password, std::string &confirm_password);
    auto ProfileMenu(const std::string &status_msg) -> ProfileMenuOption;
    void CardsList(const std::string &cards_string);

    void DisplayHashing();

    void PromptCardCvv(const std::string &status_msg, std::string &cvv);
    void PromptCardMonth(const std::string &status_msg, std::string &month);
    void PromptCardName(const std::string &status_msg, std::string &card_name);
    void PromptCardNumber(const std::string &status_msg, std::string &card_number);
    void PromptCardYear(const std::string &status_msg, std::string &year);
    void PromptLogin(std::string &password);
    auto PromptConfirmation(const std::string &msg) -> bool;

  private:
    auto GetSelection(int lower, int upper) -> int;
    inline auto PromptInput() -> std::string;
    inline auto PromptInputMasked() -> std::string;
};

#endif // UI_HPP
