#include "console_sender.hpp"

int ConsoleSender::send_alert(std::string status)
{
    std::cout << status << std::endl;
    return 0;
}
