#pragma once
#include <string>

class Sender {
    public:
        virtual int send_alert(std::string status);
        int check = 1;
};