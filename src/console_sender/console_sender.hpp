#pragma once

#include <iostream>

#include "../detector/ISender.hpp"

class ConsoleSender : public Sender
{
public:
    int send_alert(std::string status);
};