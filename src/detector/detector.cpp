#include "detector.hpp"
#include <unistd.h>
#include <filesystem>

extern "C"
{    
#include "../log.c/log.h"
}

int yara_callback(YR_SCAN_CONTEXT *context,
                  int message,
                  void *message_data,
                  void *user_data)
{
    if (message == CALLBACK_MSG_RULE_MATCHING)
    {
        //log_info("Process packet in query");
        Sender* s = (Sender* )user_data;
        YR_RULE *r = (YR_RULE *)message_data;
        auto st = std::string("Alert: ") + std::string(r->identifier);
        s->send_alert(st);
        return CALLBACK_ABORT;
    }

    return CALLBACK_CONTINUE;
}

void yara_error_callback(
    int error_level,
    const char* file_name,
    int line_number,
    const YR_RULE* rule,
    const char* message,
    void* user_data) {
        if (error_level == YARA_ERROR_LEVEL_ERROR) {
            log_error("%s", message);
        } else {
            log_warn("%s", message);
        }
    }

void Detector::process_tcp_payload(std::queue<tcp_payload> *q, Sender* s, YR_RULES* rules)
{
    while (true)
    {
        if (!q->empty())
        {
            tcp_payload p = q->front();
            q->pop();
            yr_rules_scan_mem(rules, p.payload, p.len, NULL, yara_callback, s, 100);
        }
    }
}

void Detector::init_yara_rules(FILE *rules_file)
{
    if (yr_initialize() != ERROR_SUCCESS)
    {
        throw DException("Cant initialize yara");
    }

    log_info("Yara loaded to memory");

    if (yr_compiler_create(&_yc) != ERROR_SUCCESS)
    {
        throw DException("Cant create compiler for yara");
    }

    yr_compiler_set_callback(_yc, yara_error_callback, NULL);
    log_info("Yara compiler loaded to memory");

    if (yr_compiler_add_file(_yc, rules_file, NULL, "yara.log") > 0)
    {
        throw DException("Found errors in rules file");
    }

    log_info("Yara rules compiled");

    if (yr_compiler_get_rules(_yc, &_rules) != ERROR_SUCCESS)
    {
        throw DException("Can't get rules from compiler");
    }

    log_info("Yara sucessfully initialized");
}

Detector::Detector(Sender* sender, FILE *yara_rules_file)
{
    _s = sender;
    log_info("Yara rules initiation");
    init_yara_rules(yara_rules_file);
    _t = std::thread(&process_tcp_payload, &_q, std::ref(_s), _rules);
    log_info("Async thread created");
    log_info("Sucessfully create Detector class");
}

Detector::~Detector()
{
    _t.detach();
    yr_finalize();

    if (_yc != nullptr)
    {
        yr_compiler_destroy(_yc);
    }
}

D_ERROR Detector::check_tcp_payload(const u_char *payload, size_t len)
{
    tcp_payload p;
    p.len = len;
    p.payload = payload;
    _q.push(p);
}