/*
 * This file is part of the MAVLink Router project
 *
 * Copyright (C) 2019 FishSemi Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <common/log.h>
#include <common/util.h>
#include "mainloop.h"
#include "controller.h"

#define COMMAND_LEN_MAX 255

typedef bool (Controller::*MESSAGE_HANDLER)(char *payload);

typedef struct {
    const char *key;
    MESSAGE_HANDLER handler;
}control_command_table;

static control_command_table g_command_table[] {
    {"ADD_ENDPOINT",      &Controller::_handle_add_endpoint},
    {"REMOVE_ENDPOINT",   &Controller::_handle_remove_endpoint},
};

Controller Controller::_instance{};
Controller::Controller()
{
}

void Controller::open(struct options *opt)
{
    if(_instance._open_socket(opt->controller) >= 0) {
        _instance._load_options(opt);
        Mainloop::get_instance().add_fd(_instance.fd, &_instance, EPOLLIN);
        log_info("controller added.");
    }
}

int Controller::handle_read()
{
    bool ret;
    char buf[COMMAND_LEN_MAX+1] = {0};
    struct sockaddr_un src_addr;
    socklen_t addrlen = sizeof(src_addr);

    bzero((void*)&src_addr, sizeof(src_addr));
    ssize_t r = ::recvfrom(fd, buf, COMMAND_LEN_MAX, 0, (struct sockaddr*)&src_addr, &addrlen);

    if (r == -1) {
        if(errno != EAGAIN) {
            log_error("controller: _read_msg receive from fd error %d", errno);
        }
        return 0;
    }
    if (r == 0) {
        log_error("controller: _read_msg receive empty data");
        return 0;
    }

    _process_message(buf, r, (struct sockaddr*)&src_addr, addrlen);
    return 0;
}

bool Controller::_handle_add_endpoint(char *payload)
{
    char* ipaddress;
    int port = _endpoint_default_port;

    if (_parse_endpoint_info(payload, &ipaddress, &port)) {
        return _add_dynamic_udp_endpoint(ipaddress, port);
    }
    return false;
}

bool Controller::_handle_remove_endpoint(char *payload)
{
    char* ipaddress;
    int port = _endpoint_default_port;

    if (_parse_endpoint_info(payload, &ipaddress, &port)) {
        return _remove_dynamic_udp_endpoint(ipaddress, port);
    }
    return false;
}

int Controller::_open_socket(const char* name)
{
    int flags = 0;
    struct sockaddr_un addr;
    socklen_t addr_len;

    bzero((void*)&addr, sizeof(addr));
    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        log_error("controller: opening datagram socket failure");
        return -1;
    }
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = 0;
    strcpy(addr.sun_path+1, name);
	addr_len = strlen(name) + offsetof(struct sockaddr_un, sun_path) +1;

    if (bind(fd, (struct sockaddr *) &addr, addr_len)) {
        log_error("controller: binding to server socket failure %d", errno);
        goto fail;
    }
    if ((flags = fcntl(fd, F_GETFL, 0) == -1)) {
        log_error("controller: Error getfl for fd");
        goto fail;
    }
    if (fcntl(fd, F_SETFL, O_NONBLOCK | flags) < 0) {
        log_error("controller: Error setting socket fd as non-blocking");
        goto fail;
    }
    log_info("controller: Open controller [%d] %s", fd, name);

    return fd;

fail:
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
    return -1;
}

void Controller::_load_options(struct options *opt)
{
    endpoint_config *conf;
    filter_config *filter;
    char* p = nullptr;
    int len;

    for (conf = opt->endpoints; conf; conf = conf->next) {
        if (conf->type == Dynamic) {
            _endpoint_name = conf->name;
            _endpoint_default_port = conf->port_number;
            break;
        }
    }
    for (filter = opt->filters; filter; filter = filter->next) {
        if ((p = strchr(_endpoint_name, ':')) != nullptr) {
            len = p - _endpoint_name;
        } else {
            len = strlen(_endpoint_name);
        }

        if(!strncmp(filter->endpoint_name, _endpoint_name, len)) {
            _endpoint_msg_filter = *(filter->msg_ids);
            _endpoint_sys_comp_filter = *(filter->sys_comp_ids);
            _endpoint_filter_type = filter->type;
            break;
        }
    }
}

bool Controller::_process_message(char *msg, ssize_t len, struct sockaddr *src_addr, socklen_t addrlen)
{
    bool ret;
    char* p;
    uint32_t i, keylen;

    if(len > COMMAND_LEN_MAX) {
        log_error("controller: invalid message received");
        return false;
    }
    p = strchr(msg, ':');
    if (p == NULL) {
        log_error("controller: invalid command received: %s", msg);
        return false;
    }
    keylen = p-msg;
    for (i = 0; i < sizeof(g_command_table)/sizeof(g_command_table[0]); i++) {
        if ((keylen == strlen(g_command_table[i].key)) && !strncmp(msg, g_command_table[i].key, keylen)) {
            MESSAGE_HANDLER handler = g_command_table[i].handler;
            ret = (this->*handler)(p+1);
            _send_ack(g_command_table[i].key, ret, src_addr, addrlen);
            log_info("controller: complete handling command: %s ret=%d", msg, ret);
            return ret;
        }
    }

    log_error("controller: command received without handler: %s", msg);
    return false;
}

void Controller::_send_ack(const char *key, bool success, struct sockaddr *addr, socklen_t addrlen)
{
    char buf[COMMAND_LEN_MAX+1] = {0};

    strcpy(buf, key);
    strcat(buf, ":");
    if(success) {
        ::strcat(buf, "OK");
    } else {
        ::strcat(buf, "FAIL");
    }
    ::sendto(fd, buf, ::strlen(buf), 0, addr, addrlen);
}

bool Controller::_add_dynamic_udp_endpoint(const char *ipaddr, unsigned long port)
{
    bool ret;

    if (Mainloop::get_instance().find_udp_endpoint(ipaddr, port)) {
        log_info("controller: endpoint %s:%ld already exists", ipaddr, port);
        return true;
    }
    log_info("controller: add endpoint %s:%ld", ipaddr, port);

    std::unique_ptr<UdpEndpoint> udp_endpoint{new UdpEndpoint{_endpoint_name}};

    if (udp_endpoint->open(ipaddr, port, false) < 0) {
        log_error("controller: could not open %s:%ld", ipaddr, port);
        return false;
    }

    udp_endpoint->set_filter(_endpoint_filter_type, _endpoint_msg_filter,
                             _endpoint_sys_comp_filter);

    ret = Mainloop::get_instance().add_udp_endpoint(udp_endpoint.release());
    if (!ret) {
      log_error("controller: add udp endpoint failed");
      return false;
    }

    return true;
}

bool Controller::_remove_dynamic_udp_endpoint(const char *ipaddr, unsigned long port)
{
    if (!Mainloop::get_instance().find_udp_endpoint(ipaddr, port)) {
        log_info("controller: endpoint %s:%ld not exists", ipaddr, port);
        return true;
    }
    return Mainloop::get_instance().remove_udp_endpoint(ipaddr, port);
}

bool Controller::_parse_endpoint_info(char *payload, char **pIpaddress, int* pPort)
{
    char *str = NULL;
    char seps[] = ":";

    str = strtok(payload, seps);
    if (str != NULL) {
        *pIpaddress = str;
        str = strtok(NULL, seps);
        // port is optional
        if (str != NULL) {
            safe_atoi(str, pPort);
        }
        return true;
    }
    return false;
}
