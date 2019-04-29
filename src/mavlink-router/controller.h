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

#pragma once
#include "pollable.h"

class Controller: public Pollable {
public:
    Controller();
    int handle_read() override;
    bool handle_canwrite() override { return false; }
    static void open(struct options *opt);

    bool _handle_add_endpoint(char *payload);
    bool _handle_remove_endpoint(char *payload);

private:
    int _open_socket(const char *name);
    void _load_options(struct options *opt);
    bool _process_message(char *msg, ssize_t len, struct sockaddr *src_addr, socklen_t addrlen);
    void _send_ack(const char *key, bool success, struct sockaddr *addr, socklen_t addrlen);
    bool _add_dynamic_udp_endpoint(const char *ipaddr, unsigned long port);
    bool _remove_dynamic_udp_endpoint(const char *ipaddr, unsigned long port);
    bool _parse_endpoint_info(char *payload, char **pIpaddress, int* pPort);

    static Controller _instance;
    char *_endpoint_name = nullptr;
    int _endpoint_group = 0;
    int _endpoint_default_port = -1;
    filter_type _endpoint_filter_type = NoFilter;
    std::vector<uint32_t> _endpoint_msg_filter;
    std::vector<uint16_t> _endpoint_sys_comp_filter;
};
