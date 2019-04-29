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

#include <sys/types.h>
#include "endpoint.h"
#include "timeout.h"

#ifdef LAMP_SIGNAL_EXIST
#include <ISystemStatusListener.h>

using namespace android;
#endif

class SerialEndpoint : public Endpoint {
public:
    SerialEndpoint(const char* name);
    virtual ~SerialEndpoint();
    virtual int open(const char* path);
    int write_msg(const struct buffer* pbuf);
    void close();
    int set_flow_control(bool enabled);
    int set_speed(uint32_t baudrate);
    int add_speeds(std::vector<unsigned long> bauds);
    int flush_pending_msgs() override { return -ENOSYS; }
protected:
    virtual int read_msg(struct buffer* pbuf, int* target_sysid, int* target_compid,
                         uint8_t* src_sysid, uint8_t* src_compid, uint32_t* pmsg_id) override;
    ssize_t _read_msg(uint8_t* buf, size_t len);
    void _signal_data_available();
    bool _change_baudrate(void *data);
    uint32_t _retrieve_baudrate_property();
    bool _save_baudrate_property(uint32_t baudrate);
private:
    int _ttyfd;
    int _read_error_count;
    int _baudrate_index;
    uint32_t _try_count;
    uint32_t _last_baudrate;
    Timeout* _change_baudrate_timeout;
    std::vector<unsigned long> _available_baudrates;
    uint64_t _last_time_stamp;
#ifdef LAMP_SIGNAL_EXIST
    sp<ISystemStatusListener> _listener;
#endif
};
