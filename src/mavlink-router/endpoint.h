/*
 * This file is part of the MAVLink Router project
 *
 * Copyright (C) 2016  Intel Corporation. All rights reserved.
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

#include <mavlink.h>

#include <memory>
#include <vector>
#include <sys/un.h>

#include "comm.h"
#include "pollable.h"
#include "timeout.h"

class Mainloop;

/*
 * mavlink 2.0 packet in its wire format
 *
 * Packet size:
 *      sizeof(mavlink_router_mavlink2_header)
 *      + payload length
 *      + 2 (checksum)
 *      + signature (0 if not signed)
 */
struct _packed_ mavlink_router_mavlink2_header {
    uint8_t magic;
    uint8_t payload_len;
    uint8_t incompat_flags;
    uint8_t compat_flags;
    uint8_t seq;
    uint8_t sysid;
    uint8_t compid;
    uint32_t msgid : 24;
};

/*
 * mavlink 1.0 packet in its wire format
 *
 * Packet size:
 *      sizeof(mavlink_router_mavlink1_header)
 *      + payload length
 *      + 2 (checksum)
 */
struct _packed_ mavlink_router_mavlink1_header {
    uint8_t magic;
    uint8_t payload_len;
    uint8_t seq;
    uint8_t sysid;
    uint8_t compid;
    uint8_t msgid;
};

enum filter_type { NoFilter, BlackList, WhiteList };

class Endpoint : public Pollable {
public:
    /*
     * Success returns for @read_msg()
     */
    enum read_msg_result {
        CrcErrorMsg = -1,
        ReadOk = 1,
        ReadUnkownMsg,
    };

    Endpoint(const char *name, bool crc_check_enabled);
    virtual ~Endpoint();

    int handle_read() override;
    bool handle_canwrite() override;

    virtual void print_statistics();
    virtual int write_msg(const struct buffer *pbuf) = 0;
    virtual int flush_pending_msgs() = 0;

    void log_aggregate(unsigned int interval_sec);

    uint8_t get_trimmed_zeros(const mavlink_msg_entry_t *msg_entry, const struct buffer *buffer);

    bool has_sys_id(unsigned sysid);
    bool has_sys_comp_id(unsigned sys_comp_id);
    bool has_sys_comp_id(unsigned sysid, unsigned compid) {
        uint16_t sys_comp_id = ((sysid & 0xff) << 8) | (compid & 0xff);
        return has_sys_comp_id(sys_comp_id);
    }

    bool accept_msg(int target_sysid, int target_compid, uint8_t src_sysid, uint8_t src_compid,
                    Endpoint* src_endpoint, uint32_t msg_id);
    const char* name();
    int group();

    void set_filter(filter_type type, std::vector<uint32_t> _msg_ids, std::vector<uint16_t> sys_comp_ids);
    bool in_msg_filter(uint32_t msg_id);
    bool in_sys_comp_filter(uint8_t sysid, uint8_t compid);

    bool in_pass_through_group();
    bool allow_pass_through(Endpoint* src);

    struct buffer rx_buf;
    struct buffer tx_buf;

    char *map_endpoint_name = nullptr;
    Endpoint *map_endpoint = nullptr;

protected:
    virtual int read_msg(struct buffer *pbuf, int *target_system, int *target_compid,
                         uint8_t *src_sysid, uint8_t *src_compid, uint32_t *pmsg_id);
    virtual ssize_t _read_msg(uint8_t *buf, size_t len) = 0;
    bool _check_crc(const mavlink_msg_entry_t *msg_entry);
    void _add_sys_comp_id(uint16_t sys_comp_id);

    char *_name = nullptr;
    size_t _last_packet_len = 0;

    // Statistics
    struct {
        struct {
            uint64_t crc_error_bytes = 0;
            uint64_t handled_bytes = 0;
            uint32_t total = 0; // handled + crc error + seq lost
            uint32_t crc_error = 0;
            uint32_t handled = 0;
            uint32_t drop_seq_total = 0;
            uint8_t expected_seq = 0;
        } read;
        struct {
            uint64_t bytes = 0;
            uint32_t total = 0;
        } write;
    } _stat;

    int _group = -1;
    const bool _crc_check_enabled;
    uint32_t _incomplete_msgs = 0;
    std::vector<uint16_t> _sys_comp_ids;
    filter_type _filter_type = NoFilter;
    std::vector<uint32_t> _msg_filter;
    std::vector<uint16_t> _sys_comp_filter;
};

class UartEndpoint : public Endpoint {
public:
    UartEndpoint(const char *name) : Endpoint{name, true} { }
    virtual ~UartEndpoint();
    int write_msg(const struct buffer *pbuf) override;
    int flush_pending_msgs() override { return -ENOSYS; }

    int open(const char *path);
    int set_speed(speed_t baudrate);
    int set_flow_control(bool enabled);
    int add_speeds(std::vector<unsigned long> baudrates);

protected:
    int read_msg(struct buffer *pbuf, int *target_system, int *target_compid, uint8_t *src_sysid,
                 uint8_t *src_compid, uint32_t *pmsg_id) override;
    ssize_t _read_msg(uint8_t *buf, size_t len) override;

private:
    size_t _current_baud_idx = 0;
    Timeout *_change_baud_timeout = nullptr;
    std::vector<unsigned long> _baudrates;

    bool _change_baud_cb(void *data);
};

class UdpEndpoint : public Endpoint {
public:
    UdpEndpoint(const char *name);
    ~UdpEndpoint();

    int write_msg(const struct buffer *pbuf) override;
    int flush_pending_msgs() override { return -ENOSYS; }

    int open(const char *ip, unsigned long port, bool bind = false, unsigned long bindport = 0);
    void close();

    inline const char *get_ip() {
        return _ip ? _ip : "";
    }

    inline unsigned long get_port() {
        return _port;
    }

    struct sockaddr_in sockaddr;

protected:
    ssize_t _read_msg(uint8_t *buf, size_t len) override;

private:
    char *_ip = nullptr;
    unsigned long _port = 0;
};

class TcpEndpoint : public Endpoint {
public:
    TcpEndpoint(const char *name);
    ~TcpEndpoint();

    int accept(int listener_fd);
    int open(const char *ip, unsigned long port);
    void close();

    int write_msg(const struct buffer *pbuf) override;
    int flush_pending_msgs() override { return -ENOSYS; }

    struct sockaddr_in sockaddr;
    int retry_timeout = 0;

    inline const char *get_ip() {
        return _ip;
    }

    inline unsigned long get_port() {
        return _port;
    }

    bool is_valid() override { return _valid; };

protected:
    ssize_t _read_msg(uint8_t *buf, size_t len) override;

private:
    char *_ip = nullptr;
    unsigned long _port = 0;
    bool _valid = true;
};

class LocalEndpoint : public Endpoint {
public:
    LocalEndpoint(const char *name);
    ~LocalEndpoint() { }

    int write_msg(const struct buffer *pbuf) override;
    int flush_pending_msgs() override { return -ENOSYS; }

    int open(const char* sock_name, const char* remote_name);

    struct sockaddr_un sockaddr;
    socklen_t sockaddr_len = 0;

protected:
    ssize_t _read_msg(uint8_t *buf, size_t len) override;
};
