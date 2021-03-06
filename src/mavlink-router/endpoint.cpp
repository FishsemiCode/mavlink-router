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
#include "endpoint.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <common/log.h>
#include <common/util.h>
#include <common/xtermios.h>

#include "mainloop.h"

#define RX_BUF_MAX_SIZE (MAVLINK_MAX_PACKET_LEN * 4)
#define TX_BUF_MAX_SIZE (8U * 1024U)

#define UART_BAUD_RETRY_SEC 5

#define PASS_THROUGH_GROUP_BEGIN 100
#define PASS_THROUGH_GROUP_END (PASS_THROUGH_GROUP_BEGIN + 99)

Endpoint::Endpoint(const char *name, bool crc_check_enabled)
    : _crc_check_enabled{crc_check_enabled}
{
    rx_buf.data = (uint8_t *) malloc(RX_BUF_MAX_SIZE);
    rx_buf.len = 0;
    tx_buf.data = (uint8_t *) malloc(TX_BUF_MAX_SIZE);
    tx_buf.len = 0;

    assert(rx_buf.data);
    assert(tx_buf.data);
    if (name != nullptr) {
        char* p = strchr(name, ':');
        if (p != nullptr) {
            safe_atoi(p+1, &_group);
            _name = strndup(name, p-name);
        } else {
            _name = strdup(name);
        }
    }
}

Endpoint::~Endpoint()
{
    free(_name);
    free(rx_buf.data);
    free(tx_buf.data);
}

bool Endpoint::handle_canwrite()
{
    int r = flush_pending_msgs();
    return r == -EAGAIN;
}

int Endpoint::handle_read()
{
    int target_sysid, target_compid, r;
    uint8_t src_sysid, src_compid;
    uint32_t msg_id;
    struct buffer buf{};
    uint64_t now_msec, duration;

    // Map endpoint exists, just pass data to it
    if (map_endpoint != nullptr) {
        now_msec = now_usec() / USEC_PER_MSEC;
        r = _read_msg(rx_buf.data, RX_BUF_MAX_SIZE);
        duration = now_usec() / USEC_PER_MSEC - now_msec;
        if (duration > 3) {
            log_warning("[%s] reading may block mainloop: [%lums]", name(), duration);
        }
        if (r > 0) {
            rx_buf.len = r;
            log_debug("mapping data from [%s] to [%s], size [%d]", name(), (map_endpoint)->name(), r);
            Mainloop::get_instance().write_msg(map_endpoint, &rx_buf);
        }
        return r;
    }

    // In pass-through mode, need not parse message
    if (Mainloop::get_instance().passthrough_mode || in_pass_through_group()) {
        now_msec = now_usec() / USEC_PER_MSEC;
        r = _read_msg(rx_buf.data, RX_BUF_MAX_SIZE);
        duration = now_usec() / USEC_PER_MSEC - now_msec;
        if (duration > 3) {
            log_warning("[%s] reading may block mainloop: [%lums]", name(), duration);
        }
        if (r > 0) {
            rx_buf.len = r;
            Mainloop::get_instance().passthrough_data(&rx_buf, this);
        } else {
            log_warning("[%s] reading fail: [%d]", name(), r);
        }
        return r;
    }

    do {
        now_msec = now_usec() / USEC_PER_MSEC;
        r = read_msg(&buf, &target_sysid, &target_compid, &src_sysid, &src_compid, &msg_id);
        duration = now_usec() / USEC_PER_MSEC - now_msec;
        if (duration > 3) {
            log_warning("[%s] reading may block mainloop: [%lums]", name(), duration);
        }
        if (r > 0) {
            Mainloop::get_instance().route_msg(&buf, target_sysid, target_compid, src_sysid,
                                               src_compid, this, msg_id);
        }
    } while(r > 0);

    return r;
}

int Endpoint::read_msg(struct buffer *pbuf, int *target_sysid, int *target_compid,
                       uint8_t *src_sysid, uint8_t *src_compid, uint32_t *pmsg_id)
{
    bool should_read_more = true;
    uint32_t msg_id;
    const mavlink_msg_entry_t *msg_entry;
    uint8_t *payload, seq, payload_len;

    if (fd < 0) {
        log_error("Trying to read invalid fd");
        return -EINVAL;
    }

    if (_last_packet_len != 0) {
        /*
         * read_msg() should be called in a loop after writting to each
         * output. However we don't want to keep busy looping on a single
         * endpoint reading more data. If we left data behind, move them
         * to the beginning and check we have a complete packet, but don't
         * read more data right now - it will be handled on next
         * iteration when more data is available
         */
        should_read_more = false;

        /* see TODO below about using bigger buffers: we could just walk on
         * the buffer rather than moving bytes */
        rx_buf.len -= _last_packet_len;
        if (rx_buf.len > 0) {
            memmove(rx_buf.data, rx_buf.data + _last_packet_len, rx_buf.len);
        }

        _last_packet_len = 0;
    }

    if (should_read_more) {
        ssize_t r = _read_msg(rx_buf.data + rx_buf.len, RX_BUF_MAX_SIZE - rx_buf.len);
        if (r <= 0)
            return r;

        log_debug("%s: Got %zd bytes [%d]", _name, r, fd);
        rx_buf.len += r;
    }

    bool mavlink2 = rx_buf.data[0] == MAVLINK_STX;
    bool mavlink1 = rx_buf.data[0] == MAVLINK_STX_MAVLINK1;

    /*
     * Find magic byte as the start byte:
     *
     * we either enter here due to new bytes being written to the
     * beginning of the buffer or due to _last_packet_len not being 0
     * above, which means we moved some bytes we read previously
     */
    if (!mavlink1 && !mavlink2) {
        unsigned int stx_pos = 0;

        for (unsigned int i = 1; i < (unsigned int) rx_buf.len; i++) {
            if (rx_buf.data[i] == MAVLINK_STX)
                mavlink2 = true;
            else if (rx_buf.data[i] == MAVLINK_STX_MAVLINK1)
                mavlink1 = true;

            if (mavlink1 || mavlink2) {
                stx_pos = i;
                break;
            }
        }

        /* Discarding data since we don't have a marker */
        if (stx_pos == 0) {
            rx_buf.len = 0;
            return 0;
        }

        /*
         * TODO: a larger buffer would allow to avoid the memmove in case a
         * new message would still fit in our buffer
         */
        rx_buf.len -= stx_pos;
        memmove(rx_buf.data, rx_buf.data + stx_pos, rx_buf.len);
    }

    const uint8_t checksum_len = 2;
    size_t expected_size;

    if (mavlink2) {
        struct mavlink_router_mavlink2_header *hdr =
                (struct mavlink_router_mavlink2_header *)rx_buf.data;

        if (rx_buf.len < sizeof(*hdr))
            return 0;

        msg_id = hdr->msgid;
        payload = rx_buf.data + sizeof(*hdr);
        seq = hdr->seq;
        *src_sysid = hdr->sysid;
        *src_compid = hdr->compid;
        payload_len = hdr->payload_len;

        expected_size = sizeof(*hdr);
        expected_size += hdr->payload_len;
        expected_size += checksum_len;
        if (hdr->incompat_flags & MAVLINK_IFLAG_SIGNED)
            expected_size += MAVLINK_SIGNATURE_BLOCK_LEN;
    } else {
        struct mavlink_router_mavlink1_header *hdr =
                (struct mavlink_router_mavlink1_header *)rx_buf.data;

        if (rx_buf.len < sizeof(*hdr))
            return 0;

        msg_id = hdr->msgid;
        payload = rx_buf.data + sizeof(*hdr);
        seq = hdr->seq;
        *src_sysid = hdr->sysid;
        *src_compid = hdr->compid;
        payload_len = hdr->payload_len;

        expected_size = sizeof(*hdr);
        expected_size += hdr->payload_len;
        expected_size += checksum_len;
    }

    /* check if we have a valid mavlink packet */
    if (rx_buf.len < expected_size)
        return 0;

    /* We always want to transmit one packet at a time; record the number
     * of bytes read in addition to the expected size and leave them for
     * the next iteration */
    _last_packet_len = expected_size;
    _stat.read.total++;

    msg_entry = mavlink_get_msg_entry(msg_id);
    if (_crc_check_enabled && msg_entry) {
        /*
         * It is accepting and forwarding unknown messages ids because
         * it can be a new MAVLink message implemented only in
         * Ground Station and Flight Stack. Although it can also be a
         * corrupted message is better forward than silent drop it.
         */
        if (!_check_crc(msg_entry)) {
            _stat.read.crc_error++;
            _stat.read.crc_error_bytes += expected_size;
            return CrcErrorMsg;
        }
    }

    _stat.read.handled++;
    _stat.read.handled_bytes += expected_size;

    if (!_crc_check_enabled || msg_entry) {
        _add_sys_comp_id(((uint16_t)*src_sysid << 8) | *src_compid);
    }

    *pmsg_id = msg_id;

    *target_sysid = -1;
    *target_compid = -1;

    if (msg_entry == nullptr) {
        log_debug("No message entry for %u", msg_id);
    } else {
        if (msg_entry->flags & MAV_MSG_ENTRY_FLAG_HAVE_TARGET_SYSTEM) {
            // if target_system is 0, it may have been trimmed out on mavlink2
            if (msg_entry->target_system_ofs < payload_len) {
                *target_sysid = payload[msg_entry->target_system_ofs];
            } else {
                *target_sysid = 0;
            }
        }
        if (msg_entry->flags & MAV_MSG_ENTRY_FLAG_HAVE_TARGET_COMPONENT) {
            // if target_system is 0, it may have been trimmed out on mavlink2
            if (msg_entry->target_component_ofs < payload_len) {
                *target_compid = payload[msg_entry->target_component_ofs];
            } else {
                *target_compid = 0;
            }
        }
    }

    // Check for sequence drops
    if (_stat.read.expected_seq != seq) {
        if (_stat.read.total > 1) {
            uint8_t diff;

            if (seq > _stat.read.expected_seq)
                diff = (seq - _stat.read.expected_seq);
            else
                diff = (UINT8_MAX - _stat.read.expected_seq) + seq;

            _stat.read.drop_seq_total += diff;
            _stat.read.total += diff;
        }
        _stat.read.expected_seq = seq;
    }
    _stat.read.expected_seq++;

    pbuf->data = rx_buf.data;
    pbuf->len = expected_size;

    return msg_entry != nullptr ? ReadOk : ReadUnkownMsg;
}

void Endpoint::_add_sys_comp_id(uint16_t sys_comp_id)
{
    if (has_sys_comp_id(sys_comp_id))
        return;

    _sys_comp_ids.push_back(sys_comp_id);
}

bool Endpoint::has_sys_id(unsigned sysid)
{
    for (auto it = _sys_comp_ids.begin(); it != _sys_comp_ids.end(); it++) {
        if (((*it >> 8) | (sysid & 0xff)) == sysid)
            return true;
    }
    return false;
}

bool Endpoint::has_sys_comp_id(unsigned sys_comp_id)
{
    for (auto it = _sys_comp_ids.begin(); it != _sys_comp_ids.end(); it++) {
        if (sys_comp_id == *it)
            return true;
    }

    return false;
}

bool Endpoint::accept_msg(int target_sysid, int target_compid, uint8_t src_sysid,
                          uint8_t src_compid, Endpoint* src_endpoint, uint32_t msg_id)
{
    if (Log::get_max_level() >= Log::Level::DEBUG) {
        log_debug("Endpoint [%s][%d] got message [%u] to %d/%d from [%s]%u/%u",
                  name(), fd,
                  msg_id, target_sysid, target_compid,
                  (src_endpoint == nullptr) ? "NONAME" : src_endpoint->name(),
                  src_sysid, src_compid);
        log_debug("\tKnown endpoints:");
        for (auto it = _sys_comp_ids.begin(); it != _sys_comp_ids.end(); it++) {
            log_debug("\t\t%u/%u", (*it >> 8), *it & 0xff);
        }
        log_debug("\tMsg filter [%d]:", _filter_type);
        for (auto it = _msg_filter.begin(); it != _msg_filter.end(); it++) {
            log_debug("\t\t%u", *it);
        }
        for (auto it = _sys_comp_filter.begin(); it != _sys_comp_filter.end(); it++) {
            log_debug("\t\t%u/%u", *it >> 8, *it & 0xff);
        }
    }

    // message will not route to sender itself
    if(src_endpoint == this ) {
        return false;
    }

    // map endpoint exists, ignore other messages
    if (map_endpoint != nullptr && map_endpoint != src_endpoint) {
        return false;
    }

    // message will not route to pass-through endpoint
    if (in_pass_through_group()) {
        return false;
    }

    // message will not route to endpoint in same group
    if((_group >= 0) && (src_endpoint != nullptr) && (src_endpoint->group() == _group)) {
        return false;
    }

    // This endpoint sent the message, and there's no other sys_comp_id: reject msg
    if (has_sys_comp_id(src_sysid, src_compid) && _sys_comp_ids.size() == 1)
        return false;

    // black list filter
    if (_filter_type == BlackList
            && (in_msg_filter(msg_id) || in_sys_comp_filter(src_sysid, src_compid))) {
        return false;
    }

    // Message is broadcast on sysid: accept msg
    if (target_sysid == 0 || target_sysid == -1) {
        // in whitelist mode, only accept boardcast msg in white list filter
        if (_filter_type == WhiteList &&
                ((_msg_filter.size() > 0 && !in_msg_filter(msg_id)) ||
                 (_sys_comp_filter.size() > 0 && !in_sys_comp_filter(src_sysid, src_compid)))) {
            return false;
        }
        return true;
    }

    // This endpoint has the target of message (sys and comp id): accept
    if (target_compid > 0 && has_sys_comp_id(target_sysid, target_compid))
        return true;

    // This endpoint has the target sys id of message: accept
    if (has_sys_id(target_sysid))
        return true;

    // Reject everything else
    return false;
}

const char* Endpoint::name()
{
    return (_name == nullptr) ? "NONAME" : _name;
}

int Endpoint::group()
{
    return _group;
}

void Endpoint::set_filter(filter_type type, std::vector<uint32_t> msg_ids, std::vector<uint16_t> sys_comp_ids)
{
    _filter_type = type;
    _msg_filter = msg_ids;
    _sys_comp_filter = sys_comp_ids;
    for (auto it = _msg_filter.begin(); it != _msg_filter.end(); it++) {
        log_info("msg filter for [%s], type [%d]: [%u]", _name, _filter_type, *it);
    }
    for (auto it = _sys_comp_filter.begin(); it != _sys_comp_filter.end(); it++) {
        log_info("sys comp filter for [%s], type [%d]: [%u/%u]", _name, _filter_type, (*it) >> 8, (*it) & 0xff);
    }
}

bool Endpoint::in_msg_filter(uint32_t msg_id)
{
    for (auto it = _msg_filter.begin(); it != _msg_filter.end(); it++) {
        if (msg_id == *it)
            return true;
    }

    return false;
}

bool Endpoint::in_sys_comp_filter(uint8_t sysid, uint8_t compid)
{
    uint8_t id;

    for (auto it = _sys_comp_filter.begin(); it != _sys_comp_filter.end(); it++) {
        if (compid == ((*it) & 0xff)) {
            id = (*it) >> 8;
            if (id == 0 || id == sysid) {
                return true;
            }
        } else if (sysid == ((*it) >> 8)) {
            id = (*it) & 0xff;
            if (id == 0 || id == compid) {
                return true;
            }
        }
    }
    return false;
}

bool Endpoint::in_pass_through_group()
{
    return (_group >= PASS_THROUGH_GROUP_BEGIN) && (_group <= PASS_THROUGH_GROUP_END);
}

bool Endpoint::allow_pass_through(Endpoint* src)
{
    if (((Mainloop::get_instance().passthrough_mode && group() >= 0) || in_pass_through_group())
        && (map_endpoint == nullptr || map_endpoint == src)
        && group() != src->group()) {
        return true;
    }
    return false;
}

bool Endpoint::_check_crc(const mavlink_msg_entry_t *msg_entry)
{
    const bool mavlink2 = rx_buf.data[0] == MAVLINK_STX;
    uint16_t crc_msg, crc_calc;
    uint8_t payload_len, header_len, *payload;

    if (mavlink2) {
        struct mavlink_router_mavlink2_header *hdr =
                    (struct mavlink_router_mavlink2_header *)rx_buf.data;
        payload = rx_buf.data + sizeof(*hdr);
        header_len = sizeof(*hdr);
        payload_len = hdr->payload_len;
    } else {
        struct mavlink_router_mavlink1_header *hdr =
                    (struct mavlink_router_mavlink1_header *)rx_buf.data;
        payload = rx_buf.data + sizeof(*hdr);
        header_len = sizeof(*hdr);
        payload_len = hdr->payload_len;
    }

    crc_msg = payload[payload_len] | (payload[payload_len + 1] << 8);
    crc_calc = crc_calculate(&rx_buf.data[1], header_len + payload_len - 1);
    crc_accumulate(msg_entry->crc_extra, &crc_calc);
    if (crc_calc != crc_msg) {
        return false;
    }

    return true;
}

void Endpoint::print_statistics()
{
    const uint32_t read_total = _stat.read.total == 0 ? 1 : _stat.read.total;

    log_info("Endpoint %s [%d] {", _name, fd);
    log_info("\n\tReceived messages {");
    log_info("\n\t\tCRC error: %u %u%% %luKBytes", _stat.read.crc_error,
           (_stat.read.crc_error * 100) / read_total, _stat.read.crc_error_bytes / 1000);
    log_info("\n\t\tSequence lost: %u %u%%", _stat.read.drop_seq_total,
           (_stat.read.drop_seq_total * 100) / read_total);
    log_info("\n\t\tHandled: %u %luKBytes", _stat.read.handled, _stat.read.handled_bytes / 1000);
    log_info("\n\t\tTotal: %u", _stat.read.total);
    log_info("\n\t}");
    log_info("\n\tTransmitted messages {");
    log_info("\n\t\tTotal: %u %luKBytes", _stat.write.total, _stat.write.bytes / 1000);
    log_info("\n\t}");
    log_info("\n}\n");
}

uint8_t Endpoint::get_trimmed_zeros(const mavlink_msg_entry_t *msg_entry, const struct buffer *buffer)
{
    struct mavlink_router_mavlink2_header *msg
        = (struct mavlink_router_mavlink2_header *)buffer->data;

    /* Only MAVLink 2 trim zeros */
    if (buffer->data[0] != MAVLINK_STX)
        return 0;

    /* Should never happen but if happens it will cause stack overflow */
    if (msg->payload_len > msg_entry->msg_len)
        return 0;

    return msg_entry->msg_len - msg->payload_len;
}

void Endpoint::log_aggregate(unsigned int interval_sec)
{
    if (_incomplete_msgs > 0) {
        log_warning("Endpoint %s [%d]: %u incomplete messages in the last %d seconds", _name, fd,
                    _incomplete_msgs, interval_sec);
        _incomplete_msgs = 0;
    }
}

UartEndpoint::~UartEndpoint()
{
    if (fd > 0) {
        reset_uart(fd);
    }
}

int UartEndpoint::set_speed(speed_t baudrate)
{
    struct termios2 tc;

    if (fd < 0) {
        return -1;
    }

    bzero(&tc, sizeof(tc));
    if (ioctl(fd, TCGETS2, &tc) == -1) {
        log_error("Could not get termios2 (%m)");
        return -1;
    }

    /* speed is configured by c_[io]speed */
    tc.c_cflag &= ~CBAUD;
    tc.c_cflag |= BOTHER;
    tc.c_ispeed = baudrate;
    tc.c_ospeed = baudrate;

    if (ioctl(fd, TCSETS2, &tc) == -1) {
        log_error("Could not set terminal attributes (%m)");
        return -1;
    }

    log_info("UART [%d] speed = %u", fd, baudrate);

    if (ioctl(fd, TCFLSH, TCIOFLUSH) == -1) {
        log_error("Could not flush terminal (%m)");
        return -1;
    }

    return 0;
}

int UartEndpoint::set_flow_control(bool enabled)
{
    struct termios2 tc;

    if (fd < 0) {
        return -1;
    }

    bzero(&tc, sizeof(tc));
    if (ioctl(fd, TCGETS2, &tc) == -1) {
        log_error("Could not get termios2 (%m)");
        return -1;
    }

    if (enabled)
        tc.c_cflag |= CRTSCTS;
    else
        tc.c_cflag &= ~CRTSCTS;

    if (ioctl(fd, TCSETS2, &tc) == -1) {
        log_error("Could not set terminal attributes (%m)");
        return -1;
    }

    log_info("UART [%d] flowcontrol = %s", fd, enabled ? "enabled" : "disabled");

    return 0;
}

int UartEndpoint::open(const char *path)
{
    struct termios2 tc;
    const int bit_dtr = TIOCM_DTR;
    const int bit_rts = TIOCM_RTS;

    fd = ::open(path, O_RDWR|O_NONBLOCK|O_CLOEXEC|O_NOCTTY);
    if (fd < 0) {
        log_error("Could not open %s (%m)", path);
        return -1;
    }

    if (reset_uart(fd) < 0) {
        log_error("Could not reset uart");
        goto fail;
    }

    bzero(&tc, sizeof(tc));

    if (ioctl(fd, TCGETS2, &tc) == -1) {
        log_error("Could not get termios2 (%m)");
        goto fail;
    }

    tc.c_iflag &= ~(IGNBRK | BRKINT | ICRNL | INLCR | PARMRK | INPCK | ISTRIP | IXON);
    tc.c_oflag &= ~(OCRNL | ONLCR | ONLRET | ONOCR | OFILL | OPOST);

    tc.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | ECHONL | ICANON | IEXTEN | ISIG);

    /* never send SIGTTOU*/
    tc.c_lflag &= ~(TOSTOP);

    /* disable flow control */
    tc.c_cflag &= ~(CRTSCTS);
    tc.c_cflag &= ~(CSIZE | PARENB);

    /* ignore modem control lines */
    tc.c_cflag |= CLOCAL;

    /* 8 bits */
    tc.c_cflag |= CS8;

    /* we use epoll to get notification of available bytes */
    tc.c_cc[VMIN] = 0;
    tc.c_cc[VTIME] = 0;

    if (ioctl(fd, TCSETS2, &tc) == -1) {
        log_error("Could not set terminal attributes (%m)");
        goto fail;
    }

    /* set DTR/RTS */
    if (ioctl(fd, TIOCMBIS, &bit_dtr) == -1 ||
        ioctl(fd, TIOCMBIS, &bit_rts) == -1) {
        log_error("Could not set DTR/RTS (%m)");
        goto fail;
    }

    if (ioctl(fd, TCFLSH, TCIOFLUSH) == -1) {
        log_error("Could not flush terminal (%m)");
        goto fail;
    }

    log_info("Open UART [%d] %s *", fd, path);

    return fd;

fail:
    ::close(fd);
    fd = -1;
    return -1;
}

bool UartEndpoint::_change_baud_cb(void *data)
{
    _current_baud_idx = (_current_baud_idx + 1) % _baudrates.size();

    log_info("Retrying UART [%d] on new baudrate: %lu", fd, _baudrates[_current_baud_idx]);

    set_speed(_baudrates[_current_baud_idx]);

    return true;
}

int UartEndpoint::read_msg(struct buffer *pbuf, int *target_sysid, int *target_compid,
                           uint8_t *src_sysid, uint8_t *src_compid, uint32_t *pmsg_id)
{
    int ret = Endpoint::read_msg(pbuf, target_sysid, target_compid, src_sysid, src_compid, pmsg_id);

    if (_change_baud_timeout != nullptr && ret == ReadOk) {
        log_info("Baudrate %lu responded, keeping it", _baudrates[_current_baud_idx]);
        Mainloop::get_instance().del_timeout(_change_baud_timeout);
        _change_baud_timeout = nullptr;
    }

    return ret;
}

ssize_t UartEndpoint::_read_msg(uint8_t *buf, size_t len)
{
    ssize_t r = ::read(fd, buf, len);
    if ((r == -1 && errno == EAGAIN) || r == 0)
        return 0;
    if (r == -1)
        return -errno;

    return r;
}

int UartEndpoint::write_msg(const struct buffer *pbuf)
{
    if (fd < 0) {
        log_error("Trying to write invalid fd");
        return -EINVAL;
    }

    /* TODO: send any pending data */
    if (tx_buf.len > 0) {
        ;
    }

    ssize_t r = ::write(fd, pbuf->data, pbuf->len);
    if (r == -1 && errno == EAGAIN)
        return -EAGAIN;

    _stat.write.total++;
    _stat.write.bytes += pbuf->len;

    /* Incomplete packet, we warn and discard the rest */
    if (r != (ssize_t) pbuf->len) {
        _incomplete_msgs++;
        log_debug("Discarding packet, incomplete write %zd but len=%u", r, pbuf->len);
    }

    log_debug("UART: [%d] wrote %zd bytes", fd, r);

    return r;
}

int UartEndpoint::add_speeds(std::vector<unsigned long> bauds)
{
    if (!bauds.size())
        return -EINVAL;

    _baudrates = bauds;

    set_speed(_baudrates[0]);

    _change_baud_timeout = Mainloop::get_instance().add_timeout(
        MSEC_PER_SEC * UART_BAUD_RETRY_SEC,
        std::bind(&UartEndpoint::_change_baud_cb, this, std::placeholders::_1), this);

    return 0;
}

UdpEndpoint::UdpEndpoint(const char* name)
    : Endpoint{name, false}
{
    bzero(&sockaddr, sizeof(sockaddr));
}

UdpEndpoint::~UdpEndpoint()
{
    close();
    free(_ip);
    _ip = nullptr;
}

int UdpEndpoint::open(const char *ip, unsigned long port, bool to_bind, unsigned long bindport)
{
    const int broadcast_val = 1;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        log_error("Could not create socket (%m)");
        return -1;
    }

    if (to_bind) {
        sockaddr.sin_family = AF_INET;
        sockaddr.sin_addr.s_addr = inet_addr("0.0.0.0");
        sockaddr.sin_port = htons(bindport);
        if (bind(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
            log_error("Error binding socket to port %lu", bindport);
            goto fail;
        }
    }

    if (fcntl(fd, F_SETFL, O_NONBLOCK | FASYNC) < 0) {
        log_error("Error setting socket fd as non-blocking (%d)", errno);
        goto fail;
    }

    bzero(&sockaddr, sizeof(sockaddr));
    if (ip != nullptr) {
        _ip = strdup(ip);
        _port = port;
        sockaddr.sin_family = AF_INET;
        sockaddr.sin_addr.s_addr = inet_addr(ip);
        sockaddr.sin_port = htons(port);
        if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &broadcast_val, sizeof(broadcast_val))) {
            log_error("Error enabling broadcast in socket (%d)", errno);
            goto fail;
        }
    }

    log_info("Open UDP [%d] %s:%lu %c %lu", fd, ip, port, to_bind ? '*' : ' ', bindport);

    return fd;

fail:
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
    return -1;
}

void UdpEndpoint::close()
{
    if (fd > -1) {
        ::close(fd);
        log_info("UDP connection closed [%d]", fd);
    }

    fd = -1;
}

ssize_t UdpEndpoint::_read_msg(uint8_t *buf, size_t len)
{
    socklen_t addrlen = sizeof(sockaddr);
    ssize_t r = ::recvfrom(fd, buf, len, 0,
                           (struct sockaddr *)&sockaddr, &addrlen);
    if (r == -1 && errno == EAGAIN)
        return 0;
    if (r == -1)
        return -errno;

    return r;
}

int UdpEndpoint::write_msg(const struct buffer *pbuf)
{
    if (fd < 0) {
        log_error("Trying to write invalid fd");
        return -EINVAL;
    }

    /* TODO: send any pending data */
    if (tx_buf.len > 0) {
        ;
    }

    if (!sockaddr.sin_port) {
        log_debug("No one ever connected to %d. No one to write for", fd);
        return 0;
    }

    ssize_t r = ::sendto(fd, pbuf->data, pbuf->len, 0,
                         (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    if (r == -1) {
        if (errno != EAGAIN && errno != ECONNREFUSED && errno != ENETUNREACH)
            log_error("Error sending udp packet (%d)", errno);
        return -errno;
    };

    _stat.write.total++;
    _stat.write.bytes += pbuf->len;

    /* Incomplete packet, we warn and discard the rest */
    if (r != (ssize_t) pbuf->len) {
        _incomplete_msgs++;
        log_debug("Discarding packet, incomplete write %zd but len=%u", r, pbuf->len);
    }

    log_debug("UDP: [%d] wrote %zd bytes", fd, r);

    return r;
}

TcpEndpoint::TcpEndpoint(const char* name)
    : Endpoint{name, false}
{
    bzero(&sockaddr, sizeof(sockaddr));
}

TcpEndpoint::~TcpEndpoint()
{
    close();
    free(_ip);
}

int TcpEndpoint::accept(int listener_fd)
{
    socklen_t addrlen = sizeof(sockaddr);
    fd = accept4(listener_fd, (struct sockaddr *)&sockaddr, &addrlen, SOCK_NONBLOCK);

    if (fd == -1)
        return -1;

    log_info("TCP connection [%d] accepted", fd);

    return fd;
}

int TcpEndpoint::open(const char *ip, unsigned long port)
{
    if (!_ip || strcmp(ip, _ip)) {
        free(_ip);
        _ip = strdup(ip);
        _port = port;
    }

    assert_or_return(_ip, -ENOMEM);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        log_error("Could not create socket (%m)");
        return -1;
    }

    sockaddr.sin_family = AF_INET;
    sockaddr.sin_addr.s_addr = inet_addr(ip);
    sockaddr.sin_port = htons(port);

    if (connect(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
        log_error("Error connecting to socket (%m)");
        goto fail;
    }

    if (fcntl(fd, F_SETFL, O_NONBLOCK | FASYNC) < 0) {
        log_error("Error setting socket fd as non-blocking (%m)");
        goto fail;
    }

    log_info("Open TCP [%d] %s:%lu", fd, ip, port);

    _valid = true;
    return fd;

fail:
    ::close(fd);
    return -1;
}

ssize_t TcpEndpoint::_read_msg(uint8_t *buf, size_t len)
{
    socklen_t addrlen = sizeof(sockaddr);
    errno = 0;
    ssize_t r = ::recvfrom(fd, buf, len, 0,
                           (struct sockaddr *)&sockaddr, &addrlen);

    if (r == -1 && errno == EAGAIN)
        return 0;
    if (r == -1)
        return -errno;

    // a read of zero on a stream socket means that other side shut down
    if (r == 0 && len != 0) {
        _valid = false;
        return EOF; // TODO is EOF always negative?
    }

    return r;
}

int TcpEndpoint::write_msg(const struct buffer *pbuf)
{
    if (fd < 0) {
        log_error("Trying to write invalid fd");
        return -EINVAL;
    }

    /* TODO: send any pending data */
    if (tx_buf.len > 0) {
        ;
    }

    ssize_t r = ::sendto(fd, pbuf->data, pbuf->len, 0,
                         (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    if (r == -1) {
        if (errno != EAGAIN && errno != ECONNREFUSED)
            log_error("Error sending tcp packet (%m)");
        if (errno == EPIPE)
            _valid = false;
        return -errno;
    };

    _stat.write.total++;
    _stat.write.bytes += pbuf->len;

    /* Incomplete packet, we warn and discard the rest */
    if (r != (ssize_t) pbuf->len) {
        _incomplete_msgs++;
        log_debug("Discarding packet, incomplete write %zd but len=%u", r, pbuf->len);
    }

    log_debug("TCP: [%d] wrote %zd bytes", fd, r);

    return r;
}

void TcpEndpoint::close()
{
    if (fd > -1) {
        ::close(fd);

        log_info("TCP Connection [%d] closed", fd);
    }

    fd = -1;
}

LocalEndpoint::LocalEndpoint(const char *name)
    : Endpoint{name, false}
{
    bzero(&sockaddr, sizeof(sockaddr));
}

int LocalEndpoint::open(const char *sock_name, const char* remote_name)
{
    int flags = 0;
    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd == -1) {
        log_error("Could not create socket (%m)");
        return -1;
    }

    if (sock_name != nullptr) {
        sockaddr.sun_family = AF_UNIX;
        sockaddr.sun_path[0] = 0;
        strcpy(sockaddr.sun_path+1, sock_name);
        sockaddr_len = strlen(sock_name) + offsetof(struct sockaddr_un, sun_path) + 1;

        if (bind(fd, (struct sockaddr *) &sockaddr, sockaddr_len)) {
            log_error("Error binding socket to %s (%m)", sock_name);
            goto fail;
        }
    }

    bzero(&sockaddr, sizeof(sockaddr));
    sockaddr_len = 0;

    if (remote_name != nullptr) {
        sockaddr.sun_family = AF_UNIX;
        sockaddr.sun_path[0] = 0;
        strcpy(sockaddr.sun_path+1, remote_name);
        sockaddr_len = strlen(remote_name) + offsetof(struct sockaddr_un, sun_path) + 1;
    }

    if ((flags = fcntl(fd, F_GETFL, 0) == -1)) {
        log_error("controller: Error getfl for fd");
        goto fail;
    }
    if (fcntl(fd, F_SETFL, O_NONBLOCK | flags) < 0) {
        log_error("controller: Error setting socket fd as non-blocking");
        goto fail;
    }
    log_info("Open LOCAL [%d] [%s]-[%s]", fd, sock_name, remote_name);

    return fd;

fail:
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
    return -1;
}

ssize_t LocalEndpoint::_read_msg(uint8_t *buf, size_t len)
{
    struct sockaddr* pSockaddr = nullptr;
    socklen_t * pLen = nullptr;
    if(sockaddr_len == 0) {
        sockaddr_len = sizeof(sockaddr);
        pSockaddr = (struct sockaddr*)&sockaddr;
        pLen = &sockaddr_len;
    }
    ssize_t r = ::recvfrom(fd, buf, len, 0, pSockaddr, pLen);
    if (r == -1 && errno == EAGAIN)
        return 0;
    if (r == -1)
        return -errno;

    return r;
}

int LocalEndpoint::write_msg(const struct buffer *pbuf)
{
    if (fd < 0) {
        log_error("Trying to write invalid fd");
        return -EINVAL;
    }

    if (sockaddr_len == 0) {
        log_debug("No one ever connected to %d. No one to write for", fd);
        return 0;
    }

    ssize_t r = ::sendto(fd, pbuf->data, pbuf->len, 0,
                         (struct sockaddr *)&sockaddr, sockaddr_len);
    if (r == -1) {
        if (errno != EAGAIN && errno != ECONNREFUSED && errno != ENETUNREACH)
            log_error("Error sending datagram packet (%m)");
        return -errno;
    };

    _stat.write.total++;
    _stat.write.bytes += pbuf->len;

    /* Incomplete packet, we warn and discard the rest */
    if (r != (ssize_t) pbuf->len) {
        _incomplete_msgs++;
        log_debug("Discarding datagram packet, incomplete write %zd but len=%u", r, pbuf->len);
    }

    log_debug("LOCAL: [%d] wrote %zd bytes", fd, r);

    return r;
}
