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

#include "serialendpoint.h"

#include "mainloop.h"
#include "mavlink_types.h"
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <fcntl.h>
#include <errno.h>
#include <utils/Errors.h>
#include <utils/Timers.h>

#include <sys/stat.h>
#include <common/log.h>
#include <common/util.h>
#include "common/custom_types.h"
#include <cutils/properties.h>

#ifdef LAMP_SIGNAL_EXIST
#include "LampSignalService.h"
#include <binder/IServiceManager.h>
#endif

#define TTY_BAUD_RETRY_SEC 3

using namespace android;

SerialEndpoint::SerialEndpoint(const char* name)
    : Endpoint(name, true)
{
    _ttyfd = -1;
    _read_error_count = 0;
    _baudrate_index = -1;
    _try_count = 0;
    _last_baudrate = _retrieve_baudrate_property();
    _change_baudrate_timeout = nullptr;
    _last_time_stamp = systemTime(SYSTEM_TIME_MONOTONIC);
}

SerialEndpoint::~SerialEndpoint()
{
    close();
}

bool SerialEndpoint::_save_baudrate_property(uint32_t baudrate)
{
    char value[PROPERTY_VALUE_MAX];
    snprintf(value, sizeof(value), "%u", baudrate);
    int status = property_set("persist.serial.lastbaudrate", value);
    if (status < 0) {
        log_error("Could not update mavlink.serial.lastbaudrate property (%d)", status);
        return false;
    }
    log_info("_save_baudrate_property: %u %s", baudrate, value);
    return true;
}

uint32_t SerialEndpoint::_retrieve_baudrate_property()
{
    char prop[PROPERTY_VALUE_MAX];
    property_get("persist.serial.lastbaudrate", prop, "0");

    int baudrate = atoi(prop);
    log_info("_retrieve_baudrate_property: %d", baudrate);
    return baudrate;
}

int SerialEndpoint::open(const char* path)
{
    struct termios opt;
    _ttyfd = ::open(path, O_RDWR|O_CLOEXEC|O_NOCTTY);
    if (_ttyfd < 0) {
        log_error("failed to open tty %s", path);
        return -1;
    }

    tcgetattr(_ttyfd, &opt);
    cfmakeraw(&opt);
    tcsetattr(_ttyfd, TCSANOW, &opt);

#ifdef LAMP_SIGNAL_EXIST
    sp<IBinder> binder = defaultServiceManager()->getService(String16(LampSignalService::getServiceName()));
    if (binder == nullptr) {
        log_error("failed to get service: %s", LampSignalService::getServiceName());
    } else {
        _listener = interface_cast<ISystemStatusListener>(binder);
        if (_listener == nullptr) {
            log_error("failed to cast LampSignalService interface");
        }
    }
#endif

    fd = _ttyfd;
    return _ttyfd;
}

int SerialEndpoint::set_flow_control(bool enabled)
{
    struct termios2 tc;
    if (_ttyfd < 0) {
        return -1;
    }
    bzero(&tc, sizeof(tc));
    if (ioctl(_ttyfd, TCGETS2, &tc) == -1) {
        log_error("Could not get termios2 (%m)");
        return -1;
    }
    if (enabled)
        tc.c_cflag |= CRTSCTS;
    else
        tc.c_cflag &= ~CRTSCTS;
    if (ioctl(_ttyfd, TCSETS2, &tc) == -1) {
        log_error("Could not set terminal attributes (%m)");
        return -1;
    }
    log_info("uart [%d] flowcontrol = %s", _ttyfd, enabled ? "enabled" : "disabled");
    return 0;
}

int SerialEndpoint::set_speed(uint32_t baudrate)
{
    struct termios2 tc;
    bzero(&tc, sizeof(tc));
    if (ioctl(_ttyfd, TCGETS2, &tc) == -1) {
        log_error("Could not get termios2 (%m)");
        return -1;
    }
    tc.c_cflag &= ~CBAUD;
    tc.c_cflag |= BOTHER;
    tc.c_ispeed = baudrate;
    tc.c_ospeed = baudrate;
    if (ioctl(_ttyfd, TCSETS2, &tc) == -1) {
        log_error("Could not set terminal attributes (%m)");
        return -1;
    }
    if (ioctl(_ttyfd, TCFLSH, TCIOFLUSH) == -1) {
        log_error("Could not flush terminal (%m)");
        return -1;
    }
    _last_baudrate = baudrate;
    log_info("set uart baudrate to: [%u]", _last_baudrate);
    return 0;
}

void SerialEndpoint::close()
{
    if (_ttyfd >= 0) {
        ::close(_ttyfd);
        _ttyfd = -1;
    }
}

int SerialEndpoint::add_speeds(std::vector<unsigned long> bauds)
{
    if (!bauds.size()) {
        return -EINVAL;
    }

    _available_baudrates = bauds;
    if(_last_baudrate > 0) {
        set_speed(_last_baudrate);
    } else {
        set_speed(bauds[0]);
    }
    return 0;
}

ssize_t SerialEndpoint::_read_msg(uint8_t* buf, size_t len)
{
    ssize_t r = ::read(_ttyfd, buf, len);
    if ((r == -1 && errno == EAGAIN) || r == 0) {
        return 0;
    }
    if (r == -1) {
        return -errno;
    }
    return r;
}

int SerialEndpoint::read_msg(struct buffer* pbuf, int* target_sysid, int* target_compid,
                             uint8_t* src_sysid, uint8_t* src_compid, uint32_t* pmsg_id)
{
    int ret = Endpoint::read_msg(pbuf, target_sysid, target_compid, src_sysid, src_compid, pmsg_id);
    if (ret == CrcErrorMsg || ret == ReadUnkownMsg) {
        _read_error_count++;
        if ((_change_baudrate_timeout == nullptr) && (_read_error_count > 1)) {
            _read_error_count = 0;
            if(_available_baudrates.size() > 1) {
                // read invalid data, try to change to other baudrate
                log_info("request to change baudrate, current is %d", _last_baudrate);
                _change_baudrate_timeout = Mainloop::get_instance().add_timeout(MSEC_PER_SEC * TTY_BAUD_RETRY_SEC,
                                           std::bind(&SerialEndpoint::_change_baudrate, this, std::placeholders::_1), this);
            }
        }
    } else if (ret == ReadOk) {
        _read_error_count = 0;
        _signal_data_available();
        // read valid data, do not try other baudrate anymore
        if (_change_baudrate_timeout != nullptr) {
            Mainloop::get_instance().del_timeout(_change_baudrate_timeout);
            _change_baudrate_timeout = nullptr;
            _try_count = 0;
            log_info("finish change baudrate newbaudrate: %d", _last_baudrate);
            _save_baudrate_property(_available_baudrates[_baudrate_index]);
        }
    }
    return ret;
}

bool SerialEndpoint::_change_baudrate(void *data)
{
    if (_try_count++ >= 2 * _available_baudrates.size()) {
        _try_count = 0;
        _change_baudrate_timeout = nullptr;
        return false; //return false will delete this timer
    }
    _baudrate_index = (_baudrate_index + 1) % _available_baudrates.size();
    uint32_t newbaud = _available_baudrates[_baudrate_index];
    if (newbaud == _last_baudrate) {
        _baudrate_index = (_baudrate_index + 1) % _available_baudrates.size();
        newbaud = _available_baudrates[_baudrate_index];
    }
    log_info("_change_baudrate newbaud=%d\n", newbaud);

    set_speed(newbaud);
    return true;
}

int SerialEndpoint::write_msg(const struct buffer *pbuf)
{
    if (_ttyfd < 0) {
        log_error("Trying to write invalid fd");
        return -EINVAL;
    }

    if (!pbuf || !pbuf->data || pbuf->len <= 0) {
        log_info("SerialEndpoint::write_msg invalid param");
        return -EINVAL;
    }

    ssize_t r = ::write(_ttyfd, pbuf->data, pbuf->len);
    if (r == -1 && errno == EAGAIN)
        return -EAGAIN;

    return r;
}

void SerialEndpoint::_signal_data_available()
{
#ifdef LAMP_SIGNAL_EXIST
    if (_listener == nullptr) {
        log_error("signalDataAvailable: StatusChange Listener invalid");
        return;
    }
    static const nsecs_t updateinterval = 1 * 100; //1s (1000ms)
    nsecs_t cur_ts = systemTime(SYSTEM_TIME_MONOTONIC);
    nsecs_t interval = nanoseconds_to_milliseconds(cur_ts - _last_time_stamp);
    if (interval > updateinterval) {
        _listener->onStatusChanged(FLYCONTROLDATA_RECEIVED, false);
        _last_time_stamp = systemTime(SYSTEM_TIME_MONOTONIC);
    }
#endif
}
