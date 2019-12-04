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

#include <assert.h>
#include <dirent.h>
#include <getopt.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>

#include <common/conf_file.h>
#include <common/dbg.h>
#include <common/log.h>
#include <common/util.h>

#include "comm.h"
#include "endpoint.h"
#include "mainloop.h"
#include "controller.h"

#define MAVLINK_TCP_PORT 5760
#define DEFAULT_BAUDRATE 115200U
#define DEFAULT_CONFFILE "/system/etc/mavlink-router.conf"
#define DEFAULT_CONF_DIR "/etc/mavlink-router/config.d"
#define DEFAULT_RETRY_TCP_TIMEOUT 5

#if defined(ANDROID)
static const char *__getProgramName () {
    extern const char *__progname;
    char * arg = strrchr(__progname, '/');
    if (arg)
        return arg+1;
    else
        return __progname;
}
#define GET_PROGRAM_NAME() __getProgramName()
#define PACKAGE "mavlink-router"
#define VERSION "1.0"
#elif  (defined(__GNU_LIBRARY__) || defined(__GLIBC__)) && !defined(__UCLIBC__)
#define GET_PROGRAM_NAME() program_invocation_short_name
#else
#define GET_PROGRAM_NAME() "CMD"
#endif

static struct options opt = {
        .endpoints = nullptr,
        .filters = nullptr,
        .conf_file_name = nullptr,
        .conf_dir = nullptr,
        .tcp_port = ULONG_MAX,
        .controller = nullptr,
        .passthrough_mode = false,
        .report_msg_statistics = false,
        .logs_dir = nullptr,
        .debug_log_level = (int)Log::Level::INFO,
        .mavlink_dialect = Auto
};

static const struct option long_options[] = {
    { "endpoints",              required_argument,  NULL,   'e' },
    { "conf-file",              required_argument,  NULL,   'c' },
    { "conf-dir" ,              required_argument,  NULL,   'd' },
    { "report_msg_statistics",  no_argument,        NULL,   'r' },
    { "tcp-port",               required_argument,  NULL,   't' },
    { "tcp-endpoint",           required_argument,  NULL,   'p' },
    { "log",                    required_argument,  NULL,   'l' },
    { "debug-log-level",        required_argument,  NULL,   'g' },
    { "verbose",                no_argument,        NULL,   'v' },
    { "version",                no_argument,        NULL,   'V' },
    { }
};

static const char* short_options = "he:rt:c:d:l:p:g:vV";

static void help(FILE *fp) {
    fprintf(fp,
            "%s [OPTIONS...] [<uart>|<udp_address>]\n\n"
            "  <uart>                       UART device (<device>[:<baudrate>]) that will be routed\n"
            "  <udp_address>                UDP address (<ip>:<port>) that will be routed\n"
            "  -e --endpoint <ip[:port]>    Add UDP endpoint to communicate port is optional\n"
            "                               and in case it's not given it starts in 14550 and\n"
            "                               continues increasing not to collide with previous\n"
            "                               ports\n"
            "  -p --tcp-endpoint <ip:port>  Add TCP endpoint client, which will connect to given\n"
            "                               address\n"
            "  -r --report_msg_statistics   Report message statistics\n"
            "  -t --tcp-port <port>         Port in which mavlink-router will listen for TCP\n"
            "                               connections. Pass 0 to disable TCP listening.\n"
            "                               Default port 5760\n"
            "  -c --conf-file <file>        .conf file with configurations for mavlink-router.\n"
            "  -d --conf-dir <dir>          Directory where to look for .conf files overriding\n"
            "                               default conf file.\n"
            "  -l --log <directory>         Enable Flight Stack logging\n"
            "  -g --debug-log-level <level> Set debug log level. Levels are\n"
            "                               <error|warning|info|debug>\n"
            "  -v --verbose                 Verbose. Same as --debug-log-level=debug\n"
            "  -V --version                 Show version\n"
            "  -h --help                    Print this message\n"
            , GET_PROGRAM_NAME());
}

static unsigned long find_next_endpoint_port(const char *ip)
{
    unsigned long port = 14550U;

    while (true) {
        struct endpoint_config *conf;

        for (conf = opt.endpoints; conf; conf = conf->next) {
            if (conf->type == Udp && streq(conf->address, ip) && conf->port == port) {
                port++;
                break;
            }
        }
        if (!conf)
            break;
    }

    return port;
}

static int split_on_colon(const char *str, char **base, unsigned long *number)
{
    char *colonstr;

    *base = strdup(str);
    colonstr = strchrnul(*base, ':');
    *number = ULONG_MAX;

    if (*colonstr != '\0') {
        *colonstr = '\0';
        if (safe_atoul(colonstr + 1, number) < 0) {
            free(*base);
            return -EINVAL;
        }
    }

    return 0;
}

static int log_level_from_str(const char *str)
{
    if (strcaseeq(str, "error"))
        return (int)Log::Level::ERROR;
    if (strcaseeq(str, "warning"))
        return (int)Log::Level::WARNING;
    if (strcaseeq(str, "info"))
        return (int)Log::Level::INFO;
    if (strcaseeq(str, "debug"))
        return (int)Log::Level::DEBUG;

    return -EINVAL;
}

static int add_tcp_endpoint_address(const char *name, size_t name_len, const char *ip,
                                    long unsigned port, int timeout, const char *map_endpoint)
{
    int ret;

    struct endpoint_config *conf
        = (struct endpoint_config *)calloc(1, sizeof(struct endpoint_config));
    assert_or_return(conf, -ENOMEM);
    conf->type = Tcp;
    conf->port = ULONG_MAX;

    if (!conf->name && name) {
        conf->name = strndup(name, name_len);
        if (!conf->name) {
            ret = -ENOMEM;
            goto fail;
        }
    }

    if (ip) {
        free(conf->address);
        conf->address = strdup(ip);
        if (!conf->address) {
            ret = -ENOMEM;
            goto fail;
        }
    }

    if (map_endpoint) {
        free(conf->map_endpoint);
        conf->map_endpoint = strdup(map_endpoint);
        if (!conf->map_endpoint) {
            ret = -ENOMEM;
            goto fail;
        }
    }

    if (!conf->address) {
        ret = -EINVAL;
        goto fail;
    }

    if (port != ULONG_MAX) {
        conf->port = port;
    }

    if (conf->port == ULONG_MAX) {
        ret = -EINVAL;
        goto fail;
    }

    conf->retry_timeout = timeout;

    conf->next = opt.endpoints;
    opt.endpoints = conf;

    return 0;

fail:
    free(conf->address);
    free(conf->name);
    free(conf->map_endpoint);
    free(conf);

    return ret;
}

static int add_endpoint_address(const char *name, size_t name_len, const char *ip,
                                long unsigned port, bool eavesdropping, long unsigned bindport, const char* map_endpoint)
{
    int ret;

    struct endpoint_config *conf
        = (struct endpoint_config *)calloc(1, sizeof(struct endpoint_config));
    assert_or_return(conf, -ENOMEM);
    conf->type = Udp;
    conf->port = ULONG_MAX;

    if (!conf->name && name) {
        conf->name = strndup(name, name_len);
        if (!conf->name) {
            ret = -ENOMEM;
            goto fail;
        }
    }

    if (ip) {
        free(conf->address);
        conf->address = strdup(ip);
        if (!conf->address) {
            ret = -ENOMEM;
            goto fail;
        }
    }

    if (map_endpoint) {
        free(conf->map_endpoint);
        conf->map_endpoint = strdup(map_endpoint);
        if (!conf->map_endpoint) {
            ret = -ENOMEM;
            goto fail;
        }
    }

    if (!conf->address && !eavesdropping) {
        ret = -EINVAL;
        goto fail;
    }

    if (port != ULONG_MAX) {
        conf->port = port;
    }

    conf->eavesdropping = eavesdropping;
    conf->bindport = bindport;

    conf->next = opt.endpoints;
    opt.endpoints = conf;

    return 0;

fail:
    free(conf->address);
    free(conf->name);
    free(conf->map_endpoint);
    free(conf);

    return ret;
}

static int add_local_endpoint(const char *name, size_t name_len, const char *sockname,
                              const char *remotename, const char *map_endpoint)
{
    int ret;

    struct endpoint_config *conf
        = (struct endpoint_config *)calloc(1, sizeof(struct endpoint_config));
    assert_or_return(conf, -ENOMEM);
    conf->type = Local;

    if (!conf->name && name) {
        conf->name = strndup(name, name_len);
        if (!conf->name) {
            ret = -ENOMEM;
            goto fail;
        }
    }

    conf->sockname = strdup(sockname);
    if (!conf->sockname) {
        ret = -ENOMEM;
        goto fail;
    }

    if (remotename != nullptr) {
        conf->remotename = strdup(remotename);
        if (!conf->remotename) {
            ret = -ENOMEM;
            goto fail;
        }
    }

    if (map_endpoint) {
        free(conf->map_endpoint);
        conf->map_endpoint = strdup(map_endpoint);
        if (!conf->map_endpoint) {
            ret = -ENOMEM;
            goto fail;
        }
    }

    conf->next = opt.endpoints;
    opt.endpoints = conf;

    return 0;

fail:
    free(conf->sockname);
    free(conf->remotename);
    free(conf->map_endpoint);
    free(conf->name);
    free(conf);

    return ret;
}

static int add_dynamic_endpoint(const char *name, size_t name_len, int port)
{
    int ret;

    struct endpoint_config *conf
        = (struct endpoint_config *)calloc(1, sizeof(struct endpoint_config));
    assert_or_return(conf, -ENOMEM);
    conf->type = Dynamic;

    if (!conf->name && name) {
        conf->name = strndup(name, name_len);
        if (!conf->name) {
            ret = -ENOMEM;
            goto fail;
        }
    }

    conf->port_number = port;

    conf->next = opt.endpoints;
    opt.endpoints = conf;

    return 0;

fail:
    free(conf->name);
    free(conf);

    return ret;
}

static std::vector<unsigned long> *strlist_to_ul(const char *list,
                                                 const char *listname,
                                                 const char *delim,
                                                 unsigned long default_value)
{
    char *s, *tmp_str;
    std::unique_ptr<std::vector<unsigned long>> v{new std::vector<unsigned long>()};

    if (!list || list[0] == '\0') {
        v->push_back(default_value);
        return v.release();
    }

    tmp_str = strdup(list);
    if (!tmp_str) {
        return nullptr;
    }

    s = strtok(tmp_str, delim);
    while (s) {
        unsigned long l;
        if (safe_atoul(s, &l) < 0) {
            log_error("Invalid %s %s", listname, s);
            goto error;
        }
        v->push_back(l);
        s = strtok(NULL, delim);
    }

    free(tmp_str);

    if (!v->size()) {
        log_error("No valid %s on %s", listname, list);
        return nullptr;
    }

    return v.release();

error:
    free(tmp_str);
    return nullptr;
}

static int add_uart_endpoint(const char *name, size_t name_len, const char *uart_device,
                             const char *bauds, bool flowcontrol, const char *map_endpoint)
{
    int ret;

    struct endpoint_config *conf
        = (struct endpoint_config *)calloc(1, sizeof(struct endpoint_config));
    assert_or_return(conf, -ENOMEM);
    conf->type = Uart;

    if (name) {
        conf->name = strndup(name, name_len);
        if (!conf->name) {
            ret = -ENOMEM;
            goto fail;
        }
    }

    conf->device = strdup(uart_device);
    if (!conf->device) {
        ret = -ENOMEM;
        goto fail;
    }

    conf->bauds = strlist_to_ul(bauds, "baud", ",", DEFAULT_BAUDRATE);
    if (!conf->bauds) {
        ret = -EINVAL;
        goto fail;
    }

    if (map_endpoint) {
        conf->map_endpoint = strdup(map_endpoint);
        if (!conf->map_endpoint) {
            ret = -ENOMEM;
            goto fail;
        }
    }

    conf->flowcontrol = flowcontrol;

    conf->next = opt.endpoints;
    opt.endpoints = conf;

    return 0;

fail:
    free(conf->device);
    free(conf->name);
    free(conf->map_endpoint);
    free(conf);

    return ret;
}

static int add_msg_filter(const char *endpoint_name, filter_type type, char *filter)
{
    int ret;
    char *s;
    const char *delim = ", ";
    struct filter_config *conf;

    conf = (struct filter_config *)calloc(1, sizeof(struct filter_config));
    assert_or_return(conf, -ENOMEM);
    conf->type = type;

    if (endpoint_name) {
        conf->endpoint_name = strdup(endpoint_name);
        if (!conf->endpoint_name) {
            ret = -ENOMEM;
            goto fail;
        }
    }

    conf->msg_ids = new std::vector<uint32_t>();
    conf->sys_comp_ids = new std::vector<uint16_t>();
    if (!conf->msg_ids || !conf->sys_comp_ids) {
        ret = -ENOMEM;
        goto fail;
    }

    s = strtok(filter, delim);
    while (s) {
        int i, j;
        char *p, *q;
        p = strchr(s, '/');
        if (p != nullptr) {
            q = strndup(s, p-s);
            if (safe_atoi(q, &i) < 0 || safe_atoi(p+1, &j)) {
                free(q);
                log_error("Invalid %s %s", filter, s);
                ret = -EINVAL;
                goto fail;
            }
            free(q);
            conf->sys_comp_ids->push_back((uint16_t)((i << 8) | (j & 0xff)));
        } else {
            if (safe_atoi(s, &i) < 0) {
                log_error("Invalid %s %s", filter, s);
                ret = -EINVAL;
                goto fail;
            }
            conf->msg_ids->push_back(i);
        }
        s = strtok(NULL, delim);
    }

    conf->next = opt.filters;
    opt.filters = conf;

    return 0;

fail:
    free(conf->msg_ids);
    free(conf->endpoint_name);
    free(conf);

    return ret;
}

static int get_endpoint_count()
{
    struct endpoint_config *conf;
    int count = 0;
    for (conf = opt.endpoints; conf; conf = conf->next) {
        count++;
    }
    return count;
}

static bool pre_parse_argv(int argc, char *argv[])
{
    // This function parses only conf-file and conf-dir from
    // command line, so we can read the conf files.
    // parse_argv will then parse all other options, overriding
    // config files definitions

    int c;

    while ((c = getopt_long(argc, argv, short_options, long_options, NULL)) >= 0) {
        switch (c) {
        case 'c': {
            opt.conf_file_name = optarg;
            break;
        }
        case 'd': {
            opt.conf_dir = optarg;
            break;
        }
        case 'V':
            puts(PACKAGE " version " VERSION);
            return false;
        }
    }

    // Reset getopt*
    optind = 1;

    return true;
}

static int parse_argv(int argc, char *argv[])
{
    int c;
    struct stat st;

    assert(argc >= 0);
    assert(argv);

    while ((c = getopt_long(argc, argv, short_options, long_options, NULL)) >= 0) {
        switch (c) {
        case 'h':
            help(stdout);
            return 0;
        case 'e': {
            char *ip;
            unsigned long port;

            if (split_on_colon(optarg, &ip, &port) < 0) {
                log_error("Invalid port in argument: %s", optarg);
                help(stderr);
                return -EINVAL;
            }

            add_endpoint_address(NULL, 0, ip, port, false, 0, NULL);
            free(ip);
            break;
        }
        case 'r': {
            opt.report_msg_statistics = true;
            break;
        }
        case 't': {
            if (safe_atoul(optarg, &opt.tcp_port) < 0) {
                log_error("Invalid argument for tcp-port = %s", optarg);
                help(stderr);
                return -EINVAL;
            }
            break;
        }
        case 'l': {
            opt.logs_dir = strdup(optarg);
            break;
        }
        case 'g': {
            int lvl = log_level_from_str(optarg);
            if (lvl == -EINVAL) {
                log_error("Invalid argument for debug-log-level = %s", optarg);
                help(stderr);
                return -EINVAL;
            }
            opt.debug_log_level = lvl;
            break;
        }
        case 'v': {
            opt.debug_log_level = (int)Log::Level::DEBUG;
            break;
        }
        case 'p': {
            char *ip;
            unsigned long port;

            if (split_on_colon(optarg, &ip, &port) < 0) {
                log_error("Invalid port in argument: %s", optarg);
                help(stderr);
                return -EINVAL;
            }
            if (port == ULONG_MAX) {
                log_error("Missing port in argument: %s", optarg);
                free(ip);
                help(stderr);
                return -EINVAL;
            }

            add_tcp_endpoint_address(NULL, 0, ip, port, DEFAULT_RETRY_TCP_TIMEOUT, nullptr);
            free(ip);
            break;
        }
        case 'c':
        case 'd':
        case 'V':
            break; // These options were parsed on pre_parse_argv
        case '?':
        default:
            help(stderr);
            return -EINVAL;
        }
    }

    /* positional arguments */
    while (optind < argc) {
        // UDP and UART master endpoints are of the form:
        // UDP: <ip>:<port> UART: <device>[:<baudrate>]
        char *base;
        unsigned long number;

        if (split_on_colon(argv[optind], &base, &number) < 0) {
            log_error("Invalid argument %s", argv[optind]);
            help(stderr);
            return -EINVAL;
        }

        if (stat(base, &st) == -1 || !S_ISCHR(st.st_mode)) {
            if (number == ULONG_MAX) {
                log_error("Invalid argument for UDP port = %s", argv[optind]);
                help(stderr);
                free(base);
                return -EINVAL;
            }

            add_endpoint_address(NULL, 0, base, number, true, number, NULL);
        } else {
            const char *bauds = number != ULONG_MAX ? base + strlen(base) + 1 : NULL;
            int ret = add_uart_endpoint(NULL, 0, base, bauds, false, NULL);
            if (ret < 0) {
                free(base);
                return ret;
            }
        }
        free(base);
        optind++;
    }

    return 2;
}

static const char *get_conf_file_name()
{
    char *s;

    if (opt.conf_file_name)
        return opt.conf_file_name;

    s = getenv("MAVLINK_ROUTERD_CONF_FILE");
    if (s)
        return s;

    return DEFAULT_CONFFILE;
}

static const char *get_conf_dir()
{
    char *s;

    if (opt.conf_dir)
        return opt.conf_dir;

    s = getenv("MAVLINK_ROUTERD_CONF_DIR");
    if (s)
        return s;

    return DEFAULT_CONF_DIR;
}

static int parse_mavlink_dialect(const char *val, size_t val_len, void *storage, size_t storage_len)
{
    assert(val);
    assert(storage);
    assert(val_len);

    enum mavlink_dialect *dialect = (enum mavlink_dialect *)storage;

    if (storage_len < sizeof(options::mavlink_dialect))
        return -ENOBUFS;
    if (val_len > INT_MAX)
        return -EINVAL;

    if (memcaseeq(val, val_len, "auto", sizeof("auto") - 1)) {
        *dialect = Auto;
    } else if (memcaseeq(val, val_len, "common", sizeof("common") - 1)) {
        *dialect = Common;
    } else if (memcaseeq(val, val_len, "ardupilotmega", sizeof("ardupilotmega") - 1)) {
        *dialect = Ardupilotmega;
    } else {
        log_error("Invalid argument for MavlinkDialect = %.*s", (int)val_len, val);
        return -EINVAL;
    }

    return 0;
}

#define MAX_LOG_LEVEL_SIZE 10
static int parse_log_level(const char *val, size_t val_len, void *storage, size_t storage_len)
{
    assert(val);
    assert(storage);
    assert(val_len);

    if (storage_len < sizeof(options::debug_log_level))
        return -ENOBUFS;
    if (val_len > MAX_LOG_LEVEL_SIZE)
        return -EINVAL;

//    const char *log_level = strndupa(val, val_len);
    char log_level[MAX_LOG_LEVEL_SIZE+1] = {0};
    strncpy(log_level, val, val_len);
    int lvl = log_level_from_str(log_level);
    if (lvl == -EINVAL) {
        log_error("Invalid argument for DebugLogLevel = %s", log_level);
        return -EINVAL;
    }
    *((int *)storage) = lvl;

    return 0;
}
#undef MAX_LOG_LEVEL_SIZE

static int parse_mode(const char *val, size_t val_len, void *storage, size_t storage_len)
{
    assert(val);
    assert(storage);
    assert(val_len);

    if (storage_len < sizeof(bool))
        return -ENOBUFS;
    if (val_len > INT_MAX)
        return -EINVAL;

    bool *eavesdropping = (bool *)storage;
    if (memcaseeq(val, val_len, "normal", sizeof("normal") - 1)) {
        *eavesdropping = false;
    } else if (memcaseeq(val, val_len, "eavesdropping", sizeof("eavesdropping") - 1)) {
        *eavesdropping = true;
    } else {
        log_error("Unknown 'mode' key: %.*s", (int)val_len, val);
        return -EINVAL;
    }

    return 0;
}

static int parse_confs(ConfFile &conf)
{
    int ret;
    size_t offset;
    struct ConfFile::section_iter iter;
    const char *pattern;

    static const ConfFile::OptionsTable option_table[] = {
        {"TcpServerPort",   false, ConfFile::parse_ul,      OPTIONS_TABLE_STRUCT_FIELD(options, tcp_port)},
        {"Controller",      false, ConfFile::parse_str_dup, OPTIONS_TABLE_STRUCT_FIELD(options, controller)},
        {"PassThroughMode", false, ConfFile::parse_bool,    OPTIONS_TABLE_STRUCT_FIELD(options, passthrough_mode)},
        {"ReportStats",     false, ConfFile::parse_bool,    OPTIONS_TABLE_STRUCT_FIELD(options, report_msg_statistics)},
        {"MavlinkDialect",  false, parse_mavlink_dialect,   OPTIONS_TABLE_STRUCT_FIELD(options, mavlink_dialect)},
        {"Log",             false, ConfFile::parse_str_dup, OPTIONS_TABLE_STRUCT_FIELD(options, logs_dir)},
        {"DebugLogLevel",   false, parse_log_level,         OPTIONS_TABLE_STRUCT_FIELD(options, debug_log_level)},
    };

    struct option_uart {
        char *device;
        char *bauds;
        bool flowcontrol;
        char *mapEndpoint;
    };
    static const ConfFile::OptionsTable option_table_uart[] = {
        {"baud",        false,  ConfFile::parse_str_dup,    OPTIONS_TABLE_STRUCT_FIELD(option_uart, bauds)},
        {"device",      true,   ConfFile::parse_str_dup,    OPTIONS_TABLE_STRUCT_FIELD(option_uart, device)},
        {"FlowControl", false,  ConfFile::parse_bool,       OPTIONS_TABLE_STRUCT_FIELD(option_uart, flowcontrol)},
        {"mapEndpoint", false,  ConfFile::parse_str_dup,    OPTIONS_TABLE_STRUCT_FIELD(option_uart, mapEndpoint)},
    };

    struct option_udp {
        char *addr;
        bool eavesdropping;
        unsigned long port;
        unsigned long bindport;
        char *mapEndpoint;
    };
    static const ConfFile::OptionsTable option_table_udp[] = {
        {"address", false,  ConfFile::parse_str_dup,    OPTIONS_TABLE_STRUCT_FIELD(option_udp, addr)},
        {"mode",    true,   parse_mode,                 OPTIONS_TABLE_STRUCT_FIELD(option_udp, eavesdropping)},
        {"port",    false,  ConfFile::parse_ul,         OPTIONS_TABLE_STRUCT_FIELD(option_udp, port)},
        {"bindPort", false, ConfFile::parse_ul,         OPTIONS_TABLE_STRUCT_FIELD(option_udp, bindport)},
        {"mapEndpoint", false, ConfFile::parse_str_dup, OPTIONS_TABLE_STRUCT_FIELD(option_udp, mapEndpoint)},
    };

    struct option_tcp {
        char *addr;
        unsigned long port;
        int timeout;
        char *mapEndpoint;
    };
    static const ConfFile::OptionsTable option_table_tcp[] = {
        {"address",         true,   ConfFile::parse_str_dup,    OPTIONS_TABLE_STRUCT_FIELD(option_tcp, addr)},
        {"port",            true,   ConfFile::parse_ul,         OPTIONS_TABLE_STRUCT_FIELD(option_tcp, port)},
        {"RetryTimeout",    false,  ConfFile::parse_i,          OPTIONS_TABLE_STRUCT_FIELD(option_tcp, timeout)},
        {"mapEndpoint",     false,  ConfFile::parse_str_dup,    OPTIONS_TABLE_STRUCT_FIELD(option_tcp, mapEndpoint)},
    };

    struct option_local {
        char *sockname;
        char *remotename;
        char *mapEndpoint;
    };
    static const ConfFile::OptionsTable option_table_local[] = {
        {"SockName",     true,   ConfFile::parse_str_dup,    OPTIONS_TABLE_STRUCT_FIELD(option_local, sockname)},
        {"RemoteName",   false,  ConfFile::parse_str_dup,    OPTIONS_TABLE_STRUCT_FIELD(option_local, remotename)},
        {"mapEndpoint",  false,  ConfFile::parse_str_dup,    OPTIONS_TABLE_STRUCT_FIELD(option_local, mapEndpoint)},
    };

    struct option_dynamic {
        int port;
    };
    static const ConfFile::OptionsTable option_table_dynamic[] = {
        {"port",        true,   ConfFile::parse_i,      OPTIONS_TABLE_STRUCT_FIELD(option_dynamic, port)},
    };

    ret = conf.extract_options("General", option_table, ARRAY_SIZE(option_table), &opt);
    if (ret < 0)
        return ret;

    iter = {};
    pattern = "uartendpoint *";
    offset = strlen(pattern) - 1;
    while (conf.get_sections(pattern, &iter) == 0) {
        struct option_uart opt_uart = {nullptr, nullptr, false, nullptr};
        ret = conf.extract_options(&iter, option_table_uart, ARRAY_SIZE(option_table_uart),
                                   &opt_uart);
        if (ret == 0)
            ret = add_uart_endpoint(iter.name + offset, iter.name_len - offset, opt_uart.device,
                                    opt_uart.bauds, opt_uart.flowcontrol, opt_uart.mapEndpoint);
        free(opt_uart.device);
        free(opt_uart.bauds);
        free(opt_uart.mapEndpoint);
        if (ret < 0)
            return ret;
    }

    iter = {};
    pattern = "udpendpoint *";
    offset = strlen(pattern) - 1;
    while (conf.get_sections(pattern, &iter) == 0) {
        struct option_udp opt_udp = {nullptr, false, ULONG_MAX, ULONG_MAX, nullptr};
        ret = conf.extract_options(&iter, option_table_udp, ARRAY_SIZE(option_table_udp), &opt_udp);
        if (ret == 0) {
            if (opt_udp.eavesdropping && opt_udp.bindport == ULONG_MAX) {
                log_error("Expected 'port' key for section %.*s", (int)iter.name_len, iter.name);
                ret = -EINVAL;
            } else {
                ret = add_endpoint_address(iter.name + offset, iter.name_len - offset, opt_udp.addr,
                                           opt_udp.port, opt_udp.eavesdropping, opt_udp.bindport, opt_udp.mapEndpoint);
            }
        }

        free(opt_udp.addr);
        free(opt_udp.mapEndpoint);
        if (ret < 0)
            return ret;
    }

    iter = {};
    pattern = "tcpendpoint *";
    offset = strlen(pattern) - 1;
    while (conf.get_sections(pattern, &iter) == 0) {
        struct option_tcp opt_tcp = {nullptr, ULONG_MAX, DEFAULT_RETRY_TCP_TIMEOUT, nullptr};
        ret = conf.extract_options(&iter, option_table_tcp, ARRAY_SIZE(option_table_tcp), &opt_tcp);

        if (ret == 0) {
            ret = add_tcp_endpoint_address(iter.name + offset, iter.name_len - offset, opt_tcp.addr,
                                           opt_tcp.port, opt_tcp.timeout, opt_tcp.mapEndpoint);
        }
        free(opt_tcp.addr);
        free(opt_tcp.mapEndpoint);
        if (ret < 0)
            return ret;
    }

    iter = {};
    pattern = "localendpoint *";
    offset = strlen(pattern) - 1;
    while (conf.get_sections(pattern, &iter) == 0) {
        struct option_local opt_local = {nullptr, nullptr, nullptr};
        ret = conf.extract_options(&iter, option_table_local, ARRAY_SIZE(option_table_local), &opt_local);
        if (ret == 0) {
            ret = add_local_endpoint(iter.name + offset, iter.name_len - offset, opt_local.sockname,
                                       opt_local.remotename, opt_local.mapEndpoint);
        }

        free(opt_local.sockname);
        free(opt_local.remotename);
        free(opt_local.mapEndpoint);
        if (ret < 0)
            return ret;
    }

    iter = {};
    pattern = "dynamicendpoint *";
    offset = strlen(pattern) - 1;
    while (conf.get_sections(pattern, &iter) == 0) {
        struct option_dynamic opt_dynamic = {0};
        ret = conf.extract_options(&iter, option_table_dynamic, ARRAY_SIZE(option_table_dynamic), &opt_dynamic);
        if (ret == 0) {
            ret = add_dynamic_endpoint(iter.name + offset, iter.name_len - offset, opt_dynamic.port);
        }
        if (ret < 0)
            return ret;
    }

    // All endpoints been added, then parse filters
    struct endpoint_config *endpoint;
    filter_type type;
    int i = 0;
    const char* filter_wl = "whitelist";
    const char* filter_bl = "blacklist";
    int array_size = get_endpoint_count();
    char* filter_array[array_size];
    ConfFile::OptionsTable option_table_filter[array_size];

    for (endpoint = opt.endpoints; endpoint; endpoint = endpoint->next) {
        char* p = strchr(endpoint->name, ':');
        if (p != nullptr) {
            p = strndup(endpoint->name, p-endpoint->name);
        } else {
            p = strdup(endpoint->name);
        }
        option_table_filter[i].key = p;
        option_table_filter[i].required = false;
        option_table_filter[i].parser_func = ConfFile::parse_str_dup;
        option_table_filter[i].storage = {static_cast<off_t>(i*sizeof(char*)), sizeof(char*)};
        i++;
        if (i >= array_size) {
            break;
        }
    }
    pattern = "MessageFilter *";
    offset = strlen(pattern) - 1;
    while (conf.get_sections(pattern, &iter) == 0) {
        if ((strlen(filter_wl) == iter.name_len-offset)
            && !strncmp(iter.name + offset, filter_wl, iter.name_len-offset)) {
            type = WhiteList;
        } else if ((strlen(filter_bl) == iter.name_len-offset)
                   && !strncmp(iter.name + offset, filter_bl, iter.name_len-offset)) {
            type = BlackList;
        } else {
            continue;
        }
        bzero((void*)filter_array, sizeof(filter_array));
        ret = conf.extract_options(&iter, option_table_filter, array_size, filter_array);
        if (ret == 0) {
            for (i = 0; i < array_size; i++) {
                if (filter_array[i] != NULL) {
                    add_msg_filter(option_table_filter[i].key, type, filter_array[i]);
                    free(filter_array[i]);
                    filter_array[i] = NULL;
                }
            }
        }
    }
    for(i = 0; i < array_size; i++) {
        free((void*)option_table_filter[i].key);
    }
    // End of parsing filters

    return 0;
}

static int cmpstr(const void *s1, const void *s2)
{
    return strcmp(*(const char **)s1, *(const char **)s2);
}

static int parse_conf_files()
{
    DIR *dir;
    struct dirent *ent;
    const char *filename, *dirname;
    int ret = 0;
    char *files[128] = {};
    int i = 0, j = 0;
    ConfFile conf;

    // First, open default conf file
    filename = get_conf_file_name();
    ret = conf.parse(filename);

    // If there's no default conf file, everything is good
    if (ret < 0 && ret != -ENOENT) {
        return ret;
    }

    dirname = get_conf_dir();
    // Then, parse all files on configuration directory
    dir = opendir(dirname);
    if (!dir)
        return parse_confs(conf);

    while ((ent = readdir(dir))) {
        char path[PATH_MAX];
        struct stat st;

        ret = snprintf(path, sizeof(path), "%s/%s", dirname, ent->d_name);
        if (ret >= (int)sizeof(path)) {
            log_error("Couldn't open directory %s", dirname);
            ret = -EINVAL;
            goto fail;
        }
        if (stat(path, &st) < 0 || !S_ISREG(st.st_mode)) {
            continue;
        }
        files[i] = strdup(path);
        if (!files[i]) {
            ret = -ENOMEM;
            goto fail;
        }
        i++;

        if ((size_t)i > sizeof(files) / sizeof(*files)) {
            log_warning("Too many files on %s. Not all of them will be considered", dirname);
            break;
        }
    }

    qsort(files, (size_t)i, sizeof(char *), cmpstr);

    for (j = 0; j < i; j++) {
        ret = conf.parse(files[j]);
        if (ret < 0)
            goto fail;
        free(files[j]);
    }

    closedir(dir);

    return parse_confs(conf);
fail:
    while (j < i) {
        free(files[j++]);
    }

    closedir(dir);

    return ret;
}

int main(int argc, char *argv[])
{
    Mainloop &mainloop = Mainloop::init();

    Log::open();

    if (!pre_parse_argv(argc, argv)) {
        Log::close();
        return 0;
    }

    if (parse_conf_files() < 0)
        goto close_log;

    if (parse_argv(argc, argv) != 2)
        goto close_log;

    Log::set_max_level((Log::Level) opt.debug_log_level);

    dbg("Cmd line and options parsed");

    if (mainloop.open() < 0)
        goto close_log;

    if (opt.tcp_port == ULONG_MAX)
        opt.tcp_port = 0; //MAVLINK_TCP_PORT;

    if (!mainloop.add_endpoints(mainloop, &opt))
        goto endpoint_error;

    if(opt.controller != nullptr) {
        Controller::open(&opt);
    }

    mainloop.loop();

    mainloop.free_endpoints(&opt);

    free(opt.logs_dir);

    Log::close();

    return 0;

endpoint_error:
    mainloop.free_endpoints(&opt);
    free(opt.logs_dir);

close_log:
    Log::close();
    return EXIT_FAILURE;
}
