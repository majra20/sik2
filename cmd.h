#ifndef CMD_H
#define CMD_H

#include <stdint.h>

struct __attribute__((__packed__)) simpl_cmd {
    char cmd[10];
    uint64_t cmd_seq;
    char data[];
};

struct __attribute__((__packed__)) cmplx_cmd {
    char cmd[10];
    uint64_t cmd_seq;
    uint64_t param;
    char data[];
};

#endif //CMD_H
