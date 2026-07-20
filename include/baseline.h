#ifndef BASELINE_H
#define BASELINE_H

#include <stdint.h>

#define MAX_PATH_LEN 256
#define MAX_NAME_LEN 64
#define HASH_LEN     65   // SHA256 hex + '\0'

enum action_type {
    ACTION_LOG = 0,
    ACTION_ALERT = 1,
    ACTION_THROTTLE = 2,
    ACTION_BLOCK = 3,
    ACTION_KILL = 4
};

struct baseline_rule {
    char name[MAX_NAME_LEN];
    char path[MAX_PATH_LEN];
    uint32_t mode;           // expected mode, e.g., 000
    char hash[HASH_LEN];     // expected sha256, or empty
    enum action_type action;
    int has_hash;            // 0=no hash check, 1=check hash
};

struct baseline_config {
    struct baseline_rule *rules;
    int count;
    int capacity;
};

#endif