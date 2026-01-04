#pragma once
#include "protocol.h"

struct RoundResult {
    GoatState new_state = GoatState::ALIVE;
    bool hid = false;
    bool got_caught = false;
    bool resurrected = false;
};

// Computes new goat state based on rules from the assignment.
RoundResult apply_rules(GoatState prev, int goat_num, int wolf_num, int n_goats);
