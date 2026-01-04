#include "game.h"
#include "util.h"

RoundResult apply_rules(GoatState prev, int goat_num, int wolf_num, int n_goats) {
    RoundResult r{};
    const int diff = abs_int(goat_num - wolf_num);

    // thresholds are 70/n and 20/n (integer division is fine in assignment context).
    const int hide_thr = (n_goats > 0) ? (70 / n_goats) : 0;
    const int res_thr  = (n_goats > 0) ? (20 / n_goats) : 0;

    if (prev == GoatState::ALIVE) {
        if (diff <= hide_thr) {
            r.new_state = GoatState::ALIVE;
            r.hid = true;
        } else {
            r.new_state = GoatState::DEAD;
            r.got_caught = true;
        }
    } else {
        if (diff <= res_thr) {
            r.new_state = GoatState::ALIVE;
            r.resurrected = true;
        } else {
            r.new_state = GoatState::DEAD;
        }
    }
    return r;
}
