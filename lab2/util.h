#pragma once
#include <string>

bool parse_int(const std::string& s, int& out);
int clamp_int(int v, int lo, int hi);
int abs_int(int x);
