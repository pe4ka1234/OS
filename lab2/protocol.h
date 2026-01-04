#pragma once
#include <cstdint>

static constexpr uint32_t kMagic = 0xC0DECAFEu;

enum class PacketType : uint32_t {
    HELLO = 1,
    START = 2,
    NUMBER = 3,
    STATUS = 4,
    STOP = 5,
};

enum class GoatState : int32_t {
    DEAD = 0,
    ALIVE = 1,
};

struct Packet {
    uint32_t magic = kMagic;
    PacketType type = PacketType::HELLO;
    int32_t client_id = 0;
    int32_t a = 0;   // payload
    int32_t b = 0;   // payload
};
static_assert(sizeof(Packet) == 20, "Packet must be fixed-size");
