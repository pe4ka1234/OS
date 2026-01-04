#include "conn_iface.h"
#include "game.h"
#include "log.h"
#include "protocol.h"
#include "util.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <poll.h>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>
#include <sys/wait.h>

struct ClientCtx {
    int id = 0;
    pid_t pid = -1;
    std::unique_ptr<IConn> conn;

    // state
    GoatState state = GoatState::ALIVE;
    int last_num = 0;
    bool hid = false;
    bool got_caught = false;
    bool resurrected = false;

    // thread coordination
    std::thread th;
};

static std::atomic_bool g_stop{false};

static void on_sigint(int) {
    g_stop.store(true);
}

static int rand_in(std::mt19937& rng, int lo, int hi) {
    std::uniform_int_distribution<int> d(lo, hi);
    return d(rng);
}

// Wait up to 3s for user input, otherwise random 1..100.
static int choose_wolf_number(std::mt19937& rng) {
    log_msg(LogLevel::INFO, "host", "Введите число волка [1..100] за 3 секунды (или будет выбрано случайно):");

    pollfd pfd{};
    pfd.fd = 0; // stdin
    pfd.events = POLLIN;

    const int rc = ::poll(&pfd, 1, 3000);
    if (rc > 0 && (pfd.revents & POLLIN)) {
        std::string line;
        std::getline(std::cin, line);
        int v = 0;
        if (parse_int(line, v) && v >= 1 && v <= 100) return v;
        log_msg(LogLevel::WARN, "host", "Некорректный ввод. Будет использовано случайное число.");
    }
    return rand_in(rng, 1, 100);
}

struct RoundShared {
    std::mutex m;
    std::condition_variable cv_round;
    std::condition_variable cv_done;

    int round = 0;
    int wolf_num = 0;

    int done = 0;
    bool stop = false;
};

static void client_worker(ClientCtx* ctx, RoundShared* sh, int n_goats) {
    const std::string who = "host[client#" + std::to_string(ctx->id) + "]";
    // Expect HELLO first
    Packet p{};
    if (!ctx->conn->Read(&p, sizeof(p)) || p.magic != kMagic || p.type != PacketType::HELLO) {
        log_msg(LogLevel::ERROR, who, "Не удалось получить HELLO от клиента (таймаут/ошибка).");
        sh->stop = true;
        sh->cv_done.notify_all();
        return;
    }
    log_msg(LogLevel::INFO, who, "Клиент подключился. child_pid=" + std::to_string(p.a));

    int local_round = 0;

    for (;;) {
        // wait for next round or stop
        {
            std::unique_lock<std::mutex> lk(sh->m);
            sh->cv_round.wait(lk, [&]{ return sh->stop || sh->round > local_round; });
            if (sh->stop) break;
            local_round = sh->round;
        }

        // Send START
        Packet start{};
        start.magic = kMagic;
        start.type = PacketType::START;
        start.client_id = ctx->id;
        start.a = sh->wolf_num;     // wolf number
        start.b = local_round;      // round
        if (!ctx->conn->Write(&start, sizeof(start))) {
            log_msg(LogLevel::ERROR, who, "Ошибка/таймаут при отправке START.");
            {
                std::lock_guard<std::mutex> lk(sh->m);
                sh->stop = true;
            }
            sh->cv_done.notify_all();
            break;
        }

        // Receive NUMBER
        Packet num{};
        if (!ctx->conn->Read(&num, sizeof(num)) || num.magic != kMagic || num.type != PacketType::NUMBER) {
            log_msg(LogLevel::ERROR, who, "Ошибка/таймаут при чтении NUMBER.");
            {
                std::lock_guard<std::mutex> lk(sh->m);
                sh->stop = true;
            }
            sh->cv_done.notify_all();
            break;
        }

        const int goat_num = num.a;
        const GoatState prev_state = ctx->state;

        // Apply rules and respond
        const RoundResult rr = apply_rules(prev_state, goat_num, sh->wolf_num, n_goats);
        ctx->last_num = goat_num;
        ctx->hid = rr.hid;
        ctx->got_caught = rr.got_caught;
        ctx->resurrected = rr.resurrected;
        ctx->state = rr.new_state;

        Packet st{};
        st.magic = kMagic;
        st.type = PacketType::STATUS;
        st.client_id = ctx->id;
        st.a = static_cast<int32_t>(ctx->state);
        st.b = local_round;
        if (!ctx->conn->Write(&st, sizeof(st))) {
            log_msg(LogLevel::ERROR, who, "Ошибка/таймаут при отправке STATUS.");
            {
                std::lock_guard<std::mutex> lk(sh->m);
                sh->stop = true;
            }
            sh->cv_done.notify_all();
            break;
        }

        // mark done
        {
            std::lock_guard<std::mutex> lk(sh->m);
            sh->done++;
        }
        sh->cv_done.notify_one();
    }

    // Send STOP best-effort
    Packet stop{};
    stop.magic = kMagic;
    stop.type = PacketType::STOP;
    stop.client_id = ctx->id;
    (void)ctx->conn->Write(&stop, sizeof(stop));

    log_msg(LogLevel::INFO, who, "Поток завершён.");
}

static void usage() {
    std::cout << "Usage: ./host_" << conn_type_code() << " [--n <goats>]\n"
              << "  --n  количество козлят (по умолчанию 7)\n";
}

int main(int argc, char** argv) {
    std::signal(SIGINT, on_sigint);

    int n = 7;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--n" && i + 1 < argc) {
            int v = 0;
            if (!parse_int(argv[++i], v) || v <= 0 || v > 1000) {
                log_msg(LogLevel::ERROR, "host", "Некорректное значение --n.");
                usage();
                return 2;
            }
            n = v;
        } else if (a == "--help" || a == "-h") {
            usage();
            return 0;
        } else {
            log_msg(LogLevel::ERROR, "host", "Неизвестный аргумент: " + a);
            usage();
            return 2;
        }
    }

    log_msg(LogLevel::INFO, "host", std::string("Вариант 8. TYPE_CODE=") + conn_type_code() + ". n=" + std::to_string(n));

    // Seed RNG
    std::random_device rd;
    std::mt19937 rng(rd());

    const int host_pid = static_cast<int>(getpid());

    std::vector<ClientCtx> clients;
    clients.reserve(static_cast<size_t>(n));

    RoundShared shared;

    // Create clients (children) and per-client connections
    for (int i = 1; i <= n; i++) {
        ConnPair pair = create_conn_pair(i, host_pid);

        pid_t pid = ::fork();
        if (pid < 0) {
            log_msg(LogLevel::ERROR, "host", std::string("fork failed: ") + std::strerror(errno));
            shared.stop = true;
            break;
        }

        if (pid == 0) {
            // child
            for (int fd : pair.child.close_fds) {
                if (fd >= 0) ::close(fd);
            }
            auto conn = make_conn(pair.child.spec);
            if (!conn) {
                log_msg(LogLevel::ERROR, "client", "Не удалось создать соединение.");
                std::_Exit(3);
            }

            std::seed_seq seq{
                static_cast<unsigned>(getpid()),
                static_cast<unsigned>(i),
                static_cast<unsigned>(
                    std::chrono::high_resolution_clock::now().time_since_epoch().count()
                )
            };
            rng.seed(seq);

            // Client main loop (in child process)
            // Send HELLO
            Packet hello{};
            hello.magic = kMagic;
            hello.type = PacketType::HELLO;
            hello.client_id = i;
            hello.a = static_cast<int32_t>(getpid());
            if (!conn->Write(&hello, sizeof(hello))) {
                log_msg(LogLevel::ERROR, "client", "Не удалось отправить HELLO (таймаут/ошибка).");
                std::_Exit(4);
            }

            GoatState state = GoatState::ALIVE;
            for (;;) {
                Packet p{};
                if (!conn->Read(&p, sizeof(p)) || p.magic != kMagic) {
                    log_msg(LogLevel::ERROR, "client", "Ошибка/таймаут чтения. Завершаюсь.");
                    break;
                }
                if (p.type == PacketType::STOP) break;
                if (p.type != PacketType::START) {
                    log_msg(LogLevel::WARN, "client", "Неожиданный пакет. Пропускаю.");
                    continue;
                }

                const int wolf = p.a;
                (void)wolf;
                // generate goat number depending on state
                int goat_num = 0;
                if (state == GoatState::ALIVE) {
                    goat_num = rand_in(rng, 1, 100);
                } else {
                    goat_num = rand_in(rng, 1, 50);
                }

                Packet num{};
                num.magic = kMagic;
                num.type = PacketType::NUMBER;
                num.client_id = i;
                num.a = goat_num;
                num.b = static_cast<int32_t>(state);
                if (!conn->Write(&num, sizeof(num))) {
                    log_msg(LogLevel::ERROR, "client", "Не удалось отправить NUMBER (таймаут/ошибка).");
                    break;
                }

                Packet st{};
                if (!conn->Read(&st, sizeof(st)) || st.magic != kMagic || st.type != PacketType::STATUS) {
                    log_msg(LogLevel::ERROR, "client", "Не удалось получить STATUS (таймаут/ошибка).");
                    break;
                }
                state = static_cast<GoatState>(st.a);
            }

            log_msg(LogLevel::INFO, "client", "Завершился.");
            std::_Exit(0);
        }

        // parent
        for (int fd : pair.host.close_fds) {
            if (fd >= 0) ::close(fd);
        }

        ClientCtx ctx;
        ctx.id = i;
        ctx.pid = pid;
        ctx.conn = make_conn(pair.host.spec);
        if (!ctx.conn) {
            log_msg(LogLevel::ERROR, "host", "Не удалось создать соединение для клиента #" + std::to_string(i));
            shared.stop = true;
            break;
        }
        clients.push_back(std::move(ctx));
    }

    if (clients.size() != static_cast<size_t>(n)) {
        log_msg(LogLevel::ERROR, "host", "Не удалось создать всех клиентов. Завершение.");
        shared.stop = true;
    }

    // Start threads (one per client) and wait for HELLO in each worker
    for (auto& c : clients) {
        c.th = std::thread(client_worker, &c, &shared, n);
    }

    // Wait a bit for connections; if workers fail they'll set shared.stop
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    int consecutive_all_dead = 0;
    int round = 0;

    while (!shared.stop && !g_stop.load()) {
        round++;

        const int wolf = choose_wolf_number(rng);

        // announce new round
        {
            std::lock_guard<std::mutex> lk(shared.m);
            shared.wolf_num = wolf;
            shared.round = round;
            shared.done = 0;
        }
        shared.cv_round.notify_all();

        // wait until all threads processed the round or stop requested
        {
            std::unique_lock<std::mutex> lk(shared.m);
            shared.cv_done.wait(lk, [&]{ return shared.stop || shared.done >= static_cast<int>(clients.size()); });
        }
        if (shared.stop) break;

        // summarize round
        int alive_cnt = 0;
        int dead_cnt = 0;
        int hid_cnt = 0;
        int caught_cnt = 0;
        int resurrected_cnt = 0;

        std::ostringstream nums;
        nums << "Раунд " << round << ": волк=" << wolf << " | козлята: ";

        for (const auto& c : clients) {
            nums << "#" << c.id << "=" << c.last_num;
            if (c.state == GoatState::ALIVE) {
                alive_cnt++;
                if (c.hid) nums << "(спрятался)";
            } else {
                dead_cnt++;
            }
            if (c.got_caught) caught_cnt++;
            if (c.resurrected) resurrected_cnt++;
            nums << " ";
            if (c.hid) hid_cnt++;
        }

        log_msg(LogLevel::INFO, "host", nums.str());
        log_msg(LogLevel::INFO, "host",
                "Итог раунда: спрятались=" + std::to_string(hid_cnt) +
                ", попались=" + std::to_string(caught_cnt) +
                ", мертвы=" + std::to_string(dead_cnt) +
                ", воскресли=" + std::to_string(resurrected_cnt));

        if (alive_cnt == 0) {
            consecutive_all_dead++;
        } else {
            consecutive_all_dead = 0;
        }

        if (consecutive_all_dead >= 2) {
            log_msg(LogLevel::INFO, "host", "Все козлята мертвы 2 раунда подряд. Игра окончена.");
            break;
        }
    }

    // Stop threads and children
    {
        std::lock_guard<std::mutex> lk(shared.m);
        shared.stop = true;
    }
    shared.cv_round.notify_all();

    for (auto& c : clients) {
        if (c.th.joinable()) c.th.join();
    }

    // Wait for child processes
    for (auto& c : clients) {
        int st = 0;
        (void)::waitpid(c.pid, &st, 0);
    }

    cleanup_host_resources(host_pid, n);

    log_msg(LogLevel::INFO, "host", "Завершился.");
    return 0;
}
