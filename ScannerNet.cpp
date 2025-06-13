#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <chrono>
#include <thread>
#include <format>
#include <ranges>
#include <expected>
#include <print>

#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/algorithm/string.hpp>

namespace asio = boost::asio;
namespace po = boost::program_options;
using namespace std::chrono_literals;

// Struttura per rappresentare un risultato di scansione
struct ScanResult {
    std::string ip;
    bool is_alive;
    std::chrono::milliseconds response_time;
};

// Classe per gestire la scansione ICMP
class NetworkScanner {
private:
    asio::io_context io_context_;
    asio::ip::icmp::resolver resolver_;
    asio::ip::icmp::socket socket_;
    std::vector<ScanResult> results_;

    static constexpr uint16_t ICMP_ECHO_REQUEST = 8;
    static constexpr uint16_t ICMP_ECHO_REPLY = 0;

    // Struttura ICMP header
    struct icmp_header {
        uint8_t type;
        uint8_t code;
        uint16_t checksum;
        uint16_t identifier;
        uint16_t sequence_number;
    };

    uint16_t calculate_checksum(const void* data, size_t size) {
        const uint16_t* ptr = static_cast<const uint16_t*>(data);
        uint32_t sum = 0;

        while (size > 1) {
            sum += *ptr++;
            size -= 2;
        }

        if (size > 0) {
            sum += *reinterpret_cast<const uint8_t*>(ptr);
        }

        while (sum >> 16) {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        return static_cast<uint16_t>(~sum);
    }

public:
    NetworkScanner()
        : resolver_(io_context_),
        socket_(io_context_, asio::ip::icmp::v4()) {
#ifdef _WIN32
        // Su Windows potrebbe essere necessario eseguire come amministratore
        // per socket raw ICMP
#else
        // Su Linux potrebbe essere necessario capability CAP_NET_RAW
        // o eseguire come root
#endif
    }

    std::expected<bool, std::string> ping_host(const std::string& ip_address,
        std::chrono::milliseconds timeout = 1000ms) {
        try {
            asio::ip::icmp::endpoint destination(
                asio::ip::address::from_string(ip_address), 0);

            // Prepara pacchetto ICMP
            icmp_header echo_request{};
            echo_request.type = ICMP_ECHO_REQUEST;
            echo_request.code = 0;
            echo_request.identifier = static_cast<uint16_t>(std::this_thread::get_id()._Hash());
            echo_request.sequence_number = 1;
            echo_request.checksum = 0;

            // Calcola checksum
            echo_request.checksum = calculate_checksum(&echo_request, sizeof(echo_request));

            // Invia richiesta
            auto start_time = std::chrono::steady_clock::now();
            socket_.send_to(asio::buffer(&echo_request, sizeof(echo_request)), destination);

            // Imposta timeout
            std::array<uint8_t, 1024> reply_buffer;
            asio::ip::icmp::endpoint sender_endpoint;
            bool received = false;

            asio::steady_timer timer(io_context_);
            timer.expires_after(timeout);

            socket_.async_receive_from(
                asio::buffer(reply_buffer),
                sender_endpoint,
                [&received](std::error_code ec, std::size_t) {
                    if (!ec) received = true;
                });

            timer.async_wait([this](std::error_code) {
                socket_.cancel();
                });

            io_context_.run_for(timeout);
            io_context_.restart();

            if (received) {
                auto end_time = std::chrono::steady_clock::now();
                auto response_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                    end_time - start_time);

                results_.push_back({ ip_address, true, response_time });
                return true;
            }
            else {
                results_.push_back({ ip_address, false, 0ms });
                return false;
            }

        }
        catch (const std::exception& e) {
            return std::unexpected(std::format("Errore ping {}: {}", ip_address, e.what()));
        }
    }

    void scan_range(const std::string& base_ip, int start, int end) {
        // Estrai i primi tre ottetti dell'IP
        auto parts = base_ip | std::views::split('.')
            | std::views::transform([](auto&& r) {
            return std::string(r.begin(), r.end());
                })
            | std::ranges::to<std::vector>();

        if (parts.size() != 4) {
            std::println(std::cerr, "Formato IP non valido: {}", base_ip);
            return;
        }

        std::string network_prefix = std::format("{}.{}.{}.", parts[0], parts[1], parts[2]);

        std::println("Scansione rete {} dal host {} al {}", network_prefix, start, end);
        std::println("Attendere...\n");

        for (int i = start; i <= end; ++i) {
            std::string ip = network_prefix + std::to_string(i);

            auto result = ping_host(ip, 500ms);

            if (result.has_value() && result.value()) {
                std::println("Host {} è ATTIVO ({}ms)", ip, results_.back().response_time.count());
            }
            else if (!result.has_value()) {
                std::println(std::cerr, "Errore: {}", result.error());
            }

            // Piccola pausa tra le richieste per non sovraccaricare la rete
            std::this_thread::sleep_for(10ms);
        }
    }

    void save_results(const std::string& filename) {
        std::ofstream file(filename);
        if (!file) {
            std::println(std::cerr, "Impossibile aprire il file: {}", filename);
            return;
        }

        file << std::format("Network Scan Results - {:%Y-%m-%d %H:%M:%S}\n",
            std::chrono::system_clock::now());
        file << std::format("{}\n", std::string(60, '-'));
        file << std::format("{:<20} {:<10} {:<15}\n", "IP Address", "Status", "Response Time");
        file << std::format("{}\n", std::string(60, '-'));

        for (const auto& result : results_) {
            file << std::format("{:<20} {:<10} {:<15}\n",
                result.ip,
                result.is_alive ? "ATTIVO" : "INATTIVO",
                result.is_alive ? std::format("{}ms", result.response_time.count()) : "N/A");
        }

        auto alive_count = std::ranges::count_if(results_,
            [](const auto& r) { return r.is_alive; });

        file << std::format("\n{}\n", std::string(60, '-'));
        file << std::format("Host totali scansionati: {}\n", results_.size());
        file << std::format("Host attivi: {}\n", alive_count);
        file << std::format("Host inattivi: {}\n", results_.size() - alive_count);

        std::println("Risultati salvati in: {}", filename);
    }

    void print_summary() {
        auto alive_count = std::ranges::count_if(results_,
            [](const auto& r) { return r.is_alive; });

        std::println("\n{}", std::string(60, '='));
        std::println("RIEPILOGO SCANSIONE");
        std::println("{}", std::string(60, '='));
        std::println("Host totali scansionati: {}", results_.size());
        std::println("Host attivi: {}", alive_count);
        std::println("Host inattivi: {}", results_.size() - alive_count);

        if (alive_count > 0) {
            std::println("\nHost attivi trovati:");
            for (const auto& result : results_ | std::views::filter([](const auto& r) { return r.is_alive; })) {
                std::println("  {} ({}ms)", result.ip, result.response_time.count());
            }
        }
    }
};

// Parser per gli argomenti del range IP
struct IPRange {
    std::string base_ip;
    int start;
    int end;

    static std::expected<IPRange, std::string> parse(const std::vector<std::string>& args) {
        if (args.empty()) {
            // Default: scansiona la subnet locale
            return IPRange{ "192.168.1.0", 0, 254 };
        }

        if (args.size() != 2) {
            return std::unexpected("Formato: <ip_base> <start:end>");
        }

        IPRange range;
        range.base_ip = args[0];

        // Parse del range start:end
        auto range_parts = args[1] | std::views::split(':')
            | std::views::transform([](auto&& r) {
            return std::string(r.begin(), r.end());
                })
            | std::ranges::to<std::vector>();

        if (range_parts.size() != 2) {
            return std::unexpected("Range deve essere nel formato start:end");
        }

        try {
            range.start = std::stoi(range_parts[0]);
            range.end = std::stoi(range_parts[1]);

            if (range.start < 0 || range.start > 255 ||
                range.end < 0 || range.end > 255 ||
                range.start > range.end) {
                return std::unexpected("Range non valido (0-255)");
            }

        }
        catch (...) {
            return std::unexpected("Errore nel parsing del range");
        }

        return range;
    }
};

int main(int argc, char* argv[]) {
    try {
        // Configurazione opzioni linea di comando
        po::options_description desc("Network Scanner - Opzioni");
        desc.add_options()
            ("help,h", "Mostra questo messaggio di aiuto")
            ("output,o", po::value<std::string>(), "Salva i risultati su file")
            ("ip-range", po::value<std::vector<std::string>>()->multitoken(),
                "Range IP da scansionare (es: 192.168.1.0 0:254)");

        po::positional_options_description pos;
        pos.add("ip-range", -1);

        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv)
            .options(desc)
            .positional(pos)
            .run(), vm);
        po::notify(vm);

        if (vm.count("help")) {
            std::println("Network Scanner C++23 con Boost 1.88.0\n");
            std::println("Utilizzo: {} [opzioni] [ip_base start:end]", argv[0]);
            std::println("\nEsempi:");
            std::println("  {} # Scansiona la subnet locale di default", argv[0]);
            std::println("  {} 192.168.1.0 0:254", argv[0]);
            std::println("  {} 10.0.0.0 1:100 -o risultati.txt", argv[0]);
            std::cout << "\n" << desc << std::endl;
            return 0;
        }

        // Parse del range IP
        std::vector<std::string> ip_args;
        if (vm.count("ip-range")) {
            ip_args = vm["ip-range"].as<std::vector<std::string>>();
        }

        auto range_result = IPRange::parse(ip_args);
        if (!range_result.has_value()) {
            std::println(std::cerr, "Errore: {}", range_result.error());
            return 1;
        }

        auto range = range_result.value();

        // Esegui scansione
        NetworkScanner scanner;

        std::println("=== NETWORK SCANNER ===");
        std::println("Sistema operativo: {}",
#ifdef _WIN32
            "Windows"
#else
            "Linux"
#endif
        );

        scanner.scan_range(range.base_ip, range.start, range.end);
        scanner.print_summary();

        // Salva risultati se richiesto
        if (vm.count("output")) {
            scanner.save_results(vm["output"].as<std::string>());
        }

    }
    catch (const std::exception& e) {
        std::println(std::cerr, "Errore: {}", e.what());
        std::println(std::cerr, "\nNota: Questo programma richiede privilegi di amministratore/root per l'uso di socket ICMP raw.");
        return 1;
    }

    return 0;
}