#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <chrono>
#include <thread>
#include <format>
#include <ranges>
#include <expected>
#include <array>
#include <cstdint>
#include <algorithm>
#include <atomic>
#include <mutex>
#include <future>
#include <memory>
#include <queue>
#include <condition_variable>
#include <iomanip>
#include <csignal>

// Fallback per std::print se non disponibile
#if __has_include(<print>)
#include <print>
#else
namespace std {
	template<typename... Args>
	void println(std::ostream& os, std::format_string<Args...> fmt, Args&&... args) {
		os << std::format(fmt, std::forward<Args>(args)...) << '\n';
	}

	template<typename... Args>
	void println(std::format_string<Args...> fmt, Args&&... args) {
		std::cout << std::format(fmt, std::forward<Args>(args)...) << '\n';
	}
}
#endif

#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/algorithm/string.hpp>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

namespace asio = boost::asio;
namespace po = boost::program_options;
using namespace std::chrono_literals;

// Flag globale per interruzione
std::atomic<bool> g_interrupted{ false };

// Gestore del segnale di interruzione
void signal_handler(int signal) {
	if (signal == SIGINT || signal == SIGTERM) {
		g_interrupted = true;
		std::cout << "\n\nInterruzione richiesta. Attendere il completamento delle scansioni in corso...\n" << std::flush;
	}
}

// Struttura per rappresentare un risultato di scansione
struct ScanResult {
	std::string ip;
	std::string hostname;
	bool is_alive;
	std::chrono::milliseconds response_time;
};

// Struttura per le metriche di performance
struct PerformanceMetrics {
	std::chrono::steady_clock::time_point start_time;
	std::chrono::steady_clock::time_point end_time;
	std::atomic<int> total_scanned{ 0 };
	std::atomic<int> total_alive{ 0 };
	std::atomic<int64_t> total_response_time_ms{ 0 };
	std::atomic<int> dns_resolved{ 0 };
	std::atomic<int> dns_failed{ 0 };

	double get_average_response_time() const {
		if (total_alive == 0) return 0.0;
		return static_cast<double>(total_response_time_ms) / total_alive;
	}

	std::chrono::milliseconds get_total_scan_time() const {
		return std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
	}

	double get_scan_rate() const {
		auto duration_ms = get_total_scan_time().count();
		if (duration_ms == 0) return 0.0;
		return (static_cast<double>(total_scanned) * 1000.0) / duration_ms;
	}
};



// Classe per l'animazione del progresso
class ProgressAnimator {
private:
	std::atomic<bool> running_{ true };
	std::atomic<int> scanned_{ 0 };
	std::atomic<int> found_{ 0 };
	int total_;
	std::thread animator_thread_;
	std::mutex print_mutex_;
	bool verbose_;

	void animate() {
#ifdef _WIN32
		static constexpr std::array<char, 4> spinner{ '\\', '|', '/', '-' };
#else
		static constexpr std::array<std::string, 4> spinner{ "⠋", "⠙", "⠹", "⠸" };
#endif
		int spinner_idx = 0;

		while (running_) {
			{
				std::lock_guard<std::mutex> lock(print_mutex_);
				if (!verbose_) {
					std::cout << "\r" << spinner[spinner_idx] << " Scansione in corso... "
						<< "Analizzati: " << scanned_.load() << "/" << total_
						<< " | Attivi: " << found_.load() << " " << std::flush;
				}
			}

			spinner_idx = (spinner_idx + 1) % spinner.size();
			std::this_thread::sleep_for(100ms);
		}

		// Pulisci la linea
		if (!verbose_) {
			std::cout << "\r" << std::string(80, ' ') << "\r" << std::flush;
		}
	}

public:
	explicit ProgressAnimator(int total, bool verbose = false)
		: total_(total), verbose_(verbose) {
		animator_thread_ = std::thread(&ProgressAnimator::animate, this);
	}

	~ProgressAnimator() {
		running_ = false;
		if (animator_thread_.joinable()) {
			animator_thread_.join();
		}
	}

	void increment_scanned() { scanned_++; }
	void increment_found() { found_++; }

	void log_found(const std::string& ip, const std::string& hostname) {
		if (verbose_) {
			std::lock_guard<std::mutex> lock(print_mutex_);
			auto now = std::chrono::system_clock::now();
			auto time_t_now = std::chrono::system_clock::to_time_t(now);
			std::cout << "[" << std::put_time(std::localtime(&time_t_now), "%H:%M:%S") << "] "
				<< "TROVATO: " << ip;
			if (!hostname.empty()) {
				std::cout << " (" << hostname << ")";
			}
			std::cout << std::endl;
		}
	}
};

// Classe per gestire la scansione di rete
// Utilizza Boost.Asio thread pool per esecuzione parallela efficiente
// Vantaggi: bilanciamento automatico del carico, gestione eccezioni,
// integrazione con I/O asincrono, cleanup automatico
class NetworkScanner {
private:
	std::vector<ScanResult> results_;
	std::mutex results_mutex_;
	asio::thread_pool thread_pool_;
	std::string filter_;
	asio::executor_work_guard<asio::thread_pool::executor_type> work_guard_;
	PerformanceMetrics metrics_;

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

	// Ottieni l'indirizzo IP locale e la subnet mask
	std::expected<std::pair<std::string, std::string>, std::string> get_local_network() {
#ifdef _WIN32
		ULONG bufferSize = 15000;
		std::vector<BYTE> buffer(bufferSize);
		PIP_ADAPTER_ADDRESSES addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

		DWORD result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX,
			nullptr, addresses, &bufferSize);

		if (result != NO_ERROR) {
			return std::unexpected("Errore nel recupero degli indirizzi di rete");
		}

		for (PIP_ADAPTER_ADDRESSES adapter = addresses; adapter; adapter = adapter->Next) {
			if (adapter->OperStatus != IfOperStatusUp) continue;

			for (PIP_ADAPTER_UNICAST_ADDRESS unicast = adapter->FirstUnicastAddress;
				unicast; unicast = unicast->Next) {

				if (unicast->Address.lpSockaddr->sa_family != AF_INET) continue;

				sockaddr_in* addr_in = reinterpret_cast<sockaddr_in*>(unicast->Address.lpSockaddr);
				char ip_str[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &addr_in->sin_addr, ip_str, INET_ADDRSTRLEN);
				std::string ip(ip_str);

				// Salta loopback e link-local
				if (ip.starts_with("127.") || ip.starts_with("169.254.")) continue;

				// Calcola subnet basandosi sul prefisso
				uint32_t mask = 0xFFFFFFFF << (32 - unicast->OnLinkPrefixLength);
				in_addr mask_addr;
				mask_addr.s_addr = htonl(mask);
				char mask_str[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &mask_addr, mask_str, INET_ADDRSTRLEN);

				return std::make_pair(ip, std::string(mask_str));
			}
		}
#else
		struct ifaddrs* ifaddr;
		if (getifaddrs(&ifaddr) == -1) {
			return std::unexpected("Errore nel recupero degli indirizzi di rete");
		}

		std::string local_ip;
		std::string subnet_mask;

		for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
			if (ifa->ifa_addr == nullptr) continue;

			if (ifa->ifa_addr->sa_family == AF_INET) {
				char host[NI_MAXHOST];
				getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
					host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);

				std::string ip(host);

				// Salta loopback e link-local
				if (ip.starts_with("127.") || ip.starts_with("169.254.")) continue;

				local_ip = ip;

				// Ottieni subnet mask
				if (ifa->ifa_netmask) {
					struct sockaddr_in* mask = (struct sockaddr_in*)ifa->ifa_netmask;
					char mask_str[INET_ADDRSTRLEN];
					inet_ntop(AF_INET, &mask->sin_addr, mask_str, INET_ADDRSTRLEN);
					subnet_mask = mask_str;
				}

				if (!local_ip.empty() && !subnet_mask.empty()) {
					break;
				}
			}
		}

		freeifaddrs(ifaddr);

		if (local_ip.empty()) {
			return std::unexpected("Nessun indirizzo IP locale trovato");
		}

		return std::make_pair(local_ip, subnet_mask);
#endif

		return std::unexpected("Nessun indirizzo IP valido trovato");
	}

	// Calcola il range di IP dalla subnet
	std::pair<std::string, std::pair<int, int>> calculate_network_range(
		const std::string& ip, const std::string& mask) {

		struct in_addr ip_addr, mask_addr, net_addr;

#ifdef _WIN32
		inet_pton(AF_INET, ip.c_str(), &ip_addr);
		inet_pton(AF_INET, mask.c_str(), &mask_addr);
#else
		inet_aton(ip.c_str(), &ip_addr);
		inet_aton(mask.c_str(), &mask_addr);
#endif

		uint32_t network = ip_addr.s_addr & mask_addr.s_addr;
		uint32_t broadcast = network | ~mask_addr.s_addr;

		net_addr.s_addr = network;

		char network_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &net_addr, network_str, INET_ADDRSTRLEN);

		// Calcola il numero di host
		uint32_t num_hosts = ntohl(broadcast) - ntohl(network);

		// Per semplicità, assumiamo una /24 se la subnet è grande
		if (num_hosts > 256) {
			return { network_str, {1, 254} };
		}

		return { network_str, {1, static_cast<int>(num_hosts - 1)} };
	}

	// Risolvi hostname con timeout
	std::string resolve_hostname(const std::string& ip) {
		try {
			// Usa getnameinfo per una risoluzione più affidabile
			struct sockaddr_in sa;
			sa.sin_family = AF_INET;
			inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

			char hostname[NI_MAXHOST];

			// Usa un future per implementare un timeout
			auto future = std::async(std::launch::async, [&sa, &hostname]() {
				return getnameinfo((struct sockaddr*)&sa, sizeof(sa),
					hostname, NI_MAXHOST, nullptr, 0, 0);
				});

			// Timeout di 2 secondi per la risoluzione DNS
			if (future.wait_for(2s) == std::future_status::ready) {
				if (future.get() == 0 && strlen(hostname) > 0) {
					return std::string(hostname);
				}
			}
		}
		catch (...) {
			// Ignora errori di risoluzione
		}

		return "";
	}

public:
	NetworkScanner(const std::string& filter = "")
		: thread_pool_(std::min(static_cast<size_t>(8),
			static_cast<size_t>(std::thread::hardware_concurrency()))),
		filter_(filter),
		work_guard_(asio::make_work_guard(thread_pool_)) {
	}

	~NetworkScanner() {
		// Rilascia il work guard per permettere al thread pool di terminare
		work_guard_.reset();
		// Attendi che tutti i thread terminino
		thread_pool_.join();
	}

	std::expected<std::chrono::milliseconds, std::string> ping_host(const std::string& ip_address, int retry_count = 2) {
		for (int attempt = 0; attempt < retry_count; ++attempt) {
			try {
				asio::io_context io_context;
				asio::ip::icmp::socket socket(io_context, asio::ip::icmp::v4());

				asio::ip::icmp::endpoint destination(
					asio::ip::make_address(ip_address), 0);

				// Prepara pacchetto ICMP
				icmp_header echo_request{};
				echo_request.type = ICMP_ECHO_REQUEST;
				echo_request.code = 0;
				echo_request.identifier = static_cast<uint16_t>(std::hash<std::thread::id>{}(std::this_thread::get_id()));
				echo_request.sequence_number = static_cast<uint16_t>(attempt + 1);
				echo_request.checksum = 0;

				// Calcola checksum
				echo_request.checksum = calculate_checksum(&echo_request, sizeof(echo_request));

				// Invia richiesta
				auto start_time = std::chrono::steady_clock::now();
				socket.send_to(asio::buffer(&echo_request, sizeof(echo_request)), destination);

				// Timeout aumentato a 1 secondo
				std::array<uint8_t, 1024> reply_buffer;
				asio::ip::icmp::endpoint sender_endpoint;
				bool received = false;

				asio::steady_timer timer(io_context);
				timer.expires_after(1000ms);

				socket.async_receive_from(
					asio::buffer(reply_buffer),
					sender_endpoint,
					[&received, &sender_endpoint, &destination](std::error_code ec, std::size_t bytes_received) {
						if (!ec && bytes_received >= sizeof(icmp_header)) {
							// Verifica che la risposta sia dal giusto host
							if (sender_endpoint.address() == destination.address()) {
								received = true;
							}
						}
					});

				timer.async_wait([&socket](std::error_code) {
					socket.cancel();
					});

				io_context.run_for(1000ms);

				if (received) {
					auto end_time = std::chrono::steady_clock::now();
					auto response_time = std::chrono::duration_cast<std::chrono::milliseconds>(
						end_time - start_time);

					return response_time;
				}

				// Breve pausa tra i tentativi
				if (attempt < retry_count - 1) {
					std::this_thread::sleep_for(100ms);
				}

			}
			catch (const std::exception& e) {
				if (attempt == retry_count - 1) {
					return std::unexpected(std::format("Errore ping {}: {}", ip_address, e.what()));
				}
			}
		}

		return std::unexpected("No response");
	}

	// Scansiona un host in modo asincrono usando Boost.Asio thread pool
	// Utilizza promise/future per tracciare il completamento
	void scan_host_async(const std::string& ip, ProgressAnimator& progress,
		std::vector<std::future<void>>& futures) {
		auto promise = std::make_shared<std::promise<void>>();
		futures.push_back(promise->get_future());

		asio::post(thread_pool_, [this, ip, &progress, promise]() {
			// Controlla se è stata richiesta l'interruzione
			if (g_interrupted) {
				progress.increment_scanned();
				promise->set_value();
				return;
			}

			metrics_.total_scanned++;
			auto result = ping_host(ip);

			if (result.has_value()) {
				auto response_time = result.value();
				metrics_.total_alive++;
				metrics_.total_response_time_ms += response_time.count();

				// Host attivo, risolvi hostname
				std::string hostname = resolve_hostname(ip);
				if (!hostname.empty()) {
					metrics_.dns_resolved++;
				}
				else {
					metrics_.dns_failed++;
				}

				// Applica filtro se specificato
				if (!filter_.empty()) {
					if (hostname.empty() ||
						!boost::algorithm::icontains(hostname, filter_)) {
						progress.increment_scanned();
						promise->set_value();
						return;
					}
				}

				{
					std::lock_guard<std::mutex> lock(results_mutex_);
					results_.push_back({ ip, hostname, true, response_time });
				}

				progress.log_found(ip, hostname);
				progress.increment_found();
			}

			progress.increment_scanned();
			promise->set_value();
			});
	}

	void scan_network(const std::string& base_ip = "", int start = -1, int end = -1, bool verbose = false) {
		std::string network_ip = base_ip;
		int scan_start = start;
		int scan_end = end;

		// Se non specificato, trova automaticamente la rete locale
		if (network_ip.empty()) {
			auto local_net = get_local_network();
			if (!local_net.has_value()) {
				std::println(std::cerr, "Errore: {}", local_net.error());
				return;
			}

			auto [local_ip, subnet_mask] = local_net.value();
			auto [network, range] = calculate_network_range(local_ip, subnet_mask);

			network_ip = network;
			scan_start = (start == -1) ? range.first : start;
			scan_end = (end == -1) ? range.second : end;

			std::println("Rete locale rilevata: {} (Mask: {})", local_ip, subnet_mask);
		}

		// Estrai i primi tre ottetti
		std::vector<std::string> parts;
		std::string current;
		for (char c : network_ip) {
			if (c == '.') {
				if (!current.empty()) {
					parts.push_back(current);
					current.clear();
				}
			}
			else {
				current += c;
			}
		}
		if (!current.empty()) {
			parts.push_back(current);
		}

		if (parts.size() < 3) {
			std::println(std::cerr, "Formato IP non valido: {}", network_ip);
			return;
		}

		std::string network_prefix = std::format("{}.{}.{}.", parts[0], parts[1], parts[2]);

		// Calcola numero totale di host
		int total_hosts = scan_end - scan_start + 1;

		std::println("Scansione rete: {}x (Range: {} - {})",
			network_prefix, scan_start, scan_end);

		if (!filter_.empty()) {
			std::println("Filtro hostname: *{}*", filter_);
		}

		if (verbose) {
			std::println("Modalità verbose attiva - mostra host in tempo reale");
		}

		std::println("Attendere...\n");

		// Registra tempo di inizio
		metrics_.start_time = std::chrono::steady_clock::now();

		// Avvia animazione progresso
		ProgressAnimator progress(total_hosts, verbose);

		// Vector per tracciare tutti i futures
		std::vector<std::future<void>> scan_futures;
		scan_futures.reserve(total_hosts);

		// Avvia scansioni asincrone
		for (int i = scan_start; i <= scan_end; ++i) {
			if (g_interrupted) {
				std::println("\nScansione interrotta dall'utente.");
				break;
			}

			std::string ip = network_prefix + std::to_string(i);
			scan_host_async(ip, progress, scan_futures);

			// Delay aumentato per evitare rate limiting
			std::this_thread::sleep_for(20ms);
		}

		// Attendi che tutti i futures siano completati
		for (auto& future : scan_futures) {
			future.wait();
		}

		// Registra tempo di fine
		metrics_.end_time = std::chrono::steady_clock::now();
	}

	void save_results(const std::string& filename) {
		std::ofstream file(filename);
		if (!file) {
			std::println(std::cerr, "Impossibile aprire il file: {}", filename);
			return;
		}

		auto now = std::chrono::system_clock::now();
		auto time_t_now = std::chrono::system_clock::to_time_t(now);

		file << "Network Scan Results - "
			<< std::put_time(std::localtime(&time_t_now), "%Y-%m-%d %H:%M:%S")
			<< "\n";

		if (!filter_.empty()) {
			file << std::format("Filtro applicato: *{}*\n", filter_);
		}

		file << std::format("{}\n", std::string(80, '-'));
		file << std::format("{:<20} {:<40} {:<15}\n", "IP Address", "Hostname", "Response Time");
		file << std::format("{}\n", std::string(80, '-'));

		// Ordina risultati per IP
		std::sort(results_.begin(), results_.end(),
			[](const auto& a, const auto& b) {
				struct in_addr addr_a, addr_b;
#ifdef _WIN32
				inet_pton(AF_INET, a.ip.c_str(), &addr_a);
				inet_pton(AF_INET, b.ip.c_str(), &addr_b);
#else
				inet_aton(a.ip.c_str(), &addr_a);
				inet_aton(b.ip.c_str(), &addr_b);
#endif
				return ntohl(addr_a.s_addr) < ntohl(addr_b.s_addr);
			});

		for (const auto& result : results_) {
			file << std::format("{:<20} {:<40} {:<15}\n",
				result.ip,
				result.hostname.empty() ? "N/A" : result.hostname,
				std::format("{}ms", result.response_time.count()));
		}

		file << std::format("\n{}\n", std::string(80, '-'));
		file << std::format("STATISTICHE DI SCANSIONE\n");
		file << std::format("{}\n", std::string(80, '-'));
		file << std::format("Host totali scansionati: {}\n", metrics_.total_scanned.load());
		file << std::format("Host attivi trovati: {}\n", results_.size());
		file << std::format("Tempo totale scansione: {:.2f}s\n", metrics_.get_total_scan_time().count() / 1000.0);
		file << std::format("Velocità scansione: {:.1f} host/secondo\n", metrics_.get_scan_rate());

		if (metrics_.total_alive > 0) {
			file << std::format("\nMetriche di risposta:\n");
			file << std::format("  Tempo medio di risposta: {:.1f}ms\n", metrics_.get_average_response_time());
			file << std::format("  DNS risolti: {}/{} ({:.1f}%)\n",
				metrics_.dns_resolved.load(),
				metrics_.total_alive.load(),
				(metrics_.dns_resolved.load() * 100.0) / metrics_.total_alive.load());
		}

		std::println("\nRisultati salvati in: {}", filename);
	}

	void print_results() {
		if (results_.empty()) {
			std::println("\nNessun host attivo trovato");
			if (!filter_.empty()) {
				std::println("(con filtro hostname: *{}*)", filter_);
			}
			return;
		}

		// Ordina risultati per IP
		std::sort(results_.begin(), results_.end(),
			[](const auto& a, const auto& b) {
				struct in_addr addr_a, addr_b;
#ifdef _WIN32
				inet_pton(AF_INET, a.ip.c_str(), &addr_a);
				inet_pton(AF_INET, b.ip.c_str(), &addr_b);
#else
				inet_aton(a.ip.c_str(), &addr_a);
				inet_aton(b.ip.c_str(), &addr_b);
#endif
				return ntohl(addr_a.s_addr) < ntohl(addr_b.s_addr);
			});

		std::println("\n{}", std::string(80, '='));
		if (g_interrupted) {
			std::println("HOST ATTIVI TROVATI (Scansione interrotta)");
		}
		else {
			std::println("HOST ATTIVI TROVATI");
		}
		std::println("{}", std::string(80, '='));

		std::println("{:<20} {:<40} {:<15}", "IP Address", "Hostname", "Response Time");
		std::println("{}", std::string(80, '-'));

		for (const auto& result : results_) {
			std::println("{:<20} {:<40} {:<15}",
				result.ip,
				result.hostname.empty() ? "N/A" : result.hostname,
				std::format("{}ms", result.response_time.count()));
		}

		std::println("\n{}\nSTATISTICHE\n{}", std::string(80, '='), std::string(80, '='));
		std::println("Host totali scansionati: {}", (int)metrics_.total_scanned);
		std::println("Host attivi trovati: {}", (int)results_.size());
		std::println("Tempo totale scansione: {:.2f}s", metrics_.get_total_scan_time().count() / 1000.0);
		std::println("Velocità scansione: {:.1f} host/secondo", metrics_.get_scan_rate());

		if (metrics_.total_alive > 0) {
			std::println("\nMetriche di risposta:");
			std::println("  Tempo medio di risposta: {:.1f}ms", metrics_.get_average_response_time());
			std::println("  DNS risolti con successo: {}/{} ({:.1f}%)",
				metrics_.dns_resolved.load(),
				metrics_.total_alive.load(),
				(metrics_.dns_resolved.load() * 100.0) / metrics_.total_alive.load());
		}

		if (!filter_.empty()) {
			std::println("\nFiltro applicato: *{}*", filter_);
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
			// Default: auto-detect
			return IPRange{ "", -1, -1 };
		}

		if (args.size() != 2) {
			return std::unexpected("Formato: <ip_base> <start:end>");
		}

		IPRange range;
		range.base_ip = args[0];

		// Parse del range start:end
		std::vector<std::string> range_parts;
		std::string current;
		for (char c : args[1]) {
			if (c == ':') {
				if (!current.empty()) {
					range_parts.push_back(current);
					current.clear();
				}
			}
			else {
				current += c;
			}
		}
		if (!current.empty()) {
			range_parts.push_back(current);
		}

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
		// Registra il gestore per Ctrl+C
		std::signal(SIGINT, signal_handler);
#ifdef _WIN32
		std::signal(SIGTERM, signal_handler);
#endif

		// Configurazione opzioni linea di comando
		po::options_description desc("Network Scanner - Opzioni");
		desc.add_options()
			("help,h", "Mostra questo messaggio di aiuto")
			("output,o", po::value<std::string>(), "Salva i risultati su file")
			("filter,f", po::value<std::string>(), "Filtra per nome host (case insensitive)")
			("verbose,v", "Modalità verbose - mostra host trovati in tempo reale")
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
			std::println("Network Scanner C++23 con Boost.Asio 1.88.0\n");
			std::println("Versione 2.1 - Thread Pool con Boost.Asio\n");
			std::println("Utilizzo: {} [opzioni] [ip_base start:end]", argv[0]);
			std::println("\nEsempi:");
			std::println("  {} # Auto-rileva e scansiona la rete locale", argv[0]);
			std::println("  {} -f router # Cerca dispositivi con 'router' nel nome", argv[0]);
			std::println("  {} -v # Mostra host trovati in tempo reale", argv[0]);
			std::println("  {} 192.168.1.0 0:254 -f PC", argv[0]);
			std::println("  {} -o risultati.txt", argv[0]);
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

		// Ottieni opzioni
		std::string filter;
		if (vm.count("filter")) {
			filter = vm["filter"].as<std::string>();
		}

		bool verbose = vm.count("verbose") > 0;

		// Esegui scansione
		NetworkScanner scanner(filter);

		std::println("=== NETWORK SCANNER v2.1 ===");
		std::println("Sistema: {} | Thread Pool: {} threads (Boost.Asio)",
#ifdef _WIN32
			"Windows"
#else
			"Linux"
#endif
			, std::min(8, static_cast<int>(std::thread::hardware_concurrency())));

		scanner.scan_network(range.base_ip, range.start, range.end, verbose);
		scanner.print_results();

		// Salva risultati se richiesto
		if (vm.count("output")) {
			scanner.save_results(vm["output"].as<std::string>());
		}

	}
	catch (const std::exception& e) {
		std::println(std::cerr, "\nErrore: {}", e.what());
		std::println(std::cerr, "\nNota: Questo programma richiede privilegi di amministratore/root per l'uso di socket ICMP raw.");
		return 1;
	}

	return 0;
}