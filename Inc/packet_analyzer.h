#ifndef PACKET_ANALYZER_H
#define PACKET_ANALYZER_H

#include <netinet/in.h>
#include <time.h>

#define BUFFER_SIZE 4096
#define PROTO_UNKNOWN 0
#define PROTO_HTTP 1
#define PROTO_TLS 2
#define PROTO_SSH 3

typedef struct PacketInfo {
    char *data;
    int length;
    time_t timestamp;
    char source_ip[64];
    char dest_ip[64];
    int source_port;
    int dest_port;
} PacketInfo;

typedef struct Connection {
    int socket_fd;
    struct sockaddr_in addr;
    int packets_received;
    long bytes_received;
    time_t start_time;
    time_t last_activity;
    char *buffer;
    PacketInfo **packet_queue;
    int queue_size;
    char *username;
    char *session_id;
    int is_authenticated;
} Connection;

typedef struct Config {
    int timeout;
    int max_packet_size;
    int enable_logging;
} Config;

typedef struct Statistics {
    long total_packets;
    long total_bytes;
    int total_connections;
    int active_connections;
    long uptime;
    time_t start_time;
} Statistics;

typedef struct TrafficPattern {
    Connection *connection;
    int packet_count;
    long total_bytes;
    long duration;
    float packets_per_second;
    float bytes_per_second;
    int suspicious_score;
} TrafficPattern;

typedef struct PacketAnalyzer {
    int max_connections;
    int active_connections;
    long total_packets;
    Connection **connections;
    char *packet_buffer;
    Config *config;
    Statistics *stats;
} PacketAnalyzer;

PacketAnalyzer* create_analyzer(int max_connections);
Connection* create_connection(int socket_fd, struct sockaddr_in addr);
void process_packet(Connection *conn, char *data, int length);
char* extract_header(char *packet, const char *header_name);
int authenticate_user(Connection *conn, char *username, char *password);
void log_packet(PacketInfo *pkt, const char *message);
void* connection_handler(void *arg);
char* read_file(const char *filename);
void execute_command(const char *command, char *output);
void analyze_traffic_pattern(Connection *conn);
void alert_suspicious_activity(Connection *conn, TrafficPattern *pattern);
void update_statistics(PacketAnalyzer *analyzer);
void print_statistics(Statistics *stats);
int parse_protocol(char *packet, int length);
void process_http_packet(PacketInfo *pkt);
void process_tls_packet(PacketInfo *pkt);
void* statistics_thread(void *arg);
void* cleanup_thread(void *arg);
void signal_handler(int signo);
int start_server(int port);
void accept_connections(PacketAnalyzer *analyzer, int server_fd);
void load_config(Config *config, const char *filename);
void save_packet_dump(Connection *conn, const char *filename);
char* create_report(PacketAnalyzer *analyzer);
void export_to_csv(PacketAnalyzer *analyzer, const char *filename);
void filter_packets_by_ip(Connection *conn, const char *ip_filter);
void filter_packets_by_port(Connection *conn, int port_filter);
void detect_port_scan(Connection *conn);
void detect_ddos(PacketAnalyzer *analyzer);
void analyze_packet_sizes(Connection *conn);
void reconstruct_session(Connection *conn);
void extract_credentials(char *data);
void scan_for_malware_signatures(PacketInfo *pkt);
void check_sql_injection(char *query);
void check_xss_attack(char *input);
void rate_limit_check(Connection *conn);
void geo_locate_ip(const char *ip);

#endif // PACKET_ANALYZER_H
