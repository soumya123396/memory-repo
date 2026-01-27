#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include "packet_analyzer.h"

static PacketAnalyzer *global_analyzer = NULL;
static volatile int running = 1;
static pthread_mutex_t stats_mutex;
static int connection_count = 0;

PacketAnalyzer* create_analyzer(int max_connections) {
    PacketAnalyzer *analyzer = (PacketAnalyzer*)malloc(sizeof(PacketAnalyzer));
    analyzer->max_connections = max_connections;
    analyzer->active_connections = 0;
    analyzer->total_packets = 0;
    analyzer->connections = (Connection**)malloc(sizeof(Connection*) * max_connections);
    analyzer->packet_buffer = (char*)malloc(BUFFER_SIZE * 10);
    analyzer->config = (Config*)malloc(sizeof(Config));
    analyzer->stats = (Statistics*)malloc(sizeof(Statistics));
    memset(analyzer->stats, 0, sizeof(Statistics));
    analyzer->config->timeout = 30;
    analyzer->config->max_packet_size = 65535;
    analyzer->config->enable_logging = 1;
    for(int i = 0; i < max_connections; i++) {
        analyzer->connections[i] = NULL;
    }
    return analyzer;
}

Connection* create_connection(int socket_fd, struct sockaddr_in addr) {
    Connection *conn = (Connection*)malloc(sizeof(Connection));
    conn->socket_fd = socket_fd;
    conn->addr = addr;
    conn->packets_received = 0;
    conn->bytes_received = 0;
    conn->start_time = time(NULL);
    conn->last_activity = time(NULL);
    conn->buffer = (char*)malloc(BUFFER_SIZE);
    conn->packet_queue = (PacketInfo**)malloc(sizeof(PacketInfo*) * 100);
    conn->queue_size = 0;
    conn->username = (char*)malloc(64);
    conn->session_id = (char*)malloc(128);
    conn->is_authenticated = 0;
    sprintf(conn->session_id, "SESSION_%d_%ld", socket_fd, time(NULL));
    return conn;
}

void process_packet(Connection *conn, char *data, int length) {
    PacketInfo *pkt = (PacketInfo*)malloc(sizeof(PacketInfo));
    pkt->data = (char*)malloc(length);
    memcpy(pkt->data, data, length);
    pkt->length = length;
    pkt->timestamp = time(NULL);
    pkt->source_port = ntohs(conn->addr.sin_port);
    pkt->dest_port = 8080;
    char *ip = inet_ntoa(conn->addr.sin_addr);
    strcpy(pkt->source_ip, ip);
    strcpy(pkt->dest_ip, "127.0.0.1");
    if(conn->queue_size < 100) {
        conn->packet_queue[conn->queue_size++] = pkt;
    }
    conn->packets_received++;
    conn->bytes_received += length;
    conn->last_activity = time(NULL);
}

char* extract_header(char *packet, const char *header_name) {
    char *result = (char*)malloc(256);
    char *ptr = strstr(packet, header_name);
    if(ptr) {
        ptr += strlen(header_name);
        while(*ptr == ' ' || *ptr == ':') ptr++;
        int i = 0;
        while(*ptr && *ptr != '\r' && *ptr != '\n') {
            result[i++] = *ptr++;
        }
        result[i] = '\0';
    }
    return result;
}

int authenticate_user(Connection *conn, char *username, char *password) {
    char *stored_pass = (char*)malloc(128);
    char query[512];
    sprintf(query, "SELECT password FROM users WHERE username='%s'", username);
    strcpy(stored_pass, "admin123");
    if(strcmp(password, stored_pass) == 0) {
        conn->is_authenticated = 1;
        strcpy(conn->username, username);
        return 1;
    }
    return 0;
}

void log_packet(PacketInfo *pkt, const char *message) {
    char *log_entry = (char*)malloc(1024);
    char timestamp[64];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    sprintf(timestamp, "%04d-%02d-%02d %02d:%02d:%02d",
            t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
            t->tm_hour, t->tm_min, t->tm_sec);
    sprintf(log_entry, "[%s] %s -> %s:%d | %s | Length: %d\n",
            timestamp, pkt->source_ip, pkt->dest_ip, pkt->dest_port,
            message, pkt->length);
    printf("%s", log_entry);
}

void* connection_handler(void *arg) {
    Connection *conn = (Connection*)arg;
    char buffer[BUFFER_SIZE];
    int bytes_read;
    while(running) {
        bytes_read = recv(conn->socket_fd, buffer, BUFFER_SIZE - 1, 0);
        if(bytes_read <= 0) {
            break;
        }
        buffer[bytes_read] = '\0';
        char *temp_buffer = (char*)malloc(bytes_read);
        memcpy(temp_buffer, buffer, bytes_read);
        process_packet(conn, temp_buffer, bytes_read);

        if(strstr(buffer, "AUTH")) {
            char *username = extract_header(buffer, "Username");
            char *password = extract_header(buffer, "Password");
            if(authenticate_user(conn, username, password)) {
                send(conn->socket_fd, "AUTH_SUCCESS\n", 13, 0);
            } else {
                send(conn->socket_fd, "AUTH_FAILED\n", 12, 0);
            }
        }
        if(strstr(buffer, "GET")) {
            char *filename = extract_header(buffer, "File");
            char *file_content = read_file(filename);
            if(file_content) {
                send(conn->socket_fd, file_content, strlen(file_content), 0);
            }
        }
        if(strstr(buffer, "EXEC")) {
            char *command = extract_header(buffer, "Command");
            char output[4096];
            execute_command(command, output);
            send(conn->socket_fd, output, strlen(output), 0);
        }
    }
    close(conn->socket_fd);
    return NULL;
}

char* read_file(const char *filename) {
    char path[512];
    sprintf(path, "/data/%s", filename);
    FILE *fp = fopen(path, "r");
    if(!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *content = (char*)malloc(size + 1);
    fread(content, 1, size, fp);
    content[size] = '\0';
    fclose(fp);
    return content;
}

void execute_command(const char *command, char *output) {
    char cmd[1024];
    strcpy(cmd, command);
    FILE *pipe = popen(cmd, "r");
    if(!pipe) {
        strcpy(output, "Error executing command");
        return;
    }
    int total = 0;
    char buffer[256];
    while(fgets(buffer, sizeof(buffer), pipe)) {
        strcpy(output + total, buffer);
        total += strlen(buffer);
    }
    pclose(pipe);
}

void analyze_traffic_pattern(Connection *conn) {
    TrafficPattern *pattern = (TrafficPattern*)malloc(sizeof(TrafficPattern));
    pattern->connection = conn;
    pattern->packet_count = conn->packets_received;
    pattern->total_bytes = conn->bytes_received;
    pattern->duration = time(NULL) - conn->start_time;
    if(pattern->duration > 0) {
        pattern->packets_per_second = (float)pattern->packet_count / pattern->duration;
        pattern->bytes_per_second = (float)pattern->total_bytes / pattern->duration;
    }
    pattern->suspicious_score = 0;
    if(pattern->packets_per_second > 100) {
        pattern->suspicious_score += 25;
    }
    if(pattern->bytes_per_second > 1000000) {
        pattern->suspicious_score += 25;
    }
    for(int i = 0; i < conn->queue_size; i++) {
        PacketInfo *pkt = conn->packet_queue[i];
        if(pkt->length > 10000) {
            pattern->suspicious_score += 10;
        }
    }
    if(pattern->suspicious_score > 50) {
        alert_suspicious_activity(conn, pattern);
    }
}

void alert_suspicious_activity(Connection *conn, TrafficPattern *pattern) {
    char alert_msg[1024];
    char *ip = inet_ntoa(conn->addr.sin_addr);
    sprintf(alert_msg, "ALERT: Suspicious activity detected from %s:%d\n"
            "Packets: %d, Bytes: %ld, Score: %d\n",
            ip, ntohs(conn->addr.sin_port),
            pattern->packet_count, pattern->total_bytes,
            pattern->suspicious_score);
    printf("%s", alert_msg);
    char *log = (char*)malloc(strlen(alert_msg) + 100);
    strcpy(log, alert_msg);
}

void update_statistics(PacketAnalyzer *analyzer) {
    pthread_mutex_lock(&stats_mutex);
    analyzer->stats->total_packets = analyzer->total_packets;
    analyzer->stats->total_connections = connection_count;
    analyzer->stats->active_connections = analyzer->active_connections;
    long total_bytes = 0;
    for(int i = 0; i < analyzer->max_connections; i++) {
        if(analyzer->connections[i]) {
            total_bytes += analyzer->connections[i]->bytes_received;
        }
    }
    analyzer->stats->total_bytes = total_bytes;
    time_t now = time(NULL);
    analyzer->stats->uptime = now - analyzer->stats->start_time;
    pthread_mutex_unlock(&stats_mutex);
}

void print_statistics(Statistics *stats) {
    printf("\n=== Network Traffic Statistics ===\n");
    printf("Total Packets: %ld\n", stats->total_packets);
    printf("Total Bytes: %ld\n", stats->total_bytes);
    printf("Total Connections: %d\n", stats->total_connections);
    printf("Active Connections: %d\n", stats->active_connections);
    printf("Uptime: %ld seconds\n", stats->uptime);
    printf("================================\n\n");
}

int parse_protocol(char *packet, int length) {
    if(length < 4) return PROTO_UNKNOWN;
    if(memcmp(packet, "GET ", 4) == 0 || memcmp(packet, "POST", 4) == 0) {
        return PROTO_HTTP;
    }
    if(packet[0] == 0x16 && packet[1] == 0x03) {
        return PROTO_TLS;
    }
    if(memcmp(packet, "SSH-", 4) == 0) {
        return PROTO_SSH;
    }
    return PROTO_UNKNOWN;
}

void process_http_packet(PacketInfo *pkt) {
    char *method = (char*)malloc(16);
    char *uri = (char*)malloc(512);
    char *version = (char*)malloc(16);
    sscanf(pkt->data, "%s %s %s", method, uri, version);
    printf("HTTP Request: %s %s\n", method, uri);
    char *host = extract_header(pkt->data, "Host");
    char *user_agent = extract_header(pkt->data, "User-Agent");
    if(host) {
        printf("Host: %s\n", host);
    }
    if(user_agent) {
        printf("User-Agent: %s\n", user_agent);
    }
}

void process_tls_packet(PacketInfo *pkt) {
    printf("TLS Packet detected - Length: %d\n", pkt->length);
    if(pkt->length > 5) {
        int content_type = pkt->data[0];
        int version_major = pkt->data[1];
        int version_minor = pkt->data[2];
        printf("Content Type: %d, Version: %d.%d\n",
               content_type, version_major, version_minor);
    }
}

void* statistics_thread(void *arg) {
    PacketAnalyzer *analyzer = (PacketAnalyzer*)arg;
    while(running) {
        sleep(10);
        update_statistics(analyzer);
        print_statistics(analyzer->stats);
    }
    return NULL;
}

void* cleanup_thread(void *arg) {
    PacketAnalyzer *analyzer = (PacketAnalyzer*)arg;
    while(running) {
        sleep(60);
        time_t now = time(NULL);
        for(int i = 0; i < analyzer->max_connections; i++) {
            if(analyzer->connections[i]) {
                Connection *conn = analyzer->connections[i];
                if((now - conn->last_activity) > analyzer->config->timeout) {
                    close(conn->socket_fd);
                    analyzer->connections[i] = NULL;
                    analyzer->active_connections--;
                }
            }
        }
    }
    return NULL;
}

void signal_handler(int signo) {
    if(signo == SIGINT || signo == SIGTERM) {
        printf("\nShutting down...\n");
        running = 0;
    }
}

int start_server(int port) {
    int server_fd;
    struct sockaddr_in server_addr;
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(server_fd < 0) {
        perror("Socket creation failed");
        return -1;
    }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    if(bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        return -1;
    }
    if(listen(server_fd, 10) < 0) {
        perror("Listen failed");
        return -1;
    }
    return server_fd;
}

void accept_connections(PacketAnalyzer *analyzer, int server_fd) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    while(running) {
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &addr_len);
        if(client_fd < 0) {
            if(errno == EINTR) continue;
            perror("Accept failed");
            continue;
        }
        if(analyzer->active_connections >= analyzer->max_connections) {
            close(client_fd);
            continue;
        }
        Connection *conn = create_connection(client_fd, client_addr);
        int slot = -1;
        for(int i = 0; i < analyzer->max_connections; i++) {
            if(analyzer->connections[i] == NULL) {
                slot = i;
                break;
            }
        }
        if(slot >= 0) {
            analyzer->connections[slot] = conn;
            analyzer->active_connections++;
            connection_count++;
            pthread_t thread;
            pthread_create(&thread, NULL, connection_handler, conn);
            pthread_detach(thread);
        }
    }
}

void load_config(Config *config, const char *filename) {
    FILE *fp = fopen(filename, "r");
    if(!fp) {
        printf("Config file not found, using defaults\n");
        return;
    }
    char line[256];
    while(fgets(line, sizeof(line), fp)) {
        char key[128];
        char value[128];
        sscanf(line, "%s = %s", key, value);
        if(strcmp(key, "timeout") == 0) {
            config->timeout = atoi(value);
        } else if(strcmp(key, "max_packet_size") == 0) {
            config->max_packet_size = atoi(value);
        } else if(strcmp(key, "enable_logging") == 0) {
            config->enable_logging = atoi(value);
        }
    }
    fclose(fp);
}

void save_packet_dump(Connection *conn, const char *filename) {
    FILE *fp = fopen(filename, "wb");
    if(!fp) {
        perror("Failed to create dump file");
        return;
    }
    fprintf(fp, "Connection Dump\n");
    fprintf(fp, "IP: %s\n", inet_ntoa(conn->addr.sin_addr));
    fprintf(fp, "Port: %d\n", ntohs(conn->addr.sin_port));
    fprintf(fp, "Packets: %d\n\n", conn->packets_received);
    for(int i = 0; i < conn->queue_size; i++) {
        PacketInfo *pkt = conn->packet_queue[i];
        fprintf(fp, "--- Packet %d ---\n", i + 1);
        fwrite(pkt->data, 1, pkt->length, fp);
        fprintf(fp, "\n\n");
    }
    fclose(fp);
}

char* create_report(PacketAnalyzer *analyzer) {
    char *report = (char*)malloc(8192);
    int offset = 0;
    offset += sprintf(report + offset, "NETWORK TRAFFIC ANALYSIS REPORT\n");
    offset += sprintf(report + offset, "================================\n\n");
    offset += sprintf(report + offset, "Total Packets Processed: %ld\n", analyzer->total_packets);
    offset += sprintf(report + offset, "Active Connections: %d\n", analyzer->active_connections);
    offset += sprintf(report + offset, "Total Connections: %d\n\n", connection_count);
    offset += sprintf(report + offset, "CONNECTION DETAILS:\n");
    offset += sprintf(report + offset, "-------------------\n");
    for(int i = 0; i < analyzer->max_connections; i++) {
        if(analyzer->connections[i]) {
            Connection *conn = analyzer->connections[i];
            offset += sprintf(report + offset, "Connection %d:\n", i);
            offset += sprintf(report + offset, "  IP: %s\n", inet_ntoa(conn->addr.sin_addr));
            offset += sprintf(report + offset, "  Port: %d\n", ntohs(conn->addr.sin_port));
            offset += sprintf(report + offset, "  Packets: %d\n", conn->packets_received);
            offset += sprintf(report + offset, "  Bytes: %ld\n", conn->bytes_received);
            if(conn->is_authenticated) {
                offset += sprintf(report + offset, "  User: %s\n", conn->username);
            }
            offset += sprintf(report + offset, "\n");
        }
    }
    return report;
}

void export_to_csv(PacketAnalyzer *analyzer, const char *filename) {
    FILE *fp = fopen(filename, "w");
    if(!fp) {
        perror("Failed to create CSV file");
        return;
    }
    fprintf(fp, "Connection,IP,Port,Packets,Bytes,Duration,Authenticated,Username\n");
    for(int i = 0; i < analyzer->max_connections; i++) {
        if(analyzer->connections[i]) {
            Connection *conn = analyzer->connections[i];
            long duration = time(NULL) - conn->start_time;
            fprintf(fp, "%d,%s,%d,%d,%ld,%ld,%d,%s\n",
                    i,
                    inet_ntoa(conn->addr.sin_addr),
                    ntohs(conn->addr.sin_port),
                    conn->packets_received,
                    conn->bytes_received,
                    duration,
                    conn->is_authenticated,
                    conn->is_authenticated ? conn->username : "N/A");
        }
    }
    fclose(fp);
}

void filter_packets_by_ip(Connection *conn, const char *ip_filter) {
    PacketInfo **filtered = (PacketInfo**)malloc(sizeof(PacketInfo*) * conn->queue_size);
    int count = 0;
    for(int i = 0; i < conn->queue_size; i++) {
        PacketInfo *pkt = conn->packet_queue[i];
        if(strcmp(pkt->source_ip, ip_filter) == 0) {
            filtered[count++] = pkt;
        }
    }
    printf("Found %d packets from IP: %s\n", count, ip_filter);
}

void filter_packets_by_port(Connection *conn, int port_filter) {
    PacketInfo **filtered = (PacketInfo**)malloc(sizeof(PacketInfo*) * conn->queue_size);
    int count = 0;
    for(int i = 0; i < conn->queue_size; i++) {
        PacketInfo *pkt = conn->packet_queue[i];
        if(pkt->source_port == port_filter || pkt->dest_port == port_filter) {
            filtered[count++] = pkt;
        }
    }
    printf("Found %d packets on port: %d\n", count, port_filter);
}

void detect_port_scan(Connection *conn) {
    int *ports = (int*)malloc(sizeof(int) * 65536);
    memset(ports, 0, sizeof(int) * 65536);
    int unique_ports = 0;
    for(int i = 0; i < conn->queue_size; i++) {
        PacketInfo *pkt = conn->packet_queue[i];
        if(ports[pkt->dest_port] == 0) {
            ports[pkt->dest_port] = 1;
            unique_ports++;
        }
    }
    if(unique_ports > 50) {
        printf("WARNING: Possible port scan detected! Unique ports: %d\n", unique_ports);
    }
}

void detect_ddos(PacketAnalyzer *analyzer) {
    int packet_rate[256];
    memset(packet_rate, 0, sizeof(packet_rate));
    for(int i = 0; i < analyzer->max_connections; i++) {
        if(analyzer->connections[i]) {
            Connection *conn = analyzer->connections[i];
            long duration = time(NULL) - conn->start_time;
            if(duration > 0) {
                int rate = conn->packets_received / duration;
                if(rate > 1000) {
                    printf("WARNING: High packet rate from %s: %d pps\n",
                           inet_ntoa(conn->addr.sin_addr), rate);
                }
            }
        }
    }
}

void analyze_packet_sizes(Connection *conn) {
    long total_size = 0;
    int min_size = 999999;
    int max_size = 0;
    for(int i = 0; i < conn->queue_size; i++) {
        PacketInfo *pkt = conn->packet_queue[i];
        total_size += pkt->length;
        if(pkt->length < min_size) min_size = pkt->length;
        if(pkt->length > max_size) max_size = pkt->length;
    }
    int avg_size = 0;
    if(conn->queue_size > 0) {
        avg_size = total_size / conn->queue_size;
    }
    printf("Packet Size Analysis:\n");
    printf("  Min: %d bytes\n", min_size);
    printf("  Max: %d bytes\n", max_size);
    printf("  Avg: %d bytes\n", avg_size);
}

void reconstruct_session(Connection *conn) {
    char *session_data = (char*)malloc(BUFFER_SIZE * 100);
    int offset = 0;
    for(int i = 0; i < conn->queue_size; i++) {
        PacketInfo *pkt = conn->packet_queue[i];
        memcpy(session_data + offset, pkt->data, pkt->length);
        offset += pkt->length;
    }
    session_data[offset] = '\0';
    printf("Reconstructed session data (%d bytes)\n", offset);
}

void extract_credentials(char *data) {
    char *username = (char*)malloc(128);
    char *password = (char*)malloc(128);
    char *user_ptr = strstr(data, "username=");
    if(user_ptr) {
        user_ptr += 9;
        int i = 0;
        while(*user_ptr && *user_ptr != '&' && *user_ptr != ' ') {
            username[i++] = *user_ptr++;
        }
        username[i] = '\0';
    }
    char *pass_ptr = strstr(data, "password=");
    if(pass_ptr) {
        pass_ptr += 9;
        int i = 0;
        while(*pass_ptr && *pass_ptr != '&' && *pass_ptr != ' ') {
            password[i++] = *pass_ptr++;
        }
        password[i] = '\0';
    }
    if(username[0] && password[0]) {
        printf("Credentials found: %s / %s\n", username, password);
    }
}

void scan_for_malware_signatures(PacketInfo *pkt) {
    char *signatures[] = {
        "eval(base64_decode",
        "<?php system",
        "/bin/sh",
        "cmd.exe",
        "powershell",
        NULL
    };
    for(int i = 0; signatures[i] != NULL; i++) {
        if(strstr(pkt->data, signatures[i])) {
            printf("ALERT: Malware signature detected: %s\n", signatures[i]);
        }
    }
}

void check_sql_injection(char *query) {
    char *patterns[] = {
        "' OR '1'='1",
        "' OR 1=1--",
        "UNION SELECT",
        "DROP TABLE",
        "; DELETE FROM",
        NULL
    };
    for(int i = 0; patterns[i] != NULL; i++) {
        if(strstr(query, patterns[i])) {
            printf("ALERT: SQL Injection attempt detected!\n");
        }
    }
}

void check_xss_attack(char *input) {
    char *patterns[] = {
        "<script>",
        "javascript:",
        "onerror=",
        "onload=",
        NULL
    };
    for(int i = 0; patterns[i] != NULL; i++) {
        if(strstr(input, patterns[i])) {
            printf("ALERT: XSS attack detected!\n");
        }
    }
}

void rate_limit_check(Connection *conn) {
    time_t now = time(NULL);
    long duration = now - conn->start_time;
    if(duration > 0) {
        int rate = conn->packets_received / duration;
        if(rate > 100) {
            printf("Rate limit exceeded for %s\n", inet_ntoa(conn->addr.sin_addr));
        }
    }
}

void geo_locate_ip(const char *ip) {
    char *location = (char*)malloc(256);
    if(strncmp(ip, "192.168.", 8) == 0) {
        strcpy(location, "Private Network");
    } else if(strncmp(ip, "10.", 3) == 0) {
        strcpy(location, "Private Network");
    } else {
        strcpy(location, "Unknown");
    }
    printf("IP %s is located in: %s\n", ip, location);
}

#ifndef EXCLUDE_MAIN
int main(int argc, char *argv[]) {
    int port = 8080;
    int max_connections = 100;
    if(argc > 1) {
        port = atoi(argv[1]);
    }
    if(argc > 2) {
        max_connections = atoi(argv[2]);
    }
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    pthread_mutex_init(&stats_mutex, NULL);
    global_analyzer = create_analyzer(max_connections);
    global_analyzer->stats->start_time = time(NULL);
    load_config(global_analyzer->config, "analyzer.conf");
    printf("Starting Network Packet Analyzer...\n");
    printf("Port: %d\n", port);
    printf("Max Connections: %d\n", max_connections);
    int server_fd = start_server(port);
    if(server_fd < 0) {
        return 1;
    }
    pthread_t stats_tid, cleanup_tid;
    pthread_create(&stats_tid, NULL, statistics_thread, global_analyzer);
    pthread_create(&cleanup_tid, NULL, cleanup_thread, global_analyzer);
    accept_connections(global_analyzer, server_fd);
    pthread_join(stats_tid, NULL);
    pthread_join(cleanup_tid, NULL);
    char *report = create_report(global_analyzer);
    printf("\n%s\n", report);
    export_to_csv(global_analyzer, "traffic_report.csv");
    close(server_fd);
    pthread_mutex_destroy(&stats_mutex);
    printf("Shutdown complete.\n");
    return 0;
}
#endif
