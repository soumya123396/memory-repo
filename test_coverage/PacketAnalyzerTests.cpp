#include "CppUTest/TestHarness.h"
#include "CppUTest/CommandLineTestRunner.h"

extern "C" {
    #include "packet_analyzer.h"
    #include <string.h>
    #include <stdlib.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <time.h>
}

TEST_GROUP(PacketAnalyzerCreation)
{
    PacketAnalyzer *analyzer;

    void setup()
    {
        analyzer = NULL;
    }

    void teardown()
    {
        if(analyzer != NULL) {
            free(analyzer->connections);
            free(analyzer->packet_buffer);
            free(analyzer->config);
            free(analyzer->stats);
            free(analyzer);
        }
    }
};

TEST(PacketAnalyzerCreation, CreateAnalyzerAllocatesMemory)
{
    analyzer = create_analyzer(10);
    CHECK(analyzer != NULL);
    CHECK(analyzer->connections != NULL);
    CHECK(analyzer->packet_buffer != NULL);
    CHECK(analyzer->config != NULL);
    CHECK(analyzer->stats != NULL);
}

TEST(PacketAnalyzerCreation, CreateAnalyzerSetsMaxConnections)
{
    analyzer = create_analyzer(50);
    CHECK_EQUAL(50, analyzer->max_connections);
}

TEST(PacketAnalyzerCreation, CreateAnalyzerInitializesActiveConnections)
{
    analyzer = create_analyzer(10);
    CHECK_EQUAL(0, analyzer->active_connections);
}

TEST(PacketAnalyzerCreation, CreateAnalyzerInitializesTotalPackets)
{
    analyzer = create_analyzer(10);
    CHECK_EQUAL(0, analyzer->total_packets);
}

TEST(PacketAnalyzerCreation, CreateAnalyzerSetsDefaultConfig)
{
    analyzer = create_analyzer(10);
    CHECK_EQUAL(30, analyzer->config->timeout);
    CHECK_EQUAL(65535, analyzer->config->max_packet_size);
    CHECK_EQUAL(1, analyzer->config->enable_logging);
}

TEST(PacketAnalyzerCreation, CreateAnalyzerInitializesConnectionArray)
{
    analyzer = create_analyzer(5);
    for(int i = 0; i < 5; i++) {
        CHECK(analyzer->connections[i] == NULL);
    }
}

TEST(PacketAnalyzerCreation, CreateAnalyzerZerosStatistics)
{
    analyzer = create_analyzer(10);
    CHECK_EQUAL(0, analyzer->stats->total_packets);
    CHECK_EQUAL(0, analyzer->stats->total_bytes);
    CHECK_EQUAL(0, analyzer->stats->total_connections);
    CHECK_EQUAL(0, analyzer->stats->active_connections);
}

TEST_GROUP(ConnectionManagement)
{
    Connection *conn;
    struct sockaddr_in addr;

    void setup()
    {
        conn = NULL;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(12345);
        addr.sin_addr.s_addr = inet_addr("192.168.1.100");
    }

    void teardown()
    {
        if(conn != NULL) {
            free(conn->buffer);
            free(conn->packet_queue);
            free(conn->username);
            free(conn->session_id);
            free(conn);
        }
    }
};

TEST(ConnectionManagement, CreateConnectionAllocatesMemory)
{
    conn = create_connection(5, addr);
    CHECK(conn != NULL);
    CHECK(conn->buffer != NULL);
    CHECK(conn->packet_queue != NULL);
    CHECK(conn->username != NULL);
    CHECK(conn->session_id != NULL);
}

TEST(ConnectionManagement, CreateConnectionSetsSocketFd)
{
    conn = create_connection(42, addr);
    CHECK_EQUAL(42, conn->socket_fd);
}

TEST(ConnectionManagement, CreateConnectionInitializesPacketCounters)
{
    conn = create_connection(5, addr);
    CHECK_EQUAL(0, conn->packets_received);
    CHECK_EQUAL(0, conn->bytes_received);
}

TEST(ConnectionManagement, CreateConnectionSetsQueueSize)
{
    conn = create_connection(5, addr);
    CHECK_EQUAL(0, conn->queue_size);
}

TEST(ConnectionManagement, CreateConnectionSetsAuthenticationStatus)
{
    conn = create_connection(5, addr);
    CHECK_EQUAL(0, conn->is_authenticated);
}

TEST(ConnectionManagement, CreateConnectionGeneratesSessionId)
{
    conn = create_connection(5, addr);
    CHECK(strlen(conn->session_id) > 0);
    STRNCMP_EQUAL("SESSION_", conn->session_id, 8);
}

TEST_GROUP(PacketProcessing)
{
    Connection *conn;
    struct sockaddr_in addr;

    void setup()
    {
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(8080);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        conn = create_connection(1, addr);
    }

    void teardown()
    {
        if(conn != NULL) {
            for(int i = 0; i < conn->queue_size; i++) {
                if(conn->packet_queue[i]) {
                    free(conn->packet_queue[i]->data);
                    free(conn->packet_queue[i]);
                }
            }
            free(conn->buffer);
            free(conn->packet_queue);
            free(conn->username);
            free(conn->session_id);
            free(conn);
        }
    }
};

TEST(PacketProcessing, ProcessPacketAllocatesPacketInfo)
{
    char data[] = "Test packet data";
    process_packet(conn, data, strlen(data));
    CHECK_EQUAL(1, conn->queue_size);
    CHECK(conn->packet_queue[0] != NULL);
}

TEST(PacketProcessing, ProcessPacketCopiesData)
{
    char data[] = "Sample data";
    process_packet(conn, data, strlen(data));
    STRCMP_EQUAL(data, conn->packet_queue[0]->data);
}

TEST(PacketProcessing, ProcessPacketSetsLength)
{
    char data[] = "Test";
    process_packet(conn, data, strlen(data));
    CHECK_EQUAL(strlen(data), conn->packet_queue[0]->length);
}

TEST(PacketProcessing, ProcessPacketIncrementsPacketCount)
{
    char data[] = "Data";
    process_packet(conn, data, strlen(data));
    CHECK_EQUAL(1, conn->packets_received);
}

TEST(PacketProcessing, ProcessPacketUpdatesBytesReceived)
{
    char data[] = "Test data";
    process_packet(conn, data, strlen(data));
    CHECK_EQUAL(strlen(data), conn->bytes_received);
}

TEST(PacketProcessing, ProcessPacketSetsSourcePort)
{
    char data[] = "Test";
    process_packet(conn, data, strlen(data));
    CHECK_EQUAL(ntohs(addr.sin_port), conn->packet_queue[0]->source_port);
}

TEST(PacketProcessing, ProcessPacketSetsDestPort)
{
    char data[] = "Test";
    process_packet(conn, data, strlen(data));
    CHECK_EQUAL(8080, conn->packet_queue[0]->dest_port);
}

TEST(PacketProcessing, ProcessMultiplePackets)
{
    for(int i = 0; i < 5; i++) {
        char data[20];
        sprintf(data, "Packet %d", i);
        process_packet(conn, data, strlen(data));
    }
    CHECK_EQUAL(5, conn->queue_size);
    CHECK_EQUAL(5, conn->packets_received);
}

TEST(PacketProcessing, ProcessPacketRespectsQueueLimit)
{
    for(int i = 0; i < 105; i++) {
        char data[20];
        sprintf(data, "Packet %d", i);
        process_packet(conn, data, strlen(data));
    }
    CHECK_EQUAL(100, conn->queue_size);
}

TEST_GROUP(HeaderExtraction)
{
    char *result;

    void setup()
    {
        result = NULL;
    }

    void teardown()
    {
        if(result != NULL) {
            free(result);
        }
    }
};

TEST(HeaderExtraction, ExtractHeaderFindsExistingHeader)
{
    char packet[] = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n";
    result = extract_header(packet, "Host");
    CHECK(result != NULL);
    STRCMP_EQUAL("example.com", result);
}

TEST(HeaderExtraction, ExtractHeaderWithColon)
{
    char packet[] = "User-Agent: Mozilla/5.0\r\n";
    result = extract_header(packet, "User-Agent");
    STRCMP_EQUAL("Mozilla/5.0", result);
}

TEST(HeaderExtraction, ExtractHeaderNotFound)
{
    char packet[] = "GET /test HTTP/1.1\r\n";
    result = extract_header(packet, "Missing-Header");
    CHECK(result != NULL);
}

TEST(HeaderExtraction, ExtractHeaderMultipleSpaces)
{
    char packet[] = "Content-Type:   application/json\r\n";
    result = extract_header(packet, "Content-Type");
    STRCMP_EQUAL("application/json", result);
}

TEST_GROUP(Authentication)
{
    Connection *conn;
    struct sockaddr_in addr;

    void setup()
    {
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        conn = create_connection(1, addr);
    }

    void teardown()
    {
        if(conn != NULL) {
            free(conn->buffer);
            free(conn->packet_queue);
            free(conn->username);
            free(conn->session_id);
            free(conn);
        }
    }
};

TEST(Authentication, AuthenticateUserWithCorrectPassword)
{
    int result = authenticate_user(conn, (char*)"admin", (char*)"admin123");
    CHECK_EQUAL(1, result);
    CHECK_EQUAL(1, conn->is_authenticated);
}

TEST(Authentication, AuthenticateUserWithIncorrectPassword)
{
    int result = authenticate_user(conn, (char*)"admin", (char*)"wrongpass");
    CHECK_EQUAL(0, result);
    CHECK_EQUAL(0, conn->is_authenticated);
}

TEST(Authentication, AuthenticateUserSetsUsername)
{
    authenticate_user(conn, (char*)"testuser", (char*)"admin123");
    if(conn->is_authenticated) {
        STRCMP_EQUAL("testuser", conn->username);
    }
}

TEST_GROUP(ProtocolDetection)
{
    void setup()
    {
    }

    void teardown()
    {
    }
};

TEST(ProtocolDetection, ParseProtocolHTTPGet)
{
    char packet[] = "GET /index.html HTTP/1.1";
    int proto = parse_protocol(packet, strlen(packet));
    CHECK_EQUAL(PROTO_HTTP, proto);
}

TEST(ProtocolDetection, ParseProtocolHTTPPost)
{
    char packet[] = "POST /api/data HTTP/1.1";
    int proto = parse_protocol(packet, strlen(packet));
    CHECK_EQUAL(PROTO_HTTP, proto);
}

TEST(ProtocolDetection, ParseProtocolSSH)
{
    char packet[] = "SSH-2.0-OpenSSH_8.0";
    int proto = parse_protocol(packet, strlen(packet));
    CHECK_EQUAL(PROTO_SSH, proto);
}

TEST(ProtocolDetection, ParseProtocolUnknown)
{
    char packet[] = "UNKNOWN DATA";
    int proto = parse_protocol(packet, strlen(packet));
    CHECK_EQUAL(PROTO_UNKNOWN, proto);
}

TEST(ProtocolDetection, ParseProtocolTooShort)
{
    char packet[] = "AB";
    int proto = parse_protocol(packet, strlen(packet));
    CHECK_EQUAL(PROTO_UNKNOWN, proto);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
