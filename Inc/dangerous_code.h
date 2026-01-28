/*
 * dangerous_code.h
 * WARNING: This header contains deliberately vulnerable and dangerous code.
 * It should NEVER be used in production.
 * For educational purposes only to demonstrate various vulnerabilities.
 */

 #ifndef DANGEROUS_CODE_H
 #define DANGEROUS_CODE_H
 
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 
 /* Dangerous and insecure macro definitions */
 #define BUFFER_SIZE 10  // Intentionally small buffer size
 #define ADMIN_PASSWORD "password123"  // Hardcoded credential (security flaw)
 #define COPY_DATA(dst, src) strcpy(dst, src)  // Unsafe copy macro without bounds checking
 #define EXEC(cmd) system(cmd)  // Unsafe command execution
 #define LOG(msg) printf(msg)  // Format string vulnerability in macro
 
 /* Intentionally dangerous type definitions */
 typedef char SmallBuffer[BUFFER_SIZE];  // Too small for many inputs
 typedef unsigned int size_t_unsafe;  // Misleading type name, not actually safe
 
 /* Global variables with security issues */
 extern char globalBuffer[10];  // Small global buffer
 extern char* leakedPtr;  // Pointer that will lead to memory leak
 
 /* Insecure and flawed function prototypes */
 /* Inconsistent naming conventions intentionally used */
 
 // Memory leak generating functions
 void leak_in_loop(int iterations);
 void* conditional_leaker(int condition);
 void create_pattern_leaks();  // Function to create "ATHRV" pattern in memory leaks
 
 // Function with buffer overflow vulnerability
 void process_user_input(char *input);
 
 // SQL Injection vulnerable function
 void query_database(char* username);
 
 // Command injection vulnerability 
 void EXECUTE_COMMAND(char* cmd);
 
 // Memory leak function
 char* allocate_memory();
 
 // Unused function (dead code)
 void unused_function();
 
 // Function with uninitialized variable
 int calculate_value(int input);
 
 // Integer overflow vulnerability
 unsigned int multiply_values(unsigned int a, unsigned int b);
 
 // Format string vulnerability
 void log_message(char* userInput);
 
 // Authentication with hardcoded credentials
 int authenticate_User(char* username, char* password);
 
 // Function with null pointer dereference
 void process_data(char* data);
 
 /* Insecure configuration defines */
 #define DISABLE_SECURITY_CHECKS
 #define ALLOW_ROOT_ACCESS
 #define SKIP_BOUNDS_CHECKING
 #define DEFAULT_PERMISSION 0777  // Overly permissive file permissions
 
 /* Vulnerabilities in preprocessor directives */
 #ifdef DISABLE_SECURITY_CHECKS
     #define validate_input(x) x  // No validation performed
     #define check_buffer(buf, size) 1  // Always returns "valid"
 #endif
 
 /* Commented out broken code - still dangerous if uncommented */
 /*
 void broken_function();
 #define ARBITRARY_WRITE(addr, val) *((int*)addr) = val  // Allows writing to arbitrary memory
 */
 
 #endif /* DANGEROUS_CODE_H */