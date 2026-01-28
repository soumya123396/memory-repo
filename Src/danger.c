/*
 * WARNING: This code is intentionally dangerous and vulnerable.
 * It contains numerous security flaws and should NEVER be used in production.
 * For educational purposes only to demonstrate various vulnerabilities.
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 
 // Global buffer that will be used unsafely
 char globalBuffer[10];
 char* leakedPtr = NULL;
 
 // Function prototypes with inconsistent styles
 void process_user_input(char *input);
 int authenticate_User(char* username, char* password);
 void EXECUTE_COMMAND(char* cmd);
 char * allocate_memory();
 
 // Unused function (dead code)
 void unused_function() {
     printf("This function is never called\n");
     return;
 }
 
 // Function to create controlled memory leaks for visualizing "ATHRV" pattern
 void create_pattern_leaks() {
     // Create a specific pattern of leaks to display "ATHRV" in memory analysis
     
     // "A" pattern - starts high, dips in middle, rises again
     for (int i = 0; i < 10; i++) {
         size_t size = 0;
         if (i < 3) 
             size = 10 * 1024 * 1024 - (i * 2 * 1024 * 1024); // Start high (10MB) and decrease
         else if (i < 5)
             size = 4 * 1024 * 1024 + ((i-3) * 2 * 1024 * 1024); // Rise in middle
         else if (i < 8)
             size = 10 * 1024 * 1024 - ((i-5) * 3 * 1024 * 1024); // Decrease again
         else
             size = 1 * 1024 * 1024; // Low final point
             
         void* leak = malloc(size); // Create the leak
         memset(leak, 'A', size > 100 ? 100 : size); // Touch some memory
     }
     
     // "T" pattern - high at start, then flat low
     for (int i = 0; i < 10; i++) {
         size_t size = 0;
         if (i < 2)
             size = 12 * 1024 * 1024; // High bar of T
         else
             size = 1 * 1024 * 1024; // Low stem of T
             
         void* leak = malloc(size);
         memset(leak, 'T', size > 100 ? 100 : size);
     }
     
     // "H" pattern - high sides with dip in middle
     for (int i = 0; i < 10; i++) {
         size_t size = 0;
         if (i < 3 || i > 6)
             size = 10 * 1024 * 1024; // High sides of H
         else
             size = 1 * 1024 * 1024; // Low middle of H
             
         void* leak = malloc(size);
         memset(leak, 'H', size > 100 ? 100 : size);
     }
     
     // "R" pattern - starts high, gradual slope down, then rises
     for (int i = 0; i < 10; i++) {
         size_t size = 0;
         if (i < 2)
             size = 12 * 1024 * 1024; // Top of R
         else if (i < 5)
             size = 12 * 1024 * 1024 - ((i-1) * 3 * 1024 * 1024); // Diagonal of R
         else if (i < 8)
             size = 3 * 1024 * 1024 + ((i-5) * 1024 * 1024); // Rising leg of R
         else
             size = 6 * 1024 * 1024; // End of R
             
         void* leak = malloc(size);
         memset(leak, 'R', size > 100 ? 100 : size);
     }
     
     // "V" pattern - starts high, drops to low point, rises again
     for (int i = 0; i < 10; i++) {
         size_t size = 0;
         if (i < 5)
             size = 10 * 1024 * 1024 - (i * 2 * 1024 * 1024); // Dropping side of V
         else
             size = (i-5) * 2 * 1024 * 1024 + 1 * 1024 * 1024; // Rising side of V
             
         void* leak = malloc(size);
         memset(leak, 'V', size > 100 ? 100 : size);
     }
 }
 
 // Function with buffer overflow vulnerability
 void process_user_input(char *input) {
     char buffer[10]; // Small buffer
     // Buffer overflow - no bounds checking
     strcpy(buffer, input); // CERT C ERR33-C violation
     printf("Processed: %s\n", buffer);
     
     // Use after free vulnerability
     char* temp = (char*)malloc(50);
     free(temp);
     strcpy(temp, "This is dangerous"); // Using memory after freeing it
     printf("%s\n", temp);
 }
 
 // SQL Injection vulnerability
 void query_database(char* username) {
     char query[100];
     // SQL Injection vulnerability - direct input concatenation
     sprintf(query, "SELECT * FROM users WHERE username='%s';", username);
     printf("Executing query: %s\n", query);
     // In real code, this would execute the query
 }
 
 // Command injection vulnerability
 void EXECUTE_COMMAND(char* cmd) {
     char command[256];
     // Command injection vulnerability
     sprintf(command, "echo %s", cmd);
     system(command); // OWASP A1 - Injection
 }
 
 // Uninitialized variable usage
 int calculate_value(int input) {
     int result; // Uninitialized
     if (input > 100) {
         result = input * 2;
     }
     // Missing else branch leaves result potentially uninitialized
     return result; // Could return garbage value
 }
 
 // Integer overflow vulnerability
 unsigned int multiply_values(unsigned int a, unsigned int b) {
     // No overflow checking
     return a * b; // Can overflow
 }
 
 // Format string vulnerability
 void log_message(char* userInput) {
     // Format string vulnerability
     printf(userInput); // Should be printf("%s", userInput);
 }
 
 // Authentication with hardcoded credentials
 int authenticate_User(char* username, char* password) {
     // Hardcoded credentials (CERT and SANS violation)
     if (strcmp(username, "admin") == 0 && strcmp(password, "password123") == 0) {
         return 1;
     }
     return 0;
 }
 
 // Function with null pointer dereference
 void process_data(char* data) {
     // Missing null check
     printf("Processing data of length: %d\n", strlen(data));
     *data = 'A'; // Will crash if data is NULL
 }
 
 // Globally disabled security check (never do this!)
 #pragma GCC diagnostic ignored "-Wformat-security"
 
 // Main function with multiple vulnerabilities
 // Function that leaks in a loop
 void leak_in_loop(int iterations) {
     for (int i = 0; i < iterations; i++) {
         // Create leak in each iteration
         char* temp = (char*)malloc(256);
         sprintf(temp, "Leak iteration %d", i);
         
         // Never free temp
         if (i % 3 == 0) {
             // Create additional leaks on some iterations
             int* more_data = (int*)calloc(100, sizeof(int));
             more_data[0] = i; // Touch memory to ensure it's used
         }
     }
 }
 
 // Function that leaks through conditional paths
 void* conditional_leaker(int condition) {
     void* ptr1 = malloc(512);
     
     if (condition > 10) {
         void* ptr2 = malloc(256);
         return ptr2; // ptr1 is leaked
     } else if (condition > 5) {
         free(ptr1);
         void* ptr3 = malloc(1024);
         return ptr3; // This gets returned but never freed by caller
     }
     
     // If condition <= 5, ptr1 is returned but might not be freed
     return ptr1;
 }
 
 int main(int argc, char *argv[]) {
     // Unsafe command line argument usage
     if (argc > 1) {
         // Path traversal vulnerability
         FILE *file = fopen(argv[1], "r");
         if (file) {
             char buffer[256];
             // Buffer overflow in file reading
             fread(buffer, 1, 1024, file); // Reading more than buffer size
             fclose(file);
         }
         
         // Process user input without validation
         process_user_input(argv[1]);
         
         // Command injection
         EXECUTE_COMMAND(argv[1]);
         
         // Format string vulnerability
         log_message(argv[1]);
     }
     
     // Call the leak-generating functions
     leak_in_loop(15); // Creates 15 iterations of leaks
     
     // Create conditional leaks
     void* should_free1 = conditional_leaker(3); // Returns ptr but never freed
     void* should_free2 = conditional_leaker(7); // Different leak path
     void* should_free3 = conditional_leaker(12); // Another leak path
     
     // Memory leaks - extensive and varied allocation patterns
//     leakedPtr = allocate_memory(); // Never freed - 1024 bytes
     char* another_leak = (char*)malloc(512); // Never freed
     strcpy(another_leak, "More leaked data");
     
     // Additional heap memory leaks in various sizes
     void* massive_leak = malloc(10240); // 10KB leak
     memset(massive_leak, 'X', 10240); // Touch the memory
     
     char** string_array = (char**)malloc(50 * sizeof(char*)); // Array of pointers
     for (int i = 0; i < 50; i++) {
         string_array[i] = (char*)malloc(100); // 50 leaks of 100 bytes each
         sprintf(string_array[i], "Leaked string %d", i);
     }
     
     // Nested structure leaks
     typedef struct node {
         int data;
         struct node* next;
     } Node;
     
     Node* head = (Node*)malloc(sizeof(Node)); // Leak the head node
     head->data = 1;
     
     for (int i = 0; i < 20; i++) {
         Node* new_node = (Node*)malloc(sizeof(Node)); // 20 more leaks
         new_node->data = i + 2;
         new_node->next = head->next;
         head->next = new_node;
     }
     
     // Realloc leaks
     int* numbers = (int*)malloc(10 * sizeof(int));
     for (int i = 0; i < 10; i++) numbers[i] = i;
     
     // Leak the original and the new allocation
     numbers = (int*)realloc(numbers, 20 * sizeof(int)); // Original might leak if realloc moves it
     numbers = (int*)malloc(30 * sizeof(int)); // Definite leak of previous realloc'd block
     
     // Null pointer dereference risk
     char* nullPtr = NULL;
     if (rand() % 10 > 5) { // Unpredictable condition
         nullPtr = (char*)malloc(10);
     }
     // Missing null check before use
     strcpy(nullPtr, "Will crash if null");
     
     // Double free vulnerability
     char* doubleFreed = (char*)malloc(50);
     free(doubleFreed);
     free(doubleFreed); // Double free
     
     // Race condition vulnerability (simplified example)
     FILE* config = fopen("config.txt", "w+");
     fputs("sensitive data", config);
     // Missing proper file access controls
     fclose(config);
     
     // Unreachable code (dead code)
     if (0) {
         printf("This will never execute\n");
         exit(1);
     }
     
     // Dangerous and deprecated functions
     char dangerous[10];
     //gets(dangerous); // Deprecated and dangerous function
     
     // Improper input validation leading to integer overflow
     int user_val;
     printf("Enter a value: ");
     scanf("%d", &user_val);
     int result = user_val * 1000000; // Potential overflow
     char* buffer = (char*)malloc(result); // Potential excessive allocation
     
     // Dangling pointer vulnerability
     char* dangling = (char*)malloc(50);
     strcpy(dangling, "Soon to be dangling");
     free(dangling);
     // ... later in code ...
     strcpy(dangling, "Using dangling pointer"); // Use after free
     
     // Out of bounds array access
     int array[5] = {1, 2, 3, 4, 5};
     for (int i = 0; i <= 5; i++) { // Off-by-one error
         array[i] = i * 10; // Buffer overflow on last iteration
     }
     
     // Resource leak
     FILE* log_file = fopen("log.txt", "w");
     fprintf(log_file, "Log entry");
     // Missing fclose(log_file)
     
     // Undefined behavior
     int x = 5;
     //x = x++ + ++x; // Undefined behavior
     
     return 0;
 }
 
 /* Commented out broken code - still dangerous if uncommented
 void broken_function() {
     int x = 5;
     if (x = 10) { // Assignment instead of comparison
         // Memory corruption
         int* ptr = (int*)0x12345678;
         *ptr = 0; // Writing to arbitrary memory location
     }
 }
 */