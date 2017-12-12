/*
*Jake Mitchell
*December 8th, 2017
*Network Systems Programming Assignment 4
*/


//TODO: get port out of a url, currently defaults to port 80


#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <assert.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <netdb.h>

#include "uthash.h"

#define LINESIZE 2048


//Structs
struct keyValue {
    char key[LINESIZE];
    char value[LINESIZE];
    UT_hash_handle hh;
};
struct httpRequest {
    char* command;
    char* document;
    char* protocol;
    char* cleanDocument;
    char* host;
};


char* appendString(char* str1, char* str2);
void add_key_value(struct keyValue **hash, char* keyIn, char* valueIn);
struct keyValue *findKey(struct keyValue **hash, char* keyId);
char *trimwhitespace(char *str);
char* return_value(struct keyValue **hash, char* key);
void print_hash(struct keyValue **hash, int showKeyValue);
void parse_blacklist(char* file);
void split_string(char* string, char delim, char** before, char** after);
void *connection_handler(void *socket_desc);
struct httpRequest parse_http(char*);
char* send_recieve_from_server(char* ip, char* port, char* message);



int port;
//Implement this by creating a new thread that sleeps for the timeout, then deletes the cached file.
//inefficient but should work without blocking the main process
int timeout;
char blackIP[20][64];
char blackHost[20][256];
int socket_desc;
struct keyValue *ipCache;
struct keyValue *failedHostCache;


int main(int argc, char **argv) {
    if (argc < 3) {
      printf("missing argument\n");
      exit(-1);
    }
    port = atoi(argv[1]);
    timeout = atoi(argv[2]);
    int client_sock , *new_sock;
    struct sockaddr_in server , client;

    printf("port:%d\n", port);
    printf("timeout:%d\n", timeout);
    parse_blacklist("blacklist.conf");
    int index = 0;
    while (strcmp(blackIP[index],"")) {
        printf("blackIP[%d] = %s\n", index, blackIP[index]);
        index += 1;
    }
    index = 0;
    while (strcmp(blackHost[index],"")) {
        printf("blackHost[%d] = %s\n", index, blackHost[index]);
        index += 1;
    }

    //base code from http://www.binarytides.com/server-client-example-c-sockets-linux/
    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1){ printf("Could not create socket");    }

    setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(port);
    //Bind
    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        //print the error message
        printf("bind failed. Error\nn");

        return 1;
    }
    listen(socket_desc , 3);

    //Accept and incoming connection
    int c = sizeof(struct sockaddr_in);
    while( (client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)) )
    {
        pthread_t sniffer_thread;
        new_sock = malloc(1);
        *new_sock = client_sock;

        if( pthread_create( &sniffer_thread , NULL ,  connection_handler , (void*) new_sock) < 0)
        {
            perror("could not create thread");
            return 1;
        }
    }

    if (client_sock < 0)
    {
        perror("accept failed");
        return 1;
    }

    close(socket_desc);

}


//local functions
void parse_blacklist(char* file){
    char * line = NULL;
    FILE *confFile;
    size_t len = 0;
    ssize_t read;

    confFile = fopen(file, "r");
    if (confFile == NULL)
        exit(EXIT_FAILURE);
    bzero(blackHost, sizeof(blackHost));
    bzero(blackIP, sizeof(blackIP));
    int ipIndex = 0;
    int hostIndex = 0;
    while ((read = getline(&line, &len, confFile)) != -1) {
        if(line[0] != '#'){
            //Assume that the line is well formatted if it is not a comment line
            //printf("%s", line);
            char* type;
            char* item;
            split_string(line, ':', &type, &item);

            if (!strcmp(type, "ip")) {
                strcpy(blackIP[ipIndex], item);
                ipIndex += 1;
            }
            else if (!strcmp(type, "host")) {
                strcpy(blackHost[hostIndex], item);
                hostIndex += 1;
            }
            else {
                printf("Malformated blacklist line: %s\n", line);
            }
        }
    }
    fclose(confFile);
}


/*
 * This will handle connection for each client
 * */
void *connection_handler(void *socket_desc)
{
    //Get the socket descriptor
    int sock = *(int*)socket_desc;
    int read_size, certified;
    char *message, *user, *pass, *command, client_message[LINESIZE];
    char *outMessage, *forwardIP;
    struct httpRequest request;
    int good = 1;
    int blacklisted = 0;

    read_size = recv(sock , client_message , LINESIZE , 0);
    //printf("client_message:%s\n", client_message);
    if (read_size > 0){
        message = &client_message[0];
        request = parse_http(message);
    }
    if (!strcmp(request.cleanDocument, "detectportal.firefox.com/success.txt")){
        //Free the socket pointer
    free(socket_desc);
    close(sock);

    return 0;
    }

    printf("Request:%s\n", request.document);


    outMessage = request.protocol;
    outMessage = appendString(outMessage, " ");

    if (!strcmp(request.command, "GET")) {
        //Check if website is blacklisted
        int index = 0;
        while (strcmp(blackHost[index],"")) {
            if (!strcmp(request.cleanDocument, blackHost[index])){
                good = 0;
                blacklisted = 1;
                printf("Host is blacklisted:%s\n", request.cleanDocument);
            }
            index += 1;
        }
        if (!blacklisted) {
            //if ip not in cache
            if ((forwardIP = return_value(&ipCache, request.cleanDocument)) == NULL){
                struct hostent *he;
                struct in_addr **addr_list;
                //if it is not on the failed host cache, then try and get it
                if (return_value(&failedHostCache, request.cleanDocument)) {
                    good = 0;
                    printf("%s has already failed to be found\n", request.cleanDocument);
                } else {
                    printf("Looking up host for:%s\n", request.cleanDocument);
                    if ((he = gethostbyname(request.cleanDocument)) == NULL) {
                        good = 0;
                        printf("Failed to find host:%s\n", request.cleanDocument);
                        add_key_value(&failedHostCache, request.cleanDocument, "");
                    } else {
                        addr_list = (struct in_addr **)he->h_addr_list;
                        //printf("Official name is: %s\n", he->h_name);
                        //printf("    IP addresses: ");
                        for (int i = 0; addr_list[i] != NULL; i++) {
                            forwardIP = inet_ntoa(*addr_list[i]);
                            for (int j = 0; strcmp(blackIP[j], ""); j++) {
                                if (!strcmp(forwardIP, blackIP[j])) {
                                    good = 0;
                                    blacklisted = 1;
                                    printf("Ip is blacklisted:%s\n", forwardIP);
                                }
                            }
                        }
                        if (!blacklisted) {
                            add_key_value(&ipCache, request.cleanDocument, forwardIP);
                        }
                    }
                }
            } else {
                //ip is in cache
                printf("ip in cache:%s\n", forwardIP);
            }
        }
        if(good){
            //TODO: need to implement the request forwarding
            char* serverResponse = send_recieve_from_server(forwardIP, "80", message);

            //need to implement error checking here, currently everything connect to fails
            printf("%s||\n%s\n||\n", request.cleanDocument, serverResponse);


        }

        //if host not blacklisted
        // check cache
        // if not cache, get hostbyname
        //  check ip for blacklist
        //  if not blacklist
        //   add pair to cache
        // else
        //  return ip
    }
    else {
        good = 0;
    }

    if (good) {
        outMessage = appendString(outMessage, "200 Document Follows\n\n<html><body>Good</body></html>");
    } else {
        if (blacklisted) {
            outMessage = "ERROR 403 Forbidden";
        } else {
            outMessage = "ERROR 400 bad request";
        }
    }

    printf("%s RESPONSE:%s\n", request.cleanDocument, outMessage);
    write(sock , outMessage, strlen(outMessage));

    //Free the socket pointer
    free(socket_desc);
    close(sock);
    printf("\n");

    return 0;
}

struct httpRequest parse_http(char* http) {
    struct httpRequest h;
    char *command, *document, *protocol, *firstLine, *contents, *cleanDocument, *host;

    split_string(http, '\n', &firstLine, &contents);
    //printf("contents:%s\n", contents);
    split_string(firstLine, ' ', &command, &firstLine);
    split_string(firstLine, ' ', &document, &protocol);
    h.command = command;
    h.document = document;
    h.protocol = protocol;
    cleanDocument = document;
    char maybeHttp[8];
    memcpy(maybeHttp, &cleanDocument[0], 7);
    maybeHttp[7] = '\0';
    if (!strcmp(maybeHttp, "http://")){
        cleanDocument = cleanDocument + 7;
    }
    char maybeWWWdot[5];
    memcpy(maybeWWWdot, &cleanDocument[0], 4);
    maybeWWWdot[4] = '\0';
    if (!strcmp(maybeWWWdot, "www.")){
        cleanDocument = cleanDocument + 4;
    }
    char maybeSlash[2];
    memcpy(maybeSlash, &cleanDocument[strlen(cleanDocument)-1], 1);
    maybeSlash[1] = '\0';
    if (!strcmp(maybeSlash, "/")){
        cleanDocument[strlen(cleanDocument)-1] = '\0';
    }
    h.cleanDocument = cleanDocument;
    //need to clean the document in order to get the host.  http://google.com/ does not work
    //but google.com does.  Also simplifies the blacklisting
    return h;
}


char* send_recieve_from_server(char* ipStr, char* port, char* message) {
    //could change this to retun "" if something goes wrong, and print out the error
    //to aid in error checking in final program
    int sock;
    struct sockaddr_in server;
    sock = socket(AF_INET , SOCK_STREAM , 0);
    if (sock == -1) {
        printf("Could not create socket");
        return "";
    }
    server.sin_addr.s_addr = inet_addr(ipStr);
    server.sin_family = AF_INET;
    server.sin_port = htons( atoi(port) );

    //Connect to remote server
    if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0) {
        //printf("connect failed. Error\n");
        char* errorMessage = "connect to ";
        errorMessage = appendString(errorMessage, ipStr);
        errorMessage = appendString(errorMessage, " failed.");
        return errorMessage;
    }
    printf("%s connection successful\n", ipStr);
    if( write(sock , message , strlen(message)) < 0) {
        printf("Send failed\n");
        return "";
    }
    char* serverReply = "";
    int read;
    char fromServer[256];
    bzero(fromServer, sizeof(fromServer));
    while((read = recv(sock, fromServer, sizeof(fromServer), 0)) != 0) {
        serverReply = appendString(serverReply, fromServer);
        printf("ServerFrom:%s\n", fromServer);
        bzero(fromServer, sizeof(fromServer));
    }

    close(sock);

    return serverReply;
}



//helper functions
void split_string(char* string, char delim, char** before, char** after) {
    assert(before);
    assert(after);

    *after = strchr(string, delim);
    size_t lengthOfFirst = *after - string;
    *before = (char*)malloc((lengthOfFirst + 1)*sizeof(char));
    strncpy(*before, string, lengthOfFirst);
    *after = *after+1;
    trimwhitespace(*before);
    trimwhitespace(*after);
}


char* appendString(char* str1, char* str2) {
    char * str3 = (char *) malloc(1 + strlen(str1)+ strlen(str2) );
    strcpy(str3, str1);
    strcat(str3, str2);
    return str3;
}

void add_key_value(struct keyValue **hash, char* keyIn, char* valueIn) {
    struct keyValue *f = findKey(hash, keyIn);
    if (f != NULL) {
        HASH_DEL(*hash, f);
        free(f);
    }
    struct keyValue *s;
    HASH_FIND_INT(*hash, &keyIn, s);  //id already in the hash?
    if (s==NULL) {
        s = malloc(sizeof(struct keyValue));
        strcpy(s->key, keyIn);
        strcpy(s->value, valueIn);
        HASH_ADD_STR(*hash, key, s);
    }
}

struct keyValue *findKey(struct keyValue **hash, char* keyId) {
    struct keyValue *s;
    HASH_FIND_STR(*hash, keyId, s);
    return s;
};

//from https://stackoverflow.com/questions/122616/how-do-i-trim-leading-trailing-whitespace-in-a-standard-way
char *trimwhitespace(char *str)
{
  char *end;

  while(isspace((unsigned char)*str)) str++; // Trim leading space

  if(*str == 0)  // All spaces?
    return str;

  end = str + strlen(str) - 1; // Trim trailing space
  while(end > str && isspace((unsigned char)*end)) end--;

  *(end+1) = 0; // Write new null terminator

  return str;
}

char* return_value(struct keyValue **hash, char* key) {
    struct keyValue *f = findKey(hash, key);
    if (f != NULL) {
        char * copy = malloc(strlen(f->value) + 1);
        strcpy(copy, f->value);
        return copy;
    } else {
        return NULL;
    }
}

void print_hash(struct keyValue **hash, int showKeyValue) {
    struct keyValue *s;
    for(s=*hash; s != NULL; s = s->hh.next) {
        if (showKeyValue) {
            printf("key: |%s|, value: |%s|\n", s->key, s->value);
        } else {
            printf("%s %s\n", s->key, s->value);
        }
    }
}
