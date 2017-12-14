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
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>

#include "uthash.h"

#define LINESIZE 2048
#define BUFSIZE 419200


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
    int port;
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
char* send_recieve_from_server(char* ip, int port, char* message);
void update_file_cache_dict(long int time);
void add_to_file_cache_dict(char *name, long int time);
void clear_hash(struct keyValue **hash);



int port;
//Implement this by creating a new thread that sleeps for the timeout, then deletes the cached file.
//inefficient but should work without blocking the main process
int timeout;
char blackIP[20][64];
char blackHost[20][256];
int socket_desc;
struct keyValue *ipCache;
struct keyValue *failedHostCache;
struct keyValue *fileCache;
char *msg[BUFSIZE];



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
    printf("\n\n");


    //Test section


    //TODO: Does not work
    /*struct httpRequest hat = parse_http("GET test.com:400/index.html");
    printf("document:|%s|\n", hat.document);
    printf("cleanDocument:|%s|\n", hat.cleanDocument);
    printf("port:|%d|\n", hat.port);*/




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
    char* serverResponse;

    read_size = recv(sock , client_message , LINESIZE , 0);
    //printf("client_message:%s\n", client_message);
    if (read_size > 0){
        message = &client_message[0];
        //printf("MESSAGE:|%s|\n", message);
        request = parse_http(message);
    }
    message = appendString(message, "\n\n");
    if (!strcmp(request.cleanDocument, "detectportal.firefox.com/success.txt")){
        //Free the socket pointer
    free(socket_desc);
    close(sock);

    return 0;
    }

    //printf("Request:%s | %s\n",request.command, request.document);


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
            //If we want to check full cache every time: Keeps it cleaner, but costs more time
            //Build local dict of locally cached files
            //  for file in cache directory
            //    Check that they are within timeout, else delete them
            //    Add files to local dict
            //  Check dict for wanted documents
            //  Return wanted doc or try to get document

            //If we want to only check this document
            //Look through all files in cache directory
            //  if its name matches the wanted document
            //    check if it has past its timeout
            //      if it has, delete it, otherwise return it.
            time_t currentTime = time(NULL);
            //create directory if it doesn't exist
            int resultOfMkdir = mkdir("./cache", 0777);
            //List all files and subdirectorys into fileCache
            update_file_cache_dict(currentTime);
            //printf("print_hash\n");
            //print_hash(&fileCache,1);
            //printf("print_hash\n");
            //Check if fileCache has what we want
            char* path = return_value(&fileCache, request.cleanDocument);
            if (path != NULL) {
                //rintf("retrieve cachePath, need to find actual file:%s\n", path);
                FILE * file = fopen(path, "rb");
                bzero(msg, BUFSIZE);
                int n;
                while ((n = fread(msg, 1, sizeof(msg), file)) > 0){
                    write(sock, msg, n);
                    bzero(msg, BUFSIZE);
                }

            } else {
                printf("Document not in cache\n");
            }


            //TODO: need to implement the request forwarding
            serverResponse = send_recieve_from_server(forwardIP, request.port, message);

            //need to implement error checking here, currently everything connect to fails
            if (!strcmp(serverResponse, "")) {
                printf("Send Recieve to %s:%d failed\n", request.cleanDocument, request.port);
                good = 0;
            } else {
                char timeStr[32];
                sprintf(timeStr, "%ld", currentTime);
                char* cachePath = appendString("cache/", request.cleanDocument);
                //printf("cachePath:%s*\n", cachePath);
                popen(appendString("rm -rf ", appendString(cachePath, "*")), "r");
                cachePath = appendString(cachePath, ".");
                cachePath = appendString(cachePath, &timeStr[0]);
                //printf("saving cachePath:%s\n", cachePath);

                FILE *fp;
                fp = fopen(cachePath, "w+");
                fputs(serverResponse, fp);
                fclose(fp);

                //printf("%s||\n%s\n||\n", request.cleanDocument, serverResponse);
            }


        }
    }
    else {
        good = 0;
        //printf("not get\n");
    }

    if (good) {
        outMessage = serverResponse;
    } else {
        if (blacklisted) {
            outMessage = "ERROR 403 Forbidden";
        } else {
            outMessage = "ERROR 400 bad request";
        }
    }

    printf("REQUEST:\n||\n%s\n||\nRESPONSE:\n||\n%s||\n", message, outMessage);
    write(sock , outMessage, strlen(outMessage));

    //Free the socket pointer
    free(socket_desc);
    close(sock);
    printf("\n");

    return 0;
}

struct httpRequest parse_http(char* http) {
    //May need to handle test:400/index.html?


    struct httpRequest h;
    char *command, *document, *protocol, *firstLine, *contents, *cleanDocument;

    split_string(http, '\n', &firstLine, &contents);
    //printf("contents:%s\n", contents);
    split_string(firstLine, ' ', &command, &firstLine);
    split_string(firstLine, ' ', &document, &protocol);
    h.command = command;
    h.document = document;
    h.protocol = protocol;
    h.port = 80;
    h.cleanDocument = NULL;
    cleanDocument = document;
    char maybeSlash[2];
    memcpy(maybeSlash, &cleanDocument[strlen(cleanDocument)-1], 1);
    maybeSlash[1] = '\0';
    if (!strcmp(maybeSlash, "/")){
        cleanDocument[strlen(cleanDocument)-1] = '\0';
    }
    char maybeHttp[8];
    memcpy(maybeHttp, &cleanDocument[0], 7);
    maybeHttp[7] = '\0';
    if (!strcmp(maybeHttp, "http://")){
        cleanDocument = cleanDocument + 7;
    }
    char* maybePort;
    split_string(cleanDocument, ':', &cleanDocument, &maybePort);
    if (maybePort != NULL) {
        h.port = atoi(maybePort);
    }
    char maybeWWWdot[5];
    memcpy(maybeWWWdot, &cleanDocument[0], 4);
    maybeWWWdot[4] = '\0';
    if (!strcmp(maybeWWWdot, "www.")){
        cleanDocument = cleanDocument + 4;
    }


    h.cleanDocument = cleanDocument;
    return h;
}


char* send_recieve_from_server(char* ipStr, int port, char* message) {
    //could change this to retun "" if something goes wrong, and print out the error
    //to aid in error checking in final program
    int connfd;
    struct sockaddr_in server;
    connfd = socket(AF_INET , SOCK_STREAM , 0);
    if (connfd == -1) {
        printf("Could not create socket");
        return "";
    }
    server.sin_addr.s_addr = inet_addr(ipStr);
    server.sin_family = AF_INET;
    server.sin_port = htons( port );
    //printf("ip:%s port:%d\n", ipStr, port);

    //Connect to remote server
    if (connect(connfd , (struct sockaddr *)&server , sizeof(server)) < 0) {
        //printf("connect failed. Error\n");
        char* errorMessage = "connect to ";
        errorMessage = appendString(errorMessage, ipStr);
        errorMessage = appendString(errorMessage, " failed.");
        printf("%s\n", errorMessage);
        return "";
    }
    printf("%s:%d connection successful\n", ipStr, port);
    //printf("MESSAGETOSEND:\n|%s|\n", message);
    if( send(connfd , message , strlen(message),0) < 0) {
        printf("Send failed\n");
        return "";
    }
    //printf("Send complete\n");

    char* serverReply = "";
    int m, index;
    char fromServer[256];
    bzero(fromServer, sizeof(fromServer));
    send(connfd , message , strlen(message),0);
    //printf("after send, before while\n");
    while((m = recv(connfd, fromServer, sizeof(fromServer), 0)) == 256) {
        serverReply = appendString(serverReply, fromServer);
        //printf("SERVERFROM: m=%d i=%d:|%s|\n\n", m, index, fromServer);
        bzero(fromServer, sizeof(fromServer));
    }
    serverReply = appendString(serverReply, "\n");
    //printf("SERVERREPLY:||%s||\n", serverReply);

    close(connfd);

    return serverReply;
}



//helper functions
void update_file_cache_dict(long int time) {
    //need to run different version for top level cache directory
    clear_hash(&fileCache);
    DIR *dir;
    struct dirent *entry;

    if (!(dir = opendir("cache")))
        return;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            char path[1024];
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            snprintf(path, sizeof(path), "%s/%s", "cache", entry->d_name);
            add_to_file_cache_dict(path, time);
        } else {
            char* path = appendString("cache/", entry->d_name);
            char* dotAt = strrchr(entry->d_name, '.');
            *dotAt = '\0';
            long int timeSinceCached = time-atol(dotAt+1);
            if (timeout >= timeSinceCached) {
                //printf("%s: File is good on timeout\n", entry->d_name);
                add_key_value(&fileCache, entry->d_name, path);
            } else {
                //printf("%s: File is bad on timeout\n", entry->d_name);
                //printf("to delete:%s\n", entry->d_name);
                remove(entry->d_name);
            }
        }
    }
    closedir(dir);
}


void add_to_file_cache_dict(char *name, long int time)
{
    DIR *dir;
    struct dirent *entry;

    if (!(dir = opendir(name)))
        return;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            char path[1024];
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            snprintf(path, sizeof(path), "%s/%s", name, entry->d_name);
            add_to_file_cache_dict(path, time);
        } else {
            char* path = appendString("cache/", entry->d_name);
            char* dotAt = strrchr(entry->d_name, '.');
            *dotAt = '\0';
            long int timeSinceCached = time-atol(dotAt+1);
            if (timeout >= timeSinceCached) {
                //printf("%s: File is good on timeout\n", entry->d_name);
                char* fileWOCache = name + 6;
                fileWOCache = appendString(fileWOCache, "/");
                fileWOCache = appendString(fileWOCache, entry->d_name);
                add_key_value(&fileCache, fileWOCache, path);
            } else {
                //printf("%s: File is bad on timeout\n", entry->d_name);
                char* cachePath = name;
                cachePath = appendString(cachePath, "/");
                cachePath = appendString(cachePath, entry->d_name);
                //printf("to delete:%s\n", cachePath);
                remove(cachePath);
            }
        }
    }
    closedir(dir);
}



void split_string(char* string, char delim, char** before, char** after) {
    assert(before);
    assert(after);

    *after = strchr(string, delim);

    if (*after == NULL) {
        //printf("|%c| after is NULL\n", delim);
        *before = string;
    } else {
        //printf("|%c| after is not NULL\n", delim);

        size_t lengthOfFirst = *after - string;
        *before = (char*)malloc((lengthOfFirst + 1)*sizeof(char));
        strncpy(*before, string, lengthOfFirst);
        *after = *after+1;
        trimwhitespace(*before);
        trimwhitespace(*after);
    }
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

void clear_hash(struct keyValue **hash) {
  struct keyValue *current_user, *tmp;

  HASH_ITER(hh, *hash, current_user, tmp) {
    HASH_DEL(*hash,current_user);  /* delete; users advances to next */
    free(current_user);            /* optional- if you want to free  */
  }
}
