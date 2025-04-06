#include <signal.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/inotify.h>
#include <pthread.h>
#include <dirent.h>

#include <bpf/libbpf.h>

//dependency includes headers
#include <uthash/uthash.h>
#include <base64/base64.h>
#include <cJSON/cJSON.h>

//dependency includes implementations
#include <base64/base64.c>
#include <cJSON/cJSON.c>

typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

////////////////////////////////////////
// constants

#define MAX_PROGS 8
#define MAX_MAPS 8

#define DEFAULT_EBPF_PROGRAMS_DIR "./build/config"
#define NAMING_CONVENTION ".json"

#define MAP_NAME_MAX_LEN 255
#define PROG_NAME_MAX_LEN 255
#define FILE_NAME_MAX_LEN 255

#define EVENT_HEADER_SIZE  (sizeof(struct inotify_event))
#define NUM_EVENTS 15 // arbitrary size (inotify events)
#define BUFFER_SIZE EVENT_HEADER_SIZE * NUM_EVENTS

////////////////////////////////////////
// structs
typedef struct ebpf_params ebpf_params;
struct ebpf_params {
    char *maps[MAX_MAPS];
    size_t map_count;
    char *progs[MAX_PROGS];
    size_t prog_count;
    unsigned char *elf_data;
    int elf_data_size;
};

typedef struct ebpf_map_table ebpf_map_table;
struct ebpf_map_table {
    char *name;
    struct bpf_map *map;
};

typedef struct ebpf_program ebpf_program;
struct ebpf_program {
    char *name;
    struct bpf_object *obj;
    ebpf_map_table *maps;
    size_t map_count;
    struct bpf_program **progs;
    size_t prog_count;     
    struct bpf_link **links;
    size_t link_count;
};

typedef struct hash_record hash_record;
struct hash_record {
    char key[FILE_NAME_MAX_LEN];        // key of hashmap record
    ebpf_program *value;                // "value" of hashmap record
    UT_hash_handle hh;
};

typedef struct thread_params thread_params;
struct thread_params {
    hash_record **ebpf_programs_map;
    char *ebpf_programs_dir;
};

////////////////////////////////////////
// globals

struct bpf_map *maps[MAX_MAPS];

struct bpf_program *progs[MAX_PROGS];
struct bpf_link *links[MAX_PROGS];
static bool g_run = true;
pthread_t tid;
pthread_mutex_t hash_mutex = PTHREAD_MUTEX_INITIALIZER;

ebpf_program* ebpf_program_open_and_load(char *prog_name, ebpf_params *params) {
    ebpf_program *prog = calloc(1, sizeof(*prog));
    prog->name = prog_name;

    prog->obj = bpf_object__open_mem(params->elf_data, params->elf_data_size, NULL);
    if (!prog->obj) {
        fprintf(stderr, "[error] bpf_object__open failed: %s\n", strerror(errno)); 
        goto exit_with_error;
    }

    int ret = bpf_object__load(prog->obj);
    if (ret != 0) {
        fprintf(stderr, "[error] bpf_object__load failed: %s\n", strerror(errno)); 
        goto exit_with_error;
    }

    prog->prog_count = params->prog_count;
    prog->progs      = calloc(prog->prog_count, sizeof(*prog->progs));
    for (size_t i = 0; i < prog->prog_count; ++i) {
        prog->progs[i] = bpf_object__find_program_by_name(prog->obj, params->progs[i]);
        if (!prog->progs[i]) {
            fprintf(stderr, "[error] bpf_object__find_program_by_name failed: %s\n", strerror(errno)); 
            goto exit_with_error;
        }
        #ifndef DEBUG
        printf("[DEBUG] found program: %s\n", params->progs[i]);
        #endif /*DEBUG*/
    }

    

    prog->map_count = params->map_count;
    prog->maps      = calloc(prog->map_count, sizeof(*prog->maps));
    for (size_t i = 0; i < prog->map_count; ++i) {
        prog->maps[i].map  = bpf_object__find_map_by_name(prog->obj, params->maps[i]);
        prog->maps[i].name = params->maps[i];
        if (!prog->maps[i].map) {
            fprintf(stderr, "[error] bpf_object__find_map_by_name failed: %s\n", strerror(errno)); 
            goto exit_with_error;
        }
        #ifndef DEBUG
        printf("[DEBUG] found map: %s\n", params->maps[i]);
        #endif /*DEBUG*/
    }

    prog->link_count = prog->prog_count;
    prog->links      = calloc(prog->link_count, sizeof(*prog->links));
    for (size_t i = 0; i < prog->prog_count; ++i) {
        prog->links[i] = bpf_program__attach(prog->progs[i]);
        if (!prog->links[i]) {
            fprintf(stderr, "[error] bpf_program__attach failed: %s\n", strerror(errno)); 
            goto exit_with_error;
        }
    }

    return prog;

exit_with_error:
    free(prog);
    return NULL;
}

static void 
ebpf_program_destroy(ebpf_program *prog)
{
    for (size_t i = 0; i < prog->prog_count; ++i) {
        bpf_link__destroy(prog->links[i]);
        bpf_program__unload(prog->progs[i]);
    }

    free(prog->links);
    free(prog->progs);
    free(prog->maps);
    free(prog->name);

    bpf_object__close(prog->obj);
    free(prog);
}

static void
ebpf_params_destroy(ebpf_params *params)
{
    for(size_t i = 0; i < params->map_count; i++) {
        free(params->maps[i]);
    }
    
    for(size_t i = 0; i < params->prog_count; i++) {
        free(params->progs[i]);
    }

    free(params->elf_data);

    free(params);
}

static void 
hash_record_destroy(hash_record **table_head, hash_record *hr)
{
    #ifdef DEBUG
    printf("[DEBUG] Want to destroy program at %p\n", hr->value);
    #endif /*DEBUG*/

    ebpf_program_destroy(hr->value); // this also deletes maps
    
    HASH_DEL(*table_head, hr);
    free(hr);
}

static struct bpf_map *
ebpf_program_find_map_by_name(ebpf_program *prog, const char *name)
{
    for (size_t i = 0; i < prog->map_count; ++i) {
        if (strcmp(prog->maps[i].name, name) == 0) {
            return prog->maps[i].map;
        }
    }

    return NULL;
}

////////////////////////////////////////
// functions

static void print_map_element(hash_record *hr) {
    printf("key: %s, value: (omitted)\n", (char*)hr->key); // value is not necessarily a string...
    printf("key: %p, value: %p\n", hr->key, hr->value);
}

static void print_all_map_elements(hash_record *map_head) {
    printf("\n");
    printf("-------- FILE TABLE PRINTOUT ----------\n");
    hash_record *hr;
    for (hr = map_head; hr != NULL; hr = hr->hh.next) {
        print_map_element(hr);
    }
    printf("\n");
}

static void print_prog_name(hash_record *hr) {
    printf("prog->name: %s\n", hr->value->name);
}

static int string_ends_with(char *string, char *suffix) {
    int string_len = strlen(string);
    int suffix_len = strlen(suffix);

    if(string_len <= suffix_len) {
        return 0;
    }

    return !strcmp(string + string_len - suffix_len, suffix);
}

static ebpf_params* read_params_from_file(char *filename) {
    ebpf_params *params = (ebpf_params*)calloc(1, sizeof(ebpf_params));
    
    long file_len;
    FILE *json_file = fopen(filename, "r");
    fseek(json_file, 0, SEEK_END);
    file_len = ftell(json_file);
    rewind(json_file);
    char *json_content = (char*)calloc(file_len + 1, sizeof(char)); // a bit spooky since the file could be arbitrarily big
    if(fread(json_content, sizeof(char), file_len, json_file) != file_len) {
        perror("[ERROR] error while reading json file");
    }
    fclose(json_file);

    cJSON *parsed = cJSON_Parse(json_content);
    if (parsed) {
        int i;
        char *tmp;

        cJSON *maps = cJSON_GetObjectItem(parsed, "maps");
        cJSON *progs = cJSON_GetObjectItem(parsed, "progs");

        params->map_count = cJSON_GetArraySize(maps);
        params->prog_count = cJSON_GetArraySize(progs);

        if(params->map_count > MAX_MAPS || params->prog_count > MAX_PROGS) {
            printf("Max maps: %d, provided maps in config file: %zu\n", MAX_MAPS, params->map_count);
            printf("Max progs: %d, provided programs in config file: %zu\n", MAX_PROGS, params->prog_count);
            printf("Required fix of config file %s", filename);
            exit(EXIT_FAILURE);
        }

        for (i = 0; i < params->map_count; i++) {
            params->maps[i] = (char*)calloc(MAP_NAME_MAX_LEN, sizeof(char));
            tmp = cJSON_GetStringValue(cJSON_GetArrayItem(maps, i));
            strncpy(params->maps[i], tmp, strlen(tmp));
        }

        for (i = 0; i < params->prog_count; i++) {
            params->progs[i] = (char*)calloc(PROG_NAME_MAX_LEN, sizeof(char));
            tmp = cJSON_GetStringValue(cJSON_GetArrayItem(progs, i));
            strncpy(params->progs[i], tmp, strlen(tmp));
        }

        char *encoded_ebpf_prog = cJSON_GetStringValue(cJSON_GetObjectItem(parsed, "ebpf_prog"));
        params->elf_data = base64_decode((unsigned char*)encoded_ebpf_prog, strlen(encoded_ebpf_prog), &params->elf_data_size);
        
        cJSON_Delete(parsed);

        #ifdef DEBUG
        for (int i = 0; i < params->map_count; i++) {
            printf("[DEBUG] Config file %s, found map %d: %s\n", filename, i, params->maps[i]);
        }

        for (int i = 0; i < params->prog_count; i++) {
            printf("[DEBUG] Config file %s, found prog %d: %s\n", filename, i, params->progs[i]);
        }
        #endif /*DEBUG*/
       
    } else {
        printf("Error while parsing %s\n", filename);
    }

    free(json_content);
    return params;
}

static ebpf_program* load_ebpf_program(char *filename) {

    ebpf_program *ebpf_prog_data;
    ebpf_params *params;
    
    params = read_params_from_file(filename);
    
    #ifdef DEBUG
    printf("[DEBUG] %s Initialized params!\n", filename);
    #endif /*DEBUG*/

    char *prog_name = (char*)calloc(FILE_NAME_MAX_LEN, sizeof(char));
    strncpy(prog_name, filename, strlen(filename));
    prog_name[(strstr(prog_name, NAMING_CONVENTION) - prog_name)] = '\0'; //truncate the string to the sole name

    ebpf_prog_data = ebpf_program_open_and_load(prog_name, params);
    if (!ebpf_prog_data) {
        char *filename_path = (char*)calloc(FILE_NAME_MAX_LEN, sizeof(char));
        snprintf(filename_path, FILE_NAME_MAX_LEN*sizeof(char), "%s/%s", ".", filename);
        fprintf(stderr, "[error] %s ebpf_program_open_and_load failed: %s\n", filename_path, strerror(errno)); 
        free(filename_path);
        return NULL;
    }

    // maps population

    #ifdef DEBUG
    printf("[DEBUG] (%s) program opened and loaded!\n", ebpf_prog_data->name);
    #endif /*DEBUG*/

    ebpf_params_destroy(params);

    return ebpf_prog_data;
    
}

// used when the program has just started to load the ebpf programs that are already present in dirname
static void populate_hashmap_with_files_in_dir(hash_record **table_head, char *dirname, char* naming_convention) {
    struct dirent **file_list;
    int n;

    n = scandir(dirname, &file_list, NULL, alphasort);
    if (n == -1) {
        perror("[ERROR - child] Problems while scanning directory");
        exit(EXIT_FAILURE);
    }

    n--;
    while (n >= 0) {
        if(string_ends_with(file_list[n]->d_name, naming_convention)) {
            ebpf_program *ebpf_program_data = load_ebpf_program(file_list[n]->d_name);

            #ifdef DEBUG
            printf("[DEBUG - child] ebpf_program_data->name: %s\n", ebpf_program_data->name);
            #endif /*DEBUG*/
            
            if(!ebpf_program_data) {
                printf("[ERROR - child] Error while loading %s\n", file_list[n]->d_name);
            } else {

                hash_record *new_entry = (hash_record*)calloc(1, sizeof(hash_record));
                strncpy(new_entry->key, file_list[n]->d_name, strlen(file_list[n]->d_name));
                new_entry->value = ebpf_program_data;

                // mandatory check for uniqueness
                hash_record *tmp;

                pthread_mutex_lock(&hash_mutex);
                HASH_FIND_STR(*table_head, file_list[n]->d_name, tmp);
                if (!tmp) { // if tmp is NULL there is no key conflict
                    #ifdef DEBUG
                    printf("[DEBUG - child] added new entry\n");
                    #endif /*DEBUG*/
                    HASH_ADD_STR(*table_head, key, new_entry);
                } else { // otherwise we add the freshest data of the program
                    #ifdef DEBUG
                    printf("[DEBUG  - child] replaced entry\n");
                    #endif /*DEBUG*/
                    HASH_REPLACE_STR(*table_head, key, new_entry, tmp);
                }
                pthread_mutex_unlock(&hash_mutex);

                #ifdef DEBUG
                printf("[DEBUG - child] Added %s to the hashmap\n", file_list[n]->d_name);
                #endif /*DEBUG*/

                #ifdef TABLE_PRINTOUT
                print_all_map_elements(*table_head);
                #endif /*TABLE_PRINTOUT*/

            }
        }
        n--;
    }

}

// thread code
static void *directory_monitor(void *args) {
    int bytes_read;
    int fd;
    char buffer[BUFFER_SIZE];
    struct inotify_event *event;
    thread_params *t_params = (thread_params*) args; 

    chdir(t_params->ebpf_programs_dir); // move to compiled ebpf programs dir 

    populate_hashmap_with_files_in_dir(t_params->ebpf_programs_map, ".", NAMING_CONVENTION);

    // initialization of inotify
    fd = inotify_init();
    if (fd < 0) {
        perror("[ERROR - child] Problems while performing inotify_init");
        exit(EXIT_FAILURE);
    }

    // add inotify watch on current directory (.) for create, delete or modify
    //int wd = inotify_add_watch(fd, ".", IN_CREATE | IN_DELETE | IN_MODIFY);
    int wd = inotify_add_watch(fd, ".", IN_CREATE | IN_DELETE); // for now we don't consider modification
    if (wd < 0) {
        perror("[ERROR - child] Problems while performing inotify_add_watch");
        exit(EXIT_FAILURE);
    }

    fcntl(fd, F_SETFL, O_NONBLOCK);

    printf("[INFO - child] Watching for changes in current directory (%s)...\n", t_params->ebpf_programs_dir);

    while (g_run) {
        
        // read events
        bytes_read = read(fd, buffer, sizeof(buffer)); // read a chunk of events
        if (bytes_read == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                usleep(10 * 1000);
                continue;
            }
            if (errno != EINTR) { // if it's EINTR it's not a problem
                perror("[ERROR - child] Problems while performing event read from buffer");
                exit(EXIT_FAILURE);
            }
            break;
        }
        
        event = (struct inotify_event *)buffer; // event points to the first inotify_event struct inside buffer 

        #ifdef DEBUG
        printf("\n\n[DEBUG] bytes_read:%d\n", bytes_read); 
        #endif /* [DEBUG] */

        ebpf_program *ebpf_program_data;
        // read events one by one, 
        while (bytes_read > 0) {
            if(string_ends_with(event->name, NAMING_CONVENTION)) {
                switch (event->mask) {
                case IN_CREATE:
                    ebpf_program_data = load_ebpf_program(event->name);
                    if(!ebpf_program_data) {
                        printf("[INFO - child] Error while loading %s\n", event->name);
                    } else {
                        hash_record *new_entry = (hash_record*)calloc(1, sizeof(hash_record));
                        strncpy(new_entry->key, event->name, strlen(event->name));
                        new_entry->value = ebpf_program_data;
                        
                        // mandatory check for uniqueness
                        hash_record *tmp;
                        pthread_mutex_lock(&hash_mutex);
                        HASH_FIND_STR(*(t_params->ebpf_programs_map), event->name, tmp);
                        if (!new_entry) { // if tmp is NULL there is no key conflict
                            HASH_ADD_STR(*(t_params->ebpf_programs_map), key, new_entry);
                        } else { // otherwise we add the freshest data of the program
                            HASH_REPLACE_STR(*(t_params->ebpf_programs_map), key, new_entry, tmp);
                        }
                        pthread_mutex_unlock(&hash_mutex);
                        printf("[INFO - child] File created: %s\n", event->name);
                        printf("[INFO - child] Program loaded: %s\n", event->name);
                    }
                    break;
                case IN_DELETE:
                    ; // labels cannot be followed by declarations
                    hash_record *tmp;
                    pthread_mutex_lock(&hash_mutex);
                    HASH_FIND_STR(*(t_params->ebpf_programs_map), event->name, tmp);
                    if(tmp) {
                        hash_record_destroy(t_params->ebpf_programs_map, tmp);
                        #ifdef DEBUG
                        printf("[DEBUG] Correctly removed entry with key %s\n", event->name);
                        #endif /* [DEBUG] */
                    } // delete from hashmap if removed, used as a trigger for unloading a running bpf program
                    pthread_mutex_unlock(&hash_mutex);

                    printf("[INFO - child] File deleted: %s\n", event->name);
                    printf("[INFO - child] BPF program unloaded: %s\n", event->name);
                    break;
                /*case IN_MODIFY:
                    printf("File modified: %s\n", event->name);
                    break;
                */ // can be used for hot reloading of bpf programs
            }
            } else {
                printf("[INFO - child] Filename does not follow naming convention\n");
            }

            bytes_read -= (EVENT_HEADER_SIZE + event->len); // decrement by bytes used
            
            event = (struct inotify_event *)(((char*)event + EVENT_HEADER_SIZE + event->len)); // now event points to the next event in the buffer (if any)

            #ifdef DEBUG
            printf("[DEBUG] byte left to be processed: %d\n", bytes_read);
            //printf("[DEBUG] event->mask=%d\n", event->mask);
            //printf("[DEBUG] event->name=%s\n", event->name);
            #ifdef TABLE_PRINTOUT
            print_all_map_elements(*(t_params->ebpf_programs_map));
            #endif /*TABLE_PRINTOUT*/
            #endif /* [DEBUG] */
        }
    }

    // clean up inotify related
    inotify_rm_watch(fd, wd);
    close(fd);

    // free hash table
    hash_record *curr_hr, *tmp;

    pthread_mutex_lock(&hash_mutex);
    HASH_ITER(hh, *(t_params->ebpf_programs_map), curr_hr, tmp) {
        hash_record_destroy(t_params->ebpf_programs_map, curr_hr);
    }
    pthread_mutex_unlock(&hash_mutex);

    printf("[INFO - child] All structures cleared, exiting.\n");
    exit(EXIT_SUCCESS);
    
}

////////////////////////////////////////
// handlers
void
sig_int(int signo)
{
    fprintf(stderr, "[info] signal %d received\n", signo);
    g_run = false;
}

////////////////////////////////////////
int
main(int argc, char *argv[])
{
    
    
    char *ebpf_programs_dir = DEFAULT_EBPF_PROGRAMS_DIR;
    if (argc == 2) {
        ebpf_programs_dir = argv[1];
    }

    signal(SIGINT, sig_int);

    // "initializiation" of the hashtable
    hash_record *ebpf_progs_map = NULL;

    thread_params thread_params = {
        .ebpf_programs_map = &ebpf_progs_map,
        .ebpf_programs_dir = ebpf_programs_dir,
    };

    int res = pthread_create(&tid, NULL, directory_monitor, &thread_params);

    if (res != 0) {
        printf("Error creating thread\n");
        return EXIT_FAILURE;
    }

    // parent code

    while (g_run) {
        
       // do something ...

        sleep(1);
    }

    printf("[INFO] Waiting for the thread...\n");
    pthread_join(tid, NULL);

    return EXIT_SUCCESS;
}