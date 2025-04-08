#include "vmlinux.h"

#include <errno.h>
#include <bpf/bpf_helpers.h>


#define MAX_PATH_LEN 100
#define MAX_ENTRIES 5



//OPEN FILES AND PROCESSES

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES); //max 5 file da proteggere per questa syscall
    	__type(key, char[MAX_PATH_LEN]);
	__type(value, u32);
} open_files_map SEC(".maps") ;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES); //max 5 proc esenti per questa syscall
    	__type(key, char[MAX_PATH_LEN]);
	__type(value, u32);
} open_proc_map SEC(".maps") ;

/*
    MIND THAT THIS TRIGGERS ONLY WHEN THE FILE IS OPEN(AT)ED WITH ABSOLUTE PATH
*/

SEC("tracepoint/syscalls/sys_enter_openat")
int openat_on_tracepoint(struct trace_event_raw_sys_enter *ctx)
{
    int ret;
    int flag_process=1; //1 vuol dire che il processo corrente non è un processo che puo fare l'azione
    int flag_path=0; //1 vuol dire che il path del file è il path non consentito
    int *value_file;
    int *value_proc;
    char comm[MAX_PATH_LEN]={0};
    char filename[MAX_PATH_LEN]={0};
        
        //otteniamo nome del file
    bpf_probe_read_user_str(filename, sizeof(filename), (char*)ctx->args[1]);
        //otteniamo nome del processo
    bpf_get_current_comm(comm, sizeof(comm));

    bpf_printk("File da aprire: %s, Processo: %s\n",filename,comm); 
    
    value_file = bpf_map_lookup_elem(&open_files_map,&filename);

    value_proc = bpf_map_lookup_elem(&open_proc_map,&comm); 


    //bpf_printk("value_file: %p, value_proc: %p\n", value_file, value_proc);

    if(value_file && (*value_file > 0)){ // value_file is not null if it's on the map, hence protected
        flag_path=1; // once set the redirection can be triggered
        bpf_printk("Si sta cercando di accedere ad un file protetto!\n");}
    
    if(value_proc && (*value_proc > 0)) // value_proc is not null if it's on the map, hence allowed
        flag_process=0;
    
    // if the file is protected and the process is not allowed
    if(flag_path==1 && flag_process==1){ 
        bpf_printk("Accesso negato\n"); // cat /sys/kernel/tracing/trace_pipe
        char new_path[29] = "/home/user/error"; // Percorso del file alternativo
        ret = bpf_probe_write_user((void *)ctx->args[1], new_path, sizeof(new_path));
        return 0;
        
    }
    else {
        bpf_printk("Accesso consentito!\n");
        return 0;
    }
}

char _license[] SEC("license") = "GPL";
