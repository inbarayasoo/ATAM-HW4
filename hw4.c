#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "elf64.h"

#define	ET_NONE	0	//No file type 
#define	ET_REL	1	//Relocatable file 
#define	ET_EXEC	2	//Executable file 
#define	ET_DYN	3	//Shared object file 
#define	ET_CORE	4	//Core file 


/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */

unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {

    FILE* file = fopen(exe_file_name, "r");
    if (file == NULL) {
        *error_val = -3;
        return 0;
    }

    Elf64_Ehdr header;
    fread(&header, sizeof(header), 1, file);
    if(header.e_type != ET_EXEC) {
        *error_val = -3;
        return 0;
    }

    bool Global = false;
    bool Local = false;
    bool In_Exe = false;
    bool Found = false;
    long sym_addr = 0;

    fseek(file,header.e_shoff,SEEK_SET);
    Elf64_Shdr *section_header = (Elf64_Shdr*)malloc(sizeof(Elf64_Shdr)*  header.e_shnum);
    fread(section_header, sizeof(Elf64_Shdr), header.e_shnum, file);

    int sym_ndx = -1;
    int string_ndx = -1;



    Elf64_Half j;
    for( j = 0; j < header.e_shnum; j++) {
        if(section_header[j].sh_type == 2) {
            sym_ndx = j;
            break;
        }
    }


    if (sym_ndx == -1) {
        *error_val = -3;
        fclose(file);
        free(section_header);
        return 0;
    }

    int symbol_len = strlen(symbol_name) + 1;

    Elf64_Sym * sym_table = (Elf64_Sym*)malloc(sizeof(Elf64_Sym) * (section_header[sym_ndx].sh_size/section_header[sym_ndx].sh_entsize));
    fseek(file, section_header[sym_ndx].sh_offset, SEEK_SET);
    fread(sym_table, sizeof(Elf64_Sym), (section_header[sym_ndx].sh_size/section_header[sym_ndx].sh_entsize), file);

    Elf64_Xword i;
    Elf64_Xword index_of_our_symbol = -1;

    for( i = 0; i < (section_header[sym_ndx].sh_size/section_header[sym_ndx].sh_entsize); i++){
        fseek(file, section_header[section_header[sym_ndx].sh_link].sh_offset + sym_table[i].st_name, SEEK_SET);
        char* symbol_to_compare = (char *)malloc(sizeof(char ) * symbol_len);
        fread(symbol_to_compare, sizeof(char), symbol_len ,file);
        if(strcmp(symbol_to_compare, symbol_name) == 0) {
            index_of_our_symbol = i;
        }

        free(symbol_to_compare);
    }


    if(index_of_our_symbol != -1) {
        Found = true;
        if (ELF64_ST_BIND(sym_table[index_of_our_symbol].st_info) == 0) {
            Local = true;
        } else {
            Global = true;
            if (sym_table[index_of_our_symbol].st_shndx != SHN_UNDEF) {
                sym_addr = sym_table[index_of_our_symbol].st_value;
                In_Exe = true;
            }
        }
    }


    if(Local && !Global && Found){
        *error_val = -2;
    }
    if(Global && In_Exe && Found){
        *error_val = 1;
        free(section_header);
        free(sym_table);
        fclose(file);
        return sym_addr;
    }
    if(Global && !In_Exe && Found){

        *error_val = -4;


        int dynsym_ndx = -1;
        int num_of_dyn_symb = 0;
       

        Elf64_Shdr header_section_header_string_table = section_header[header.e_shstrndx];
        char *section_header_string_table = (char *)malloc(header_section_header_string_table.sh_size);
        fseek(file, header_section_header_string_table.sh_offset, SEEK_SET);
        fread(section_header_string_table, header_section_header_string_table.sh_size, 1, file);

        for (int i = 0; i < header.e_shnum; i++) {
            if (strcmp(section_header_string_table + section_header[i].sh_name, ".dynsym") == 0) {
                dynsym_ndx = i;
		break;
		
            }
		
		
        }

        //find the dynamic symbol table
        Elf64_Shdr dynsymSection = section_header[dynsym_ndx];
        Elf64_Sym* dynsymbolTable = (Elf64_Sym*)malloc(dynsymSection.sh_size);
        fseek(file, dynsymSection.sh_offset, SEEK_SET);
        fread(dynsymbolTable,  dynsymSection.sh_size , 1, file);
        int symbolCount = dynsymSection.sh_size / dynsymSection.sh_entsize;


        //find the dynamic string table
        Elf64_Shdr dynstrtabSection = section_header[section_header[dynsym_ndx].sh_link];
        char *dynstr_table = (char *)malloc(dynstrtabSection.sh_size);
        fseek(file, dynstrtabSection.sh_offset, SEEK_SET);
        fread(dynstr_table, dynstrtabSection.sh_size, 1, file);


        //find the relocation section
        int rel_ndx;

        for (j = 0; j < header.e_shnum; j++) {
           if(strcmp(".rela.plt", section_header_string_table + section_header[j].sh_name) == 0) {
                rel_ndx = j;
                break;
            }
        }
        Elf64_Shdr relSection = section_header[rel_ndx];

        //find the relocation table
        Elf64_Rela* relocationTable;
        relocationTable = (Elf64_Rela*)malloc(relSection.sh_size);
        int relocationCount = relSection.sh_size / relSection.sh_entsize;
        fseek(file, relSection.sh_offset, SEEK_SET);
        fread(relocationTable ,relSection.sh_size,  1 ,file);

        int symbol_len = strlen(symbol_name) + 1;
        for( i = 0; i < symbolCount ; i++){
            fseek(file, dynstrtabSection.sh_offset + dynsymbolTable[i].st_name, SEEK_SET);
            char* symbol_to_compare = (char *)malloc(sizeof(char ) * symbol_len);
            fread(symbol_to_compare, sizeof(char), symbol_len ,file);           

	if(strcmp(symbol_to_compare, symbol_name) == 0) {
                index_of_our_symbol = i;
            }

            free(symbol_to_compare);
        }

        for (int i = 0; i < relocationCount; i++) {
            Elf64_Rela relocationEntry = relocationTable[i];
            int symbolIndex = ELF64_R_SYM(relocationEntry.r_info);

            if (symbolIndex == index_of_our_symbol) {
                sym_addr = relocationEntry.r_offset;
                free(dynstr_table);
                free(dynsymbolTable);
                free(relocationTable);
                free(section_header);
		free(sym_table);
		free(section_header_string_table);
                fclose(file);
                return sym_addr;
            }
        }


    }
    if (!Found){
        *error_val = -1;
    }

    free(section_header);
    free(sym_table);
    fclose(file);

    return 0;
}

pid_t runTarget(char *const argv[])
{
    pid_t pid;
    pid = fork();

    if (pid > 0) {
        return pid;
    }
    else if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            exit(1);
        }
        execv(argv[2], &argv[2]);
    } else {
        exit(1);
    }
}

long AddBreakPoint(unsigned long func_address, pid_t child_pid)
{
    long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)func_address, NULL);
    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void *)func_address, (void *)data_trap);
    return data;
}

void removeBreakpoint(pid_t child_pid, unsigned long func_addr, unsigned long data)
{
    ptrace(PTRACE_POKETEXT, child_pid, (void *)func_addr, (void *)data);
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
    regs.rip --;
    ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
}


void singleStep(pid_t child_pid)
{
    int wait_status;
    ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0);
    wait(&wait_status);
}



void runDebugger(pid_t child_pid, unsigned long functionAddress, bool isDynamic)
{
    int wait_status;
    struct user_regs_struct regs;
    unsigned long got = 0;
    int counterOfCalls = 0;
  //  int counter_for_recursion = 0;

    wait(&wait_status);

    if (isDynamic) {
        got = functionAddress;
        functionAddress = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)got, NULL);
    }
    long functionStart = AddBreakPoint(functionAddress, child_pid);
    
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    wait(&wait_status);
    
    while (WIFSTOPPED(wait_status))
    {
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        if (regs.rip - 1 == functionAddress)
        {
		counterOfCalls++;
            ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
            printf("PRF:: run #%d first parameter is %d\n",  counterOfCalls , ( int)regs.rdi);


		    removeBreakpoint(child_pid, functionAddress, functionStart);
		    unsigned long rspRetAddress = regs.rsp;
            unsigned long returnAddress = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) rspRetAddress, NULL);
		    long infoReturn = AddBreakPoint(returnAddress, child_pid);
		
		    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
		    wait(&wait_status);

		    unsigned long stackAddress = regs.rsp + 8;
		    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
	    	while (regs.rsp != stackAddress)
		    {
                removeBreakpoint(child_pid, returnAddress, infoReturn);
                singleStep(child_pid);
                infoReturn = AddBreakPoint(returnAddress, child_pid);
                ptrace(PTRACE_CONT, child_pid, NULL, NULL);
                wait(&wait_status);
                ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
		    }
		
		    removeBreakpoint(child_pid, returnAddress, infoReturn);
 	        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
			
		    printf("PRF:: run #%d returned with %d\n", counterOfCalls, ( int)regs.rax);
		    if (counterOfCalls == 1 && isDynamic) {
		        functionAddress = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)got, NULL);
		    }
		    functionStart = AddBreakPoint(functionAddress, child_pid);
		    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
		    wait(&wait_status);
		
	} else {
	       ptrace(PTRACE_CONT, child_pid, NULL, NULL);
	       wait(&wait_status);
	       continue;
          }

    }
}

int main(int argc, char *argv[])
{
    int err = 1;
    unsigned long addr = find_symbol(argv[1], argv[2], &err);
    
    if (err == -2) {
        printf("PRF:: %s is not a global symbol!\n", argv[1]);
        return 0;
    }
    else if (err == -1) {
	printf("PRF:: %s not found! :(\n", argv[1]);
	return 0;
    }
    else if (err == -3)
    {
        printf("PRF:: %s not an executable!\n", argv[2]);
        return 0;
    }
    else {
	    pid_t child_pid = runTarget(argv);
	    runDebugger(child_pid, addr, err == -4);
    }
    return 0;
}
