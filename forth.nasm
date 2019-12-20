;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; A Forth by Chris Hinsley
;; Modified by Mike Schwartz to support 64 bits and Linux
;;
;; nasm -f macho forth.nasm
;; ld -o forth -e _main forth.o
;; ./forth
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	%define VERSION_NUM 30

	; various buffer area sizes
	%define DATA_STACK_SIZE 1024
	%define USER_DEFS_SIZE (64*1024)
	%define NUM_HASH_CHAINS 64
	%define MAX_LINE_SIZE 128

%ifdef MACOS
	%define SYS_exit 1
	%define SYS_read 3
	%define SYS_write 4
	%define SYS_open 5
	%define SYS_close 6
	%define SYS_unlink 10
	%define SYS_mprotect 74
	%define SYS_fsync 95
	%define SYS_rename 128
	%define SYS_stat 188
	%define SYS_lseek 199
	%define SYS_fstat 189
	%define SYS_ftruncate 201
%else
	%define SYS_exit 60
	%define SYS_read 0
	%define SYS_write 1
	%define SYS_open 2
	%define SYS_close 3
	%define SYS_unlink 87
	%define SYS_mprotect 10
	%define SYS_fsync 74
	%define SYS_rename 82
	%define SYS_stat 4
	%define SYS_lseek 8
	%define SYS_fstat 5
	%define SYS_ftruncate 77
%endif
%define PROT_READ 0x01		;pages can be read
%define PROT_WRITE 0x02		;pages can be written
%define PROT_EXEC 0x04		;pages can be executed
%define PROT_ALL (PROT_READ | PROT_WRITE | PROT_EXEC)
%define PAGE_SIZE 4096

;;;;;;;;;;;;;;;;;;;;;;;;;;
; some NASM codeing macros
;;;;;;;;;;;;;;;;;;;;;;;;;;

	%macro loopstart 0
		%push loopstart
	%$loop_start:
	%endmacro

	%macro break 0
		jmp %$loop_exit
	%endmacro

	%macro breakif 1
		j%+1 %$loop_exit
	%endmacro

	%macro loopend 0
		jmp %$loop_start
	%$loop_exit:
		%pop
	%endmacro

	%macro repeat 0
		%push repeat
	%$loop_start:
	%endmacro

	%macro until 1
		j%-1 %$loop_start
	%$loop_exit:
		%pop
	%endmacro

	%macro if 1
		%push if
		j%-1 %$ifnot
	%endmacro

	%macro else 0
		%ifctx if
			%repl else
			jmp %$ifend
		%$ifnot:
		%else
			%error "expected `if' before `else'"
		%endif
	%endmacro

	%macro endif 0
		%ifctx if
		%$ifnot:
			%pop
		%elifctx else
		%$ifend:
			%pop
		%else
			%error "expected `if' or `else' before `endif'"
		%endif
	%endmacro

;;;;;;;;;;;;;;;;
; base VM macros
;;;;;;;;;;;;;;;;

	; eip	Forths IP
	; rsp	Forths R
	; rbp	Forths S
	; rbx	Forths TOS

	; push on to return stack
	%macro PUSHRSP 1
		push %1
	%endm

	; pop top of return stack
	%macro POPRSP 1
		pop %1
	%endm

	; save into return stack
	%macro PUTRSP 2
		%if (%2 = 0)
			mov [rsp], %1
		%elif ((%2 >= -128) && (%2 < 128))
			mov [byte rsp + %2], %1
		%else
			mov [long rsp + %2], %1
		%endif
	%endm

	; load from return stack
	%macro PICKRSP 2
		%if (%2 = 0)
			mov %1, [rsp]
		%elif ((%2 >= -128) && (%2 < 128))
			mov %1, [byte rsp + %2]
		%else
			mov %1, [long rsp + %2]
		%endif
	%endm

	; set return stack
	%macro SETRSP 1
		mov rsp, %1
	%endm

	; get return stack
	%macro GETRSP 1
		mov %1, rsp
	%endm

	; adjust return stack
	%macro ADDRSP 1
		%if ((%1 >= -128) && (%1 < 128))
			add rsp, byte %1
		%else
			add rsp, %1
		%endif
	%endm

	; push on to data stack
	%macro PUSHDSP 1
		sub rbp, byte 4
		mov [rbp], %1
	%endm

	; pop top of data stack
	%macro POPDSP 1
		mov %1, [rbp]
		add rbp, byte 4
	%endm

	; save into data stack
	%macro PUTDSP 2
		%if (%2 = 0)
			mov [rbp], %1
		%elif ((%2 >= -128) && (%2 < 128))
			mov [byte rbp + %2], %1
		%else
			mov [long rbp + %2], %1
		%endif
	%endm

	; load from data stack
	%macro PICKDSP 2
		%if (%2 = 0)
			mov %1, [rbp]
		%elif ((%2 >= -128) && (%2 < 128))
			mov %1, [byte rbp + %2]
		%else
			mov %1, [long rbp + %2]
		%endif
	%endm

	; set data stack
	%macro SETDSP 1
		mov rbp, %1
	%endm

	; get data stack
	%macro GETDSP 1
		mov %1, rbp
	%endm

	; adjust data stack
	%macro ADDDSP 1
		%if ((%1 >= -128) && (%1 < 128))
			add rbp, byte %1
		%else
			add rbp, %1
		%endif
	%endm

	; load value onto data stack
	%macro LOADTOS 1
		PUSHDSP rbx
		mov rbx, %1
	%endm

	; move from data to return stack
	%macro TORSP 0
		PUSHRSP rbx
		POPDSP rbx
	%endm

	; move from return to data stack
	%macro FROMRSP 0
		PUSHDSP rbx
		POPRSP rbx
	%endm

	; copy from return to data stack
	%macro FETCHRSP 0
		PUSHDSP rbx
		PICKRSP rbx, 0
	%endm

	; align reg
	%define DP_ALIGN 3
	%macro ALIGNREG 1
		add %1, byte DP_ALIGN
		and %1, byte ~DP_ALIGN
	%endm

;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; dictionary building macros
;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	; format of dictionary entry flag byte
	%define F_IMMED 0x80
	%define F_HIDDEN 0x20
	%define F_LENMASK 0x1f

	%define NULL 0
	%define H_LLINK 0
	%define H_HLINK 4
	%define H_NSIZE 8
	%define H_NAME 9

	%define XT_BODY -12
	%define XT_LENGTH -8
	%define XT_COMPILE -4
	%define XT_SIZE 12
	
	%macro defword 4
		%push newword
		%strlen len %1
		align 4
	dic_%3:
		dd NULL				; LATEST list link
		dd NULL				; hash chain link
		db len + %2			; flags + length byte
		db %1				; the name
		dd %3				; body pointer
		dd %$code_end - %3	; code length
		dd %4				; compile action word
    global %3
	%3:
	%endm					; assembler code follows

	%macro defword_end 0
	%$code_end:
		%pop
	%endm

	%macro defvar 4
		defword %1, %2, %3, WORD_INLINE_COMMA
		LOADTOS var_%3
		ret
		defword_end
		align 4
	var_%3:
		dd %4
	%endm

	%macro defvar2 5
		defword %1, %2, %3, WORD_INLINE_COMMA
		LOADTOS var_%3
		ret
		defword_end
		align 4
	var_%3:
		dd %4
		dd %5
	%endm

	%macro defconst 4
		defword %1, %2, %3, WORD_INLINE_COMMA
		LOADTOS %4
		ret
		defword_end
	%endm

;;;;;;;;;;;;;;;;;;;;;;;;;;
; entry point
;;;;;;;;;;;;;;;;;;;;;;;;;;

	SECTION .text
	global _main
_main:
%ifdef MACOS
	; use mprotect to allow read/write/execute of the data section
	mov rdx, forth_start
	and rdx, -PAGE_SIZE		;start address
	mov rcx, forth_end
	sub rcx, rdx			;length
	mov rbx, PROT_ALL		;flags
	push rbx
	push rcx
	push rdx
	push 0					;padding
	mov rax, SYS_mprotect
	int 0x80
	add rsp, 16
%endif
	jmp forth_start

	SECTION .data
forth_start:
	; init data and return stacks, saving initial positions
	; in Forth vars R0 and S0
	cld
	GETRSP [var_WORD_SZ]
	SETDSP [var_WORD_SZ]
	ADDRSP -DATA_STACK_SIZE
	GETRSP [var_WORD_RZ]

	; link built in dictionary
	mov rsi, dictionary_start
	xor rdi, rdi
	repeat
		lodsd
		mov [rax + H_LLINK], rdi
		mov rdi, rax
		push rsi
		mov cl, [rax + H_NSIZE]
		and rcx, F_LENMASK
		lea rsi, [rax + H_NAME]
		call strhashi
		and rbx, NUM_HASH_CHAINS-1
		mov rsi, hash_buckets
		mov rax, [rsi + (rbx * 4)]
		mov [rsi + (rbx * 4)], rdi
		mov [rdi + H_HLINK], rax
		pop rsi
		cmp rsi, dictionary_end
	until z
	mov [var_WORD_LATEST], rdi

	; run temp interpreter loop till we can get into the real QUIT word
	call WORD_LBRAC			; interpret state
	LOADTOS 666q			; octal !
	TORSP
	LOADTOS 0
	TORSP
	LOADTOS bootfile
	TORSP
	call WORD_SYS_OPEN
	call WORD_SYSCALL
	ADDRSP 12
	TORSP					; ( fd ) of "forth.f"
	loopstart
		LOADTOS tib_buffer
		LOADTOS MAX_LINE_SIZE
		FETCHRSP			; ( c-addr len fd )
		call WORD_READLINE	; ( num flag flag )
		call WORD_DROP2
		LOADTOS tib_buffer
		call WORD_SWAP
		call WORD_INHASH
		call WORD_STORE2
		LOADTOS 0
		call WORD_TOIN
		call WORD_STORE
		call WORD_INTERPRET
	loopend					; and loop till QUIT takes over

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; a few case insensative string operations
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	%macro to_lower 1
		; lower case check
		cmp %1, 'A'
		if ge
			cmp %1, 'Z'
			if le
				; make it lower case
				add %1, byte 'a' - 'A'
			endif
		endif
	%endm

strcpyi:
	test rcx, rcx
	if nz
	strcpyi_l1:
		lodsb
		to_lower al
		stosb
		loop strcpyi_l1
	endif
	ret

strcmpi:
	test rcx, rcx
	if nz
	strcmpi_l1:
		lodsb
		mov bl, [rdi]
		lea rdi, [rdi + 1]
		to_lower al
		to_lower bl
		cmp bl, al
		if z
			loop strcmpi_l1
		endif
	endif
	ret

;;;;;;;;;;;;;;;
; hash function
;;;;;;;;;;;;;;;

strhashi:
	mov rbx, 5381
	test rcx, rcx
	if nz
		mov rdx, 33
	strhashi_l1:
		lodsb
		movzx rax, al
		to_lower rax
		imul rbx, rdx
		add rbx, rax
		loop strhashi_l1
	endif
	ret

;;;;;;;;;;;;;;;;;;;
; syscall functions
;;;;;;;;;;;;;;;;;;;

_syscall:
	int 0x80
	if c
		neg rax
	endif
	ret

_lsyscall:
	int 0x80
	if c
		not rax
		not rdx
		add rax, 1
		adc rdx, 0
	endif
	ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; built in variables
; STATE		Is the interpreter executing code (0) or compiling a word (non-zero)?
; LATEST	Points to the latest (most recently defined) word in the dictionary.
; DP		Points to the next free byte of memory. When compiling, compiled words go here.
; S0		Stores the address of the top of the parameter stack.
; R0		The address of the top of the return stack.
; BASE		The current base for printing and reading numbers.
; #IN		The current input buffer descriptor.
; >IN		The current input offset.
; SOURCEFD	The current input source file descriptor.
; BLK		The current block number.
; CHARBUF	Single char buffer.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	defvar "state", 0, WORD_STATE, 0
	defvar "dp", 0, WORD_DP, dictionary_start
	defvar "latest", 0, WORD_LATEST, 0
	defvar "s0", 0, WORD_SZ, 0
	defvar "r0", 0, WORD_RZ, 0
	defvar "base", 0, WORD_BASE, 10
	defvar2 "#IN", 0, WORD_INHASH, 0, 0
	defvar ">in", 0, WORD_TOIN, 0
	defvar "sourcefd", 0, WORD_SOURCEFD, 0
	defvar "blk", 0, WORD_BLK, 0
	defvar "charbuf", 0, WORD_CHARBUF, 0

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; built in constants
; VERSION		The current version of this FORTH.
; WORDBUF		The address of the buffer WORD uses.
; LINESIZE		The line buffer size.
; F_IMMED		The IMMEDIATE flag's actual value.
; F_HIDDEN		The HIDDEN flag's actual value.
; F_LENMASK		The length mask in the flags/len byte.
; H_NSIZE		The flags/len field offset.
; H_NAME		The name field offset.
; XT_BODY		The xt body pointer.
; XT_LENGTH		The xt length field offset.
; XT_COMPILE	The xt compile field offset.
; XT_SIZE		The xt size offset.
; SYS_*			The numeric codes of various syscalls.
; O_*			Various sycall flags/modes.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	defconst "version", 0, WORD_VERSION, VERSION_NUM
	defconst "wordbuf", 0, WORD_WORDBUF, word_buf
	defconst "linesize", 0, WORD_LINESIZE, MAX_LINE_SIZE
	defconst "f_immed", 0, WORD__F_IMMED, F_IMMED
	defconst "f_hidden", 0, WORD__F_HIDDEN, F_HIDDEN
	defconst "f_lenmask", 0, WORD__F_LENMASK, F_LENMASK
	defconst "h_nsize", 0, WORD__H_NSIZE, H_NSIZE
	defconst "h_name", 0, WORD__H_NAME, H_NAME
	defconst "xt_body", 0, WORD__XT_BODY, XT_BODY
	defconst "xt_length", 0, WORD__XT_LENGTH, XT_LENGTH
	defconst "xt_compile", 0, WORD__XT_COMPILE, XT_COMPILE
	defconst "xt_size", 0, WORD__XT_SIZE, XT_SIZE

	defconst "sys_exit", 0, WORD_SYS_EXIT, SYS_exit
	defconst "sys_open", 0, WORD_SYS_OPEN, SYS_open
	defconst "sys_close", 0, WORD_SYS_CLOSE, SYS_close
	defconst "sys_read", 0, WORD_SYS_READ, SYS_read
	defconst "sys_write", 0, WORD_SYS_WRITE, SYS_write
	defconst "sys_unlink", 0, WORD_SYS_UNLINK, SYS_unlink
	defconst "sys_rename", 0, WORD_SYS_RENAME, SYS_rename
	defconst "sys_ftruncate", 0, WORD_SYS_FTRUNCATE, SYS_ftruncate
	defconst "sys_fsync", 0, WORD_SYS_FSYNC, SYS_fsync
	defconst "sys_lseek", 0, WORD_SYS_LSEEK, SYS_lseek
	defconst "sys_fstat", 0, WORD_SYS_FSTAT, SYS_fstat
	defconst "sys_stat", 0, WORD_SYS_STAT, SYS_stat

	defconst "o_rdonly", 0, WORD_O_RDONLY, 0x0
	defconst "o_wronly", 0, WORD_O_WRONLY, 0x1
	defconst "o_rdwr", 0, WORD_O_RDWR, 0x2
	defconst "o_creat", 0, WORD_O_CREAT, 0x100
	defconst "o_excl", 0, WORD_O_EXCL, 0x200
	defconst "o_trunc", 0, WORD_O_TRUNC, 0x1000
	defconst "o_append", 0, WORD_O_APPEND, 0x2000
	defconst "o_nonblock", 0, WORD_O_NONBLOCK, 0x4000

;;;;;;;;;;;;;;;;;;;;;;;;;;;
; data stack ordering words
;;;;;;;;;;;;;;;;;;;;;;;;;;;

	defword "dsp@", 0, WORD_DSPFETCH, WORD_INLINE_COMMA
	PUSHDSP rbx
	GETDSP rbx
	ret
	defword_end

	defword "dsp!", 0, WORD_DSPSTORE, WORD_INLINE_COMMA
	SETDSP rbx
	POPDSP rbx
	ret
	defword_end

	defword "drop", 0, WORD_DROP, WORD_INLINE_COMMA
	POPDSP rbx
	ret
	defword_end

	defword "swap", 0, WORD_SWAP, WORD_INLINE_COMMA
	xchg rbx, [rbp]
	ret
	defword_end

	defword "dup", 0, WORD_DUP, WORD_INLINE_COMMA
	PUSHDSP rbx
	ret
	defword_end

	defword "over", 0, WORD_OVER, WORD_INLINE_COMMA
	PUSHDSP rbx
	PICKDSP rbx, 4
	ret
	defword_end

	defword "rot", 0, WORD_ROT, WORD_INLINE_COMMA
	mov rax, rbx
	PICKDSP rcx, 0
	PICKDSP rbx, 4
	PUTDSP rax, 0
	PUTDSP rcx, 4
	ret
	defword_end

	defword "-rot", 0, WORD_NROT, WORD_INLINE_COMMA
	mov rax, rbx
	PICKDSP rbx, 0
	PICKDSP rcx, 4
	PUTDSP rcx, 0
	PUTDSP rax, 4
	ret
	defword_end

	defword "2drop", 0, WORD_DROP2, WORD_INLINE_COMMA
	PICKDSP rbx, 4
	ADDDSP 8
	ret
	defword_end

	defword "2dup", 0, WORD_DUP2, WORD_INLINE_COMMA
	PICKDSP rax, 0
	ADDDSP -8
	PUTDSP rax, 0
	PUTDSP rbx, 4
	ret
	defword_end

	defword "2swap", 0, WORD_SWAP2, WORD_INLINE_COMMA
	mov rax, rbx
	PICKDSP rcx, 0
	PICKDSP rbx, 4
	PICKDSP rdx, 8
	PUTDSP rdx, 0
	PUTDSP rax, 4
	PUTDSP rcx, 8
	ret
	defword_end

	defword "2rot", 0, WORD_ROT2, WORD_INLINE_COMMA
	mov rax, rbx
	PICKDSP rcx, 16
	PICKDSP rbx, 12
	PICKDSP rdx, 8
	PICKDSP rdi, 4
	PICKDSP rsi, 0
	PUTDSP rdx, 16
	PUTDSP rdi, 12
	PUTDSP rsi, 8
	PUTDSP rax, 4
	PUTDSP rcx, 0
	ret
	defword_end

	defword "?dup", 0, WORD_QDUP, WORD_INLINE_COMMA
	test rbx, rbx
	if nz
		PUSHDSP rbx
	endif
	ret
	defword_end

	defword "!?dup", 0, WORD_NQDUP, WORD_INLINE_COMMA
	test rbx, rbx
	if z
		PUSHDSP rbx
	endif
	ret
	defword_end

	defword "nip", 0, WORD_NIP, WORD_INLINE_COMMA
	ADDDSP 4
	ret
	defword_end

	defword "tuck", 0, WORD_TUCK, WORD_INLINE_COMMA
	PICKDSP rax, 0
	PUTDSP rbx, 0
	PUSHDSP rax
	ret
	defword_end

	defword "pick", 0, WORD_PICK, WORD_INLINE_COMMA
	mov rbx, [rbp + (rbx * 4)]
	ret
	defword_end

	defword "2tuck", 0, WORD_TUCK2, WORD_INLINE_COMMA
	PICKDSP rax, 0
	PICKDSP rcx, 4
	PICKDSP rdx, 8
	ADDDSP -8
	PUTDSP rax, 0
	PUTDSP rcx, 4
	PUTDSP rdx, 8
	PUTDSP rbx, 12
	PUTDSP rax, 16
	ret
	defword_end

	defword "2nip", 0, WORD_NIP2, WORD_INLINE_COMMA
	PICKDSP rax, 0
	ADDDSP 8
	PUTDSP rax, 0
	ret
	defword_end

	defword "2over", 0, WORD_OVER2, WORD_INLINE_COMMA
	ADDDSP -8
	PUTDSP rbx, 4
	PICKDSP rbx, 16
	PUTDSP rbx, 0
	PICKDSP rbx, 12
	ret
	defword_end

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; return stack ordering words
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	defword ">r", 0, WORD_TOR, WORD_INLINE_COMMA
	TORSP
	ret
	defword_end

	defword "r>", 0, WORD_FROMR, WORD_INLINE_COMMA
	FROMRSP
	ret
	defword_end

	defword "2>r", 0, WORD_TOR2, WORD_INLINE_COMMA
	ADDRSP -8
	PICKDSP rcx, 0
	PUTRSP rbx, 0
	PUTRSP rcx, 4
	PICKDSP rbx, 4
	ADDDSP 8
	ret
	defword_end

	defword "2r>", 0, WORD_FROMR2, WORD_INLINE_COMMA
	ADDDSP -8
	PUTDSP rbx, 4
	PICKRSP rbx, 0
	PICKRSP rcx, 4
	PUTDSP rcx, 0
	ADDRSP 8
	ret
	defword_end

	defword "rsp@", 0, WORD_RSPFETCH, WORD_INLINE_COMMA
	PUSHDSP rbx
	GETRSP rbx
	ret
	defword_end

	defword "r@", 0, WORD_RFETCH, WORD_INLINE_COMMA
	PUSHDSP rbx
	PICKRSP rbx, 0
	ret
	defword_end

	defword "r!", 0, WORD_RSTORE, WORD_INLINE_COMMA
	PUTRSP rbx, 0
	POPDSP rbx
	ret
	defword_end

	defword "2r@", 0, WORD_RFETCH2, WORD_INLINE_COMMA
	ADDDSP -8
	PUTDSP rbx, 4
	PICKRSP rbx, 4
	PICKRSP rcx, 0
	PUTDSP rcx, 0
	ret
	defword_end

	defword "rsp!", 0, WORD_RSPSTORE, WORD_INLINE_COMMA
	SETRSP rbx
	POPDSP rbx
	ret
	defword_end

	defword "rdrop", 0, WORD_RDROP, WORD_INLINE_COMMA
	ADDRSP 4
	ret
	defword_end

	defword "2rdrop", 0, WORD_RDROP2, WORD_INLINE_COMMA
	ADDRSP 8
	ret
	defword_end

	defword "n>r", 0, WORD_NTOR, WORD_CALL_COMMA
	PUSHDSP rbx
	PICKRSP rax, 0
	mov rcx, rbx
	inc rcx
	neg rbx
	lea rsp, [rsp + (rbx * 4)]
	mov rsi, rbp
	mov rdi, rsp
	rep movsd
	mov rbp, rsi
	POPDSP rbx
	jmp rax
	defword_end

	defword "nr>", 0, WORD_NFROMR, WORD_CALL_COMMA
	PUSHDSP rbx
	POPRSP rax
	PICKRSP rbx, 0
	inc rbx
	mov rcx, rbx
	neg rbx
	lea rbp, [rbp + (rbx * 4)]
	mov rsi, rsp
	mov rdi, rbp
	rep movsd
	mov rsp, rsi
	POPDSP rbx
	jmp rax
	defword_end

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; memory fetch and store words
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	defword "!", 0, WORD_STORE, WORD_INLINE_COMMA
	PICKDSP rax, 0
	mov [rbx], rax
	PICKDSP rbx, 4
	ADDDSP 8
	ret
	defword_end

	defword "@", 0, WORD_FETCH, WORD_INLINE_COMMA
	mov rbx, [rbx]
	ret
	defword_end

	defword "+!", 0, WORD_ADDSTORE, WORD_INLINE_COMMA
	PICKDSP rax, 0
	add [rbx], rax
	PICKDSP rbx, 4
	ADDDSP 8
	ret
	defword_end

	defword "-!", 0, WORD_SUBSTORE, WORD_INLINE_COMMA
	PICKDSP rax, 0
	sub [rbx], rax
	PICKDSP rbx, 4
	ADDDSP 8
	ret
	defword_end

	defword "c!", 0, WORD_STOREBYTE, WORD_INLINE_COMMA
	PICKDSP rax, 0
	mov [rbx], al
	PICKDSP rbx, 4
	ADDDSP 8
	ret
	defword_end

	defword "c+!", 0, WORD_ADDBYTE, WORD_INLINE_COMMA
	PICKDSP rax, 0
	add [rbx], al
	PICKDSP rbx, 4
	ADDDSP 8
	ret
	defword_end

	defword "c@", 0, WORD_FETCHBYTE, WORD_INLINE_COMMA
	mov rax, rbx
	xor rbx, rbx
	mov bl, [rax]
	ret
	defword_end

	defword "w!", 0, WORD_STORESHORT, WORD_INLINE_COMMA
	PICKDSP rax, 0
	mov [rbx], ax
	PICKDSP rbx, 4
	ADDDSP 8
	ret
	defword_end

	defword "w@", 0, WORD_FETCHSHORT, WORD_INLINE_COMMA
	mov rax, rbx
	xor rbx, rbx
	mov bx, [rax]
	ret
	defword_end

	defword "2!", 0, WORD_STORE2, WORD_INLINE_COMMA
	PICKDSP rcx, 4
	PICKDSP rdx, 0
	mov [rbx + 4], rcx
	mov [rbx], rdx
	PICKDSP rbx, 8
	ADDDSP 12
	ret
	defword_end

	defword "2@", 0, WORD_FETCH2, WORD_INLINE_COMMA
	ADDDSP -4
	mov rcx, [rbx +4]
	mov rbx, [rbx]
	PUTDSP rcx, 0
	ret
	defword_end

	defword "blank", 0, WORD_BLANK, WORD_CALL_COMMA
	mov rcx, rbx
	PICKDSP rbx, 4
	PICKDSP rdi, 0
	ADDDSP 8
	mov rax, 0x20
	rep stosb
	ret
	defword_end

	defword "erase", 0, WORD_ERASE, WORD_CALL_COMMA
	mov rcx, rbx
	PICKDSP rbx, 4
	PICKDSP rdi, 0
	ADDDSP 8
	xor rax, rax
	rep stosb
	ret
	defword_end

	defword "fill", 0, WORD_FILL, WORD_CALL_COMMA
	mov rax, rbx
	PICKDSP rbx, 8
	PICKDSP rdi, 4
	PICKDSP rcx, 0
	ADDDSP 12
	rep stosb
	ret
	defword_end

	defword "cmove>", 0, WORD_CMOVEB, WORD_CALL_COMMA
	mov rcx, rbx
	PICKDSP rbx, 8
	PICKDSP rsi, 4
	PICKDSP rdi, 0
	ADDDSP 12
	lea rsi, [rsi + rcx - 1]
	lea rdi, [rdi + rcx - 1]
	std
	rep movsb
	cld
	ret
	defword_end

	defword "cmove", 0, WORD_CMOVE, WORD_CALL_COMMA
	mov rcx, rbx
	PICKDSP rbx, 8
	PICKDSP rsi, 4
	PICKDSP rdi, 0
	ADDDSP 12
	rep movsb
	ret
	defword_end

	defword "move", 0, WORD_MOVE, WORD_CALL_COMMA
	mov rcx, rbx
	PICKDSP rbx, 8
	PICKDSP rsi, 4
	PICKDSP rdi, 0
	ADDDSP 12
	cmp rsi, rdi
	if a
		rep movsb
	else
		lea rsi, [rsi + rcx -1]
		lea rdi, [rdi + rcx -1]
		std
		rep movsb
		cld
	endif
	ret
	defword_end

;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; single precision alu words
;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	defword "+", 0, WORD_ADD, WORD_INLINE_COMMA
	add rbx, [rbp]
	ADDDSP 4
	ret
	defword_end

	defword "-", 0, WORD_SUB, WORD_INLINE_COMMA
	mov rax, rbx
	POPDSP rbx
	sub rbx, rax
	ret
	defword_end

	defword "*", 0, WORD_MULL, WORD_INLINE_COMMA
	imul rbx, [rbp]
	ADDDSP 4
	ret
	defword_end

	defword "/", 0, WORD_DIV, WORD_INLINE_COMMA
	POPDSP rax
	cdq
	idiv rbx
	mov rbx, rax
	ret
	defword_end

	defword "mod", 0, WORD_MOD, WORD_INLINE_COMMA
	POPDSP rax
	cdq
	idiv rbx
	mov rbx, rdx
	ret
	defword_end

	defword "1+", 0, WORD_INCR, WORD_INLINE_COMMA
	add rbx, byte 1
	ret
	defword_end

	defword "1-", 0, WORD_DECR, WORD_INLINE_COMMA
	sub rbx, byte 1
	ret
	defword_end

	defword "4+", 0, WORD_INCR4, WORD_INLINE_COMMA
	add rbx, byte 4
	ret
	defword_end

	defword "4-", 0, WORD_DECR4, WORD_INLINE_COMMA
	sub rbx, byte 4
	ret
	defword_end

	defword "2+", 0, WORD_INCR2, WORD_INLINE_COMMA
	add rbx, byte 2
	ret
	defword_end

	defword "2-", 0, WORD_DECR2, WORD_INLINE_COMMA
	sub rbx, byte 2
	ret
	defword_end

	defword "2*", 0, WORD_TWOMUL, WORD_INLINE_COMMA
	shl rbx, byte 1
	ret
	defword_end

	defword "2/", 0, WORD_TWODIV, WORD_INLINE_COMMA
	sar rbx, byte 1
	ret
	defword_end

	defword "abs", 0, WORD_ABS, WORD_INLINE_COMMA
	mov rax, rbx
	sar rax, byte 31
	add rbx, rax
	xor rbx, rax
	ret
	defword_end

	defword "min", 0, WORD_MIN, WORD_INLINE_COMMA
	POPDSP rax
	cmp rbx, rax
	if g
		mov rbx, rax
	endif
	ret
	defword_end

	defword "max", 0, WORD_MAX, WORD_INLINE_COMMA
	POPDSP rax
	cmp rbx, rax
	if l
		mov rbx, rax
	endif
	ret
	defword_end

	defword "lshift", 0, WORD_LSHIFT, WORD_INLINE_COMMA
	mov rcx, rbx
	POPDSP rbx
	shl rbx, cl
	ret
	defword_end

	defword "rshift", 0, WORD_RSHIFT, WORD_INLINE_COMMA
	mov rcx, rbx
	POPDSP rbx
	shr rbx, cl
	ret
	defword_end

	defword "and", 0, WORD_AND, WORD_INLINE_COMMA
	and rbx, [rbp]
	ADDDSP 4
	ret
	defword_end

	defword "or", 0, WORD_OR, WORD_INLINE_COMMA
	or rbx, [rbp]
	ADDDSP 4
	ret
	defword_end

	defword "xor", 0, WORD_XOR, WORD_INLINE_COMMA
	xor rbx, [rbp]
	ADDDSP 4
	ret
	defword_end

	defword "negate", 0, WORD_NEGATE, WORD_INLINE_COMMA
	neg rbx
	ret
	defword_end

	defword "invert", 0, WORD_INVERT, WORD_INLINE_COMMA
	not rbx
	ret
	defword_end

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; single precision comparision words
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	defword "=", 0, WORD_EQ, WORD_INLINE_COMMA
	cmp [rbp], rbx
	sete bl
	ADDDSP 4
	movzx rbx, bl
	neg rbx
	ret
	defword_end

	defword "<>", 0, WORD_NE, WORD_INLINE_COMMA
	cmp [rbp], rbx
	setne bl
	ADDDSP 4
	movzx rbx, bl
	neg rbx
	ret
	defword_end

	defword "<", 0, WORD_LT, WORD_INLINE_COMMA
	cmp [rbp], rbx
	setl bl
	ADDDSP 4
	movzx rbx, bl
	neg rbx
	ret
	defword_end

	defword ">", 0, WORD_GT, WORD_INLINE_COMMA
	cmp [rbp], rbx
	setg bl
	ADDDSP 4
	movzx rbx, bl
	neg rbx
	ret
	defword_end

	defword "u<", 0, WORD_ULT, WORD_INLINE_COMMA
	cmp [rbp], rbx
	setb bl
	ADDDSP 4
	movzx rbx, bl
	neg rbx
	ret
	defword_end

	defword "u>", 0, WORD_UGT, WORD_INLINE_COMMA
	cmp [rbp], rbx
	seta bl
	ADDDSP 4
	movzx rbx, bl
	neg rbx
	ret
	defword_end

	defword "u<=", 0, WORD_ULTEQ, WORD_INLINE_COMMA
	cmp [rbp], rbx
	setbe bl
	ADDDSP 4
	movzx rbx, bl
	neg rbx
	ret
	defword_end

	defword "u>=", 0, WORD_UGTEQ, WORD_INLINE_COMMA
	cmp [rbp], rbx
	setae bl
	ADDDSP 4
	movzx rbx, bl
	neg rbx
	ret
	defword_end

	defword "<=", 0, WORD_LTEQ, WORD_INLINE_COMMA
	cmp [rbp], rbx
	setle bl
	ADDDSP 4
	movzx rbx, bl
	neg rbx
	ret
	defword_end

	defword ">=", 0, WORD_GTEQ, WORD_INLINE_COMMA
	cmp [rbp], rbx
	setge bl
	ADDDSP 4
	movzx rbx, bl
	neg rbx
	ret
	defword_end

	defword "0=", 0, WORD_ZEQ, WORD_INLINE_COMMA
	test rbx, rbx
	setz bl
	movzx rbx, bl
	neg rbx
	ret
	defword_end

	defword "0<>", 0, WORD_ZNE, WORD_INLINE_COMMA
	test rbx, rbx
	setnz bl
	movzx rbx, bl
	neg rbx
	ret
	defword_end

	defword "0<", 0, WORD_ZLT, WORD_INLINE_COMMA
	test rbx, rbx
	setl bl
	movzx rbx, bl
	neg rbx
	ret
	defword_end

	defword "0>", 0, WORD_ZGT, WORD_INLINE_COMMA
	test rbx, rbx
	setg bl
	movzx rbx, bl
	neg rbx
	ret
	defword_end

	defword "0<=", 0, WORD_ZLTEQ, WORD_INLINE_COMMA
	test rbx, rbx
	setle bl
	movzx rbx, bl
	neg rbx
	ret
	defword_end

	defword "0>=", 0, WORD_ZGTEQ, WORD_INLINE_COMMA
	test rbx, rbx
	setge bl
	movzx rbx, bl
	neg rbx
	ret
	defword_end

;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; double precision ALU words
;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	defword "s>d", 0, WORD_STOD, WORD_INLINE_COMMA
	mov rax, rbx
	cdq
	PUSHDSP rax
	mov rbx, rdx
	ret
	defword_end

	defword "d>s", 0, WORD_DTOS, WORD_INLINE_COMMA
	POPDSP rbx
	ret
	defword_end

	defword "d+", 0, WORD_DPLUS, WORD_INLINE_COMMA
	PICKDSP rcx, 8
	PICKDSP rdx, 4
	PICKDSP rax, 0
	add rax, rcx
	adc rbx, rdx
	PUTDSP rax, 8
	ADDDSP 8
	ret
	defword_end

	defword "d-", 0, WORD_DMINUS, WORD_INLINE_COMMA
	PICKDSP rcx, 8
	PICKDSP rdx, 4
	PICKDSP rax, 0
	sub rcx, rax
	sbb rdx, rbx
	PUTDSP rcx, 8
	mov rbx, rdx
	ADDDSP 8
	ret
	defword_end

	defword "d2*", 0, WORD_D2STAR, WORD_INLINE_COMMA
	PICKDSP rax, 0
	shl rax, 1
	rcl rbx, 1
	PUTDSP rax, 0
	ret
	defword_end

	defword "d2/", 0, WORD_D2SLASH, WORD_INLINE_COMMA
	PICKDSP rax, 0
	sar rbx, 1
	rcr rax, 1
	PUTDSP rax, 0
	ret
	defword_end

	defword "*/", 0, WORD_MULDIV, WORD_INLINE_COMMA
	PICKDSP rdx, 4
	PICKDSP rax, 0
	imul rdx
	idiv rbx
	mov rbx, rax
	ADDDSP 8
	ret
	defword_end

	defword "*/mod", 0, WORD_STARSMOD, WORD_INLINE_COMMA
	PICKDSP rdx, 4
	PICKDSP rax, 0
	imul rdx
	idiv rbx
	PUTDSP rdx, 4
	ADDDSP 4
	mov rbx, rax
	ret
	defword_end

	defword "/mod", 0, WORD_DIVMOD, WORD_INLINE_COMMA
	PICKDSP rax, 0
	cdq
	idiv rbx
	PUTDSP rdx, 0
	mov rbx, rax
	ret
	defword_end

	defword "dnegate", 0, WORD_DNEGATE, WORD_INLINE_COMMA
	PICKDSP rax, 0
	not rax
	not rbx
	add rax, 1
	adc rbx, 0
	PUTDSP rax, 0
	ret
	defword_end

	defword "dabs", 0, WORD_DABS, WORD_INLINE_COMMA
	test rbx, rbx
	if l
		PICKDSP rax, 0
		not rax
		not rbx
		add rax, 1
		adc rbx, 0
		PUTDSP rax, 0
	endif
	ret
	defword_end

	defword "dmax", 0, WORD_DMAX, WORD_INLINE_COMMA
	PICKDSP rcx, 8
	PICKDSP rdx, 4
	PICKDSP rax, 0
	ADDDSP 8
	mov rsi, rcx
	mov rdi, rdx
	sub rsi, rax
	sbb rdi, rbx
	if l
		PUTDSP rax, 0
	else
		mov rbx, rdx
	endif
	ret
	defword_end

	defword "dmin", 0, WORD_DMIN, WORD_INLINE_COMMA
	PICKDSP rcx, 8
	PICKDSP rdx, 4
	PICKDSP rax, 0
	ADDDSP 8
	mov rsi, rcx
	mov rdi, rdx
	sub rsi, rax
	sbb rdi, rbx
	if ge
		PUTDSP rax, 0
	else
		mov rbx, rdx
	endif
	ret
	defword_end

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; double precision comparision words
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	defword "d0=", 0, WORD_DZEQ, WORD_INLINE_COMMA
	or rbx, [rbp]
	setz bl
	ADDDSP 4
	movzx rbx, bl
	neg rbx
	ret
	defword_end

	defword "d0<>", 0, WORD_DZNEQ, WORD_INLINE_COMMA
	or rbx, [rbp]
	setnz bl
	ADDDSP 4
	movzx rbx, bl
	neg rbx
	ret
	defword_end

	defword "d0<", 0, WORD_DZLT, WORD_INLINE_COMMA
	test rbx, rbx
	setl bl
	ADDDSP 4
	movzx rbx, bl
	neg rbx
	ret
	defword_end

	defword "d=", 0, WORD_DEQ, WORD_INLINE_COMMA
	PICKDSP rcx, 8
	PICKDSP rax, 4
	sub rcx, [rbp]
	sbb rax, rbx
	setz bl
	ADDDSP 12
	movzx rbx, bl
	neg rbx
	ret
	defword_end

	defword "d<>", 0, WORD_DNEQ, WORD_INLINE_COMMA
	PICKDSP rcx, 8
	PICKDSP rax, 4
	sub rcx, [rbp]
	sbb rax, rbx
	setnz bl
	ADDDSP 12
	movzx rbx, bl
	neg rbx
	ret
	defword_end

	defword "d<", 0, WORD_DLT, WORD_INLINE_COMMA
	PICKDSP rcx, 8
	PICKDSP rax, 4
	sub rcx, [rbp]
	sbb rax, rbx
	setl bl
	ADDDSP 12
	movzx rbx, bl
	neg rbx
	ret
	defword_end

	defword "du<", 0, WORD_DULT, WORD_INLINE_COMMA
	PICKDSP rcx, 8
	PICKDSP rax, 4
	sub rcx, [rbp]
	sbb rax, rbx
	setb bl
	ADDDSP 12
	movzx rbx, bl
	neg rbx
	ret
	defword_end

;;;;;;;;;;;;;;;;;;;;;;;
; mixed precision words
;;;;;;;;;;;;;;;;;;;;;;;

	defword "m+", 0, WORD_MPLUS, WORD_INLINE_COMMA
	PICKDSP rax, 4
	PICKDSP rdx, 0
	add rax, rbx
	adc rdx, 0
	PUTDSP rax, 4
	mov rbx, rdx
	ADDDSP 4
	ret
	defword_end

	defword "m-", 0, WORD_MMINUS, WORD_INLINE_COMMA
	PICKDSP rax, 4
	PICKDSP rdx, 0
	sub rax, rbx
	sbb rdx, 0
	PUTDSP rax, 4
	mov rbx, rdx
	ADDDSP 4
	ret
	defword_end

	defword "m*", 0, WORD_MULSTAR, WORD_INLINE_COMMA
	PICKDSP rax, 0
	imul rbx
	PUTDSP rax, 0
	mov rbx, rdx
	ret
	defword_end

	defword "m/", 0, WORD_MSLASH, WORD_INLINE_COMMA
	PICKDSP rax, 4
	PICKDSP rdx, 0
	idiv rbx
	mov rbx, rax
	ADDDSP 8
	ret
	defword_end

	defword "um*", 0, WORD_UMULSTAR, WORD_INLINE_COMMA
	PICKDSP rax, 0
	mul rbx
	PUTDSP rax, 0
	mov rbx, rdx
	ret
	defword_end

	defword "um/mod", 0, WORD_UMDIVMOD, WORD_INLINE_COMMA
	PICKDSP rax, 4
	PICKDSP rdx, 0
	div rbx
	PUTDSP rdx, 4
	mov rbx, rax
	ADDDSP 4
	ret
	defword_end

	defword "fm/mod", 0, WORD_FMDIVMOD, WORD_INLINE_COMMA
	PICKDSP rdx, 0
	PICKDSP rax, 4
	mov rcx, rbx
	ADDDSP 4
	xor rcx, rdx
	idiv rbx
	test rcx, rcx
	if s
		test rdx, rdx
		if nz
			dec rax
			add rdx, rbx
		endif
	endif
	PUTDSP rdx, 0
	mov rbx, rax
	ret
	defword_end

	defword "sm/rem", 0, WORD_SMDIVREM, WORD_INLINE_COMMA
	PICKDSP rax, 4
	PICKDSP rdx, 0
	idiv rbx
	PUTDSP rdx, 4
	mov rbx, rax
	ADDDSP 4
	ret
	defword_end

	defword "u/mod", 0, WORD_UDIVMOD, WORD_INLINE_COMMA
	xor rdx, rdx
	PICKDSP rax, 0
	div rbx
	PUTDSP rdx, 0
	mov rbx, rax
	ret
	defword_end

	defword "dm*", 0, WORD_DMULSTAR, WORD_CALL_COMMA
	call WORD_TUCK
	call WORD_MULL
	TORSP
	call WORD_UMULSTAR
	FROMRSP
	call WORD_ADD
	ret
	defword_end

;;;;;;;;;;;;;;;;;;;;
; control flow words
;;;;;;;;;;;;;;;;;;;;

	defword "branch", 0, WORD_BRANCH, WORD_INLINE_COMMA
i_jmp:
	jmp strict near i_ret
	ret
	defword_end

	defword "0branch", 0, WORD_ZBRANCH, WORD_INLINE_COMMA
	mov rax, rbx
	POPDSP rbx
	test rax, rax
	jz strict near i_jmp
	ret
	defword_end

	defword "exit", 0, WORD_EXIT, WORD_EXIT_COMMA
i_ret:
	ret
	defword_end

	defword "exit,", 0, WORD_EXIT_COMMA, WORD_CALL_COMMA
	mov rdi, [var_WORD_DP]
	sub rdi, 5
	cmp rdi, [lastcall]	; are we just after a call instruction ?
	if z
		mov al, [i_jmp]
		mov [rdi], al	; change it to a jmp
	endif
	mov rdi, [var_WORD_DP]
	mov al, [i_ret]
	stosb
	mov [var_WORD_DP], rdi
	POPDSP rbx
	ret
	defword_end

	defword "execute", 0, WORD_EXECUTE, WORD_CALL_COMMA
	mov rax, rbx	; Get xt into rax
	POPDSP rbx		; After xt runs its ret will continue executing the current word.
	jmp rax			; and jump to it.
	defword_end

;;;;;;;;;;;;;;;;;;;;;;;;;;
; terminal input words
;;;;;;;;;;;;;;;;;;;;;;;;;;

	defword "read-char", 0, WORD_READCHAR, WORD_CALL_COMMA
	mov rcx, var_WORD_CHARBUF	; 2nd param: buffer
	mov rdx, 1					; 3rd param: max length
	push rdx
	push rcx
	push rbx
	mov rax, SYS_read			; syscall: read
	call _syscall
	add rsp, 12
	xor rbx, rbx
	test rax, rax
	if be
		mov rbx, -1
	endif
	ret
	defword_end

	defword "read-line", 0, WORD_READLINE, WORD_CALL_COMMA
	call WORD_NROT
	call WORD_OVER
	call WORD_ADD
	call WORD_OVER		; ( fd start end cur )
readline_l1:
	PICKDSP rax, 0
	cmp rbx, rax
	jz readline_l4
	PUSHDSP rbx
	PICKDSP rbx, 12
	call WORD_READCHAR
	test rbx, rbx
	jz readline_l2
	call WORD_DROP
	call WORD_DROP2
	call WORD_DROP2
	LOADTOS 0
	LOADTOS 0
	LOADTOS -1
	jmp readline_l5
readline_l2:
	mov rbx, [var_WORD_CHARBUF]
	cmp rbx, 10			; LF
	jz readline_l3
	call WORD_OVER
	call WORD_STOREBYTE
	call WORD_INCR
	jmp readline_l1
readline_l3:
	call WORD_DROP
readline_l4:
	call WORD_NIP
	call WORD_SWAP
	call WORD_SUB
	call WORD_NIP
	LOADTOS -1
	LOADTOS 0
readline_l5:
	ret
	defword_end

	defword "key", 0, WORD_KEY, WORD_CALL_COMMA
	PUSHDSP rbx
	xor rbx, rbx		; stdin
	call WORD_READCHAR
	mov rbx, [var_WORD_CHARBUF]
	ret
	defword_end

	defword "accept", 0, WORD_ACCEPT, WORD_CALL_COMMA
	call WORD_OVER
	call WORD_ADD
	call WORD_OVER	; ( start end cur )
accept_l1:
	call WORD_KEY
	cmp rbx, 127	; BS
	jz accept_l2
	cmp rbx, 10		; LF
	jz accept_l3
	call WORD_OVER	; ( start end cur key cur )
	call WORD_STOREBYTE
	call WORD_INCR	; ( start end cur' )
	PICKDSP rax, 0
	cmp rbx, rax
	jz accept_l4
	jmp accept_l1
accept_l2:
	PICKDSP rax, 4	; ( start end cur' )
	cmp rbx, rax
	jz accept_l1
	call WORD_DECR
	jmp accept_l1
accept_l3:
	call WORD_DROP	; ( start end cur' )
accept_l4:
	call WORD_NIP
	call WORD_SWAP
	call WORD_SUB
	ret
	defword_end

	defword "tabs>spaces", 0, WORD_TABSTOSPACES, WORD_CALL_COMMA
	mov rcx, rbx
	POPDSP rsi
	test rcx, rcx
	if nz
		repeat
			lodsb
			cmp al, 9	;TAB
			if z
				mov byte [rsi - 1], ' '
			endif
			dec rcx
		until z
	endif
	POPDSP rbx
	ret
	defword_end

;;;;;;;;;;;;;;;;;;;;;;;
; terminal output words
;;;;;;;;;;;;;;;;;;;;;;;

	defword "type-fd", 0, WORD_TYPE_FD, WORD_CALL_COMMA
	PICKDSP rdx, 0			; 3rd param: length of string
	PICKDSP rcx, 4			; 2nd param: address of string
	ADDDSP 8				; 1st param: FD in rbx
	mov rax, SYS_write		; write syscall
	push rdx
	push rcx
	push rbx
	call _syscall
	add rsp, 12
	POPDSP rbx
	ret
	defword_end

	defword "type", 0, WORD_TYPE, WORD_CALL_COMMA
	LOADTOS 1				; stdout
	call WORD_TYPE_FD
	ret
	defword_end

	defword "emit", 0, WORD_EMIT, WORD_CALL_COMMA
	mov [emit_scratch], bl	; write needs the address of the byte to write
	mov rbx, emit_scratch
	LOADTOS 1
	call WORD_TYPE
	ret
	defword_end

;;;;;;;;;;;;;;;;;;;
; system call words
;;;;;;;;;;;;;;;;;;;

	defword "syscall", 0, WORD_SYSCALL, WORD_CALL_COMMA
	pop rax
	mov [syscallret], rax	; save return address
	mov rax, rbx			; System call number (see <asm/unistd.h>)
	call _syscall
	mov rbx, rax			; Result (negative for -errno)
	jmp [syscallret]		; return to caller
	defword_end

	defword "lsyscall", 0, WORD_LSYSCALL, WORD_CALL_COMMA
	pop rax
	mov [syscallret], rax	; save return address
	mov rax, rbx			; System call number (see <asm/unistd.h>)
	call _lsyscall
	PUSHDSP rax
	mov rbx, rdx			; Result (negative for -errno)
	jmp [syscallret]		; return to caller
	defword_end

;;;;;;;;;;;;;;
; string words
;;;;;;;;;;;;;;

	defword "count", 0, WORD_COUNT, WORD_CALL_COMMA
	xor rax, rax
	mov al, [rbx]
	inc rbx
	LOADTOS rax
	ret
	defword_end

	defword "-trailing", 0, WORD_TRAILING, WORD_CALL_COMMA
	test rbx, rbx
	if nz
		PICKDSP rsi, 0
		mov rcx, rbx
		add rsi, rbx
		dec rsi
		std
	trailing_l1:
		lodsb
		cmp al, ' '
		if be
			loop trailing_l1
		endif
		mov rbx, rcx
		cld
	endif
	ret
	defword_end

	defword "/string", 0, WORD_SSTRING, WORD_CALL_COMMA
	mov rax, rbx
	POPDSP rbx
	PICKDSP rcx, 0
	sub rbx, rax
	add rcx, rax
	PUTDSP rcx, 0
	ret
	defword_end

	defword "compare", 0, WORD_COMPARE, WORD_CALL_COMMA
	PICKDSP rsi, 8
	PICKDSP rdx, 4
	PICKDSP rdi, 0
	ADDDSP 12
	mov rcx, rbx
	cmp rdx, rbx
	if be
		mov rcx, rdx
	endif
	test rcx, rcx		; rcx lowest length
	jnz compare_l2
	cmp rdx, rbx
	jz compare_l3		; both are 0 length
	jmp compare_l4		; otherwise the longest wins
compare_l2:
	cmpsb
	jnz compare_l4		; chars not same
	loop compare_l2
	cmp rdx, rbx		; all chars same
	jnz compare_l4		; strings not same size
compare_l3:
	xor rbx, rbx		; same
	jmp compare_l7
compare_l4:
	ja compare_l6
compare_l5:
	mov rbx, -1
	jmp compare_l7
compare_l6:
	mov rbx, 1
compare_l7:
	ret
	defword_end

	defword "icompare", 0, WORD_COMPAREI, WORD_CALL_COMMA
	PICKDSP rsi, 8
	PICKDSP rdx, 4
	PICKDSP rdi, 0
	ADDDSP 12
	mov rcx, rbx
	cmp rdx, rbx
	if be
		mov rcx, rdx
	endif
	test rcx, rcx		; rcx lowest length
	jnz comparei_l2
	cmp rdx, rbx
	jz comparei_l3		; both are 0 length
	jmp comparei_l4		; otherwise the longest wins
comparei_l2:
	mov al, [rsi]
	mov ah, [rdi]
	to_lower al
	to_lower ah
	cmp ah, al
	jnz comparei_l4		; chars not same
	inc rdi
	inc rsi
	loop comparei_l2
	cmp rdx, rbx		; all chars same
	jnz comparei_l4		; strings not same size
comparei_l3:
	xor rbx, rbx		; same
	jmp comparei_l7
comparei_l4:
	ja comparei_l6
comparei_l5:
	mov rbx, -1
	jmp comparei_l7
comparei_l6:
	mov rbx, 1
comparei_l7:
	ret
	defword_end

;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; dictionary searching words
;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	defword "find", 0, WORD_FIND, WORD_CALL_COMMA
	call WORD_DUP
	call WORD_COUNT
	call WORD_FIND_DICT
	test rbx, rbx
	if nz
		mov dl, [rbx + H_NSIZE]
		call WORD_TCFA
		LOADTOS 1
		and rdx, F_IMMED
		if z
			neg rbx
		endif
		call WORD_ROT
		call WORD_DROP
	endif
	ret
	defword_end

	defword "(find)", 0, WORD_FIND_DICT, WORD_CALL_COMMA
	mov rcx, rbx			; rcx = length
	POPDSP rdi				; rdi = address
	PUSHRSP rcx
	mov rsi, rdi
	call strhashi
	and rbx, NUM_HASH_CHAINS-1
	mov rsi, hash_buckets
	mov rdx, [rsi + (rbx * 4)]
	POPRSP rcx				; rdx can now scan back through this hash chain
findd_l1:
	test rdx, rdx			; NULL pointer?  (end of the linked list)
	je findd_l4
	xor rax, rax
	mov al, [rdx + H_NSIZE]	; al = flags+length field
	and al, (F_HIDDEN|F_LENMASK)	; al = name length
	cmp al, cl				; Length is the same?
	jne findd_l2
	PUSHRSP rcx				; Save the length
	PUSHRSP rdi				; Save the address (repe cmpsb will move this pointer)
	lea rsi, [rdx + H_NAME]	; Dictionary string we are checking against.
	call strcmpi
	POPRSP rdi
	POPRSP rcx
	jne findd_l2			; Not the same.
	mov rbx, rdx
	ret
findd_l2:
	mov rdx, [rdx + H_HLINK]	; Move back through the link field to the previous word
	jmp findd_l1			; .. and loop.
findd_l4:
	xor rbx, rbx			; Return zero to indicate not found.
	ret
	defword_end

	defword ">cfa", 0, WORD_TCFA, WORD_CALL_COMMA
	add rbx, H_NSIZE
	mov al, [rbx]			; Load flags+len into al.
	inc rbx					; skip flags+len byte.
	and rax, F_LENMASK		; Just the length, not the flags.
	add rbx, rax			; skip the name
	add rbx, XT_SIZE		; skip to the xt
	ret
	defword_end

	defword "(bucket)", 0, WORD_BUCKET, WORD_CALL_COMMA
	mov rcx, rbx		; rcx = length
	POPDSP rbx			; rbx = address of name
	PUSHRSP rsi
	mov rsi, rbx
	call strhashi
	and rbx, NUM_HASH_CHAINS-1
	mov rsi, hash_buckets
	lea rbx, [rsi + (rbx * 4)]
	POPRSP rsi
	ret
	defword_end

	defword "unused", 0, WORD_UNUSED, WORD_CALL_COMMA
	LOADTOS forth_end
	LOADTOS [var_WORD_DP]
	call WORD_SUB
	ret
	defword_end

;;;;;;;;;;;;;;;;;;;;;;;;;;;
; dictionary building words
;;;;;;;;;;;;;;;;;;;;;;;;;;;

	defword "align", 0, WORD_ALIGNDP, WORD_CALL_COMMA
	mov rax, [var_WORD_DP]
	ALIGNREG rax
	mov [var_WORD_DP], rax
	ret
	defword_end

	defword "header,", 0, WORD_HEADER_COMMA, WORD_CALL_COMMA
	mov rcx, rbx				; rcx = length
	POPDSP rbx					; rbx = address of name
	call WORD_ALIGNDP			; align header
	mov rdi, [var_WORD_DP]		; rdi is the address of the header
	mov rax, [var_WORD_LATEST]	; Get link pointer
	mov [rdi + H_LLINK], rax	; and store it in the header.
	mov [var_WORD_LATEST], rdi
	PUSHRSP rbx					; hash chain
	PUSHRSP rcx
	mov rsi, rbx
	call strhashi
	and rbx, NUM_HASH_CHAINS-1
	mov rsi, hash_buckets
	mov rax, [rsi + (rbx * 4)]
	mov [rsi + (rbx * 4)], rdi
	mov [rdi + H_HLINK], rax	; and store it in the header.
	POPRSP rcx
	POPRSP rsi
	mov [rdi + H_NSIZE], cl		; Store the length/flags byte.
	add rdi, H_NAME
	call strcpyi
	mov rcx, XT_SIZE
	xor rax, rax
	rep stosb					; clear the gap till the xt
	mov [var_WORD_DP], rdi
	mov long [rdi + XT_COMPILE], WORD_CALL_COMMA	;compile action
	POPDSP rbx
	ret
	defword_end

	defword "lit,", 0, WORD_LIT_COMMA, WORD_CALL_COMMA
	mov rsi, litc_l1
	mov rdi, [var_WORD_DP]
	mov rcx, litc_l2 - litc_l1 - 4
	rep movsb
	mov [var_WORD_DP], rdi
	ret
	defword_end
litc_l1:
	LOADTOS 0xBAADF00D
litc_l2:

	defword "slits", 0, WORD_SLITS, WORD_CALL_COMMA
	PUSHDSP rbx
	POPRSP rsi
	xor rax, rax
	lodsb				; get the length of the string
	PUSHDSP rsi			; push the address of the start of the string
	mov rbx, rax		; push length on the stack
	add rsi, rax		; skip past the string
 	jmp rsi
	defword_end

	defword "clits", 0, WORD_CLITS, WORD_CALL_COMMA
	FROMRSP
	xor rax, rax
	mov al, [rbx]
	lea rax, [rbx + rax + 1]
 	jmp rax
	defword_end

	defword ",", 0, WORD_COMMA, WORD_CALL_COMMA
	mov rdi, [var_WORD_DP]	; DP
	mov rax, rbx
	stosd					; Store it.
	mov [var_WORD_DP], rdi	; Update DP (incremented)
	POPDSP rbx
	ret
	defword_end

	defword "c,", 0, WORD_CHAR_COMMA, WORD_CALL_COMMA
	mov rax, rbx
	mov rdi, [var_WORD_DP]	; DP
	stosb					; Store it.
	mov [var_WORD_DP], rdi	; Update DP (incremented)
	POPDSP rbx
	ret
	defword_end

	defword ":", 0, WORD_COLON, WORD_CALL_COMMA
	call WORD_PARSENAME
	call WORD_HEADER_COMMA	; Create the dictionary entry / header
	mov rax, [var_WORD_DP]
	mov [rax + XT_BODY], rax
	call WORD_LATEST
	call WORD_FETCH
	call WORD_HIDDEN		; Make the word hidden
	call WORD_RBRAC			; Go into compile mode.
	ret
	defword_end

	defword "create", 0, WORD_CREATE, WORD_CALL_COMMA
	call WORD_PARSENAME
	call WORD_HEADER_COMMA
	mov rsi, create_l1
	mov rdi, [var_WORD_DP]
	PUSHRSP rdi
	mov rcx, create_l4 - create_l1
	rep movsb
	mov [var_WORD_DP], rdi
	mov rdx, rdi
	call WORD_ALIGNDP
	POPRSP rax
	mov rdi, [var_WORD_DP]
	sub rdx, rax
	mov [rax + create_l2 - create_l1 - 4], rdi
	mov [rax + XT_BODY], rdi
	mov [rax + XT_LENGTH], rdx
	ret
	defword_end
create_l1:
	LOADTOS 0xBAADF00D
create_l2:
	call strict near create_l3
create_l3:
	ret
create_l4:

	defword "dodoes", 0, WORD_DODOES, WORD_CALL_COMMA
	call WORD_LATEST
	call WORD_FETCH
	call WORD_TCFA
	add rbx, create_l3 - create_l1 - 4
	POPDSP rax
	sub rax, rbx
	sub rax, 4
	mov [rbx], rax
	POPDSP rbx
	ret
	defword_end

	defword "does>", F_IMMED, WORD_DOES, WORD_CALL_COMMA
	call WORD_LIT_COMMA
	LOADTOS [var_WORD_DP]
	add rbx, 10
	call WORD_COMMA
	LOADTOS WORD_DODOES
	call WORD_COMPILE_COMMA
	LOADTOS 0
	mov bl, [does_l1]
	call WORD_CHAR_COMMA
does_l1:
	ret
	defword_end

	defword "postpone", F_IMMED, WORD_POSTPONE, WORD_CALL_COMMA
	call WORD_PARSENAME
	call WORD_FIND_DICT
	mov dl, [rbx + H_NSIZE]
	call WORD_TCFA
	and rdx, F_IMMED
	if z
		call WORD_LIT_COMMA
		call WORD_COMMA
		LOADTOS WORD_COMPILE_COMMA
	endif
	jmp WORD_COMPILE_COMMA
	ret
	defword_end

	defword "call,", 0, WORD_CALL_COMMA, WORD_CALL_COMMA
	mov rdi, [var_WORD_DP]
	mov [lastcall], rdi	; record last location of last call
	mov rsi, i_call
	movsb
	mov rax, rbx
	sub rax, 4
	sub rax, rdi
	stosd
	mov [var_WORD_DP], rdi
	POPDSP rbx
	ret
	defword_end

	defword "inline,", 0, WORD_INLINE_COMMA, WORD_CALL_COMMA
	mov rcx, [rbx + XT_LENGTH]
	dec rcx					; actual code length minus ret
	mov rsi, rbx
	mov rdi, [var_WORD_DP]
	rep movsb				; inline copy the code
	mov [var_WORD_DP], rdi	; update DP
	POPDSP rbx
	ret
	defword_end

	defword "compile,", 0, WORD_COMPILE_COMMA, WORD_INLINE_COMMA
	call [rbx + XT_COMPILE]
	ret
	defword_end

	defword ";", F_IMMED, WORD_SEMICOLON, WORD_CALL_COMMA
	LOADTOS WORD_EXIT
i_call:
	call strict near WORD_COMPILE_COMMA
	call WORD_LATEST
	call WORD_FETCH
	call WORD_HIDDEN			; toggle hidden flag -- unhide the word (see below for definition).
	call WORD_LBRAC				; go back to IMMEDIATE mode.
	mov rdx, rbx
	mov rbx, [var_WORD_LATEST]
	call WORD_TCFA
	mov rcx, [var_WORD_DP]
	sub rcx, rbx
	mov [rbx + XT_LENGTH], rcx	; set code size of word
	mov rbx, rdx
	ret
	defword_end

	defword "immediate", 0, WORD_IMMEDIATE, WORD_CALL_COMMA
	mov rdi, [var_WORD_LATEST]	; LATEST word.
	add rdi, H_NSIZE			; Point to name/flags byte.
	xor byte [rdi], F_IMMED		; Toggle the IMMED bit.
	ret
	defword_end

	defword "hidden", 0, WORD_HIDDEN, WORD_CALL_COMMA
	add rbx, H_NSIZE			; Point to name/flags byte.
	xor byte [rbx], F_HIDDEN	; Toggle the HIDDEN bit.
	POPDSP rbx
	ret
	defword_end

	defword "[", F_IMMED, WORD_LBRAC, WORD_CALL_COMMA
	mov long [var_WORD_STATE], 0	; Set STATE to 0.
	ret
	defword_end

	defword "]", 0, WORD_RBRAC, WORD_CALL_COMMA
	mov long [var_WORD_STATE], 1	; Set STATE to 1.
	ret
	defword_end

;;;;;;;;;;;;;;;;;;;;;
; source buffer words
;;;;;;;;;;;;;;;;;;;;;

	defword "source", 0, WORD_SOURCE, WORD_CALL_COMMA
	call WORD_INHASH
	call WORD_FETCH2
	ret
	defword_end

	defword "refill", 0, WORD_REFILL, WORD_CALL_COMMA
	LOADTOS tib_buffer
	call WORD_LINESIZE	; ( tib len )
	call WORD_OVER
	call WORD_SWAP		; ( tib tib len )
	call WORD_ACCEPT	; read line into TIB
	call WORD_DUP2
	call WORD_TABSTOSPACES
	call WORD_INHASH
	call WORD_STORE2	; set as current WORD_SOURCE
	LOADTOS 0
	call WORD_TOIN
	call WORD_STORE		; set to start of buffer
	LOADTOS -1
	ret
	defword_end

	defword "isspace?", 0, WORD_ISSPACE, WORD_CALL_COMMA
	LOADTOS ' '
	call WORD_ULTEQ
	ret
	defword_end

	defword "isnotspace?", 0, WORD_ISNOTSPACE, WORD_CALL_COMMA
	call WORD_ISSPACE
	call WORD_ZEQ
	ret
	defword_end

	defword "xt-skip", 0, WORD_XTSKIP, WORD_CALL_COMMA
	TORSP
xtskip_l1:
	test rbx, rbx
	jz xtskip_l3
	call WORD_OVER
	call WORD_FETCHBYTE
	FETCHRSP
	call WORD_EXECUTE
	test rbx, rbx
	jz xtskip_l2
	mov rbx, 1
	call WORD_SSTRING
	jmp xtskip_l1
xtskip_l2:
	call WORD_DROP
xtskip_l3:
	ADDRSP 4
	ret
	defword_end

;;;;;;;;;;;;;;;;;;;;;;
; input parseing words
;;;;;;;;;;;;;;;;;;;;;;

	defword "parse-name", 0, WORD_PARSENAME, WORD_CALL_COMMA
	call WORD_SOURCE
	call WORD_TOIN
	call WORD_FETCH
	call WORD_SSTRING
	LOADTOS WORD_ISSPACE
	call WORD_XTSKIP
	call WORD_OVER
	TORSP
	LOADTOS WORD_ISNOTSPACE
	call WORD_XTSKIP
	call WORD_DUP2
	LOADTOS 1
	call WORD_MIN
	call WORD_ADD
	call WORD_SOURCE
	call WORD_DROP
	call WORD_SUB
	call WORD_TOIN
	call WORD_STORE
	call WORD_DROP
	FROMRSP
	call WORD_TUCK
	call WORD_SUB
; code to print out "P <word> CR"
;LOADTOS 80
;call WORD_EMIT
;LOADTOS 32
;call WORD_EMIT
;call WORD_DUP2
;call WORD_TYPE
;LOADTOS 10
;call WORD_EMIT
	ret
	defword_end

	defword "word-name", 0, WORD_WORDNAME, WORD_CALL_COMMA
	call WORD_PARSENAME		; ( start len )
	LOADTOS word_buf		; ( string size buf )
	call WORD_DUP2			; ( string size buf size buf )
	call WORD_STOREBYTE		; ( string size buf )
	call WORD_INCR			; ( string size buf+1 )
	call WORD_SWAP			; ( string buf+1 size )
	call WORD_CMOVE
	LOADTOS word_buf		; ( cstring )
; debug code to print out "N <word> CR"
;LOADTOS 78
;call WORD_EMIT
;LOADTOS 32
;call WORD_EMIT
;call WORD_DUP2
;call WORD_TYPE
;LOADTOS 10
;call WORD_EMIT
	ret
	defword_end

	defword "interp-name", 0, WORD_INTERPNAME, WORD_CALL_COMMA
	call WORD_PARSENAME			; ( start len )
	LOADTOS intep_name_buf		; ( string size buf )
	call WORD_DUP2				; ( string size buf size buf )
	call WORD_STOREBYTE			; ( string size buf )
	call WORD_INCR				; ( string size buf+1 )
	call WORD_SWAP				; ( string buf+1 size )
	call WORD_CMOVE
	LOADTOS intep_name_buf		;( cstring )
	ret
	defword_end

	defword "interpret", 0, WORD_INTERPRET, WORD_CALL_COMMA
	loopstart
		call WORD_INTERPNAME
		mov al, [rbx]
		test al, al
		breakif z
		; debug code to print out "I <word> CR"
		;LOADTOS 73
		;call WORD_EMIT
		;LOADTOS 32
		;call WORD_EMIT
		;call WORD_DUP
		;call WORD_COUNT
		;call WORD_TYPE
		;LOADTOS 10
		;call WORD_EMIT
		call WORD_INTERP
	loopend
	call WORD_DROP
	ret
	defword_end

	defword "interp", 0, WORD_INTERP, WORD_CALL_COMMA
	call WORD_FIND				; ( cstring 0 | xt 1 | xt | -1 )
	mov rax, rbx
	POPDSP rbx
	test rax, rax
	jz tryasnumber
	jle nonimediate
executeword:
	mov rax, rbx
	POPDSP rbx
	jmp rax
nonimediate:
	mov rax, [var_WORD_STATE]
	test rax, rax				; are we in imedeate mode ?
	jz executeword
	jmp WORD_COMPILE_COMMA		; compile xt
tryasnumber:
	call WORD_COUNT				; ( adr len )
	LOADTOS 0
	LOADTOS 0
	call WORD_SWAP2				; ( 0d addr len )
	call WORD_TOSNUMBER			; ( d addr len )
	test rbx, rbx
	jnz parseproblem
	call WORD_DROP2
	call WORD_DROP				; ( num )
	mov rax, [var_WORD_STATE]
	test rax, rax
	if nz
		call WORD_LIT_COMMA		; compile LIT
		call WORD_COMMA			; compile value
	endif
	ret
parseproblem:
	LOADTOS errmsg
	LOADTOS errmsgend - errmsg
	LOADTOS 2
	call WORD_TYPE_FD
	LOADTOS errmsgnl
	LOADTOS 1
	LOADTOS 2
	call WORD_TYPE_FD
	LOADTOS tib_buffer
	LOADTOS [var_WORD_TOIN]
	LOADTOS 2
	call WORD_TYPE_FD
	LOADTOS errmsgnl
	LOADTOS 1
	LOADTOS 2
	call WORD_TYPE_FD
	call WORD_DROP2
	call WORD_DROP2
	ret
	defword_end

	defword ">number", 0, WORD_TONUMBER, WORD_CALL_COMMA
	call WORD_OVER
	call WORD_ADD
	call WORD_SWAP			; ( ud end cur )
tonumber_l1:
	PICKDSP rax, 0
	cmp rbx, rax
	jz near tonumber_l4
	call WORD_DUP
	call WORD_FETCHBYTE		; ( ud end cur char )
	to_lower rbx
	sub rbx, byte '0'
	jb tonumber_l3			; < '0'?
	cmp rbx, byte 10
	jb tonumber_l2			; <= '9' ?
	sub rbx, byte 'a' - '0'
	jb tonumber_l3			; < 'a' ?
	add rbx, byte 10
tonumber_l2:
	cmp rbx, [var_WORD_BASE]
	jge tonumber_l3			; >= WORD_BASE ?
	TORSP
	call WORD_SWAP2			; ( end cur ud )
	LOADTOS [var_WORD_BASE]
	call WORD_DMULSTAR
	FROMRSP
	call WORD_MPLUS			; ( end cur ud' )
	call WORD_SWAP2
	call WORD_INCR			; ( ud' end cur' )
	jmp tonumber_l1
tonumber_l3:
	call WORD_DROP
tonumber_l4:
	call WORD_SWAP
	call WORD_OVER
	call WORD_SUB			; ( ud' c-addr u2 )
	ret
	defword_end

	defword ">snumber", 0, WORD_TOSNUMBER, WORD_CALL_COMMA
	test rbx, rbx
	if nz
		PICKDSP rax, 0
		mov cl, [rax]
		cmp cl, '-'
		jnz WORD_TONUMBER	; not '-'
		inc rax
		PUTDSP rax, 0
		dec rbx
		call WORD_TONUMBER
		call WORD_SWAP2
		call WORD_DNEGATE
		call WORD_SWAP2
	endif
	ret
	defword_end

;;;;;;;;;;;
; tick word
;;;;;;;;;;;

	defword "ticks", 0, WORD_TICKS, WORD_CALL_COMMA
	sub rbp, byte 8
	rdtsc
	mov [byte rbp -4], rbx
	mov [rbp], rax
	mov rbx, rdx
	ret
	defword_end

;;;;;;;;;;;
; test word
;;;;;;;;;;;

	defword "test", 0, WORD_TEST, WORD_CALL_COMMA
	ret
	defword_end

;;;;;;;;;;;;;;;;;
; read/write data
;;;;;;;;;;;;;;;;;

	align 4
syscallret:
	; return address saved by syscall
	dd 0
lastcall:
	; last call layed down by compiler
	dd 0

tib_buffer:
	; keyboard input buffer
	times MAX_LINE_SIZE db 0
word_buf:
	; static buffer where WORD returns. Subsequent calls
	; overwrite this buffer.
	times MAX_LINE_SIZE db 0
intep_name_buf:
	; static buffer where INTERPNAME returns. Subsequent calls
	; overwrite this buffer.
	times MAX_LINE_SIZE db 0
emit_scratch:
	; scratch used by EMIT
	db 0
errmsg:
	db "PARSE ERROR:"
errmsgend:
errmsgnl:
	db 10
bootfile:
	db "forth.f"
	db 0

;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; dictionary hash table (64)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	align 4
hash_buckets:
	dd 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	dd 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	dd 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	dd 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; addresses of all built in dictionary words.
; this ends up as part of the user space after booting !
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	align 8
dictionary_start:
	dq dic_WORD_ABS
	dq dic_WORD_ACCEPT
	dq dic_WORD_ADD
	dq dic_WORD_ADDBYTE
	dq dic_WORD_ADDSTORE
	dq dic_WORD_ALIGNDP
	dq dic_WORD_AND
	dq dic_WORD_BASE
	dq dic_WORD_BLANK
	dq dic_WORD_BLK
	dq dic_WORD_BRANCH
	dq dic_WORD_BUCKET
	dq dic_WORD_CALL_COMMA
	dq dic_WORD_CHARBUF
	dq dic_WORD_CHAR_COMMA
	dq dic_WORD_CLITS
	dq dic_WORD_CMOVE
	dq dic_WORD_CMOVEB
	dq dic_WORD_COLON
	dq dic_WORD_COMMA
	dq dic_WORD_COMPARE
	dq dic_WORD_COMPAREI
	dq dic_WORD_COMPILE_COMMA
	dq dic_WORD_COUNT
	dq dic_WORD_CREATE
	dq dic_WORD_D2SLASH
	dq dic_WORD_D2STAR
	dq dic_WORD_DABS
	dq dic_WORD_DECR
	dq dic_WORD_DECR2
	dq dic_WORD_DECR4
	dq dic_WORD_DEQ
	dq dic_WORD_DIV
	dq dic_WORD_DIVMOD
	dq dic_WORD_DLT
	dq dic_WORD_DMAX
	dq dic_WORD_DMIN
	dq dic_WORD_DMINUS
	dq dic_WORD_DMULSTAR
	dq dic_WORD_DNEGATE
	dq dic_WORD_DNEQ
	dq dic_WORD_DODOES
	dq dic_WORD_DOES
	dq dic_WORD_DP
	dq dic_WORD_DPLUS
	dq dic_WORD_DROP
	dq dic_WORD_DROP2
	dq dic_WORD_DSPFETCH
	dq dic_WORD_DSPSTORE
	dq dic_WORD_DTOS
	dq dic_WORD_DULT
	dq dic_WORD_DUP
	dq dic_WORD_DUP2
	dq dic_WORD_DZEQ
	dq dic_WORD_DZLT
	dq dic_WORD_DZNEQ
	dq dic_WORD_EMIT
	dq dic_WORD_EQ
	dq dic_WORD_ERASE
	dq dic_WORD_EXECUTE
	dq dic_WORD_EXIT
	dq dic_WORD_FETCH
	dq dic_WORD_FETCH2
	dq dic_WORD_FETCHBYTE
	dq dic_WORD_FETCHSHORT
	dq dic_WORD_FILL
	dq dic_WORD_FIND
	dq dic_WORD_FIND_DICT
	dq dic_WORD_FMDIVMOD
	dq dic_WORD_FROMR
	dq dic_WORD_FROMR2
	dq dic_WORD_GT
	dq dic_WORD_GTEQ
	dq dic_WORD_HEADER_COMMA
	dq dic_WORD_HIDDEN
	dq dic_WORD_IMMEDIATE
	dq dic_WORD_INCR
	dq dic_WORD_INCR2
	dq dic_WORD_INCR4
	dq dic_WORD_INHASH
	dq dic_WORD_INLINE_COMMA
	dq dic_WORD_INTERP
	dq dic_WORD_INTERPNAME
	dq dic_WORD_INTERPRET
	dq dic_WORD_INVERT
	dq dic_WORD_ISNOTSPACE
	dq dic_WORD_ISSPACE
	dq dic_WORD_KEY
	dq dic_WORD_LATEST
	dq dic_WORD_LBRAC
	dq dic_WORD_LINESIZE
	dq dic_WORD_LIT_COMMA
	dq dic_WORD_LSHIFT
	dq dic_WORD_LSYSCALL
	dq dic_WORD_LT
	dq dic_WORD_LTEQ
	dq dic_WORD_MAX
	dq dic_WORD_MIN
	dq dic_WORD_MMINUS
	dq dic_WORD_MOD
	dq dic_WORD_MOVE
	dq dic_WORD_MPLUS
	dq dic_WORD_MSLASH
	dq dic_WORD_MULDIV
	dq dic_WORD_MULL
	dq dic_WORD_MULSTAR
	dq dic_WORD_NE
	dq dic_WORD_NEGATE
	dq dic_WORD_NFROMR
	dq dic_WORD_NIP
	dq dic_WORD_NIP2
	dq dic_WORD_NQDUP
	dq dic_WORD_NROT
	dq dic_WORD_NTOR
	dq dic_WORD_OR
	dq dic_WORD_OVER
	dq dic_WORD_OVER2
	dq dic_WORD_O_APPEND
	dq dic_WORD_O_CREAT
	dq dic_WORD_O_EXCL
	dq dic_WORD_O_NONBLOCK
	dq dic_WORD_O_RDONLY
	dq dic_WORD_O_RDWR
	dq dic_WORD_O_TRUNC
	dq dic_WORD_O_WRONLY
	dq dic_WORD_PARSENAME
	dq dic_WORD_PICK
	dq dic_WORD_POSTPONE
	dq dic_WORD_QDUP
	dq dic_WORD_RBRAC
	dq dic_WORD_RDROP
	dq dic_WORD_RDROP2
	dq dic_WORD_READCHAR
	dq dic_WORD_READLINE
	dq dic_WORD_REFILL
	dq dic_WORD_RFETCH
	dq dic_WORD_RFETCH2
	dq dic_WORD_ROT
	dq dic_WORD_ROT2
	dq dic_WORD_RSHIFT
	dq dic_WORD_RSPFETCH
	dq dic_WORD_RSPSTORE
	dq dic_WORD_RSTORE
	dq dic_WORD_RZ
	dq dic_WORD_SEMICOLON
	dq dic_WORD_SLITS
	dq dic_WORD_SMDIVREM
	dq dic_WORD_SOURCE
	dq dic_WORD_SOURCEFD
	dq dic_WORD_SSTRING
	dq dic_WORD_STARSMOD
	dq dic_WORD_STATE
	dq dic_WORD_STOD
	dq dic_WORD_STORE
	dq dic_WORD_STORE2
	dq dic_WORD_STOREBYTE
	dq dic_WORD_STORESHORT
	dq dic_WORD_SUB
	dq dic_WORD_SUBSTORE
	dq dic_WORD_SWAP
	dq dic_WORD_SWAP2
	dq dic_WORD_SYSCALL
	dq dic_WORD_SYS_CLOSE
	dq dic_WORD_SYS_EXIT
	dq dic_WORD_SYS_FSTAT
	dq dic_WORD_SYS_FSYNC
	dq dic_WORD_SYS_FTRUNCATE
	dq dic_WORD_SYS_LSEEK
	dq dic_WORD_SYS_OPEN
	dq dic_WORD_SYS_READ
	dq dic_WORD_SYS_RENAME
	dq dic_WORD_SYS_STAT
	dq dic_WORD_SYS_UNLINK
	dq dic_WORD_SYS_WRITE
	dq dic_WORD_SZ
	dq dic_WORD_TABSTOSPACES
	dq dic_WORD_TCFA
	dq dic_WORD_TICKS
	dq dic_WORD_TOIN
	dq dic_WORD_TONUMBER
	dq dic_WORD_TOR
	dq dic_WORD_TOR2
	dq dic_WORD_TOSNUMBER
	dq dic_WORD_TRAILING
	dq dic_WORD_TUCK
	dq dic_WORD_TUCK2
	dq dic_WORD_TWODIV
	dq dic_WORD_TWOMUL
	dq dic_WORD_TYPE
	dq dic_WORD_TYPE_FD
	dq dic_WORD_UDIVMOD
	dq dic_WORD_UGT
	dq dic_WORD_UGTEQ
	dq dic_WORD_ULT
	dq dic_WORD_ULTEQ
	dq dic_WORD_UMDIVMOD
	dq dic_WORD_UMULSTAR
	dq dic_WORD_UNUSED
	dq dic_WORD_VERSION
	dq dic_WORD_WORDBUF
	dq dic_WORD_WORDNAME
	dq dic_WORD_XOR
	dq dic_WORD_XTSKIP
	dq dic_WORD_ZBRANCH
	dq dic_WORD_ZEQ
	dq dic_WORD_ZGT
	dq dic_WORD_ZGTEQ
	dq dic_WORD_ZLT
	dq dic_WORD_ZLTEQ
	dq dic_WORD_ZNE
	dq dic_WORD__F_HIDDEN
	dq dic_WORD__F_IMMED
	dq dic_WORD__F_LENMASK
	dq dic_WORD__H_NAME
	dq dic_WORD__H_NSIZE
	dq dic_WORD__XT_BODY
	dq dic_WORD__XT_COMPILE
	dq dic_WORD__XT_LENGTH
	dq dic_WORD__XT_SIZE
	dq dic_WORD_TEST
dictionary_end:

;;;;;;;;;;;;;;;;;;;;;;;;;;
; room for user dictionary
;;;;;;;;;;;;;;;;;;;;;;;;;;

	times USER_DEFS_SIZE db 0
forth_end:
