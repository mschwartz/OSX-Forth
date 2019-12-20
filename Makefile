all:
	nasm -g -F dwarf -D LINUX -f elf64 -l forth.lst -o forth.o forth.nasm
	ld -g -m elf_x86_64 -e _main -o forth forth.o
