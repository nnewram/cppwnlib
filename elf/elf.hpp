#pragma once

#include "basic.hpp"
#include <stdexcept>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h> 

#include <elf.h>


namespace pwn {

enum ElfFlag : std::size_t {
	bit32 = 4,
	bit64 = 8
};

namespace detail {

std::string get_section_type(std::size_t type) {
	std::string rt;

	switch (type) {
		case 0:  rt = "SHT_NULL";      /* Section header table entry unused */ break;
		case 1:  rt = "SHT_PROGBITS";  /* Program data */                      break;
		case 2:  rt = "SHT_SYMTAB";    /* Symbol table */                      break;
		case 3:  rt = "SHT_STRTAB";    /* String table */                      break;
		case 4:  rt = "SHT_RELA";      /* Relocation entries with addends */   break;
		case 5:  rt = "SHT_HASH";      /* Symbol hash table */                 break;
		case 6:  rt = "SHT_DYNAMIC";   /* Dynamic linking information */       break;
		case 7:  rt = "SHT_NOTE";      /* Notes */                             break;
		case 8:  rt = "SHT_NOBITS";    /* Program space with no data (bss) */  break;
		case 9:  rt = "SHT_REL";       /* Relocation entries, no addends */    break;
		case 11: rt = "SHT_DYNSYM";    /* Dynamic linker symbol table */       break;
		default: rt = "UNKNOWN";
	}

	return rt;
}

std::string get_segment_type(std::uint32_t segment_type) {
	std::string type;

	switch (segment_type) {
		case PT_NULL:         type = "NULL";         /* Program header table entry unused */ break;
		case PT_LOAD:         type = "LOAD";         /* Loadable program segment */          break;
		case PT_DYNAMIC:      type = "DYNAMIC";      /* Dynamic linking information */       break;
		case PT_INTERP:       type = "INTERP";       /* Program interpreter */               break;
		case PT_NOTE:         type = "NOTE";         /* Auxiliary information */             break;
		case PT_SHLIB:        type = "SHLIB";        /* Reserved */                          break;
		case PT_PHDR:         type = "PHDR";         /* Entry for header table itself */     break;
		case PT_TLS:          type = "TLS";          /* Thread-local storage segment */      break;
		case PT_NUM:          type = "NUM";          /* Number of defined types */           break;
		case PT_LOOS:         type = "LOOS";         /* Start of OS-specific */              break;
		case PT_GNU_EH_FRAME: type = "GNU_EH_FRAME"; /* GCC .eh_frame_hdr segment */         break;
		case PT_GNU_STACK:    type = "GNU_STACK";    /* Indicates stack executability */     break;
		case PT_GNU_RELRO:    type = "GNU_RELRO";    /* Read-only after relocation */        break;
		case PT_SUNWBSS:      type = "SUNWBSS";      /* Sun Specific segment */              break;
		case PT_SUNWSTACK:    type = "SUNWSTACK";    /* Stack segment */                     break;
		case PT_HIOS:         type = "HIOS";         /* End of OS-specific */                break;
		case PT_LOPROC:       type = "LOPROC";       /* Start of processor-specific */       break;
		case PT_HIPROC:       type = "HIPROC";       /* End of processor-specific */         break;
		default:              type = "UNKNOWN";
	}

	return type;
}

std::string get_segment_flags(std::uint32_t segment_flags) {
	std::string flags("");

	if (segment_flags & PF_R)
		flags += "R";
	if (segment_flags & PF_W)
		flags += "W";
	if (segment_flags & PF_X)
		flags += "X";
	
	return flags;
}

std::string get_symbol_type(std::uint8_t symbol_type) {
	std::string type;

	switch (ELF32_ST_TYPE(symbol_type)) {
		case 0:  type = "NOTYPE";   break;
		case 1:  type = "OBJECT";   break;
		case 2:  type = "FUNC";     break;
		case 3:  type = "SECTION";  break;
		case 4:  type = "FILE";     break;
		case 6:  type = "TLS";      break;
		case 7:  type = "NUM";      break;
		case 10: type = "LOOS";     break;
		case 12: type = "HIOS";     break;
		default: type = "UNKNOWN";  break;
	}

	return type;
}

std::string get_symbol_bind(std::uint8_t symbol_bind) {
	std::string bind;

	switch (ELF32_ST_BIND(symbol_bind)) {
		case 0:  bind = "LOCAL";    break;
		case 1:  bind = "GLOBAL";   break;
		case 2:  bind = "WEAK";     break;
		case 3:  bind = "NUM";      break;
		case 10: bind = "UNIQUE";   break;
		case 12: bind = "HIOS";     break;
		case 13: bind = "LOPROC";   break;
		default: bind = "UNKNOWN";  break;
	}

	return bind;
}

std::string get_symbol_visibility(std::uint8_t symbol_visibility) {
	std::string visibility;

	switch (ELF32_ST_VISIBILITY(symbol_visibility)) {
		case 0:  visibility = "DEFAULT";   break;
		case 1:  visibility = "INTERNAL";  break;
		case 2:  visibility = "HIDDEN";    break;
		case 3:  visibility = "PROTECTED"; break;
		default: visibility = "UNKNOWN";   break;
	}

	return visibility;
}

std::string get_symbol_index(std::size_t symbol_index) {
	std::string index(std::to_string(symbol_index));

	switch (symbol_index) {
		case SHN_ABS:    index = "ABS";             break;
		case SHN_COMMON: index = "COM";             break;
		case SHN_UNDEF:  index = "UND";             break;
		case SHN_XINDEX: index = "COM";             break;
	}

	return index;
}

}

template<ElfFlag width>
class section {
public:
	using size_type = typename std::conditional<width == pwn::bit64, std::uint64_t, std::uint32_t>::type;
	using Eheader_type = typename std::conditional<width == pwn::bit64, Elf64_Ehdr, Elf32_Ehdr>::type;
	using Sheader_type = typename std::conditional<width == pwn::bit64, Elf64_Shdr, Elf32_Shdr>::type;

	std::size_t index;
	std::string name;
	std::string type;
	size_type offset;
	size_type *addr;
	size_type size;
	size_type ent_size;
	size_type addr_align;

	section() {}
	section(std::size_t index, std::uint8_t *mapped, Sheader_type *shdr):
		index(index),
		name(std::string((reinterpret_cast<char *>(mapped) + (reinterpret_cast<Sheader_type *>(&(shdr[reinterpret_cast<Eheader_type *>(mapped)->e_shstrndx]))->sh_offset)) + shdr[index].sh_name)),
		type(detail::get_section_type(shdr[index].sh_type)),
		offset(shdr[index].sh_offset),
		addr(reinterpret_cast<size_type *>(shdr[index].sh_addr)),
		size(shdr[index].sh_size),
		ent_size(shdr[index].sh_entsize),
		addr_align(shdr[index].sh_addralign)
	{}
};

template<ElfFlag width>
class segment {
public:
	using size_type = typename std::conditional<width == pwn::bit64, std::uint64_t, std::uint32_t>::type;
	using Pheader_type = typename std::conditional<width == pwn::bit64, Elf64_Phdr, Elf32_Phdr>::type;
	
	std::string type;
	std::string flags;
	
	size_type offset;
	size_type virtaddr;
	size_type filesize;
	size_type memsize;

	std::size_t physaddr;
	std::size_t align;

	segment() {}
	segment(std::size_t index, std::uint8_t *mapped, Pheader_type *phdr):
		type(detail::get_segment_type(phdr[index].p_type)),
		flags(detail::get_segment_flags(phdr[index].p_flags)),
		offset(phdr[index].p_offset),
		virtaddr(phdr[index].p_vaddr),
		physaddr(phdr[index].p_paddr),
		filesize(phdr[index].p_filesz),
		memsize(phdr[index].p_memsz),
		align(phdr[index].p_align)
	{}

};

template<ElfFlag width>
class symbol {
public:
	using sym_type = typename std::conditional<width == pwn::bit64, Elf64_Sym, Elf32_Sym>::type;
	using size_type = typename std::conditional<width == pwn::bit64, std::uint64_t, std::uint32_t>::type;

	size_type value;
	size_type size;

	std::string type;
	std::string bind;
	std::string visibility;
	std::string index;

	std::string section_name;

	std::string name;

	symbol() {}
	symbol(sym_type symbol_data, section<width> parent_section, std::string name):
		value(symbol_data.st_value),
		size(symbol_data.st_size),
		type(detail::get_symbol_type(symbol_data.st_info)),
		bind(detail::get_symbol_bind(symbol_data.st_info)),
		index(detail::get_symbol_index(symbol_data.st_shndx)),
		visibility(detail::get_symbol_visibility(symbol_data.st_other)),
		section_name(parent_section.name),
		name(name)
	{}
};

template<ElfFlag width>
class relocation {

};

template<ElfFlag width = pwn::bit64>
class elf {
public:
	using size_type = typename std::conditional<width == pwn::bit64, std::uint64_t, std::uint32_t>::type;
	using Eheader_type = typename std::conditional<width == pwn::bit64, Elf64_Ehdr, Elf32_Ehdr>::type;
	using Sheader_type = typename std::conditional<width == pwn::bit64, Elf64_Shdr, Elf32_Shdr>::type;
	using Pheader_type = typename std::conditional<width == pwn::bit64, Elf64_Phdr, Elf32_Phdr>::type;
public:
	std::string path;
	int fd;
	std::uint8_t *mapped;

	/* parts of the binary */
	std::vector<section<width>> sections;
	std::vector<segment<width>> segments;
	std::vector<symbol<width>> symbols;
	std::vector<relocation<width>> relocations;

	void setup_sections() {
		Eheader_type *ehdr = reinterpret_cast<Eheader_type *>(mapped);
		Sheader_type *shdr = reinterpret_cast<Sheader_type *>(mapped + ehdr->e_shoff);

		for (std::size_t i = 0; i < ehdr->e_shnum; i++) {
			sections.emplace_back(section<width>(i, mapped, shdr));
		}
	}

	void setup_segments() {
		Pheader_type *phdr = reinterpret_cast<Pheader_type *>(mapped + reinterpret_cast<Eheader_type *>(mapped)->e_phoff);

		for (std::size_t i = 0; i < reinterpret_cast<Eheader_type *>(mapped)->e_phnum; i++) {
			segments.emplace_back(segment<width>(i, mapped, phdr));
		}
	}

	void setup_symbols() {
		using sym_type = typename std::conditional<width == pwn::bit64, Elf64_Sym, Elf32_Sym>::type;

		char *strtab = nullptr;
		char *dyn_strtab = nullptr;

		for (auto &section : sections) {
			if (section.type == "SHT_STRTAB") {
				if (section.name == ".strtab")
					strtab = reinterpret_cast<char *>(mapped) + section.offset;
				else if (section.name == ".dynstr")
					dyn_strtab = reinterpret_cast<char *>(mapped) + section.offset;
			}
		}

		for (auto &section : sections) {
			bool is_symtab = section.type == "SHT_SYMTAB";
			bool is_dyntab = section.type == "SHT_DYNSYM";

			if (!(is_symtab || is_dyntab))
				continue;

			if (is_symtab && (strtab == nullptr))
				throw std::runtime_error(pwn::format("nullptr dereference during processing of ELF file due to non-existing .strtab."));
			
			else if (is_dyntab && (dyn_strtab == nullptr))
				throw std::runtime_error(pwn::format("nullptr dereference during processing of ELF file due to non-existing .dynstr."));

			char *strtab_p = is_symtab ? strtab : dyn_strtab;

			for (std::size_t i = 0; i < section.size / sizeof(sym_type); i++) {
				std::string symbol_name("");

				sym_type symbol_data = reinterpret_cast<sym_type *>(mapped + section.offset)[i];
				symbol_name = std::string(strtab_p + symbol_data.st_name);

				symbols.emplace_back(symbol<width>(symbol_data, section, symbol_name));
			}
		}
	}

	void setup_relocations() {

	}

public:
	elf() {}
	elf(std::string path): path(path) {
		struct stat st;

		if ((fd = open(path.c_str(), O_RDONLY)) < 0)
			throw std::runtime_error(pwn::format("Could not open file {}", path));

		if (fstat(fd, &st) < 0)
			throw std::runtime_error(pwn::format("Could not stat file {}", path));
		
		mapped = static_cast<uint8_t *>(mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE | MAP_32BIT, fd, 0));

		if (mapped == MAP_FAILED)
			throw std::runtime_error(pwn::format("Could not mmap for file {} with size {}", path, st.st_size));

		setup_sections();
		setup_segments();
		setup_symbols();
		setup_relocations();
	}
};

}