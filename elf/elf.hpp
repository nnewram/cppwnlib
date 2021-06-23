#pragma once

#include "basic.hpp"
#include <stdexcept>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h> 

#include <unistd.h>

#include <elf.h>


namespace pwn {

enum elfflag : std::size_t {
	invalid = 0,
	bit32 = 4,
	bit64 = 8
};

template<elfflag width>
class section;
template<elfflag width>
class segment;
template<elfflag width>
class symbol;
template<elfflag width>
class relocation;

template<elfflag width>
using size_type = typename std::conditional<width == pwn::bit64, std::uint64_t, std::uint32_t>::type;

namespace detail {

template<elfflag width>
size_type<width> get_relocation_value(std::uint64_t r_info, std::vector<symbol<width>> &symbols) {
	constexpr bool is_64bit = width == pwn::bit64;

	std::uint64_t symbol_index = 0; 

	if (is_64bit)
		symbol_index = ELF64_R_SYM(r_info);
	else
		symbol_index = ELF32_R_SYM(r_info);

	if (symbol_index >= symbols.size())
		return 0;
	
	return symbols[symbol_index].value;
}

template<elfflag width>
std::string get_relocation_name(std::uint64_t r_info, std::vector<symbol<width>> &symbols) {
	constexpr bool is_64bit = width == pwn::bit64;

	std::uint64_t symbol_index = 0; 

	if (is_64bit)
		symbol_index = ELF64_R_SYM(r_info);
	else
		symbol_index = ELF32_R_SYM(r_info);

	if (symbol_index >= symbols.size())
		return "UNKNOWN";
	
	return symbols[symbol_index].name;
}

std::pair<std::uint8_t *, std::size_t> map_file(std::string path) {
	struct stat st;
	int fd;

	if ((fd = open(path.c_str(), O_RDONLY)) < 0)
		throw std::runtime_error(pwn::format("Could not open file {}", path));

	if (fstat(fd, &st) < 0)
		throw std::runtime_error(pwn::format("Could not stat file {}", path));
	
	std::uint8_t *mapped = static_cast<uint8_t *>(mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE | MAP_32BIT, fd, 0));

	if (mapped == MAP_FAILED)
		throw std::runtime_error(pwn::format("Could not mmap for file {} with size {}", path, st.st_size));

	close(fd);

	return std::make_pair(mapped, st.st_size);
}

bool is_elf(std::uint8_t *mapped) {
	return (mapped[0] == 0x7f &&
		mapped[1] == 'E' &&
		mapped[2] == 'L' &&
		mapped[3] == 'F');
}

elfflag get_width(std::uint8_t *mapped) {
	if (mapped[4] == 2)
		return pwn::bit64;
	else if (mapped[4] == 1)
		return pwn::bit64;
	else
		return pwn::invalid;
}

}

template<elfflag width>
class section {
public:
	using Eheader_type = typename std::conditional<width == pwn::bit64, Elf64_Ehdr, Elf32_Ehdr>::type;
	using Sheader_type = typename std::conditional<width == pwn::bit64, Elf64_Shdr, Elf32_Shdr>::type;

	std::size_t index;
	std::string name;
	size_type<width> type;
	size_type<width> offset;
	size_type<width> *address;
	size_type<width> size;
	size_type<width> ent_size;
	size_type<width> addr_align;

	section() {}
	section(std::size_t index, std::uint8_t *mapped, Sheader_type *shdr):
		index(index),
		name(std::string((reinterpret_cast<char *>(mapped) + (reinterpret_cast<Sheader_type *>(&(shdr[reinterpret_cast<Eheader_type *>(mapped)->e_shstrndx]))->sh_offset)) + shdr[index].sh_name)),
		type(shdr[index].sh_type),
		offset(shdr[index].sh_offset),
		address(reinterpret_cast<size_type<width> *>(shdr[index].sh_addr)),
		size(shdr[index].sh_size),
		ent_size(shdr[index].sh_entsize),
		addr_align(shdr[index].sh_addralign)
	{}

	std::string get_type() {
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
};

template<elfflag width>
class segment {
public:
	using Pheader_type = typename std::conditional<width == pwn::bit64, Elf64_Phdr, Elf32_Phdr>::type;
	
	std::uint32_t type;
	std::uint32_t flags;
	
	size_type<width> offset;
	size_type<width> virtaddr;
	size_type<width> filesize;
	size_type<width> memsize;

	std::size_t physaddr;
	std::size_t align;

	segment() {}
	segment(std::uint8_t *mapped, Pheader_type phdr):
		type(phdr.p_type),
		flags(phdr.p_flags),
		offset(phdr.p_offset),
		virtaddr(phdr.p_vaddr),
		physaddr(phdr.p_paddr),
		filesize(phdr.p_filesz),
		memsize(phdr.p_memsz),
		align(phdr.p_align)
	{}

	std::string get_type() {
		std::string typestr;

		switch (type) {
			case PT_NULL:         typestr = "NULL";         /* Program header table entry unused */ break;
			case PT_LOAD:         typestr = "LOAD";         /* Loadable program segment */          break;
			case PT_DYNAMIC:      typestr = "DYNAMIC";      /* Dynamic linking information */       break;
			case PT_INTERP:       typestr = "INTERP";       /* Program interpreter */               break;
			case PT_NOTE:         typestr = "NOTE";         /* Auxiliary information */             break;
			case PT_SHLIB:        typestr = "SHLIB";        /* Reserved */                          break;
			case PT_PHDR:         typestr = "PHDR";         /* Entry for header table itself */     break;
			case PT_TLS:          typestr = "TLS";          /* Thread-local storage segment */      break;
			case PT_NUM:          typestr = "NUM";          /* Number of defined types */           break;
			case PT_LOOS:         typestr = "LOOS";         /* Start of OS-specific */              break;
			case PT_GNU_EH_FRAME: typestr = "GNU_EH_FRAME"; /* GCC .eh_frame_hdr segment */         break;
			case PT_GNU_STACK:    typestr = "GNU_STACK";    /* Indicates stack executability */     break;
			case PT_GNU_RELRO:    typestr = "GNU_RELRO";    /* Read-only after relocation */        break;
			case PT_SUNWBSS:      typestr = "SUNWBSS";      /* Sun Specific segment */              break;
			case PT_SUNWSTACK:    typestr = "SUNWSTACK";    /* Stack segment */                     break;
			case PT_HIOS:         typestr = "HIOS";         /* End of OS-specific */                break;
			case PT_LOPROC:       typestr = "LOPROC";       /* Start of processor-specific */       break;
			case PT_HIPROC:       typestr = "HIPROC";       /* End of processor-specific */         break;
			default:              typestr = "UNKNOWN";
		}

		return typestr;
	}

	std::string get_flags() {
		std::string flagsstr("");

		if (flags & PF_R)
			flagsstr += "R";
		if (flags & PF_W)
			flagsstr += "W";
		if (flags & PF_X)
			flagsstr += "X";
		
		return flagsstr;
	}

};

template<elfflag width>
class symbol {
public:
	using sym_type = typename std::conditional<width == pwn::bit64, Elf64_Sym, Elf32_Sym>::type;

	size_type<width> value;
	size_type<width> size;

	std::uint8_t info; // bind & type
	std::uint8_t visibility;
	std::uint16_t index;

	std::string name;
	std::string section_name;

	symbol() {}
	symbol(sym_type symbol_data, section<width> parent_section, std::string name):
		value(symbol_data.st_value),
		size(symbol_data.st_size),
		info(symbol_data.st_info),
		index(symbol_data.st_shndx),
		visibility(symbol_data.st_other),
		section_name(parent_section.name),
		name(name)
	{}

	std::string get_type() {
		std::string type;

		switch (ELF32_ST_TYPE(info)) {
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

	std::string get_bind() {
		std::string bind;

		switch (ELF32_ST_BIND(info)) {
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

	std::string get_visibility() {
		std::string visibilitystr;

		switch (ELF32_ST_VISIBILITY(visibility)) {
			case 0:  visibilitystr = "DEFAULT";   break;
			case 1:  visibilitystr = "INTERNAL";  break;
			case 2:  visibilitystr = "HIDDEN";    break;
			case 3:  visibilitystr = "PROTECTED"; break;
			default: visibilitystr = "UNKNOWN";   break;
		}

		return visibilitystr;
	}

	std::string get_index() {
		std::string indexstr(std::to_string(index));

		switch (index) {
			case SHN_ABS:    indexstr = "ABS";             break;
			case SHN_COMMON: indexstr = "COM";             break;
			case SHN_UNDEF:  indexstr = "UND";             break;
			case SHN_XINDEX: indexstr = "COM";             break;
		}

		return indexstr;
	}
};

template<elfflag width>
class relocation {
public:
	using Rela_type = typename std::conditional<width == pwn::bit64, Elf64_Rela, Elf32_Rela>::type;
	using Rel_type = typename std::conditional<width == pwn::bit64, Elf64_Rel, Elf32_Rel>::type;

	size_type<width> offset;
	size_type<width> info;
	size_type<width> addend;
	size_type<width> *plt_address;

	size_type<width> symbol_value;
	std::string symbol_name;
	
	std::string section_name;

	relocation() {}
	relocation(Rela_type relocation_data, size_type<width> *plt_address, section<width> parent, std::vector<symbol<width>> &symbols):
		offset(relocation_data.r_offset),
		info(relocation_data.r_info),
		symbol_name(detail::get_relocation_name<width>(relocation_data.r_info, symbols)),
		symbol_value(detail::get_relocation_value<width>(relocation_data.r_info, symbols)),
		plt_address(plt_address),
		section_name(parent.name),
		addend(relocation_data.r_addend)
	{}

	relocation(Rel_type relocation_data, size_type<width> *plt_address, section<width> parent, std::vector<symbol<width>> &symbols):
		offset(relocation_data.r_offset),
		info(relocation_data.r_info),
		symbol_name(detail::get_relocation_name<width>(relocation_data.r_info, symbols)),
		symbol_value(detail::get_relocation_value<width>(relocation_data.r_info, symbols)),
		plt_address(plt_address),
		section_name(parent.name),
		addend(0)
	{}

	/*
	source: https://code.woboq.org/userspace/glibc/elf/elf.h.html#3402
	*/
	std::string get_type() {
		constexpr bool is_64bit = width == pwn::bit64;
		std::uint64_t maskedtype;
		if (is_64bit)
			maskedtype = ELF64_R_TYPE(info);
		else
			maskedtype = ELF32_R_TYPE(info);
		
		std::string rt;

		switch (maskedtype) {
			case 0:  rt = "R_X86_64_NONE";             break;
			case 1:  rt = "R_X86_64_64";               break;
			case 2:  rt = "R_X86_64_PC32";             break;
			case 3:  rt = "R_X86_64_GOT32";            break;
			case 4:  rt = "R_X86_64_PLT32";            break;
			case 5:  rt = "R_X86_64_COPY";             break;
			case 6:  rt = "R_X86_64_GLOB_DAT";         break;
			case 7:  rt = "R_X86_64_JUMP_SLOT";        break;
			case 8:  rt = "R_X86_64_RELATIVE";         break;
			case 9:  rt = "R_X86_64_GOTPCREL";         break;
			case 10: rt = "R_X86_64_32";               break;
			case 11: rt = "R_X86_64_32S";              break;
			case 12: rt = "R_X86_64_16";               break;
			case 13: rt = "R_X86_64_PC16";             break;
			case 14: rt = "R_X86_64_8";                break;
			case 15: rt = "R_X86_64_PC8";              break;
			case 16: rt = "R_X86_64_DTPMOD64";         break;
			case 17: rt = "R_X86_64_DTPOFF64";         break;
			case 18: rt = "R_X86_64_TPOFF64";          break;
			case 19: rt = "R_X86_64_TLSGD";            break;
			case 20: rt = "R_X86_64_TLSLD";            break;
			case 21: rt = "R_X86_64_DTPOFF32";         break;
			case 22: rt = "R_X86_64_GOTTPOFF";         break;
			case 23: rt = "R_X86_64_TPOFF32";          break;
			case 24: rt = "R_X86_64_PC64";             break;
			case 25: rt = "R_X86_64_GOTOFF64";         break;
			case 26: rt = "R_X86_64_GOTPC32";          break;
			case 27: rt = "R_X86_64_GOT64";            break;
			case 28: rt = "R_X86_64_GOTPCREL64";       break;
			case 29: rt = "R_X86_64_GOTPC64";          break;
			case 30: rt = "R_X86_64_GOTPLT64";         break;
			case 31: rt = "R_X86_64_PLTOFF64";         break;
			case 32: rt = "R_X86_64_SIZE32";           break;
			case 33: rt = "R_X86_64_SIZE64";           break;
			case 34: rt = "R_X86_64_GOTPC32_TLSDESC";  break;
			case 35: rt = "R_X86_64_TLSDESC_CALL";     break;
			case 36: rt = "R_X86_64_TLSDESC";          break;
			case 37: rt = "R_X86_64_IRELATIVE";        break;
			case 38: rt = "R_X86_64_RELATIVE64";       break;
			case 41: rt = "R_X86_64_GOTPCRELX";        break;
			case 42: rt = "R_X86_64_REX_GOTPCRELX";    break;
			case 43: rt = "R_X86_64_NUM";              break;
			default: rt = "OTHER";
		}

		return rt;
	}
};

template<elfflag width = pwn::bit64>
class elf {
public:
	using Eheader_type = typename std::conditional<width == pwn::bit64, Elf64_Ehdr, Elf32_Ehdr>::type;
	using Sheader_type = typename std::conditional<width == pwn::bit64, Elf64_Shdr, Elf32_Shdr>::type;
	using Pheader_type = typename std::conditional<width == pwn::bit64, Elf64_Phdr, Elf32_Phdr>::type;

	std::string path;
	std::uint8_t *mapped;

	/* parts of the binary */
	std::vector<section<width>> sections;
	std::vector<segment<width>> segments;
	std::vector<symbol<width>> symbols;
	std::vector<relocation<width>> relocations;

	std::size_t mmap_size;

private:
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
			segments.emplace_back(segment<width>(mapped, phdr[i]));
		}
	}

	void setup_symbols() {
		using sym_type = typename std::conditional<width == pwn::bit64, Elf64_Sym, Elf32_Sym>::type;

		char *strtab     = nullptr;
		char *dyn_strtab = nullptr;

		for (auto &section : sections) {
			if (section.get_type() == "SHT_STRTAB") {
				if (section.name == ".strtab")
					strtab = reinterpret_cast<char *>(mapped) + section.offset;
				else if (section.name == ".dynstr")
					dyn_strtab = reinterpret_cast<char *>(mapped) + section.offset;
			}
		}

		for (auto &section : sections) {
			bool is_symtab = section.get_type() == "SHT_SYMTAB";
			bool is_dyntab = section.get_type() == "SHT_DYNSYM";

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
		using Rela_type = typename std::conditional<width == pwn::bit64, Elf64_Rela, Elf32_Rela>::type;
		using Rel_type = typename std::conditional<width == pwn::bit64, Elf64_Rel, Elf32_Rel>::type;

		auto section = get_section(".plt");

		if (section.name != ".plt")
			throw std::runtime_error("Could not find .plt section in binary.");
		
		size_type<width> *plt_address = section.address;

		for (auto &section : sections) {
			if (section.get_type() != "SHT_RELA" && section.get_type() != "SHT_REL")
				continue;
			
			if (section.get_type() == "SHT_RELA") {
				for (std::size_t i = 0; i < section.size / sizeof(Rela_type); i++) {
					size_type<width> *plt_rel_address = plt_address + (i + 1) * section.ent_size;
					relocations.emplace_back(relocation<width>(reinterpret_cast<Rela_type *>(mapped + section.offset)[i], plt_rel_address, section, symbols));
				}
			}
			else {
				for (std::size_t i = 0; i < section.size / sizeof(Rel_type); i++) {
					size_type<width> *plt_rel_address = plt_address + (i + 1) * section.ent_size;
					relocations.emplace_back(relocation<width>(reinterpret_cast<Rel_type *>(mapped + section.offset)[i], plt_rel_address, section, symbols));
				}
			}
		}
	}

public:
	elf() {}
	elf(std::string path): path(path) {
		std::pair<std::uint8_t *, std::size_t> p = detail::map_file(path);
		mapped = p.first;
		mmap_size = p.second;

		if (!detail::is_elf(mapped))
			throw std::runtime_error(pwn::format("Provided path {} does not point to an elf file.", path));

		load(mapped);
	}

	elf(std::uint8_t *mapped): mapped(mapped), mmap_size(0) {}

	~elf() {
		if (mmap_size)
			munmap(mapped, mmap_size);
	}

	/*
		It is possible to construct an elf class from memory recieved from a remote client or similar.
		Simply construct using the trivial constructor and use the load function with the start
		of the raw memory of the binary.
	*/
	void load(std::uint8_t *start) {
		mapped = start;

		setup_sections();
		setup_segments();
		setup_symbols();
		setup_relocations();
	}

	section<width> get_section(std::string name) {
		for (auto &section : sections) {
			if (section.name == name)
				return section;
		}

		return section<width>();
	}

	std::vector<section<width>> get_sections() {
		return sections;
	}

	std::vector<segment<width>> get_segments() {
		return segments;
	}
	
	std::vector<symbol<width>> get_symbols() {
		return symbols;
	}
	
	std::vector<relocation<width>> get_relocations() {
		return relocations;
	}

	symbol<width> get_symbol(std::string name) {
		for (auto& symbol : symbols) {
			if (symbol.name == name)
				return symbol;
		}

		return symbol<width>();
	}

};


/*
	dynamic elf class, use only if you are not aware of the width beforehand.
	This will possibly be implemented in the future.
*/
/*
class DynElf {
private:
	union delf {
		elf<pwn::bit32> elf32;
		elf<pwn::bit64> elf64;
	} adelf;

	elfflag width;
public:
	union Section {
		section<pwn::bit32> section32;
		section<pwn::bit64> section64;
	};

	union Segment {
		segment<pwn::bit32> segment32;
		segment<pwn::bit64> section64;
	};

	union Section {
		symbol<pwn::bit32> section32;
		symbol<pwn::bit64> section64;
	};

	union Section {
		relocation<pwn::bit32> section32;
		relocation<pwn::bit64> section64;
	};

	elfflag get_width() {
		return width;
	}

	DynElf() {}
	DynElf(std::string path) {
		std::uint8_t *mapped = detail::map_file(path);

		width = detail::get_width(mapped);

		if (!detail::is_elf(mapped) || (width == pwn::invalid))
			throw std::runtime_error(pwn::format("Provided path {} does not point to an elf file.", path));
	
		if (width == pwn::bit64) {
			adelf.elf64 = elf<pwn::bit64>(mapped);
			adelf.elf64.load();
		}
		else {
			adelf.elf32 = elf<pwn::bit32>(mapped);
			adelf.elf32.load();
		}
	}

	std::vector<section<width>> *get_sections() {
		return sections;
	}

	std::vector<segment<width>> *segments() {
		return segments;
	}
	
	std::vector<symbol<width>> *symbols() {
		return symbols;
	}
	
	std::vector<relocation<width>> *relocations() {
		return relocations;
	}
};
*/


}