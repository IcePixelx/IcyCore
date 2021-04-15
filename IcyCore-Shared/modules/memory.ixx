module;

#include <iostream>
#include <vector>
#include <tuple>
#include <unordered_map>
#include "Windows.h"

export module memory;

export class MemoryAddress
{
public:
	MemoryAddress(std::uintptr_t ptr) : ptr(ptr) {}
	MemoryAddress(void* ptr) : ptr(std::uintptr_t(ptr)) {}
	MemoryAddress() : ptr(0) {}

	std::uintptr_t GetPtr()
	{
		return ptr;
	}

	operator std::uintptr_t() const
	{
		return ptr;
	}

	operator void* ()
	{
		return reinterpret_cast<void*>(ptr);
	}

	operator bool()
	{
		return ptr != NULL;
	}

	bool operator== (const MemoryAddress& other_class) const
	{
		return ptr == other_class.ptr;
	}

	bool operator== (const std::uintptr_t& other_ptr) const
	{
		return ptr == other_ptr;
	}

	bool operator!= (const MemoryAddress& other_class) const
	{
		return ptr != other_class.ptr;
	}

	bool operator!= (const std::uintptr_t& other_ptr) const
	{
		return ptr != other_ptr;
	}

	template<typename T> T C_Cast()
	{
		return (T)ptr;
	}

	template<typename T> T R_Cast()
	{
		return reinterpret_cast<T>(ptr);
	}

	template<class T> T GetValue()
	{
		return *reinterpret_cast<T*>(ptr);
	}

	template<class T> std::int32_t GetVirtualFunctionIndex()
	{
		return *reinterpret_cast<T*>(ptr) / 4; // Divide by 4 to get actual virtual function index.
	}

	MemoryAddress Offset(const std::ptrdiff_t offset)
	{
		return MemoryAddress(ptr + offset);
	}

	MemoryAddress OffsetSelf(const std::ptrdiff_t offset)
	{
		ptr += offset;
		return *this;
	}

	MemoryAddress FollowJmpSelf(const std::ptrdiff_t jmp_opcode_offset = 0x1)
	{
		return FollowJmpInternal(jmp_opcode_offset, true); 
	}

	MemoryAddress FollowJmp(const std::ptrdiff_t jmp_opcode_offset = 0x1)
	{
		return FollowJmpInternal(jmp_opcode_offset, false); 
	}

	MemoryAddress DerefSelf(const std::ptrdiff_t deref_count = 0x1)
	{
		return DerefInternal(deref_count, true);
	}

	MemoryAddress Deref(const std::ptrdiff_t deref_count = 0x1)
	{
		return DerefInternal(deref_count, false);
	}

	bool CheckBytes(const std::vector<std::uint8_t> byte_array)
	{
		std::uintptr_t ptr_reference = ptr;
		
		for (auto [byte_at_cur_address, i] = std::tuple{ std::uint8_t(), (std::size_t)0 }; i < byte_array.size(); i++, ptr_reference++)
		{
			byte_at_cur_address = *reinterpret_cast<std::uint8_t*>(ptr_reference);

			if (byte_at_cur_address != byte_array[i])
				return false;
		}

		return true;
	}

private:

	/* Variables */
	std::uintptr_t ptr;

	/* Internal Functions */
	MemoryAddress FollowJmpInternal(const std::ptrdiff_t jmp_opcode_offset, const bool self_jmp)
	{
		std::uintptr_t skip_jmp_instruction = ptr + jmp_opcode_offset; // Skip jmp opcode.

		std::int32_t relative_address = *reinterpret_cast<std::int32_t*>(skip_jmp_instruction); // Get the 4-byte relative address.

		if (self_jmp)
		{
			ptr += 0x5 + relative_address; // Skip full instruction and add relative address to get jmp destination.
			return *this; // Return this class.
		}
		else
		{
			return MemoryAddress(ptr + 0x5 + relative_address); // Return new class with jmp destination.
		}
	}

	MemoryAddress DerefInternal(const std::ptrdiff_t deref_count, const bool self_deref)
	{
		if (self_deref)
		{
			for (std::ptrdiff_t i = 0; i < deref_count; i++)
			{
				if (ptr)
				{
					ptr = *reinterpret_cast<std::uintptr_t*>(ptr); // Derefence pointer.
				}
			}

			return *this; // Return this.
		}
		else
		{
			std::uintptr_t ptr_reference = ptr; // Get pointer reference.

			for (std::ptrdiff_t i = 0; i < deref_count; i++)
			{
				if (ptr_reference)
				{
					ptr_reference = *reinterpret_cast<std::uintptr_t*>(ptr_reference); // Dereference pointer reference.
				}
			}

			return MemoryAddress(ptr_reference); // Return new class with pointer reference.
		}
	}
};

export namespace modulemanager
{
	class MemoryModules
	{
	public:
		struct ModuleSections
		{
			ModuleSections() : section_name(0), section_start_address(0), section_size(0) {}
			ModuleSections(const char* section_name, std::uintptr_t section_start_address, DWORD section_size) : section_name(section_name), section_start_address(section_start_address), section_size(section_size) {}
			bool IsSectionValid()
			{
				if (section_size != 0)
					return true;

				return false;
			}

			const char* section_name;
			std::uintptr_t section_start_address = 0;
			DWORD section_size = 0;
		};

		MemoryModules() : module_name(0), module_base(0), module_size(0), module_sections(std::vector<ModuleSections>()), dos_header(nullptr), nt_headers(nullptr) {}

		MemoryModules(const char* module_name, std::uintptr_t module_base) : module_name(module_name), module_base(module_base)
		{
			dos_header = (IMAGE_DOS_HEADER*)this->module_base;
			nt_headers = (IMAGE_NT_HEADERS*)(this->module_base + dos_header->e_lfanew);
			module_size = nt_headers->OptionalHeader.SizeOfImage;

			const IMAGE_SECTION_HEADER* section_header = (PIMAGE_SECTION_HEADER)((DWORD)nt_headers + sizeof(IMAGE_NT_HEADERS)); // Grab the section header.

			for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) // Loop through the sections.
			{
				const IMAGE_SECTION_HEADER& current_section = section_header[i]; // Get current section.
				module_sections.push_back(ModuleSections((const char*)current_section.Name, (std::uintptr_t)(dos_header + current_section.VirtualAddress), current_section.SizeOfRawData)); // Push back a struct with the section data.
			}
		}
		MemoryModules(const char* module_name, void* module_base) : module_name(module_name), module_base(std::uintptr_t(module_base))
		{
			dos_header = (IMAGE_DOS_HEADER*)this->module_base;
			nt_headers = (IMAGE_NT_HEADERS*)(this->module_base + dos_header->e_lfanew);
			module_size = nt_headers->OptionalHeader.SizeOfImage;

			const IMAGE_SECTION_HEADER* section_header = (PIMAGE_SECTION_HEADER)((DWORD)nt_headers + sizeof(IMAGE_NT_HEADERS)); // Grab the section header.

			for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) // Loop through the sections.
			{
				const IMAGE_SECTION_HEADER& current_section = section_header[i]; // Get current section.
				module_sections.push_back(ModuleSections((const char*)current_section.Name, (std::uintptr_t)(dos_header + current_section.VirtualAddress), current_section.SizeOfRawData)); // Push back a struct with the section data.
			}
		}

		const char* GetModuleName() { return module_name; };
		std::uintptr_t GetModuleBaseAddress() { return module_base; };

		ModuleSections GetSectionByName(const char* section_name)
		{
			for (ModuleSections& current_section : module_sections)
			{
				if (std::strcmp(current_section.section_name, section_name) == 0)
					return current_section;
			}

			return ModuleSections();
		}

		MemoryAddress PatternScan(const char* pattern, const std::ptrdiff_t pattern_occurence = 1) // Thanks to flux for that pattern scan function. I modified it a bit to suit my needs.
		{
			static auto PatternToBytes = [](const char* pattern)
			{
				char* pattern_start = const_cast<char*>(pattern); // Cast const away and get start of pattern.
				char* pattern_end = pattern_start + std::strlen(pattern); // Get end of pattern.

				std::vector<std::int32_t> bytes = std::vector<std::int32_t>{ }; // Initialize byte vector.

				for (char* current_byte = pattern_start; current_byte < pattern_end; ++current_byte)
				{
					if (*current_byte == '?') // Is current char(byte) a wildcard?
					{
						++current_byte; // Skip 1 character.

						if (*current_byte == '?') // Is it a double wildcard pattern?
							++current_byte; // If so skip the next space that will come up so we can reach the next byte.

						bytes.push_back(-1); // Push the byte back as invalid.
					}
					else
					{
						// https://stackoverflow.com/a/43860875/12541255
						// Here we convert our string to a unsigned long integer. We pass our string then we use 16 as the base because we want it as hexadecimal.
						// Afterwards we push the byte into our bytes vector.
						bytes.push_back(std::strtoul(current_byte, &current_byte, 16));
					}
				}
				return bytes;
			};

			ModuleSections text_section = GetSectionByName(".text"); // Get the .text section.
			if (!text_section.IsSectionValid())
				return MemoryAddress();

			const std::vector<std::int32_t> bytes_to_scan = PatternToBytes(pattern); // Convert our string pattern into an vector array.
			const std::pair bytes_information = std::make_pair(bytes_to_scan.size(), bytes_to_scan.data()); // Get the size and data of our bytes.

			std::uint8_t* latest_occurence = nullptr;
			std::ptrdiff_t occurences_found = 0;

			std::uint8_t* start_of_code_section = reinterpret_cast<std::uint8_t*>(text_section.section_start_address);

			for (DWORD i = 0; i < text_section.section_size - bytes_information.first; i++)
			{
				bool found_address = true;

				for (DWORD a = 0; a < bytes_information.first; a++)
				{
					// If either the current byte equals to the byte in our pattern or our current byte in the pattern is a wildcard
					// our if clause will be false.
					if (start_of_code_section[i + a] != bytes_information.second[a] && bytes_information.second[a] != -1)
					{
						found_address = false;
						break;
					}
				}

				if (found_address)
				{
					occurences_found++;
					if (pattern_occurence == occurences_found)
						return MemoryAddress(&start_of_code_section[i]);

					latest_occurence = &start_of_code_section[i];
				}
			}

			return MemoryAddress(latest_occurence);
		}

	private:
		const char* module_name;
		std::uintptr_t module_base;
		DWORD module_size;
		std::vector<ModuleSections> module_sections = {};
		PIMAGE_DOS_HEADER dos_header;
		PIMAGE_NT_HEADERS nt_headers;
	};

	std::unordered_map<const char*, MemoryModules> cached_modules = {};

	MemoryModules* GetModuleByName(const char* module_name)
	{
		auto map_entry = cached_modules.find(module_name);

		if (map_entry == cached_modules.end())
			return nullptr;

		return &cached_modules[module_name];
	}

	MemoryModules* AddModule(const char* module_name, void* module_base_address)
	{
		cached_modules[module_name] = MemoryModules(module_name, module_base_address);
		return &cached_modules[module_name];
	}
}