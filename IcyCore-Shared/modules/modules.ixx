module;

#include <tuple>
#include <unordered_map>
#include <string>
#include <locale>
#include <codecvt>
#include "Windows.h"

export module modules;

import memory;

export namespace Modulemanager
{
	/*
	*  This class holds module information.
	*  
	*  @module_name: holds name of module.
	*  @module_base: holds module base address.
	*  @module_size: size of module.
	*  @module_sections: vector that holds ModuleSections struct which holds all sections of the module.
	*  @dos_header: holds dos header.
	*  @nt_headers: holds nt headers.
	*/

	class MemoryModules
	{
	public:

		/*
		*   This struct holds a module section.
		* 
		*   @section_name: holds name of the section.
		*   @section_start_address: holds start address of the section.
		*   @section_size: holds the section size.
		*/
		struct ModuleSections
		{
			ModuleSections() : section_name(std::string()), section_start_address(0), section_size(0) {}
			ModuleSections(std::string section_name, std::uintptr_t section_start_address, DWORD section_size) : section_name(section_name), section_start_address(section_start_address), section_size(section_size) {}

			/*
			*   This function checks if the section is valid.
			* 
			*   @calling convention: Compiler handled.
			*   @parameters:         None.
			*   @return:             If the section is not valid it will return false. If its valid it will return true.
			*/
			bool IsSectionValid()
			{
				if (section_size != 0) // If section size isn't 0 the section is valid.
					return true;

				return false;
			}

			std::string section_name;
			std::uintptr_t section_start_address = 0;
			DWORD section_size = 0;
		};

		MemoryModules() : module_name(std::string()), module_base(0), module_size(0), module_sections(std::vector<ModuleSections>()), dos_header(nullptr), nt_headers(nullptr) {}

		MemoryModules(std::string module_name, std::uintptr_t module_base) : module_name(module_name), module_base(module_base)
		{
			dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(this->module_base); // Cast module_base into dos header.
			nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(this->module_base + dos_header->e_lfanew); // Get nt_header location and cast it to it.
			module_size = nt_headers->OptionalHeader.SizeOfImage; // Grab size of the module

			const IMAGE_SECTION_HEADER* section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<DWORD>(nt_headers) + sizeof(IMAGE_NT_HEADERS)); // Grab the section header.

			for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) // Loop through the sections.
			{
				const IMAGE_SECTION_HEADER& current_section = section_header[i]; // Get current section.
				module_sections.push_back(ModuleSections(std::string(reinterpret_cast<const char*>(current_section.Name)), (std::uintptr_t)(dos_header + current_section.VirtualAddress), current_section.SizeOfRawData)); // Push back a struct with the section data.
			}
		}
		MemoryModules(std::string module_name, void* module_base) : module_name(module_name), module_base(std::uintptr_t(module_base))
		{
			dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(this->module_base); // Cast module_base into dos header.
			nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(this->module_base + dos_header->e_lfanew); // Get nt_header location and cast it to it.
			module_size = nt_headers->OptionalHeader.SizeOfImage; // Grab size of the module

			const IMAGE_SECTION_HEADER* section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<DWORD>(nt_headers) + sizeof(IMAGE_NT_HEADERS)); // Grab the section header.

			for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) // Loop through the sections.
			{
				const IMAGE_SECTION_HEADER& current_section = section_header[i]; // Get current section.
				module_sections.push_back(ModuleSections(std::string(reinterpret_cast<const char*>(current_section.Name)), (std::uintptr_t)(dos_header + current_section.VirtualAddress), current_section.SizeOfRawData)); // Push back a struct with the section data.
			}
		}

		std::string GetModuleName() { return module_name; }; // Returns module_name.
		std::uintptr_t GetModuleBaseAddress() { return module_base; }; // Returns module_base.

		/*
		*   This function gives you the section you pass by name in the first parameter.
		* 
		*   It loops through all section pushed back into the vector and checks if the name you passed as section_name equals any of the vector entries.
		* 
		*   @calling convention: Compiler handled.
		*   @parameter:          Constant std::string section_name, section name you want to get from the vector.
		*   @return:             If section is found in the vector it will return the co-responsible ModuleSections struct otherwise it will return a empty ModuleSections struct.
		*/

		ModuleSections GetSectionByName(const std::string section_name)
		{
			for (ModuleSections& current_section : module_sections)
			{
				if (current_section.section_name.compare(section_name) == 0)
					return current_section;
			}

			return ModuleSections();
		}

		/*
		*  This function allows you to scan memory sequence in any module and get the address for that specific assembly line.
		* 
		*  @calling convention: Compiler handled.
		*  @parameter:          Constant std::string pattern, memory sequence that is gonna be passed as a string.
		                        Constant std::ptrdriff_t patter_occurence, specific which occurence of the memory sequence you wanna grab in the module.
		   @return:             Returns address if the memory sequence was found as a MemoryAddress class. If it does not find it it will return an empty MemoryAddress class.
		*/

		MemoryAddress PatternScan(const std::string pattern, const std::ptrdiff_t pattern_occurence = 1) // Thanks to flux for that pattern scan function. I modified it a bit to suit my needs.
		{
			static auto PatternToBytes = [](const std::string pattern)
			{
				char* pattern_start = const_cast<char*>(pattern.c_str()); // Cast const away and get start of pattern.
				char* pattern_end = pattern_start + std::strlen(pattern.c_str()); // Get end of pattern.

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

			const std::vector<std::int32_t> bytes_to_scan = PatternToBytes(pattern.c_str()); // Convert our string pattern into an vector array.
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

				if (found_address) // Did we find one pattern?
				{
					occurences_found++; // Increment occurences found counter.
					if (pattern_occurence == occurences_found) // Is it the occurence we want?
						return MemoryAddress(&start_of_code_section[i]); // If yes return it.

					latest_occurence = &start_of_code_section[i]; // Stash latest occurence.
				}
			}

			return MemoryAddress(latest_occurence);
		}

		/*
		*  This function tries to grab the function named in the function_name parameter from the export table in the current module.
		* 
		*  @calling convention: Compiler handled.
		*  @parameter:          Constant std::string function_name, string of the function you want to grab from the export table.
		*  @return:             If it finds the exported function via name that you want it will return the address of it as a MemoryAddress class. Otherwise it will return a empty MemoryAddress class.
		*/

		MemoryAddress GetExportedFunction(const std::string function_name)
		{
			if (!dos_header || dos_header->e_magic != IMAGE_DOS_SIGNATURE) // Is dos_header valid?
				return MemoryAddress();

			if (!nt_headers || nt_headers->Signature != IMAGE_NT_SIGNATURE) // Is nt_header valid?
				return MemoryAddress();

			// Get the location of IMAGE_EXPORT_DIRECTORY for this module by adding the IMAGE_DIRECTORY_ENTRY_EXPORT relative virtual address onto our module base address.
			IMAGE_EXPORT_DIRECTORY* image_export_directory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(module_base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress); 
			if (!image_export_directory)
				return MemoryAddress();

			if (!image_export_directory->NumberOfFunctions) // Are there any exported functions?
				return MemoryAddress();

			// Get the location of the functions via adding the relative virtual address from the struct into our module base address.
			DWORD* address_of_functions_ptr = reinterpret_cast<DWORD*>(module_base + image_export_directory->AddressOfFunctions);
			if (!address_of_functions_ptr)
				return MemoryAddress();

			// Get the names of the functions via adding the relative virtual address from the struct into our module base address.
			DWORD* address_of_names_ptr = reinterpret_cast<DWORD*>(module_base + image_export_directory->AddressOfNames);
			if (!address_of_names_ptr)
				return MemoryAddress();

			// Get the ordinals of the functions via adding the relative virtual address from the struct into our module base address.
			DWORD* address_of_ordinals_ptr = reinterpret_cast<DWORD*>(module_base + image_export_directory->AddressOfNameOrdinals);
			if (!address_of_ordinals_ptr)
				return MemoryAddress();

			for (std::size_t i = 0; i < image_export_directory->NumberOfFunctions; i++) // Iterate through all the functions.
			{
				// Get virtual relative address of the function name. Then add module base address to get the actual location.
				std::string export_function_name = reinterpret_cast<char*>(reinterpret_cast<DWORD*>(module_base + address_of_names_ptr[i]));

				if (export_function_name.compare(function_name) == 0) // Is this our wanted exported function?
				{
					// Get the function ordinal. Then grab the relative virtual address of our wanted function. Then add module base address so we get the actual location.
					return MemoryAddress(module_base + address_of_functions_ptr[reinterpret_cast<WORD*>(address_of_ordinals_ptr)[i]]); // Return as MemoryAddress class.
				}
			}

			return MemoryAddress();
		}

	private:
		std::string module_name;
		std::uintptr_t module_base;
		DWORD module_size;
		std::vector<ModuleSections> module_sections = {};
		IMAGE_DOS_HEADER* dos_header;
		IMAGE_NT_HEADERS* nt_headers;
	};

	std::unordered_map<std::string, MemoryModules> cached_modules = {}; // All modules we grab.

	/*
	*  Grabs all modules from the process environment block.
	* 
	*  @calling convention: Compiler handled.
	*  @parameter:          None.
	*  @return:             None.
	*/

	void GetModules()
	{
#pragma region STRUCT_DEFINITIONS
		typedef struct _CLIENT_ID
		{
			DWORD  ProcessId;
			DWORD  ThreadId;
		} CLIENT_ID;

		typedef void** PPVOID;

		typedef struct _UNICODE_STRING
		{
			WORD Length;
			WORD MaximumLength;
			WORD* Buffer;
		} UNICODE_STRING, * PUNICODE_STRING;

		typedef struct _LDR_DATA_TABLE_ENTRY
		{
			LIST_ENTRY InLoadOrderLinks;
			LIST_ENTRY InMemoryOrderLinks;
			LIST_ENTRY InInitializationOrderLinks;
			PVOID DllBase;
			PVOID EntryPoint;
			ULONG SizeOfImage;
			UNICODE_STRING FullDllName;
			UNICODE_STRING BaseDllName;
			ULONG Flags;
			WORD LoadCount;
			WORD TlsIndex;
			union
			{
				LIST_ENTRY HashLinks;
				struct
				{
					PVOID SectionPointer;
					ULONG CheckSum;
				};
			};
			union
			{
				ULONG TimeDateStamp;
				PVOID LoadedImports;
			};
			DWORD EntryPointActivationContext;
			PVOID PatchInformation;
			LIST_ENTRY ForwarderLinks;
			LIST_ENTRY ServiceTagLinks;
			LIST_ENTRY StaticLinks;
		} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


		typedef struct _PEB_LDR_DATA {
			ULONG Length;
			BOOLEAN Initialized;
			PVOID SsHandle;
			LIST_ENTRY InLoadOrderModuleList;
			LIST_ENTRY InMemoryOrderModuleList;
			LIST_ENTRY InInitializationOrderModuleList;
		} PEB_LDR_DATA, * PPEB_LDR_DATA;


		typedef struct _PEB
		{
			BOOLEAN InheritedAddressSpace;
			BOOLEAN ReadImageFileExecOptions;
			BOOLEAN BeingDebugged;
			BOOLEAN Spare;
			HANDLE Mutant;
			PVOID ImageBaseAddress;
			PPEB_LDR_DATA LoaderData;
			DWORD ProcessParameters;
			PVOID SubSystemData;
			PVOID ProcessHeap;
			PVOID FastPebLock;
			DWORD FastPebLockRoutine;
			DWORD FastPebUnlockRoutine;
			ULONG EnvironmentUpdateCount;
			PPVOID KernelCallbackTable;
			PVOID EventLogSection;
			PVOID EventLog;
			DWORD FreeList;
			ULONG TlsExpansionCounter;
			PVOID TlsBitmap;
			ULONG TlsBitmapBits[0x2];
			PVOID ReadOnlySharedMemoryBase;
			PVOID ReadOnlySharedMemoryHeap;
			PPVOID ReadOnlyStaticServerData;
			PVOID AnsiCodePageData;
			PVOID OemCodePageData;
			PVOID UnicodeCaseTableData;
			ULONG NumberOfProcessors;
			ULONG NtGlobalFlag;
			BYTE Spare2[0x4];
			LARGE_INTEGER CriticalSectionTimeout;
			ULONG HeapSegmentReserve;
			ULONG HeapSegmentCommit;
			ULONG HeapDeCommitTotalFreeThreshold;
			ULONG HeapDeCommitFreeBlockThreshold;
			ULONG NumberOfHeaps;
			ULONG MaximumNumberOfHeaps;
			PPVOID* ProcessHeaps;
			PVOID GdiSharedHandleTable;
			PVOID ProcessStarterHelper;
			PVOID GdiDCAttributeList;
			PVOID LoaderLock;
			ULONG OSMajorVersion;
			ULONG OSMinorVersion;
			ULONG OSBuildNumber;
			ULONG OSPlatformId;
			ULONG ImageSubSystem;
			ULONG ImageSubSystemMajorVersion;
			ULONG ImageSubSystemMinorVersion;
			ULONG GdiHandleBuffer[0x22];
			ULONG PostProcessInitRoutine;
			ULONG TlsExpansionBitmap;
			BYTE TlsExpansionBitmapBits[0x80];
			ULONG SessionId;
		} PEB, * PPEB;
#pragma endregion

		const PEB* process_environment_block = reinterpret_cast<PEB*>(__readfsdword(0x30)); // Grab process environment block.
		const LIST_ENTRY* in_load_order_module_list = &process_environment_block->LoaderData->InLoadOrderModuleList; // Get the load order of the modules.

		for (LIST_ENTRY* entry = in_load_order_module_list->Flink; entry != in_load_order_module_list; entry = entry->Flink) // This method skips getting self module which we don't need anyway.
		{
			const PLDR_DATA_TABLE_ENTRY pldr_entry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(entry->Flink); // Get pldr_data from flink.
			const std::uintptr_t base_dll_address = reinterpret_cast<std::uintptr_t>(pldr_entry->DllBase); // Get DLL (module) base address.

			if (!base_dll_address) // Is module valid?
				continue;

#pragma warning( push )
#pragma warning( disable : 4996) // Codecvt is still not deprecated in c++20. Hence why we still use it. I don't wanna use the windows internal alternative.
			// Convert buffer into wchar_t* then turn wide string into sequence of character.
			std::string module_name = std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(reinterpret_cast<wchar_t*>(pldr_entry->BaseDllName.Buffer));
#pragma warning( pop ) 

			cached_modules[module_name] = MemoryModules(module_name, base_dll_address); // Push back module information into class afterwards the class into the unordered_map.
		}
	}

	/*
	*  This function tries to return a MemoryModules class pointer from the map.
	* 
	*  You pass the string for the requested module in the first parameter module_name.
	*  It will loop through the map and check if any of the map entries equal to your passed first parameter.
	* 
	*  @calling convention: Compiler handled.
	*  @paramater:          Constant std::string module_name, holds the name of the module you want to grab from the unordered_map.
	*  @return:             If we can find the module in the map it will return a pointer to the MemoryModules class, otherwise it will return a nullptr;
	*/

	MemoryModules* GetModule(const std::string module_name)
	{
		if (const auto map_entry = cached_modules.find(module_name); map_entry == cached_modules.end())
			return nullptr;

		return &cached_modules[module_name];
	}

	/*
	*  This function allows you to add modules to the cached_module unordered_map.
	* 
	*  @calling convention: Compiler handled.
	*  @parameter:          Constant std::string module_name, holds the modules name. void* module_base_address holds the modules base address.
	*  @return              None.
	*/

	void AddModule(const std::string module_name, void* module_base_address)
	{
		cached_modules[module_name] = MemoryModules(module_name, module_base_address);
	}
}