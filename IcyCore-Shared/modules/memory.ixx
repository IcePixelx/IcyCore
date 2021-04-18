module;

#include <tuple>
#include <vector>
#include <iostream>

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
