module;

#include <tuple>
#include <vector>
#include <iostream>

export module memory;

/*
*  This class will hold a memory address.
* 
*  @ptr: pointer to the memory address.
*/

export class MemoryAddress
{
public:
	MemoryAddress(std::uintptr_t ptr) : ptr(ptr) {}
	MemoryAddress(void* ptr) : ptr(std::uintptr_t(ptr)) {}
	MemoryAddress() : ptr(0) {}

	/*
	*   Will return the class member ptr.
	* 
	*   @calling convention: Compiler handled.
	*   @parameters:         None.
	*   @return:             returns class member ptr.
	*/

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

	/*
	*  Will make current memory address into a virtual function index.
	*  
	*  @calling convention: Compiler Handled.
	*  @parameter:          None.
	*  @return:             ptr casted to template divided by 4.
	*/

	template<class T> std::int32_t GetVirtualFunctionIndex()
	{
		return *reinterpret_cast<T*>(ptr) / 4; // Divide by 4 to get actual virtual function index.
	}

	/*
	*  Offset ptr by offset paremeter and return new MemoryAddress class.
	*  
	*  @calling convention: Compiler handled.
	*  @paremeter:          Constant std::ptrdiff_t offset, how much to offset ptr from its original location.
	*  @return              Return a new MemoryAddress class with the offseted ptr.
	*/

	MemoryAddress Offset(const std::ptrdiff_t offset = 0x1)
	{
		return MemoryAddress(ptr + offset);
	}

	/*
    *  Offset ptr by offset paremeter.
    *
    *  @calling convention: Compiler handled.
    *  @paremeter:          Constant std::ptrdiff_t offset, how much to offset ptr from its original location.
    *  @return              Return this.
    */

	MemoryAddress OffsetSelf(const std::ptrdiff_t offset = 0x1)
	{
		ptr += offset;
		return *this;
	}

	/*
	*  Follow jmp instruction and get address of destination.
	* 
	*  @calling convention: Compiler handled.
	*  @parameter:          Constant std::ptrdiff_t jmp_opcode_offset, offset to where the jmp opcodes end.
	*  @return              Return a new MemoryAddress class with the destination of the jmp.
	*/

	MemoryAddress FollowJmp(const std::ptrdiff_t jmp_opcode_offset = 0x1)
	{
		return FollowJmpInternal(jmp_opcode_offset, false);
	}

	/*
    *  Follow jmp instruction and get address of destination.
    *
    *  @calling convention: Compiler handled.
    *  @parameter:          Constant std::ptrdiff_t jmp_opcode_offset, offset to where the jmp opcodes end.
    *  @return              Returns this with ptr being set to the destination of the jmp.
    */

	MemoryAddress FollowJmpSelf(const std::ptrdiff_t jmp_opcode_offset = 0x1)
	{
		return FollowJmpInternal(jmp_opcode_offset, true); 
	}

	/*
	*  Dereference ptr class member.
	*  @calling convention: Compiler handled.
	*  @parameter:          Constant std::ptr_diff_t deref_count, how many times to dereference the pointer.
	*  @return              Returns a new MemoryAddress class with the dereferenced ptr class member.
	*/

	MemoryAddress Deref(const std::ptrdiff_t deref_count = 0x1)
	{
		return DerefInternal(deref_count, false);
	}

	/*
    *  Dereference ptr class member.
    *  @calling convention: Compiler handled.
    *  @parameter:          Constant std::ptr_diff_t deref_count, how many times to dereference the pointer.
    *  @return              Returns this with ptr being dereferenced.
    */

	MemoryAddress DerefSelf(const std::ptrdiff_t deref_count = 0x1)
	{
		return DerefInternal(deref_count, true);
	}

	/*
    *  Compare current ptr address location bytes with the byte array being passed with the byte_array parameter.
	* 
    *  @calling convention: Compiler handled.
    *  @parameter:          Constant std::vector<std::uint8_t> byte_array, holds the byte array to compare against to.
    *  @return              Returns false if the ptr location doesn't equal the byte array. If it does it returns true.
    */

	bool CheckBytes(const std::vector<std::uint8_t> byte_array)
	{
		std::uintptr_t ptr_reference = ptr; // Create pointer reference.
		
		for (auto [byte_at_cur_address, i] = std::tuple{ std::uint8_t(), (std::size_t)0 }; i < byte_array.size(); i++, ptr_reference++) // Loop forward in the ptr class member.
		{
			byte_at_cur_address = *reinterpret_cast<std::uint8_t*>(ptr_reference); // Get byte at current address.

			if (byte_at_cur_address != byte_array[i]) // If byte at ptr doesn't equal in the byte array return false.
				return false;
		}

		return true;
	}

private:

	/* Variables */
	std::uintptr_t ptr;

	/*
	*  Internal function for FollowJmp.
	* 
	*  If self_jmp is declared as true it will return this as MemoryAddress, if not it will return a new MemoryAddress class with the ptr.
	* 
	*  @calling convention: Compiler handled.
	*  @parameters:         Constant std::ptrdiff_t jmp_opcode_offset offset to where the jmp opcodes end, self_jmp is explained above.
	*  @return              Will return with the jmp destination as MemoryAddress.
	*/
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

	/*
	*  Internal function for Deref.
	* 
	*  If self_deref is declared as true it will return this as MemoryAddress, if not it will return a new MemoryAddress class with the ptr.
	*  
	*  @calling convention: Compiler handled.
	*  @parameters:         Constant std::ptrdiff_t deref_count how often to dereference the pointer, self_deref is explained above.
	*  @return              Will return with the dereferenced pointer as MemoryAddress.
	*/

	MemoryAddress DerefInternal(const std::ptrdiff_t deref_count, const bool self_deref)
	{
		if (self_deref)
		{
			for (std::ptrdiff_t i = 0; i < deref_count; i++) // How often do we wanna dereference?
			{
				if (ptr) // If pointer is still valid dereference.
				{
					ptr = *reinterpret_cast<std::uintptr_t*>(ptr); // Derefence pointer.
				}
			}

			return *this; // Return this.
		}
		else
		{
			std::uintptr_t ptr_reference = ptr; // Get pointer reference.

			for (std::ptrdiff_t i = 0; i < deref_count; i++) // How often do we wanna dereference?
			{
				if (ptr_reference) // If pointer is still valid dereference.
				{
					ptr_reference = *reinterpret_cast<std::uintptr_t*>(ptr_reference); // Dereference pointer reference.
				}
			}

			return MemoryAddress(ptr_reference); // Return new class with pointer reference.
		}
	}
};
