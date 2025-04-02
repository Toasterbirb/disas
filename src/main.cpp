#include <capstone/capstone.h>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <regex>
#include <vector>

using i8	= int8_t;
using i16	= int16_t;
using i32	= int32_t;
using i64	= int64_t;

using u8	= uint8_t;
using u16	= uint16_t;
using u32	= uint32_t;
using u64	= uint64_t;

using f32	= float;
using f64	= double;
using f128	= long double;

static_assert(sizeof(f32) == sizeof(i32));
static_assert(sizeof(f64) == sizeof(i64));

std::vector<u8> hex_str_to_bytes(std::string hex_string);
void disasm_bytes(const std::vector<u8>& bytes, const u64 starting_address);

int main(int argc, char** argv)
{

	if (argc != 2)
	{
		std::cout << "Usage: disas \"<bytes>\"\nAlternatively pass '-' as the argument to read data from stdin\n";
		return 1;
	}

	std::string hex_str;

	if (argv[1][0] == '-')
		std::getline(std::cin, hex_str);
	else
		hex_str = argv[1];

	const std::vector<u8> bytes = hex_str_to_bytes(hex_str);
	disasm_bytes(bytes, 0x0);

	return 0;
}

std::vector<u8> hex_str_to_bytes(std::string hex_string)
{
	std::vector<u8> hex_values;

	// Remove all whitespace from the hex string
	std::erase(hex_string, ' ');

	// Remove all instances of "0x" from the string
	const std::regex zero_x_pattern("0x");
	hex_string = std::regex_replace(hex_string, zero_x_pattern, "");

	while (!hex_string.empty())
	{
		try
		{
			const u8 byte = hex_string.size() != 1
				? std::stoi(hex_string.substr(0, 2), 0, 16)
				: std::stoi(hex_string.substr(0, 1), 0, 16);

			hex_values.emplace_back(byte);
		}
		catch (std::exception e)
		{
			std::cout << "Error processing hex value: " << hex_string.substr(0, 2) << ": " << e.what() << "\n";
			exit(2);
		}

		// Clear the first processed byte
		hex_string = hex_string.erase(0, 2);
	}

	return hex_values;
}

void disasm_bytes(const std::vector<u8>& bytes, const u64 starting_address)
{
	csh handle;
	cs_insn* insn;

	const cs_mode capstone_mode = CS_MODE_64;

	if (cs_open(CS_ARCH_X86, capstone_mode, &handle) != CS_ERR_OK)
	{
		std::cout << "Couldn't initialize capstone\n";
		return;
	}

	const size_t instruction_count = cs_disasm(handle, bytes.data(), bytes.size(), 0x0, 0, &insn);

	if (instruction_count == 0)
	{
		std::cout << "No instructions could be disassembled from the hex string\n";
		cs_close(&handle);
	}

	constexpr u8 bytes_per_instruction = 24;

	for (size_t i = 0; i < instruction_count; ++i)
	{
		std::cout << std::left << "0x" << insn[i].address << ":\t" << std::setw(12) << insn[i].mnemonic << std::setw(32) << insn[i].op_str;

		// Print the bytes
		for (u8 j = 0; j < insn[i].size; ++j)
			printf("%02x ", insn[i].bytes[j]);

		std::cout << "\n";
	}

	cs_free(insn, instruction_count);
	cs_close(&handle);
}
