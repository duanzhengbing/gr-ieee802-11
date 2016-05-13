#include <iostream>
#include <iomanip>
#include <string>
#include <boost/crc.hpp>
namespace gr {
	namespace ieee802_11 {	
		void print_mac_address(const uint8_t *addr, bool new_line = false) 
		{
			std::cout << std::setfill('0') << std::hex << std::setw(2);
			for(int i = 0; i < 6; i++) 
			{
				std::cout << (int)addr[i];
				if(i != 5)
					std::cout << ":";
			}
			std::cout << std::dec;
			if(new_line) 
				std::cout << std::endl;

		}

		void print_ascii(char* buf, int length) 
		{
			for(int i = 0; i < length; i++)
			{
				//32-126是ASCII码中可显式的字符
				if((buf[i] > 31) && (buf[i] < 127))
					std::cout << buf[i];
				else
					std::cout << ".";
			}
			std::cout << std::endl;
		}

		bool checksum(const char* data,int len)
		{
			boost::crc_32_type result;
			result.process_bytes(data, len);
			if(result.checksum() != 558161692) 
			{
				std::cout << "校验和错误!" << std::endl;
				return false;
			}
			else
			{
				std::cout << "校验和正确 " << std::endl;
				return true;
			}
		}
	}
}