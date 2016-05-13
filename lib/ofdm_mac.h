#include <vector>
namespace gr{
	namespace ieee802_11{

	class ofdm_mac_impl : public ofdm_mac 
	{
	public:
		ofdm_mac_impl(std::vector<uint8_t> src_mac, 
			std::vector<uint8_t> dst_mac, 
			std::vector<uint8_t> bss_mac);

	private:
		void phy_in (pmt::pmt_t msg);
		void app_in (pmt::pmt_t msg);
		void send_data_frame(const char *msdu, int msdu_size);
		void send_beacon_frame();
		void gen_mac_management_frame(const char *msdu, int msdu_size, int& psdu_size);
 		void gen_mac_data_frame(const char *msdu, int msdu_size, int& psdu_size);
 		bool check_mac(std::vector<uint8_t> mac); 
 	private:
		uint16_t d_seq_nr;
		uint8_t d_src_mac[6];
		uint8_t d_dst_mac[6];
		uint8_t d_bss_mac[6];//所在网络BSS的MAC地址
		uint8_t d_psdu[1528];
	};


}
}
