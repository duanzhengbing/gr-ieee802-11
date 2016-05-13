/*
 * Copyright (C) 2013 Bastian Bloessl <bloessl@ccs-labs.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "ether_encap_impl.h"
#include "utils.h"

#include <gnuradio/io_signature.h>
#include <gnuradio/block_detail.h>
#include <string>

using namespace gr::ieee802_11;

ether_encap_impl::ether_encap_impl(bool debug) :
		block("ether_encap",
				gr::io_signature::make(0, 0, 0),
				gr::io_signature::make(0, 0, 0)),
		d_debug(debug),
		d_last_seq(123) {

    message_port_register_out(pmt::mp("to tap"));
    message_port_register_out(pmt::mp("to wifi"));

    message_port_register_in(pmt::mp("from tap"));
    set_msg_handler(pmt::mp("from tap"), boost::bind(&ether_encap_impl::from_tap, this, _1));
    message_port_register_in(pmt::mp("from wifi"));
    set_msg_handler(pmt::mp("from wifi"), boost::bind(&ether_encap_impl::from_wifi, this, _1));
}

void
ether_encap_impl::from_wifi(pmt::pmt_t msg) {

	msg = pmt::cdr(msg);

	int data_len = pmt::blob_length(msg);
	const mac_header *mhdr = reinterpret_cast<const mac_header*>(pmt::blob_data(msg));

	if(d_last_seq == mhdr->seq_nr) {
		dout << "Ether Encap: frame already seen -- skipping" << std::endl;
		return;
	}

	d_last_seq = mhdr->seq_nr;


	if(data_len < 33) {
		dout << "Ether Encap: frame too short to parse (<33)" << std::endl;
		return;
	}

    if(((mhdr->frame_control >> 2) & 3) != 2) 
    {
		dout << "this is not a data frame -- ignoring" << std::endl;
		return;
	}
	char *frame = (char*)pmt::blob_data(msg);

	// this is more than needed
	const int SNAP_LEN = 6;
	const int TYPE_LEN = 2;
	const int ETHER_SFD_LEN = 4;
	int ether_len = data_len - sizeof(mac_header) - SNAP_LEN - TYPE_LEN + sizeof(ethernet_header) + ETHER_SFD_LEN;
	char *buf = static_cast<char*>(std::malloc(ether_len));
	buf[0] = 0x00;
	buf[1] = 0x00;
	std::memcpy(buf+2, frame + sizeof(mac_header)+ sizeof(SNAP_LEN), TYPE_LEN);
	std::memcpy(buf+ETHER_SFD_LEN+12, buf+2, TYPE_LEN);

	ethernet_header *ehdr = reinterpret_cast<ethernet_header*>(buf+ETHER_SFD_LEN);
	std::memcpy(ehdr->dest, mhdr->addr1, 6);
	std::memcpy(ehdr->src, mhdr->addr2, 6);
	// ehdr->type = 0x0008;


	// DATA
	if((((mhdr->frame_control) >> 2) & 63) == 2) 
	{
		memcpy(buf + sizeof(ethernet_header)+ETHER_SFD_LEN, frame + 32, data_len - 32);
		pmt::pmt_t payload = pmt::make_blob(buf, ether_len);
		message_port_pub(pmt::mp("to tap"), pmt::cons(pmt::PMT_NIL, payload));

	// QoS Data
	} else if((((mhdr->frame_control) >> 2) & 63) == 34) {

		memcpy(buf + sizeof(ethernet_header), frame + 34, data_len - 34);
		pmt::pmt_t payload = pmt::make_blob(buf, data_len - 34 + 14);
		message_port_pub(pmt::mp("to tap"), pmt::cons(pmt::PMT_NIL, payload));
	}

	free(buf);
}

//以太网头部的MAC地址必须一起传输至MAC层
void
ether_encap_impl::from_tap(pmt::pmt_t msg) 
{
	size_t len = pmt::blob_length(pmt::cdr(msg));
	const char* data = static_cast<const char*>(pmt::blob_data(pmt::cdr(msg)));

	len = len - 4;
	data = data + 4;
	//以太网头部前４个字节与type相同，但是不知有什么意义，数据并没有包含FCS
	const ethernet_header *ehdr = reinterpret_cast<const ethernet_header*>(data);
	/*std::cout << "ehdr->type : " << std::hex << ehdr->type; 
	std::cout << "  len = " << len << std::endl;
	for (int i = 0; i < len; ++i)
	{
		std::cout << std::hex << ((unsigned int)data[i] & 0xff) << " ";
	}
	std::cout << std::endl;
	print_mac_address(ehdr->dest, true);
	print_mac_address(ehdr->src, true);*/

	switch(ehdr->type) 
	{
		
		case 0x0008: 
		{
			std::cout << "ether type: IP" << std::endl;

			char *buf = static_cast<char*>(malloc(len + 6));
			LLC_encap(data,len,buf);
			pmt::pmt_t blob = pmt::make_blob(buf, len + 6);
			message_port_pub(pmt::mp("to wifi"), pmt::cons(pmt::PMT_NIL, blob));
			break;
		}
		case 0x0608:
		{
			std::cout << "ether type: ARP " << std::endl;
			char *buf = static_cast<char*>(malloc(len + 6));
			LLC_encap(data,len,buf);
			pmt::pmt_t blob = pmt::make_blob(buf, len + 6);
			message_port_pub(pmt::mp("to wifi"), pmt::cons(pmt::PMT_NIL, blob));
			break;
		}
		default:
		{
			std::cout << "unknown ether type" << std::endl;
			break;
		}
	}

}
/**
 * ether : < DST MAC | SRC MAC | type | IP | FCS >
 * LLC : < DST MAC | SRC MAC | SNAP/DSAP | SNAP/SSAP | Control | RFC || Type | IP | FCS >
 * FCS 重新计算
 */
void ether_encap_impl::LLC_encap(const char* data, int len, char*& buf)
{
	std::memcpy(buf,data,12);
	buf[12] = 0xaa; //DSAP
	buf[13] = 0xaa; //SSAP
	buf[14] = 0x03; //control
	buf[15] = 0x00; //RFC
	buf[16] = 0x00;
	buf[17] = 0x00;
	buf[18] = 0x08; //type
	buf[19] = 0x00;
	std::memcpy(buf + 20, data + sizeof(ethernet_header), len - sizeof(ethernet_header));
}
ether_encap::sptr
ether_encap::make(bool debug) {
	return gnuradio::get_initial_sptr(new ether_encap_impl(debug));
}

