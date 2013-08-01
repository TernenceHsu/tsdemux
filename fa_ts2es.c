/*

  Copyright (C) 2013 xubinbin 徐彬彬 (Beijing China)

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.

  
  filename: fa_ts2es.c
  version : v1.0.0
  time    : 2013/07/31 16:37 
  author  : xubinbin ( xubbwd@gmail.com )
  code URL: http://code.google.com/p/tsdemux/
  
*/

#include "fa_ts2es.h"

tsdemux_struc *ptsdemux = NULL;

// Adjust TS packet header
void adjust_TS_packet_header(TS_packet_header* pheader,char * buf_header)
{
    if(buf_header[0] != 0x47)
    {
        printf("packet header error ! \n");
    }
    pheader->sync_byte                        = buf_header[0];
    pheader->transport_error_indicator        = buf_header[1] >> 7;
    pheader->payload_unit_start_indicator    = buf_header[1] >> 6 & 0x01;
    pheader->transport_priority                = buf_header[1] >> 5 & 0x01;
    pheader->PID                            = (buf_header[1] & 0x1F) << 8 | buf_header[2];
    pheader->transport_scrambling_control    = buf_header[3] >> 6;
    pheader->adaption_field_control            = buf_header[3] >> 4 & 0x03;
    pheader->continuity_counter                = buf_header[3] & 0x0F;
}


// Adjust PAT table
void adjust_PAT_table ( TS_packet_header* pheader,TS_PAT * packet, char * buffer )
{
    int n = 0, i = 0;
    int len = 0;
    unsigned char adaption_field_length = 0;

    if(pheader->adaption_field_control == 2 || pheader->adaption_field_control == 3)
    {
    	adaption_field_length = buffer[0];
    	len = adaption_field_length + 1;
    }
    if(pheader->adaption_field_control == 1 || pheader->adaption_field_control == 3)
    {
    	len++;

        packet->table_id                    = buffer[len + 0];
        packet->section_syntax_indicator    = buffer[len + 1] >> 7;
        packet->zero                        = buffer[len + 1] >> 6 & 0x1;
        packet->reserved_1                  = buffer[len + 1] >> 4 & 0x3;
        packet->section_length              = (buffer[len + 1] & 0x0F) << 8 | (buffer[len + 2] & 0xFF);
//        printf("packet->section_length = %d\n",(buffer[len + 1] & 0x0F) << 8 | (buffer[len + 2] & 0xFF));
        packet->transport_stream_id         = buffer[len + 3] << 8 | buffer[len + 4];
        packet->reserved_2                    = buffer[len + 5] >> 6;
        packet->version_number                = buffer[len + 5] >> 1 &  0x1F;
        packet->current_next_indicator        = buffer[len + 5] & 0x01;
        packet->section_number                = buffer[len + 6];
        packet->last_section_number            = buffer[len + 7];

        // Get CRC_32
//        len = 3 + packet->section_length;

        packet->CRC_32                        = (buffer[len-4] & 0xFF) << 24
                                              | (buffer[len-3] & 0xFF) << 16
                                              | (buffer[len-2] & 0xFF) << 8
                                              | (buffer[len-1] & 0xFF);

        // Parse network_PID or program_map_PID
        //printf("packet->CRC_32 = 0x%x\n",packet->CRC_32);
        //printf("len-4 = %d\n"len-4);
        //printf("packet->section_length = %d\n",packet->section_length);

        //len = 3+ 1 + packet->section_length - 4;
        len += 8;

        for ( i = 5,n = len; i < packet->section_length; n+=8,i+=8 )
        {
        //    printf("@@@@@@###############\n");
            packet->program_number            = (buffer[n] & 0xFF) << 8 | (buffer[n+1] & 0xFF);
            packet->reserved_3                = buffer[n+2] >> 5;
            if ( packet->program_number == 0x0 )
            {
                packet->network_PID = (buffer[n +2] & 0x1F) << 8 | (buffer[n +3] & 0xFF);
			//	printf("packet->network_PID = %x\n",packet->network_PID);
            }
            else
            {
            	packet->program_map_PID = (buffer[n +2] & 0x1F) << 8 | (buffer[n +3] & 0xFF);
            //    printf("packet->program_map_PID = %x\n",packet->program_map_PID);
            //    printf("packet->program_map_PID = %d\n",packet->program_map_PID);
            }
        }
    }
    if(packet->program_map_PID == 0)
    {
    	printf("can't find program_map_PID !\n");
    }
}



// Adjust PMT table
void adjust_PMT_table ( TS_packet_header* pheader, TS_PMT * packet, char * buffer )
{
    int pos = 12, len = 0;
    int i = 0;
    unsigned char adaption_field_length = 0;

    if(pheader->adaption_field_control == 2 || pheader->adaption_field_control == 3)
    {
    	adaption_field_length = buffer[0];
    	len = adaption_field_length + 1;
    }
    if(pheader->adaption_field_control == 1 || pheader->adaption_field_control == 3)
    {
    	len++;
        packet->table_id                            = buffer[len + 0];
        packet->section_syntax_indicator            = buffer[len + 1] >> 7;
        packet->zero                                = buffer[len + 1] >> 6 & 0x1;
        packet->reserved_1                            = buffer[len + 1] >> 4 & 0x3;
        packet->section_length                        = (buffer[len + 1] & 0x0F) << 8 | buffer[len + 2];
//        printf("PMT packet->section_length = %d\n",packet->section_length);
        packet->program_number                        = buffer[len + 3] << 8 | buffer[len + 4];
        packet->reserved_2                            = buffer[len + 5] >> 6;
        packet->version_number                        = buffer[len + 5] >> 1 & 0x1F;
        packet->current_next_indicator                = buffer[len + 5] & 0x01;
        packet->section_number                        = buffer[len + 6];
        packet->last_section_number                    = buffer[len + 7];
        packet->reserved_3                            = buffer[len + 8] >> 5;
        packet->PCR_PID                                = ((buffer[len + 8] << 8) | buffer[len + 9]) & 0x1FFF;
        packet->reserved_4                            = buffer[len + 10] >> 4;
        packet->program_info_length                    = (buffer[len + 10] & 0x0F) << 8 | (buffer[len + 11] & 0xFF);
        // Get CRC_32

        //len = packet->section_length + 3;
        packet->CRC_32                = (buffer[len-4] & 0x000000FF) << 24
                                      | (buffer[len-3] & 0x000000FF) << 16
                                      | (buffer[len-2] & 0x000000FF) << 8
                                      | (buffer[len-1] & 0x000000FF);
        // program info descriptor
        //printf("packet->program_info_length = %d\n",packet->program_info_length);
        //printf("packet->section_length = %d\n",packet->section_length);
        //printf("pos = %d\n",pos);
        if ( packet->program_info_length != 0 )
            len += packet->program_info_length;

//        printf("pos = %d\n",pos);
        // Get stream type and PID
        for (i = 0, pos = len + 12 ; i < packet->section_length - 3 ; pos+=5,i+=5)
        {
//        	printf("########################\n");
            packet->stream_type                            = buffer[pos];
//            printf("packet->stream_type = %d\n",packet->stream_type);
            packet->reserved_5                            = buffer[pos+1] >> 5;
            packet->elementary_PID                        = ((buffer[pos+1] << 8) | buffer[pos+2]) & 0x1FFF;
//            printf("packet->elementary_PID = %d\n",packet->elementary_PID);
            packet->reserved_6                            = buffer[pos+3] >> 4;
            packet->ES_info_length                        = (buffer[pos+3] & 0x0F) << 8 | buffer[pos+4];

            if(packet->stream_type == 15)    //aac
                ptsdemux->audio_pid = packet->elementary_PID;
            if(packet->stream_type == 27)    //h264
                ptsdemux->video_pid = packet->elementary_PID;

            if ( packet->ES_info_length != 0 )
            {
                pos += packet->ES_info_length;
                i += packet->ES_info_length;
            }
        }
    }
}

void adjust_video_table (TS_packet_header *packet_head,char * buffer,FILE *fb)
{
    int length_flag = 0;
    TS_PES packet_pes;

    if(packet_head->adaption_field_control == 2||packet_head->adaption_field_control == 3)
    {
    //    adaptation_field()
        //调整字段的处理
        TS_adaptation_field adaptation_field;
        adaptation_field.adaptation_field_length                = buffer[0];
        adaptation_field.discontinuity_indicator                = buffer[1] >> 7 & 0x01;
        adaptation_field.random_access_indicator                = buffer[1] >> 6 & 0x01;
        adaptation_field.elementary_stream_priority_indicator   = buffer[1] >> 5 & 0x01;
        adaptation_field.PCR_flag                               = buffer[1] >> 4 & 0x01;
        adaptation_field.OPCR_flag                              = buffer[1] >> 3 & 0x01;
        adaptation_field.splicing_point_flag                    = buffer[1] >> 2 & 0x01;
        adaptation_field.transport_private_data_flag            = buffer[1] >> 1 & 0x01;
        adaptation_field.adaptation_field_extension_flag        = buffer[1] >> 0 & 0x01;
        length_flag = adaptation_field.adaptation_field_length+1;
        if(adaptation_field.PCR_flag == 1)
        {
        //    printf("line = %d\n",__LINE__);
            //跳过6字节
        }
        if(adaptation_field.OPCR_flag == 1)
        {
            printf("line = %d\n",__LINE__);
        }
        if(adaptation_field.splicing_point_flag == 1)
        {
            printf("line = %d\n",__LINE__);
        }
        if(adaptation_field.transport_private_data_flag == 1)
        {
            printf("line = %d\n",__LINE__);
        }
        if(adaptation_field.adaptation_field_extension_flag == 1)
        {
            printf("line = %d\n",__LINE__);
        }
        //stuffing_byte 1byte
    }
    if(packet_head->adaption_field_control== 1  ||  packet_head->adaption_field_control== 3)
    {

        if(packet_head->payload_unit_start_indicator == 0)
        {
            fwrite(buffer+length_flag,184-length_flag,1,fb);
            return 0;
        }

    //    printf("buffer[length_flag +0] = 0x%x\n",buffer[length_flag +0]);
    //    printf("buffer[length_flag +1] = 0x%x\n",buffer[length_flag +1]);
    //    printf("buffer[length_flag +2] = 0x%x\n",buffer[length_flag +2]);
        packet_pes.packet_start_code_prefix = (buffer[length_flag +0] << 16
                                             | buffer[length_flag +1] << 8
                                             | buffer[length_flag +2]) &0xffffff;

    //    printf("packet_pes.packet_start_code_prefix = 0x%x\n",packet_pes.packet_start_code_prefix);
        if(packet_pes.packet_start_code_prefix != 1)
            printf("packet_pes.packet_start_code_prefix 00 00 01 error !\n");

        packet_pes.stream_id         = buffer[length_flag +3];
        packet_pes.PES_packet_length = ( buffer[length_flag +4] << 8 | buffer[length_flag +5] ) & 0xffff;

    //    printf("packet_pes.stream_id = 0x%x\n",packet_pes.stream_id);
    //    printf("packet_pes.PES_packet_length = %d\n",packet_pes.PES_packet_length);

        packet_pes.PES_scrambling_control   = buffer[length_flag +6] >> 4 & 0x03;
        packet_pes.PES_priority             = buffer[length_flag +6] >> 3 & 0x01;
        packet_pes.data_alignment_indicator = buffer[length_flag +6] >> 2 & 0x01;
        packet_pes.copyright                = buffer[length_flag +6] >> 1 & 0x01;
        packet_pes.original_or_copy         = buffer[length_flag +6] >> 0 & 0x01;
        //应当只有DTS信息
        packet_pes.PTS_DTS_flags                = buffer[length_flag +7] >> 6 & 0x03;
        packet_pes.ESCR_flag                    = buffer[length_flag +7] >> 5 & 0x01;
        packet_pes.ES_rate_flag                 = buffer[length_flag +7] >> 4 & 0x01;
        packet_pes.DSM_trick_mode_flag          = buffer[length_flag +7] >> 3 & 0x01;
        packet_pes.additional_copy_info_flag    = buffer[length_flag +7] >> 2 & 0x01;
        packet_pes.PES_CRC_flag                 = buffer[length_flag +7] >> 1 & 0x01;
        packet_pes.PES_extension_flag           = buffer[length_flag +7] >> 0 & 0x01;

        packet_pes.PES_header_data_length           = buffer[length_flag +8];
        #if 0
        printf("packet_pes.PTS_DTS_flags = %d\n",packet_pes.PTS_DTS_flags);
        printf("packet_pes.ESCR_flag = %d\n",packet_pes.ESCR_flag);
        printf("packet_pes.ES_rate_flag = %d\n",packet_pes.ES_rate_flag);
        printf("packet_pes.DSM_trick_mode_flag = %d\n",packet_pes.DSM_trick_mode_flag);
        printf("packet_pes.additional_copy_info_flag = %d\n",packet_pes.additional_copy_info_flag);
        printf("packet_pes.PES_CRC_flag = %d\n",packet_pes.PES_CRC_flag);
        printf("packet_pes.PES_extension_flag = %d\n",packet_pes.PES_extension_flag);
        #endif

        if(packet_pes.PTS_DTS_flags == 0x02)
        {
            packet_pes.PTS_32_30 = buffer[length_flag +9] >> 1 & 0x07;
            packet_pes.PTS_29_15 = buffer[length_flag +10] >> 1 & 0x7F;
            packet_pes.PTS_14_0  = buffer[length_flag +11] >> 1 & 0x7F;
        }

    //    printf("buffer[length_flag +12] = 0x%x\n",buffer[length_flag +12]);
    //    printf("buffer[length_flag +13] = 0x%x\n",buffer[length_flag +13]);
    //    printf("buffer[length_flag +14] = 0x%x\n",buffer[length_flag +14]);
    //    printf("length_flag +12 = %d\n",length_flag +12);
     //   for  (i=0;i<N;i++)
        {
        //    data_byte                 //8
            //有效负载的剩余部分，可能为PES分组，PSI，或一些自定义的数据。
        }
        fwrite(&buffer[length_flag +14],184-length_flag-14,1,fb);

    }


}


void adjust_audio_table (TS_packet_header *packet_head,char * buffer )
{



}

void printf_TS_packet_header_info(TS_packet_header *packet_head)
{
    printf("\n###########################################\n");
    printf("TS header info:\n");
    printf("sync_byte                           \t### %x\n", packet_head->sync_byte);
    printf("transport_error_indicator     \t\t### %x\n", packet_head->transport_error_indicator);
    printf("payload_unit_start_indicator \t\t### %x\n", packet_head->payload_unit_start_indicator);
    printf("transport_priority                \t### %x\n", packet_head->transport_priority);
    printf("PID                                    \t### %d\n", packet_head->PID);
    printf("transport_scrambling_control\t\t### %x\n", packet_head->transport_scrambling_control);
    printf("adaption_field_control          \t### %x\n", packet_head->adaption_field_control);
    printf("continuity_counter               \t### %x\n", packet_head->continuity_counter);
    printf("###########################################\n\n");

}
