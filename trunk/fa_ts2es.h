/*

  Copyright (C) 2013 xubinbin Ðì±ò±ò (Beijing China)

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

  
  filename: fa_ts2es.h 
  version : v1.0.0
  time    : 2013/07/31 16:37 
  author  : xubinbin ( xubbwd@gmail.com )
  code URL: http://code.google.com/p/tsdemux/
  
*/

#ifndef	__FA_TS2ES_H__
#define __FA_TS2ES_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Transport packet header
typedef struct _TS_packet_header
{
    unsigned sync_byte                        : 8;
    unsigned transport_error_indicator        : 1;
    unsigned payload_unit_start_indicator     : 1;
    unsigned transport_priority               : 1;
    unsigned PID                              : 13;
    unsigned transport_scrambling_control     : 2;
    unsigned adaption_field_control           : 2;
    unsigned continuity_counter               : 4;
} TS_packet_header;
 
 
// PAT table
// Programm Association Table
typedef struct TS_PAT
{
    unsigned table_id                        : 8;
    unsigned section_syntax_indicator        : 1;
    unsigned zero                            : 1;
    unsigned reserved_1                      : 2;
    unsigned section_length                  : 12;
    unsigned transport_stream_id             : 16;
    unsigned reserved_2                      : 2;
    unsigned version_number                  : 5;
    unsigned current_next_indicator          : 1;
    unsigned section_number                  : 8;
    unsigned last_section_number             : 8;
    unsigned program_number                  : 16;
    unsigned reserved_3                      : 3;
    unsigned network_PID                     : 13;
    unsigned program_map_PID                 : 13;
    unsigned CRC_32                          : 32;
} TS_PAT;

// PMT table
// Program Map Table
typedef struct TS_PMT
{
    unsigned table_id                        : 8;
    unsigned section_syntax_indicator        : 1;
    unsigned zero                            : 1;
    unsigned reserved_1                        : 2;
    unsigned section_length                    : 12;
    unsigned program_number                    : 16;
    unsigned reserved_2                        : 2;
    unsigned version_number                    : 5;
    unsigned current_next_indicator            : 1;
    unsigned section_number                    : 8;
    unsigned last_section_number            : 8;
    unsigned reserved_3                        : 3;
    unsigned PCR_PID                        : 13;
    unsigned reserved_4                        : 4;
    unsigned program_info_length            : 12;
   
    unsigned stream_type                    : 8;
    unsigned reserved_5                        : 3;
    unsigned elementary_PID                    : 13;
    unsigned reserved_6                        : 4;
    unsigned ES_info_length                    : 12;
    unsigned CRC_32                            : 32;
} TS_PMT;


typedef struct TS_PES
{
    unsigned packet_start_code_prefix                : 24;
    unsigned stream_id                               : 8;
    unsigned PES_packet_length                       : 16;
    unsigned PES_scrambling_control                  : 2;
    unsigned PES_priority                            : 1;
    unsigned data_alignment_indicator                : 1;
    unsigned copyright                              : 1;
    unsigned original_or_copy                       : 1;
    unsigned PTS_DTS_flags                          : 2;
    unsigned ESCR_flag                              : 1;
    unsigned ES_rate_flag                           : 1;
    unsigned DSM_trick_mode_flag                    : 1;
    unsigned additional_copy_info_flag              : 1;
    unsigned PES_CRC_flag                           : 1;
    unsigned PES_extension_flag                     : 1;
    unsigned PES_header_data_length                 : 8;
    unsigned PTS_marker_bit                         : 1;
    unsigned PTS_32_30                              : 3;
    unsigned PTS_29_15                              : 15;
    unsigned PTS_14_0                               : 15;

} TS_PES;

typedef struct TimestampStorage {
	int have_timestamp;
	unsigned long long timestamp;
};


typedef struct tsdemux_struc
{
	struct TimestampStorage audio_pts;
	int audio_pid, video_pid, pcr_pid;
	
	int current_program; /* program we are currently decoding, -1 means no special program */
	int track_program; /* program number we track, -1 means no program
	                                                      -2 means any program
	                                                      -3 means first program of PAT
	                           */
	/* various counters */
	int transport_packets, transport_packet_errors,
	           sync_byte_errors, lost_packets,
	           audio_packets, video_packets,audio_frames,pcr_packets;
	
//	int pidcount[MAX_PIDS];
	
//	unsigned char continuity_counters[MAX_PIDS];
	
	/* Transport Header Info */
	int transport_error_indicator, payload_unit_start_indicator, 
	           pid, adaptation_field_control,
	           transport_scrambling_control;
	
	/*  program associated table */
//	struct PAT_entry PAT[MAX_PROGRAMS];
//	unsigned char PAT_temp[(MAX_PROGRAMS+1)*4];  /* one quadlet for crc */
	int current_pat_section,rest_of_pat_section; /* number of pat section currently read and remaining number of bytes */
	unsigned char *PAT_position;                 /* current position in PAT; NULL if no PAT is pending */
	unsigned char PAT_header[8];                 /* puffer for the head of the current PAT section */
	int PAT_have_bytes_of_header;
	int PAT_version,PAT_last_section;

	int transport_stream_id, number_of_programs;
	
//	struct PMT_buffer_entry pmt_buffer[PMT_BUFFERS]; /* pmt sections will be stored here, until they are complete, and will be interpreted afterwards */
	struct ProgramMapTableEntry *program_map_table;
	
	/* global (static) variables needed by audiobufferfill */
	int have_mpegaudio_header;
	int bytes_already_in_audiobuffer; /* number of bytes we already read */

	/* global (static) variables needed by get_audio_head */
	unsigned long old_mpegaudio_head,skipped_mpegaudio_bytes;

	/* global (static) variables needed by head_read */
	unsigned char audio_hbuf[4];
	int audio_header_bytes_read;
	int valid_pcrs; /* this is zero after disable_sync; when it reaches 2 (we got two valid pcrs) sync is enabled */
	int terminate;
		
	unsigned char* gBuffer; 
	int bytecount; /* position in current TS packet */
	int current;

	struct videobuffer_entry **videobuffer;//[VIDEOPESPACKETSINBUFFER];
	int videobufferstart; /* points to the entry which the consumer currently consumes */
	int videobufferend;   /* points to the entry which the producer currently fills */

	struct audiobuffer_entry **audiobuffer;//[AUDIOFRAMESINBUFFER];
	int audiobufferstart,audiobufferend;

	struct tsbuffer_entry *tsbuffer;
	struct tsbuffer_entry *tsbuffer2;
	
	int (*get_transport_packet)(struct tsdemux_struc* pdemux);
	int (*get_payload)(struct tsdemux_struc* pdemux);
	int (*get_adaptation_field)(struct tsdemux_struc* pdemux);
	int (*get_program_association_table)(struct tsdemux_struc* pdemux, int start);	
	/** copies length bytes of databytes to output (consuming them). */
	int (*copybytes)(struct tsdemux_struc* pdemux, unsigned char* output,int length);
	int (*get_pes_packet)(struct tsdemux_struc* pdemux);
	int (*get_PMT_packet)(struct tsdemux_struc* pdemux, int section_start);
}tsdemux_struc;


typedef struct TS_adaptation_field
{
    unsigned adaptation_field_length                        : 8;
    unsigned discontinuity_indicator                        : 1;
    unsigned random_access_indicator                        : 1;
    unsigned elementary_stream_priority_indicator           : 1;
    unsigned PCR_flag                                       : 1;
    unsigned OPCR_flag                                      : 1;
    unsigned splicing_point_flag                            : 1;
    unsigned transport_private_data_flag                    : 1;
    unsigned adaptation_field_extension_flag                : 1;
    unsigned program_clock_reference_base1                  : 1;
    unsigned program_clock_reference_base2                  : 32;
    unsigned reserved1                                      : 6;
    unsigned program_clock_reference_extension              : 9;
    unsigned original_program_clock_reference_base1         : 1;
    unsigned original_program_clock_reference_base2         : 32;
    unsigned reserved2                                      : 6;
    unsigned original_program_clock_reference_extension     : 9;
    unsigned splice_countdown                               : 8;
    unsigned transport_private_data_length                  : 8;
    unsigned private_data_byte                              : 8;
    unsigned adaptation_field_extension_length              : 8;
    unsigned ltw_flag                                       : 1;
    unsigned piecewise_rate_flag                            : 1;
    unsigned seamless_splice_flag                           : 1;
    unsigned reserved3                                      : 5;
    unsigned ltw_valid_flag                                 : 1;
    unsigned ltw_offset                                     : 15;
    unsigned reserved4                                      : 2;
    unsigned piecewise_rate                                 : 22;
    unsigned splice_type                                    : 4;
    unsigned marker_bit                                     : 1;
    unsigned DTS_next_AU                                    : 32;
    unsigned reserved                                       : 8;
    unsigned stuffing_byte                                  : 8;
} TS_adaptation_field;



#if 0
			switch (streams->stream_type)
			{
				case 0: fprintf(ostream," (reserved)"); break;
				case 1: fprintf(ostream," (MPEG 1 Video)"); break;
				case 2: fprintf(ostream," (MPEG 2 Video)"); break;
				case 3: fprintf(ostream," (MPEG 1 Audio)"); break;
				case 4: fprintf(ostream," (MPEG 2 Audio)"); break;
				case 5: fprintf(ostream," (private sections)"); break;
				case 6: fprintf(ostream," (PES private data)"); break;
				case 7: fprintf(ostream," (MHEG)"); break;
				case 8: fprintf(ostream," (DSM CC)"); break;
				case 9: fprintf(ostream," (ITU-T Rec. H.222.1)"); break;
				case 10: fprintf(ostream," (ISO/IEC 13818-6 type A)"); break;
				case 11: fprintf(ostream," (ISO/IEC 13818-6 type B)"); break;
				case 12: fprintf(ostream," (ISO/IEC 13818-6 type C)"); break;
				case 13: fprintf(ostream," (ISO/IEC 13818-6 type D)"); break;
				case 14: fprintf(ostream," (ISO/IEC 13818-1 auxiliary)"); break;
				case 15: fprintf(ostream," (AAC)"); break;
				case 27: fprintf(ostream," (H264)"); break;	
				default: fprintf(ostream," (reserved or user private)"); break;
			}
#endif


    extern tsdemux_struc *ptsdemux;

	void adjust_TS_packet_header(TS_packet_header* pheader,char * buf_header);
	void adjust_PAT_table ( TS_PAT * packet, char * buffer );
	void adjust_PMT_table ( TS_PMT * packet, char * buffer );
	void adjust_video_table (TS_packet_header *packet_head,char * buffer,FILE *fb);
	void adjust_audio_table (TS_packet_header *packet_head,char * buffer );
	void printf_TS_packet_header_info(TS_packet_header *packet_head);


 #endif

