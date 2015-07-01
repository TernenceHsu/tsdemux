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

  
  filename: main.c 
  version : v1.2.0
  time    : 2015/07/01 16:20 
  author  : xubinbin ( ternence.hsu@foxmail.com )
  code URL: http://code.google.com/p/tsdemux/

*/

#include "fa_parseopt.h"
#include "fa_ts2es.h"

#define READ_TS_SIZE (188*7)

tsdemux_struc ptsdemux;

FILE * fp_video_destfile = NULL;
FILE * fp_audio_destfile = NULL;

int tsdemux_init(tsdemux_struc *ptsdemux)
{	
	memset(ptsdemux, 0, sizeof(struct tsdemux_struc));

	ptsdemux->audio_pid=-1; /* disable all pids at start */
	ptsdemux->video_pid=-1;

	return 0;
}

int tsdemux_deinit(tsdemux_struc *ptsdemux)
{
	memset(ptsdemux, 0, sizeof(struct tsdemux_struc));
	ptsdemux->channel_id = -1;
	
	return 0;
}


int tsdemux_process(tsdemux_struc *ptsdemux,char * ts_buf,int buf_size)
{
	int curcos = 0;
	
    if(buf_size%188 != 0)
    {
        printf("tsdemux receive buffer size error ! \n");
        exit(0);
    }
    if(ts_buf[0] != 0x47)
    {
        printf("tsdemux receive buffer is not a ts standard data \n");
        exit(0);
    }

	unsigned char buffer_ts_header[4];
	unsigned char pat[184];

	while(curcos != buf_size)
	{
		
		memcpy(buffer_ts_header,ts_buf+curcos,4);
        curcos += 4;
		
        adjust_TS_packet_header(&(ptsdemux->packet_head),buffer_ts_header);
		
        memcpy(pat,ts_buf+curcos,184);
        curcos += 184;

        //如果这个包的pid是0 可以通过pat表查找出pmt表的pid
        if(ptsdemux->packet_head.PID  == 0)
        {
            adjust_PAT_table(&ptsdemux->packet_head,&ptsdemux->packet_pat,pat);
        }
        else if(ptsdemux->packet_head.PID  == ptsdemux->packet_pat.program_map_PID)
        {
            adjust_PMT_table(&ptsdemux->packet_head,&ptsdemux->packet_pmt,pat);
        }
        else if(ptsdemux->packet_head.PID == ptsdemux->video_pid)
        {
        	if(strlen(opt_video_outputfile) > 0) {
        		adjust_video_table(&ptsdemux->packet_head,pat,fp_video_destfile);
        	}
        }
        else if(ptsdemux->packet_head.PID == ptsdemux->audio_pid)
        {
        	if(strlen(opt_audio_outputfile) > 0) {
        		adjust_video_table(&ptsdemux->packet_head,pat,fp_audio_destfile);
        	}
        }
        else
        {
            printf("error pid\n");
        }
    }
	return 0;
}

int main(int argc,char * argv[])
{

    int ret = 0;

	char ts_buffer[READ_TS_SIZE];
	
	FILE * fp_sourcefile = NULL;

    ret = fa_parseopt(argc, argv);
    if(ret) return -1;

	if ((fp_sourcefile = fopen(opt_inputfile, "rb")) == NULL) {
		printf("input file can not be opened;\n");
		return 0;
    }
	if(strlen(opt_video_outputfile) > 0) {
		if ((fp_video_destfile = fopen(opt_video_outputfile, "w+b")) == NULL) {
			printf("video output file can not be opened\n");
			return 0;
		}
	}
	if(strlen(opt_audio_outputfile) > 0) {
		if ((fp_audio_destfile = fopen(opt_audio_outputfile, "w+b")) == NULL) {
			printf("audio output file can not be opened\n");
			return 0;
		}
	}

	tsdemux_init(&ptsdemux);

    while(1)
    {
		if(fread(ts_buffer,READ_TS_SIZE,1,fp_sourcefile) != 1) {
        		printf("read inputfile ts_head over/error !\n");
        	break;
        }
		tsdemux_process(&ptsdemux,ts_buffer,READ_TS_SIZE);
	}
    
	tsdemux_deinit(&ptsdemux);

    fclose(fp_sourcefile);
    if(strlen(opt_video_outputfile) > 0) {
    	fclose(fp_video_destfile);
    }
    if(strlen(opt_audio_outputfile) > 0) {
        fclose(fp_audio_destfile);
    }

    printf("Done.\n");

    return 0;
}
