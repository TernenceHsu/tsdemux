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

  
  filename: fa_parseopt.c 
  version : v1.1.0
  time    : 2013/08/02 16:20 
  author  : xubinbin ( xubbwd@gmail.com )
  code URL: http://code.google.com/p/tsdemux/

*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __GNUC__ 
#include <getopt.h>
#else
#include "getopt.h"
#include "getopt.c"
#endif

#include "fa_parseopt.h"

/*global option vaule*/
char  opt_inputfile[256]  = "";
char  opt_video_outputfile[256] = "";
char  opt_audio_outputfile[256] = "";


const char *usage =
"\n\n"
"Usage: faresample <-i> <inputfile> <-v> <video_outputfile> [options] \n"
"       faresample <-i> <inputfile> <-a> <audio_outputfile> [options] \n"
"       faresample <-i> <inputfile> <-v> <video_outputfile> <-a> <audio_outputfile> [options] \n"
"\n\n"
"See also:\n"
"    --help               for a description of all options for ...\n"
"    --license            for the license terms for falab.\n\n";

const char *default_set =
"\n\n"
"No argument input, run by default settings\n"
"    --type       [resample]\n"
"    --downfactor [160]\n"
"    --upfactor   [147]\n"
"    --gain       [1.0]\n"
"\n\n";

const char *help =
"\n\n"
"Usage: faresample <-i> <inputfile> <-v> <video_outputfile> <-a> <audio_outputfile> [options] \n"
"Options:\n"
"    -i <inputfile>             Set ts input filename\n"
"    -o <video_outputfile>      Set video output filename\n"
"    -o <audio_outputfile>      Set audio output filename\n"
"    --help                     Show this abbreviated help.\n"
"    --long-help                Show complete help.\n"
"    --license                  for the license terms for falab.\n"
"\n\n";


const char *license =
"\n\n"
"**************************************  WARN  *******************************************\n"
"*    Please note that the use of this software may require the payment of patent        *\n"
"*    royalties. You need to consider this issue before you start building derivative    *\n"
"*    works. We are not warranting or indemnifying you in any way for patent royalities! *\n"
"*                                                                                       *\n" 
"*                YOU ARE SOLELY RESPONSIBLE FOR YOUR OWN ACTIONS!                       *\n"
"*****************************************************************************************\n"
"\n"
"\n"
"Copyright (C) 2013 xubinbin Ðì±ò±ò (Beijing China)\n"
"\n"
"This program is free software: you can redistribute it and/or modify\n"
"it under the terms of the GNU General Public License as published by\n"
"the Free Software Foundation, either version 3 of the License, or\n"
"(at your option) any later version.\n"
"\n"
"This program is distributed in the hope that it will be useful,\n"
"but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
"GNU General Public License for more details.\n"
"\n"
"You should have received a copy of the GNU General Public License\n"
"along with this program.  If not, see <http://www.gnu.org/licenses/>.\n"
"\n"
"\n"
"                                       ---xubinbin 2012.08.02"
"\n";

static void fa_printopt()
{
    FA_PRINT("NOTE: configuration is below\n");
    FA_PRINT("NOTE: inputfile = %s\n", opt_inputfile);
    FA_PRINT("NOTE: video outputfile= %s\n", opt_video_outputfile);
    FA_PRINT("NOTE: audio outputfile= %s\n", opt_audio_outputfile);
}


/**
 * @brief: check the input value valid, should check the valid scope
 *
 * @return: 0 if success, -1 if error
 */
static int fa_checkopt(int argc)
{

    if(argc < 5) {
        FA_PRINT_ERR("FAIL: input and output file should input\n");
        return -1;
    }

    if(strlen(opt_inputfile) == 0) {
        FA_PRINT_ERR("FAIL: input and output file should input\n");
        return -1;
    }

    if(strlen(opt_video_outputfile) == 0 && strlen(opt_audio_outputfile) == 0) {
        FA_PRINT_ERR("FAIL: input and output file should input\n");
        return -1;
    }

    FA_PRINT("SUCC: check option ok\n");
    return 0;
}


/**
 * @brief: parse the command line
 *         this is the simple template which will be used by falab projects
 *
 * @param:argc
 * @param:argv[]
 *
 * @return: 0 if success, -1 if error(input value maybe not right)
 */
int fa_parseopt(int argc, char *argv[])
{
    int ret;
    const char *die_msg = NULL;

    while (1) {
        static char * const     short_options = "hHLli:v:a:";
        static struct option    long_options[] = 
                                {
                                    { "help"           , 0, 0, 'h'}, 
                                    { "help"           , 0, 0, 'H'},
                                    { "license"        , 0, 0, 'L'},
                                    { "license"        , 0, 0, 'l'},
                                    { "input"          , 1, 0, 'i'},                 
                                    { "video output"   , 1, 0, 'v'},
                                    { "audio output"   , 1, 0, 'a'},
                                    {0                 , 0, 0,  0},
                                };
        int c = -1;
        int option_index = 0;

        c = getopt_long(argc, argv, short_options, long_options, &option_index);

        if (c == -1) {
            break;
        }

        if (!c) {
            die_msg = usage;
            break;
        }

        switch (c) {
            case 'h': {
                          die_msg = help;
                          break;
                      }

            case 'H': {
                          die_msg = help;
                          break;
                      }
                      
            case 'L': {
                          die_msg = license;
                          break;
                      }

            case 'l': {
                          die_msg = license;
                          break;
                      }

            case 'i': {
                          if (sscanf(optarg, "%s", opt_inputfile) > 0) {
                              FA_PRINT("SUCC: inputfile is %s\n", opt_inputfile);
                          }else {
                              FA_PRINT_ERR("FAIL: no inputfile\n");
                          }
                          break;
                      }

            case 'v': {
                          if (sscanf(optarg, "%s", opt_video_outputfile) > 0) {
                              FA_PRINT("SUCC: video outputfile is %s\n", opt_video_outputfile);
                          }else {
                              FA_PRINT_ERR("FAIL: no video outputfile\n");
                          }
                          break;
                      }

            case 'a': {
                          if (sscanf(optarg, "%s", opt_audio_outputfile) > 0) {
                              FA_PRINT("SUCC: audio outputfile is %s\n", opt_audio_outputfile);
                          }else {
                              FA_PRINT_ERR("FAIL: no audio outputfile\n");
                          }
                          break;
                      }

            case '?':
            default:
                      die_msg = usage;
                      break;
        }
    }

    if(die_msg) {
        FA_PRINT("%s\n", die_msg);
        goto fail;
    }

    /*check the input validity*/
    ret = fa_checkopt(argc);
    if(ret) {
        die_msg = usage;
        FA_PRINT("%s\n", die_msg);
        goto fail;
    }

    /*print the settings*/
    fa_printopt();

    return 0;
fail:
    return -1;
}
