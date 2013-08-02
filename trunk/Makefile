#
#  Copyright (C) 2013 xubinbin Ðì±ò±ò (Beijing China)
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#  
#  filename: Makefile
#  version : v1.1.0
#  time    : 2013/08/02 16:20 
#  author  : xubinbin ( xubbwd@gmail.com )
#  code URL: http://code.google.com/p/tsdemux/
#  


include Makefile.include

INCLUDEDIR = ./include

LDFLAGS += -lm -lpthread -lrt 

TARGET    =  tsdemux 
CSRCFILES =  $(shell ls *.c)
COBJFILES =  $(patsubst %.c,%.o,$(CSRCFILES))

SRCFILES  =	 $(CSRCFILES) 
OBJFILES  =	 $(COBJFILES) 

CFLAGS    += -I.  -I$(INCLUDEDIR)

all: $(OBJFILES) 
	rm $(TARGET) -f 
	$(CC) -o $(TARGET) $(OBJFILES) $(LDFLAGS)	 

clean : 
	@rm *.o -f
	@rm *.out -f	
	@rm $(TARGET) -f	

install :