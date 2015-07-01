This directory contains the source code of tsdemux.
TS is the abbreviation of "Transport Stream". TS is a subcontractor,
each package has 188 bytes . The TS stream can contains many types
of data, such as video, audio, custom information and so on .
The header of a date frame has 4 bytes, and the load contains 184 bytes
(the 184 bytes are  not always  effective, there may exist some data
that are replaced by other words).The code of tsdemux is written by
referring VLC software standards . The protocol document is written
according to the ISO/IEC 13818-1.