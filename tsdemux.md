This directory contains the source code of tsdemux.
TS is the abbreviation of "Transport Stream". TS is a subcontractor,
each package has 188 bytes . The TS stream can contains many types
of data, such as video, audio, custom information and so on .
The header of a date frame has 4 bytes, and the load contains 184 bytes
(the 184 bytes are  not always  effective, there may exist some data
that are replaced by other words).The code of tsdemux is written by
referring VLC software standards . The protocol document is written
according to the ISO/IEC 13818-1.

TS stream can composite a lot of video and audio programs, but how
the decoder to distinguish them ? The key of the problem is  PMT
data list--the Program Map Table. Fristly ,The  value of  PID  and
its  flow  type can  be acquired through  PMT data list.
then parsing the code by getting a frame of date circularly ,
Lastly Extracting the valid data to synthesis of an audio or
video data stream.

Versioning:


Functionality, the H264 and aac encoding of ts stream parsing
for H264 and aac ES data flow;

Commonly used ts stream can be normal, VLC transcoding can
be parsed, currently only support H264 and parsing of aac.

Thus the first official version.