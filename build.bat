@echo off

del ozf_decoder.dll
g++ -c ozf_decoder.cpp
g++ -shared -o ozf_decoder.dll ozf_decoder.o -lz
del ozf_decoder.o

pause