#!/bin/bash

xcrun -sdk iphoneos clang -c -arch arm64e -Iinclude -fobjc-arc *.c *.m *.cpp && ar rcu downloads/jelbrekLib.a *.o && rm *.o

