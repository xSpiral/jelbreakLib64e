#!/bin/bash

xcrun -sdk /Users/Cory/Downloads/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk clang -c -arch arm64e -Iinclude -stdlib=libc++ -fobjc-arc *.c *.m *.cpp && ar rcu downloads/jelbrekLib.a *.o && rm *.o

