//
//  armstub.h
//  ndkutil
//
//  Created by banxian on 1/29/14.
//  Copyright (c) 2014 banxian. All rights reserved.
//

#ifndef ndkutil_armstub_h
#define ndkutil_armstub_h

#include "elfio/elfio.hpp"

bool fillbcblcblxarm(unsigned char* opptr, int delta, bool forceblx, bool* overflowed);
bool fillblblxthumb1(unsigned char* opptr, int distance, bool forceblx, bool* overflowed);
bool fillb11b8thumb1(unsigned char* opptr, int distance, bool* overflowed);

int extract_branchlabel_bcblcblxarm_distance(unsigned w1);
int extract_branchlabel_bcblcblxarm_target(unsigned w1, unsigned w1pc);

int extract_ldr_literal_arm_distance(unsigned w1);
unsigned extract_ldr_literal_arm_target(unsigned w1, unsigned w1pc);

void fixupbranch32(int delta, bool arm, unsigned char* addr);
void fixupmov32(int delta, unsigned char* addrlo, unsigned char* addrhi);
int extract_branchlabel_t2_distance(unsigned short hw1);
int extract_branchlabel_t4_distance(unsigned w1);
int extract_cbnzlabel_t1_distance(unsigned short hw1);
int extract_branchlabel_t2_target(unsigned short hw1, unsigned hw1pc);
int extract_branchlabel_t4_target(unsigned w1, unsigned w1pc);
int extract_cbnzlabel_t1_target(unsigned short hw1, unsigned hw1pc);
bool build_branchlabel_t2(unsigned short* hw1, unsigned caller, unsigned callee);
bool build_branchlabelW_t4(unsigned* w1, unsigned caller, unsigned callee);
bool build_branchlinklabel_t1(unsigned* w1, unsigned caller, unsigned callee);


#endif
