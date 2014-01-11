#!/usr/bin/env python
#
# DMARC parsing validating and reporting
# 
# Copyright 2012-2014 Linkedin
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#  
# version 1.0

from encodings.idna import ToASCII

file = open("publicsuffixlist.txt")

while 1:
    line = file.readline()
    if not line:
        break
    if line[0:2] != "//" and line[:-1] != "":
	pre=""
	if line[0:1]=="!":
		domain=line[1:-1].decode('string_escape')
		pre="!"
	elif line[0:2]=="*.":
		domain=line[2:-1].decode('string_escape')
		pre="*."
	else:
		domain=line[0:-1].decode('string_escape')
	domain = domain.decode('UTF-8')
	compd = domain.split(".")
	newline=""
	for atom in compd:
		newline=newline+ToASCII(atom)+"."
	print pre+newline[:-1]
