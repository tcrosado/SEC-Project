#!/bin/bash

mvn clean package

#abrir quatro terminais ubuntu, alterem para os vossos
for i in {1..4}
do
   gnome-terminal -e "mvn exec:java -Dexec.args=$i" 
done