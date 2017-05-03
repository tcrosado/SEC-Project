#!/bin/bash

KEYSTOREPASSWORD=1234567
serverResourcePath="./src/main/resources/"
pwnlibResourcePath="../pwmlib/src/main/resources/"


removeFiles() {
	if [ -f $serverResourcePath"keystore"$1".jks" ]; then
		rm $serverResourcePath"keystore"$1".jks"
	fi
	if [ -f $serverResourcePath"server"$1".cer" ]; then
		rm $serverResourcePath"server"$1".cer"
	fi
	if [ -f $pwnlibResourcePath"server"$1".cer" ]; then
		rm $pwnlibResourcePath"server"$1".cer"
	fi
}

generateCertificates() {

	for N in $(seq $SERVER); do
		removeFiles $N
		#Generate new certificates
		keytool -noprompt -genkey -alias privatekey -keyalg RSA -keystore $serverResourcePath"keystore"$N".jks" -keysize 2048 \
		-dname "CN=none, OU=none, O=none, L=none, S=none, C=none" \
		-storepass $KEYSTOREPASSWORD \
		-keypass $KEYSTOREPASSWORD
		echo "Generated keystore for server$N";
		# Generate public 
		keytool -export -alias privatekey -keystore $serverResourcePath"keystore"$N".jks" -storepass $KEYSTOREPASSWORD -rfc -file $serverResourcePath"server"$N".cer"
		cp $serverResourcePath"server"$N".cer" $pwnlibResourcePath"server"$N".cer"
		echo "Copied public certificate for server$N to client resources"
	done
}




if [ $1 == "r" ]; then
	echo "Removing files"
	for N in $(seq $2); do
		removeFiles $N
	done
	exit
fi

FAULTS=$1
SERVER=$((($FAULTS * 3)+1))
echo "$SERVER will be executed"


replace=false
for N in $(seq $SERVER); do
	if [ ! -f $serverResourcePath"keystore"$N".jks" ]; then
		replace=true
	fi
done 	

if [ $replace == true ]; then
	generateCertificates
fi


mvn clean package 
for N in $(seq $SERVER);
do
	xfce4-terminal -e "mvn exec:java -Dexec.args=$N"
done

