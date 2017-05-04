#!/bin/bash

KEYSTOREPASSWORD=1234567
serverResourcePath="./src/main/resources/"
pwnlibResourcePath="../pwmlib/src/main/resources/"


removeFilesFromServer() {

	SERVERFILES=$(ls $serverResourcePath| grep server && ls $serverResourcePath| grep keystore)

	for f in $SERVERFILES; do
		echo "removing $f from server"
		rm $serverResourcePath$f
	done

#	if [ -f $serverResourcePath"keystore"$1".jks" ]; then
#		rm $serverResourcePath"keystore"$1".jks"
#	fi
#	if [ -f $serverResourcePath"server"$1".cer" ]; then
#		rm $serverResourcePath"server"$1".cer"
#	fi
#	if [ -f $pwnlibResourcePath"server"$1".cer" ]; then
#		rm $pwnlibResourcePath"server"$1".cer"
#	fi
}

removeFilesFromClient(){

	CLIFILES=$(ls $pwnlibResourcePath| grep server)

	for f in $CLIFILES; do
		echo "removing $f from client"
		rm $pwnlibResourcePath$f
	done
}

generateCertificates() {

	echo "removing files from server"
	removeFilesFromServer
	echo "removing files from client"
	removeFilesFromClient
	echo "all files removed"

	for N in $(seq $SERVER); do
		
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
echo "Launching $SERVER servers"	

generateCertificates


mvn clean package 
for N in $(seq $SERVER);
do
	xfce4-terminal -e "mvn exec:java -Dexec.args=$N"
done

