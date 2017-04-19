mvn clean package 
for N in {1..4}
do
	xfce4-terminal -e "mvn exec:java -Dexec.args=$N"
done

