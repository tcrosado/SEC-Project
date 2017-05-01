# SEC-Project

#Maven Version: 
    -Apache Maven 3.3.9

#Java Version:
    -openjdk version "1.8.0_121"
    -OpenJDK Runtime Environment (build 1.8.0_121-8u121-b13-3-b13)
    -OpenJDK 64-Bit Server VM (build 25.121-b13, mixed mode)
    
#Running Project:
  1) run mvn clean install at "SharedResources" package
  2) run mvn clean package exec:java at "server" package in order to run server tests
  3) run mvn clean package at "pwmlib" package in order to run client tests


Questões a resolver:

 -> fazer mais testes para os servers
 -> fazer mais testes para o pwmlib

Testes possiveis:

-> testar InvalidNonceException no cliente
-> testar respostas insuficientes
-> acessos concurrentes (testNG) -----> ultima coisa a fazer
-> fazer save-password usando TSs iguais
