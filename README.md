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

 1) fazer mais testes para os servers
 2) fazer mais testes para o pwmlib

Testes possiveis:

1) testar InvalidNonceException no cliente
2) testar respostas insuficientes
3) acessos concurrentes (testNG) -----> ultima coisa a fazer
4) fazer save-password usando TSs iguais
