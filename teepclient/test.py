import simple;

#URL_TEEP='coap://teep-server:5683/teep'
URL_TEEP='coap://127.0.0.1:5683/teep'
#URL_TEEP='coap://172.18.0.2:5683/teep'
#simple.initenclave(URL_TEEP)
#simple.encrypt(0,True,'hello','123',URL_TEEP)
simple.sealingtest(URL_TEEP)
