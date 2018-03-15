#UTFPR (Universidade Tecnologica Federal do Parana)
#disciplina: Redes de Computadores 2
#autor: Renan Kodama Rodrigues
#ra: 1602098


# -*- coding: utf-8 -*-



class Codificador:
	def __init__(self,arquivo):


		arq = open('./Testes/'+arquivo, 'r')
		conteudo = arq.read()								#leitura do arquivo 	
		protocolo = ""

		print "\n\n\t Ethernet Protocol"					
		self.ethernetPack(conteudo)							#extracao do pacote Ethernet

		print "\n\t Ip Protocol"							
		protocolo = self.ipPack(conteudo)					#extracao do pacote IP

		if protocolo == "tcp":
			print "\n\t TCP Protocol"						
			self.tcpPack(conteudo)							#extracao do pacote TCP
		else:
			if protocolo == "udp":
				print "\n\t UDP Protocol"
				self.udpPack(conteudo)						#extracao do pacote UDP


	def ethernetPack(self,dado):
		mac_Destino = []									#mac destino 0-5 bytes
		mac_Destino.append(dado[0:1])
		mac_Destino.append(dado[1:2])
		mac_Destino.append(dado[2:3])
		mac_Destino.append(dado[3:4])
		mac_Destino.append(dado[4:5])
		mac_Destino.append(dado[5:6])
		
		mac_Origem = []										#mac origem 6-11 bytes
		mac_Origem.append(dado[6:7])
		mac_Origem.append(dado[7:8])
		mac_Origem.append(dado[8:9])
		mac_Origem.append(dado[9:10])
		mac_Origem.append(dado[10:11])
		mac_Origem.append(dado[11:12])

		tipo_Hex = dado[12:14]								#tipo ether 12-13 bytes 
		tipo_Str = ""

		if tipo_Hex.encode('hex') == "0800":							#selecionando tipo  do protocolo(apenas alguns)
			tipo_Str = "Internet Protocol version 4 (IPV4)"		
		if tipo_Hex.encode('hex') == "0806":
			tipo_Str = "Address Resolution Protocol (ARP)"
		if tipo_Hex.encode('hex') == "0842":
			tipo_Str = "Wake-on-LAN"
		if tipo_Hex.encode('hex') == "22F3":
			tipo_Str = "IETF TRILL Protocol"		
		if tipo_Hex.encode('hex') == "86DD":
			tipo_Str = "Internet Protocol Version 6 (IPv6)"
		if tipo_Hex.encode('hex') == "8847":
			tipo_Str = "MPLS unicast"
		if tipo_Hex.encode('hex') == "8848":
			tipo_Str = "MPLS multicast"
		if tipo_Hex.encode('hex') == "8863":
			tipo_Str = "PPPoE Discovery Stage"
		if tipo_Hex.encode('hex') == "8864":
			tipo_Str = "PPPoE Session Stage"

		#visualizacao dos resultados
		print "Mac Destino: "+mac_Destino[0].encode('hex')+":"+mac_Destino[1].encode('hex')+":"+mac_Destino[2].encode('hex')+":"+mac_Destino[3].encode('hex')+":"+mac_Destino[4].encode('hex')+":"+mac_Destino[5].encode('hex')
		print "Mac Origem: "+mac_Origem[0].encode('hex')+":"+mac_Origem[1].encode('hex')+":"+mac_Origem[2].encode('hex')+":"+mac_Origem[3].encode('hex')+":"+mac_Origem[4].encode('hex')+":"+mac_Origem[5].encode('hex')
		print "Ether Tipo: 0x"+tipo_Hex.encode('hex')+" "+tipo_Str

	def ipPack(self,dado):
		versao = dado[14:16]											#versao nos primeiros 4 bits
		versao = int(versao.encode('hex'))>>10				
		
		hl = dado[14:15]												#header length 4 bits apos versao
		hl = int(hl.encode('hex'))<<4
		hl = hl>>5
		
		tipo_servico = dado[15:16]										#tipo de servico sao os 8 bits apos header length
		
		tamanho_total = dado[16:18]										#tamanho total encontra -se nos 16 bits apos tipo servico 
		tamanho_total = int(tamanho_total.encode('hex'),16)
		
		identificacao = dado[18:20]										#primeiros 16 bits apos tamanho total
		
		flags = dado[20:21]												#4 bits para determinar a flag
		flags = int(flags.encode('hex'))>>4
		flags = hex(flags)
		
		fragment_offset = dado[21:22]	
		fragment_offset = int(fragment_offset.encode('hex'),16)
		
		time_to_live = dado[22:23]										#8 bits para time to live
		time_to_live = int(time_to_live.encode('hex'),16)
		
		protocol = dado[23:24]											#8 bits para protocolo apos time to live
		protocol = int (protocol.encode('hex'),16)
		
		header_checksum = dado[24:26]									#16 bits para checkSum 
		
		source_ip_adress = []											#atribuindo os campos do endereco IP A.B.C.D em hexadecimal
		source_ip_adress.append(dado[26:27]) 
		source_ip_adress.append(dado[27:28])
		source_ip_adress.append(dado[28:29])
		source_ip_adress.append(dado[29:30])
		source_ip_adress[0] = int(source_ip_adress[0].encode('hex'),16)		#transformando cada campo para decimal
		source_ip_adress[1] = int(source_ip_adress[1].encode('hex'),16)
		source_ip_adress[2] = int(source_ip_adress[2].encode('hex'),16)
		source_ip_adress[3] = int(source_ip_adress[3].encode('hex'),16)

		destination_ip_adress = []										#atribuindo os campos do endereco IP A.B.C.D em hexadecimal
		destination_ip_adress.append(dado[30:31])
		destination_ip_adress.append(dado[31:32])
		destination_ip_adress.append(dado[32:33])
		destination_ip_adress.append(dado[33:34])
		destination_ip_adress[0] = int(destination_ip_adress[0].encode('hex'),16)		#transformando cada campo para decimal
		destination_ip_adress[1] = int(destination_ip_adress[1].encode('hex'),16)
		destination_ip_adress[2] = int(destination_ip_adress[2].encode('hex'),16)
		destination_ip_adress[3] = int(destination_ip_adress[3].encode('hex'),16)

		#visualizacao dos resultados
		print "Versao: "+repr(versao)
		print "Header Length: "+repr(hl)+" bytes" 
		print "Tipo de Servico: 0x"+tipo_servico.encode('hex')
		print "Tamanho Total: "+repr(tamanho_total)
		print "Identificacao: 0x"+identificacao.encode('hex')+" ("+repr(int(identificacao.encode('hex'),16))+")"
		print "Flags: "+flags
		print "Fragment Offset: "+repr(fragment_offset)
		print "Time To Live: "+repr(time_to_live)
		print "Protocol: "+repr(protocol)
		print "Header CheckSum: 0x"+header_checksum.encode('hex')
		print "Source Ip: "+repr(source_ip_adress[0])+"."+repr(source_ip_adress[1])+"."+repr(source_ip_adress[2])+"."+repr(source_ip_adress[3])
		print "Destination Ip: "+repr(destination_ip_adress[0])+"."+repr(destination_ip_adress[1])+"."+repr(destination_ip_adress[2])+"."+repr(destination_ip_adress[3])

		if protocol == 06:
			return "tcp"
		else:
			if protocol == 17:
				return "udp"

	def udpPack(self,dado):
		source_port = dado[34:36]										#16 bits para porta origem 
		source_port = int(source_port.encode('hex'),16)
		destination_port = dado[36:38]									#16 bits para porta destino
		destination_port = int(destination_port.encode('hex'),16)
		lenght = dado[38:40]											#16 bits para tamanho
		lenght = int(lenght.encode('hex'),16)
		checkSum = dado[40:42]											#16 bits para checksum 

		#visualizacao dos resultados
		print "Souce Port: "+repr(source_port)
		print "Destination Port: "+repr(destination_port)
		print "Length: "+repr(lenght)
		print "CheckSum: 0x"+checkSum.encode('hex')

	def tcpPack(self,dado):	
		source_port = dado[34:36]										#16 bits para porta origem 										
		source_port = int(source_port.encode('hex'),16)			
		destination_port = dado[36:38]									#16 bits para porta destino
		destination_port = int(destination_port.encode('hex'),16)
		sequence_number = dado[38:42]									#32 bits para numero sequencia
		ack_number = dado[42:46]										#32 bits para numero ack

		header_len = dado[46:48]										
		header_len = int(header_len.encode("hex"),16)>>10

		flags = dado[47:48]
		flags = int(flags.encode('hex'),16) << 10
		flags = flags >> 10
		flags = hex(flags) 

		window_size = dado[48:50]										#16 bits para tamanho de janela
		window_size = int(window_size.encode('hex'),16)
		tcp_checksum = dado[50:52]										#16 bits para checksum
		urgent_pointers = dado[52:54]									#16 bits para pontos urgentes
		urgent_pointers = int(urgent_pointers.encode('hex'),16)

		#visualizacao dos resultados
		print "Source Port: "+repr(source_port)
		print "Destination Port: "+repr(destination_port)
		print "Sequence Number: 0x"+sequence_number.encode('hex')
		print "Ack Number: 0x"+ack_number.encode('hex')
		print "Header Length: "+repr(header_len)+" bytes"
		print "Flags: "+flags
		print "Window Size: "+repr(window_size)
		print "CheckSum: 0x"+tcp_checksum.encode('hex')
		print "Urgent Pointers: "+repr(urgent_pointers)

if __name__ == '__main__':
	print("\n\nOs arquivos de testes devem estar presentes na pasta \"Testes\"!")
	nome_arquivo = raw_input("\tEntre com o nome do arquivo ex:(packet_tcp.bin): ")
	
	Codificador(nome_arquivo)					#chamada do decodificador de datagramas
