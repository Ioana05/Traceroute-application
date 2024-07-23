import socket
import traceback
import time
import requests
import json
import plotly.express as px
import pandas as pd

# socket de UDP
udp_send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)


# socket RAW de citire a răspunsurilor ICMP
# socket ul RAW permite interactiunea directa cu pachetele IP, fara alte encapsulari tcp/uudp
icmp_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
# setam timout in cazul in care socketul ICMP la apelul recvfrom nu primeste nimic in buffer
icmp_recv_socket.settimeout(3)

def get_ip_details(ip):
    url = f"http://ip-api.com/json/{ip}"
    #trimitem cerere de tipul http GET catre serverul specificat de URL
    response = requests.get(url)
    
    #daca request-ul a avut succes, status_code ul va fi 200
    if response.status_code == 200:
        # deoarece primim un obiect de tip response, il convertim in json ca sa putem extrage datele care ne intereseaza
        data = response.json()
        if data['status'] == 'success':
            print({ "ip": data['query'],
                      "country": data['country'], 
                      "city": data['city'], 
                      "timezone": data['timezone'],
                      "region": data['region']})
            
            return ({ "ip": data['query'],
                      "country": data['country'], 
                      "city": data['city'], 
                      "timezone": data['timezone'],
                      "region": data['region'],
                      "lat": data['lat'],
                      "lon": data['lon'],
                      })
            
        else:
            print("IP-ul este privat!")
            return {
                "ip": data["query"],
                "status": "privat",
                "lat": None,
                "lon": None,    
            }
        
        
    

def traceroute(ip, port):
    # setam TTL in headerul de IP pentru socketul de UDP
    # 64 este TTL default in majoritatea cazurilor
    TTL = 64
    ip_details = {
        "ip": ip,
        "nodes": []
    }

    # incepem for-ul de la 1, ca pachetul sa ajunga macar in default gateway ul meu
    for ttl in range(1,TTL+1):
        
        udp_send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl) #IP_TTL reprezinta campul pe care dorim sa il setam

        # trimite un mesaj UDP catre un tuplu (IP, port)
        udp_send_sock.sendto(b'salut', (ip, port))  # port ul va putea fi o valoare random intre 33434 si 33534. Ideea e sa fie invalid(+ acesta este range ul folosit de UDP)
        sending_time = time.time()

        # asteapta un mesaj ICMP de tipul ICMP TTL exceeded messages
        # in cazul nostru nu verificăm tipul de mesaj ICMP
        # puteti verifica daca primul byte are valoarea Type == 11
        # https://tools.ietf.org/html/rfc792#page-5
        # https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Header
        addr = 'done!'
        try:
            # 63535 este dimensiunea bufferului in care stocam raspunsul
            data, addr = icmp_recv_socket.recvfrom(63535)
            receiving_time = time.time()
            
            # in general, header-ul contine 20 de bytes, dar nu suntem siguri asa ca va trebui sa calculam
            # primul byte contine versiunea IP si si lungimea headerului, iar ca sa extragemn lungimea header ului,
            # vom folosi operatorul logic & (&0x0F ca sa pastram doar ultimii 4 biti)
            header_length = (data[0] & 0x0F) * 4 # inmultim cu 4 ca sa luam dimensiunea in bytes

            # header-ul ICMP incepe imediat dupa header-ul IP
            icmp_type = data[header_length]
            icmp_code = data[header_length + 1]

            # code ul specifica motivul pentru mesajul time exceeded si sunt doar doua variante(0,1)
            if icmp_type == 11 and icmp_code == 0:
                print (f"{ttl}: {addr} {round(receiving_time - sending_time,3)}")
                node_details = get_ip_details(addr[0])
                ip_details["nodes"].append(node_details)

            # a ajuns la destinatie
            elif icmp_type == 3 and icmp_code == 3:
                print("The packet reached the destination!")
                print (f"{ttl}: {addr}")
                node_details = get_ip_details(addr[0])
                ip_details["nodes"].append(node_details)
                break
            
            
        except Exception as e:
            # print("Socket timeout ", str(e))
            print(f'{ttl}: * * *')
            #print(traceback.format_exc())

    # salvez in fisierul json
    with open('traceroute.json', 'a') as json_file:
        json.dump(ip_details, json_file, indent=4)
        
    # configuram harta
    # transformam lista de dictionare intr-un DataFrame Pandas(fiecare dictionar va reprezenta o linie in DataFrame)
    df = pd.DataFrame(ip_details["nodes"])
    
    
    # creem harta
    # scatter geo foloseste coloane lat si lon din data frame pentru a plasa punctele pe harta
    fig = px.scatter_geo(df, lat = 'lat', lon = 'lon', hover_name='ip', hover_data={'country': True})
    fig.update_geos(showcountries = True, countrycolor = "pink" )
    
    # am dat write intr-un fisier map.html pentruca nu vrea sa mearga show-ul(deschidem cu chrome)
    fig.write_html("map.html", auto_open=True)
        
    return addr

'''
 Exercitiu hackney carriage (optional)!
    e posibil ca ipinfo sa raspunda cu status code 429 Too Many Requests
    cititi despre campul X-Forwarded-For din antetul HTTP
        https://www.nginx.com/resources/wiki/start/topics/examples/forwarded/
    si setati-l o valoare in asa fel incat
    sa puteti trece peste sistemul care limiteaza numarul de cereri/zi

    Alternativ, puteti folosi ip-api (documentatie: https://ip-api.com/docs/api:json).
    Acesta permite trimiterea a 45 de query-uri de geolocare pe minut.
'''

traceroute('139.130.4.5', 33434)

# inchidem socket-urile
udp_send_sock.close()
icmp_recv_socket.close()