from tkinter import Tk,Label,ttk,StringVar,Text,Scrollbar,Button
import tkinter as tk
import psutil
import threading
from datetime import datetime
from scapy.all import *
from scapy.layers.inet import IP,TCP

detener=False
autor="Programa creado por Mariano Aghazarian."
interfaces=list(psutil.net_if_addrs().keys())
print(interfaces)

def detener_sniffer():
    global detener
    detener=True
    analizar_btn.config(state="normal")
    parar_btn.config(state="disabled")
    print("Sniffer detenido")

def stop(packet):
    global detener
    return detener

def filtrar(packet:Packet):
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return False
    if packet[TCP].dport!=80:
        return False
    if len(packet[TCP].payload)==0:
        return False
    return True

def packet_callback(packet):
    now=datetime.now()
    if filtrar(packet):
        payload=str(bytes(packet[TCP].payload))
        custom_packet={
            "dia":f"{now.day}/{now.month}/{now.year}",
            "hora":f"{now.hour}:{now.minute}:{now.second}",
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "src_port": packet[TCP].sport,
            "dst_port": packet[TCP].dport,
            "timestamp": packet.time,
            "payload": payload
        }
        print(f"[i] Capturado HTTP: {custom_packet}")
        with open("./paquetes_capturados.txt","a") as f:
            f.write(str(custom_packet)+"\n")
        root.after(0,lambda:text_area.insert(tk.END,f"{custom_packet}\n"))

def capturar_paquetes(inter=None):
    if inter:
        print(inter)
        sniff(iface=inter,filter="tcp port 80",stop_filter=stop,prn=packet_callback,store=False)

def ejecutar_sniffer(inter):
    global detener
    detener=False
    hilo=threading.Thread(target=capturar_paquetes,args=(inter,),daemon=True)
    analizar_btn.config(state="disabled")
    parar_btn.config(state="normal")
    if not hilo.is_alive():
        hilo.start()
        print("Ejecutando sniffing.")

root=Tk()

v_interfaces=StringVar()
v_interfaces.set(interfaces[0])

root.geometry("500x500")
root.resizable(False,False)
root.title("Gran Sniffer by Trípode")

interface_lbl=Label(root,text="Interface:",font=("Arial",12,"bold"))
interface_lbl.place(y=10,x=10)
interface_box=ttk.Combobox(root,state="readonly",textvariable=v_interfaces,values=interfaces,
                           font=("Arial",12,"bold"))
interface_box.place(y=10,x=90)

text_area=Text(root,height=20,width=57,wrap="none")
text_area.place(y=40,x=10)

sv=Scrollbar(root,orient="vertical",command=text_area.yview)
sv.place(y=40,x=470,height=330,width=20)
text_area.configure(yscrollcommand=sv.set)

sh=Scrollbar(root,orient="horizontal",command=text_area.xview)
sh.place(y=370,x=10,height=20,width=460)
text_area.configure(xscrollcommand=sh.set)

analizar_btn=Button(root,text="Analizar",command=lambda:ejecutar_sniffer(interface_box.get()),
                font=("Arial",12,"bold"))
analizar_btn.place(y=390,x=10,height=40,width=230)

parar_btn=Button(root,text="Parar",command=lambda:detener_sniffer(),font=("Arial",12,"bold"))
parar_btn.place(y=390,x=250,height=40,width=230)

donaciones=Label(root,text=autor,font=("Arial",12,"bold"))
donaciones.place(y=440,x=10,height=40,width=480)

root.after(0,parar_btn.config(state="disabled"))

root.mainloop()