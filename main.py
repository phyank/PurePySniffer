from tkinter import *
from tkinter import ttk
from tkinter.messagebox import *
from tkinter.filedialog import *
from pickle import *
from binascii import hexlify,b2a_hex
import threading
import socket, sys
from struct import *
import queue
from time import sleep
import os
import re
from io import StringIO

from definition import *
from widgets import *
from threads import *

if os.name=='nt':
    print("This program can only be run on Linux with root priviledge")
    sys.exit(1)

def notdone():
    pass


def quit():
    pcap.quit = True
    sys.exit()


def startcapture(root,fliter):
    StartBox(pcap, (sl, stext, stext2, stextph), root,fliter)


def stopcapture():
    if pcap.start:
        answer = askyesno("info", "Stop current process without saving?")
        if answer:
            pcap.start = False
            pcap.pcap = []
            sl.listbox.delete(0, END)
            stext.text.delete('1.0', END)
            stext2.text.delete('1.0', END)
            stextph.text.delete('1.0', END)
            pcap.new_proto_no = []
            print('Delete Request:2333 Reason:Stop Cap')
            infoqueue.put((2333,DELETE_THREAD))
        else:
            pass
    else:
        showinfo("Info", "No processing thread.")


def storepackage(pcap):
    while True:
        src=asksaveasfilename(defaultextension='.mycap',filetypes =[('MyCap File','.mycap')],initialdir ='~\\')
        try:
            file=open(src,'wb')
            dump(pcap.pcap,file)
            file.close()
            break
        except:
            if askyesno('Saving Failed','Failed to save file,continue to save?'):
                pass
            else:
                break

def loadpackage(root,pcap,sl,stext,stext2,stextph):
    if pcap.start:
        answer = askyesno("info", "Stop current process without saving?")
        if answer:
            pcap.start = False
            pcap.pcap = []
            pcap.new_proto_no = []
            if pcap.threads:
                print("Delete Request.Reason:Load File.")
                infoqueue.put((2333,DELETE_THREAD))
        else:
            return

    while True:
        sl.listbox.delete(0, END)
        stext.text.delete('1.0', END)
        stext2.text.delete('1.0', END)
        stextph.text.delete('1.0', END)
        try:
            src=askopenfilename(defaultextension='.mycap',filetypes =[('MyCap File','.mycap')],initialdir ='~\\')
            file=open(src,'rb')
            obj=load(file)
            pcap.pcap=obj

            StartBox(pcap, (sl, stext, stext2, stextph), root,fliter,False,LOAD_FILE)

            break
        except:
            r=askyesno('Loading Failed','Failed to load file,continue to load?')
            if r:
                continue
            else:
                break

def changefliter(root,pcap,texts,fliter):
    StartBox(pcap, (sl, stext, stext2, stextph), root, fliter, False, LOAD_FILE)

def savecurrentraw(stext):
    try:
        src = asksaveasfilename(defaultextension='.', initialdir='~\\')
        file=open(src,'wb')
        file.write(stext.textbytes)
        file.close()
    except:
        showerror('Error',"Saving RAW data failed.")

def full_quit(root,pcap):
    pcap.quit=True
    root.destroy()



root = Tk()
root.title(MAIN_TITLE)
options = []

pcap = Database()
topframe = Frame(root)
bottomframe = LabelFrame(root, text='Data')

toptopframe = Frame(topframe)
topbottomframe = LabelFrame(topframe, text='Package Info')

topframe.pack(side=LEFT, fill=BOTH)
bottomframe.pack(side=RIGHT, fill=BOTH)
toptopframe.pack(side=TOP, fill=BOTH)
topbottomframe.pack(side=BOTTOM, fill=BOTH)



stext = ScrolledText(bottomframe)
stext2 = ScrolledText(bottomframe)
stextph = ScrolledText(topbottomframe, 70)

fliter=fliter()

sl = slist(pcap, stext, stext2, stextph, options, mutex, toptopframe,fliter)

tpMnu = Menu(root)
root.config(menu=tpMnu)
file = Menu(tpMnu)
file.add_command(label="Open mycap File", command=(lambda:loadpackage(root,pcap,sl,stext,stext2,stextph)), underline=0)
file.add_command(label="Save All Captured Packages", command=(lambda:storepackage(pcap)), underline=0)
file.add_command(label="Save Current RAW Data", command=(lambda:savecurrentraw(stext)), underline=0)
#file.add_command(label="Interpret Current RAW Data", command=notdone, underline=0)
file.add_command(label="Quit", command=(lambda: full_quit(root,pcap)), underline=0)
tpMnu.add_cascade(label='File', menu=file, underline=0)

controller = Menu(tpMnu)
controller.add_command(label="Fliter", command=(lambda: changefliter(root,pcap,(stext, stext2, stextph),fliter)), underline=0)
controller.add_command(label="Start Cap", command=(lambda: startcapture(root,fliter)), underline=0)
controller.add_command(label="Stop Cap", command=stopcapture, underline=0)
tpMnu.add_cascade(label='Control', menu=controller, underline=0)

about = Menu(tpMnu)
about.add_command(label="About",command=(lambda:showinfo('About',"Pure Python Sniffer using RAW_SOCKET\nVersion : 0.1\nAuthor : phyank \nEmail : hbyyeah@qq.com\n")))
tpMnu.add_cascade(label='About', menu=about, underline=0)





refreshth = refreshthread(1, 0, pcap,fliter,sl)
refreshth.daemon = True

refreshth.start()

root.resizable(0, 0)
root.withdraw()

startcapture(root,fliter)

root.mainloop()
