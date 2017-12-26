from definition import *
from tkinter import *
from tkinter import ttk
from tkinter.messagebox import *
from binascii import hexlify
import os
from threads import *

class slist(Frame):
    def __init__(self, db, stext, stext2, stextph, options, mutex, parent,fliter):
        Frame.__init__(self, parent)
        self.pack(side=LEFT, fill=BOTH)
        self.pos = 0
        self.db = db
        self.stext = stext
        self.stext2 = stext2
        self.stextph = stextph
        self.mutex = mutex
        self.fliter=fliter
        self.makeWidgets(options)



    def handlelist(self, e):
        index = self.listbox.curselection()
        # label=self.listbox.get(index)
        self.runCommand(index[0])

    def makeWidgets(self, options):
        sbar = Scrollbar(self)
        list = Listbox(self, width=70, relief=SUNKEN)
        sbar.config(command=list.yview)
        list.config(yscrollcommand=sbar.set)
        sbar.pack(side=RIGHT, fill=Y)
        list.pack(side=LEFT, fill=BOTH)
        self.pos = 0
        for label in options:
            list.insert(self.pos, label)
            self.pos += 1
        list.bind('<ButtonRelease-1>', self.handlelist)
        self.listbox = list

    def runCommand(self, selection):
        try:
            self.stext.advancedsettext(1, self.db.pcap2show[selection][PCAP_DATA])
            self.stext2.advancedsettext(0, self.db.pcap2show[selection][PCAP_DATA])
            self.stextph.setheader(self.db.pcap2show[selection])
        except:
             print("Index Out of Range")

    def list_label(self,p):
        if p[PCAP_ETH_PROTO]==0x0800:
            if p[PCAP_PROTO]==PROTO_ICMP:
                return parseproto(p[PCAP_PROTO]) +" type"+interpret_icmp(p[PCAP_PROTO_OPT][0])+ " from " + str(p[PCAP_SRC_IP])  + " to " + str(p[PCAP_DST_IP])
            else:
                if p[PCAP_SRC_PORT]==UNDEFINED:
                    return parseproto(p[PCAP_PROTO]) + " Damaged "+" from " + str(p[PCAP_SRC_IP])  + " to " + str(p[PCAP_DST_IP])
                else:
                    return parseproto(p[PCAP_PROTO]) + " from " + str(p[PCAP_SRC_IP]) + ":" + str(p[PCAP_SRC_PORT]) + " to " + str(
                        p[PCAP_DST_IP]) + ":" + str(p[PCAP_DST_PORT])
        elif p[PCAP_ETH_PROTO]==0x0806:
            if p[PCAP_PROTO_OPT]!=UNDEFINED:
                if p[PCAP_PROTO_OPT][8]==UNDEFINED:
                    return 'ARP gratuitous from '+str(p[PCAP_PROTO_OPT][6])
                else:
                    return 'ARP from '+str(p[PCAP_PROTO_OPT][6])+' '+('asking for' if p[PCAP_PROTO_OPT][4]==1 else 'response of')+' '+str(p[PCAP_PROTO_OPT][8])
            else:
                return 'ARP Damaged?'
        elif p[PCAP_ETH_PROTO]==0x8035:
            if p[PCAP_PROTO_OPT]!=UNDEFINED:
                return 'RARP from '+mac_formater(p[PCAP_PROTO_OPT][5])+' '+('asking for' if p[PCAP_PROTO_OPT][4]==3 else 'response of')+' '+str(p[PCAP_PROTO_OPT][7])
            else:
                return 'RARP Damaged?'



    def list_insert(self, p):
        self.listbox.insert(self.pos, self.list_label(p))
        self.pos += 1

class ScrolledText(Frame):
    def __init__(self, parent=None, width=32, text='', file=None):
        Frame.__init__(self, parent)
        self.pack(side=LEFT, fill=BOTH)
        self.width = width
        self.makewidgets()
        self.settext(text, file)
        self.textbytes=b''

    def makewidgets(self):
        tsbar = Scrollbar(self)
        if self.width:
            text = Text(self, width=self.width, relief=SUNKEN)
        else:
            text = Text(self, relief=SUNKEN)
        tsbar.config(command=text.yview)
        text.config(yscrollcommand=tsbar.set)
        tsbar.pack(side=RIGHT, fill=Y)
        text.pack(side=LEFT, expand=YES, fill=BOTH)

        self.text = text

    def settext(self, text='', file=None):
        if file:
            text = open(file, 'r').read()
        self.text.delete('1.0', END)
        self.text.insert('1.0', text)

    def gettext(self):
        return self.text.get('1.0', END + '-1c')

    def ByteToHex(self, bins):
        return ''.join(["%02X  " % x for x in bins]).strip()

    def setheader(self, tuple):


        out = ''
        eth_protocol, source_mac, destination_mac, version, ihl,service,totallen,id,flags,f_offset, ttl, protocol, s_addr, d_addr, source_port, dest_port, protocol_opt, data,iph_chksum,eth_fcs = tuple
        out+='Content Protocol Type:'+str(eth_protocol)+\
             "\n Source MAC:"+mac_formater(source_mac)+\
             '\n Destination MAC:'+mac_formater(destination_mac)+\
             '\n Ethernet FCS:'+(hexlify(eth_fcs)).decode('ascii')+\
             '\n\n'

        if eth_protocol==0x0800:
            flagstring='%01d %01d %01d' % ((flags & 0b100)>>2,(flags & 0b010)>>1,(flags & 0b001))

            out += 'IPv'
            out += str(version)
            out += ' package\n IP Header Length : ' + str(ihl) +\
                   '\n Type of Service:'+str(service) +\
                   '\n Total Length : '+str(totallen)+\
                   "\n Identification : "+str(id)+\
                   "\n Flags : "+flagstring+\
                   "\n Fragment Offset : "+str(f_offset)+\
                   '\n TTL : ' + str(ttl) +\
                   '\n Source Address : ' + str(s_addr) +\
                   '\n Destination Address : ' + str(d_addr)+\
                   '\n IP Header Checksum : '+hexlify(iph_chksum).decode('ascii','ignore')

            if protocol == PROTO_ICMP:
                out += '\n\nProtocol:ICMP' +\
                       '\n ICMP Type:' + interpret_icmp(protocol_opt[0]) +\
                       '\n' + ' ICMP Code:' + str(protocol_opt[1]) +\
                       '\n' + ' ICMP Checksum:'+hexlify(protocol_opt[2]).decode('ascii','ignore')+\
                       '\n\n'
            elif protocol == PROTO_TCP:
                out += '\n\nProtocol:TCP'
                if source_port==UNDEFINED:
                    out+="\n Package seems to be damaged.See data."
                else:
                    out+='\n Source Port : ' + str(source_port) +\
                         '\n' + ' Dest Port : ' + str(dest_port) +\
                         '\n' + ' Sequence Number : ' +str(protocol_opt[1]) +\
                         '\n' + ' Acknowledgement : ' + str(protocol_opt[2]) +\
                         '\n' + ' TCP header length : ' + str(protocol_opt[3])+'\n\n'
            elif protocol == PROTO_UDP:
                out += '\n\nProtocol:UDP'
                if source_port==UNDEFINED:
                    out+='\n Package seems to be damaged.See data.'
                else:
                    out+='\n Source Port : ' + str(source_port) +\
                         '\n Dest Port : ' + str(dest_port) +\
                         '\n Length:' + str(protocol_opt[2]) +\
                         '\n Checksum: ' + hexlify(protocol_opt[3]).decode('ascii')+'\n\n'
            else:
                out += 'Unknown Header'

            out+=interpret_data_protocol(data)

        elif eth_protocol==0x0806:
            out += "ARP Package\n"

            if protocol_opt==UNDEFINED:
                out+=" Unreadable.See data"
            else:
                device,upper_proto,hlen,plen,code,smac,sip,dmac,dip=protocol_opt
                out+=" Device Type:"+str(device)+'\n Upper Protocol:'+str(upper_proto)\
                +"\n MAC Address Length:"+str(hlen)\
                +"\n IP Address Length:"+str(plen)\
                +"\n Operation Code:"+str(code)+' '+('Request' if code==1 else 'Response')+(' (gratuitous)' if dmac==UNDEFINED else '')\
                +"\n Source MAC:"+mac_formater(smac)\
                +"\n Source IP Address:"+str(sip) \
                + (("\n Destination MAC:" + mac_formater(dmac) ) if dmac!=UNDEFINED else '')\
                +(("\n Destination IP Address:"+str(dip)) if dip!=UNDEFINED else '')
        elif eth_protocol==0x8035:
            out += "RARP Package\n"

            if protocol_opt==UNDEFINED:
                out+=" Unreadable.See data"
            else:
                device,upper_proto,hlen,plen,code,smac,sip,dmac,dip=protocol_opt
                out+=" Device Type:"+str(device)+'\n Upper Protocol:'+str(upper_proto)\
                +"\n MAC Address Length:"+str(hlen)\
                +"\n IP Address Length:"+str(plen)\
                +"\n Operation Code:"+str(code)+' '+('Request' if code==3 else 'Response')\
                +"\n Source MAC:"+mac_formater(smac)\
                +"\n Source IP Address:"+str(sip)\
                +"\n Destination MAC:"+mac_formater(dmac)\
                +"\n Destination IP Address:"+str(dip)
        else:
            out+="Unkown Protocol."

        self.text.delete('1.0', END)
        self.text.insert('1.0', out)

    def advancedsettext(self, display=1, bins=b''):
        if display:
            self.textbytes=bins
            text = self.ByteToHex(bins)
        else:
            text = bins.decode('ascii', 'ignore')
        self.text.delete('1.0', END)
        self.text.insert('1.0', text)


class StartBox:
    def __init__(self, pcap, texts, parent,fliter,ifdevice=True,mode=FIRST_START):

        self.fliter=fliter
        self.ifdevice=ifdevice

        self.mode=mode

        sl, stext, stext2, stextph = texts
        self.sl, self.stext, self.stext2, self.stextph=sl, stext, stext2, stextph



        process = os.popen('ifconfig')
        output = process.read()
        process.close()
        mode = r'([a-zA-Z0-9]+: flags=)'
        result = re.findall(mode, output)

        devices = []
        for i in result:
            # i=i[0]
            index = i.find(':')
            devices.append(i[:index])

        self.deviceip={}
        for device in devices:
            process=os.popen('ifconfig '+device)
            output=process.read()
            process.close()
            try:
                inet = re.search('inet ((([01][0-9][0-9])|(2[0-4][0-9])|(25[0-5])|([0-9]{2})|[0-9])\.){3}(([01][0-9][0-9])|(2[0-4][0-9])|(25[0-5])|([0-9]{2})|[0-9])', output).group()
                ip=re.search('((([01][0-9][0-9])|(2[0-4][0-9])|(25[0-5])|([0-9]{2})|[0-9])\.){3}(([01][0-9][0-9])|(2[0-4][0-9])|(25[0-5])|([0-9]{2})|[0-9])', inet).group()
            except:
                ip='no'
            self.deviceip[device]=ip


        if pcap.start:
            if mode==FIRST_START:
                answer = askyesno('Restart Cap', 'If continue, current process will be stopped without saving. Continue?')
                if answer:
                    pcap.pcap = []
                else:
                    return

            pcap.start = False
            pcap.pcap2show=[]
            pcap.new_proto_no = []



        self.parent = parent
        self.pcap = pcap
        self.top = Toplevel()

        self.top.title('Settings')
        self.top.resizable(0, 0)

        #self.fsm = LabelFrame(self.top, text="Source Machine MAC(Blank Means All)")
        #self.fdm = LabelFrame(self.top, text="Destination Machine MAC(Blank Means All)")
        self.fsip = LabelFrame(self.top, text="Source IP Address and Port(Blank Means All)")
        self.fdip = LabelFrame(self.top, text="Destination IP Address and Port(Blank Means All)")


        self.f1 = LabelFrame(self.top, text="Device")
        self.fn = LabelFrame(self.top, text="Network Layer")
        self.f2 = LabelFrame(self.top, text="Protocol")
        self.f3 = Frame(self.top)



        self.f1.pack(side=TOP, fill=BOTH)
        self.fn.pack(side=TOP,fill=BOTH)
        self.f2.pack(side=TOP, fill=BOTH)
        #self.fsm.pack(side=TOP, fill=BOTH)
        #self.fdm.pack(side=TOP, fill=BOTH)

        self.fsip.pack(side=TOP, fill=BOTH)
        self.fdip.pack(side=TOP, fill=BOTH)
        self.f3.pack(side=BOTTOM, fill=BOTH)

        #self.srcmac=StringVar()
        #self.destmac=StringVar()
        self.srcip=StringVar()
        self.destip=StringVar()
        self.sport=StringVar()
        self.dstport=StringVar()

        #Entry(self.fsm,textvariable=self.srcmac).pack(fill=BOTH)
        #Entry(self.fdm, textvariable=self.destmac).pack(fill=BOTH)
        Entry(self.fsip, textvariable=self.srcip).grid(columnspan=2,row=0)
        Entry(self.fsip, textvariable=self.sport).grid(column=2,row=0)
        Entry(self.fdip, textvariable=self.dstport).grid(column=2,row=1)
        Entry(self.fdip, textvariable=self.destip).grid(columnspan=2,row=1)

        if self.ifdevice:
            self.box_value = StringVar()
            self.devicelist = ttk.Combobox(self.f1,textvariable=self.box_value, state='readonly')
            self.devicelist['values'] = devices
            self.devicelist.pack(fill=X)
            self.devicelist.current(0)

        # devicelist.bind("<<ComboboxSelected>>", notdone)
        self.protoVar = [IntVar(self.top), IntVar(self.top), IntVar(self.top)]

        self.networkVar=[IntVar(self.top), IntVar(self.top), IntVar(self.top)]

        self.pip = Checkbutton(self.fn, text='IP', variable=self.networkVar[0],command=self.checkip)
        self.parp = Checkbutton(self.fn, text='ARP', variable=self.networkVar[1])
        self.prarp = Checkbutton(self.fn, text='RARP', variable=self.networkVar[2])

        self.p1 = Checkbutton(self.f2, text='ICMP', variable=self.protoVar[0])
        self.p6 = Checkbutton(self.f2, text='TCP', variable=self.protoVar[1])
        self.p17 = Checkbutton(self.f2, text='UDP', variable=self.protoVar[2])

        self.p1.select()
        self.p6.select()
        self.p17.select()

        self.pip.select()

        self.pip.pack(side=LEFT)
        self.parp.pack(side=LEFT)
        self.prarp.pack(side=LEFT)

        self.p1.pack(side=LEFT)
        self.p6.pack(side=LEFT)
        self.p17.pack(side=LEFT)

        self.networkCheck=[self.pip,self.parp,self.prarp]
        self.protoCheck = [self.p1, self.p6, self.p17]



        Button(self.f3, text='OK', command=self.startthread).pack(
            side=LEFT)
        Button(self.f3, text='Cancel', command=self.top.destroy).pack(side=RIGHT)

        if mode==FIRST_START:
            for i in self.pcap.threads:
                print("Delete request:" + str(i))
                infoqueue.put((i, DELETE_THREAD))

    def checkip(self):
        if self.networkVar[0].get():
            self.p1.configure(state=NORMAL)
            self.p6.configure(state=NORMAL)
            self.p17.configure(state=NORMAL)
        else:
            self.p1.deselect()
            self.p6.deselect()
            self.p17.deselect()
            self.p1.configure(state=DISABLED)
            self.p6.configure(state=DISABLED)
            self.p17.configure(state=DISABLED)

    def startthread(self):
        self.sl.listbox.delete(0, END)
        self.stext.text.delete('1.0', END)
        self.stext2.text.delete('1.0', END)
        self.stextph.text.delete('1.0', END)

        if self.mode==FIRST_START:

            if self.pcap.threads:
                print("Delete Request.Reason:Restart.")
                infoqueue.put((2333,DELETE_THREAD))

            while not self.pcap.newthread:
                    print('emm...Some thread still alive.')
                    sleep(0.1)

            self.pcap.clean()
            self.fliter.reinit()
            #srcm=(self.srcmac.get()).lower()
            #dstm=(self.destmac.get()).lower()
            srcin=self.srcip.get()
            dstin=self.destip.get()

            # if (re.findall(r'(^([0-9a-f]{1,2}[:]){5}([0-9a-f]{1,2})$)|(^$)', srcm)):

            src=re.search('((([01][0-9][0-9])|(2[0-4][0-9])|(25[0-5])|([0-9]{2})|[0-9])\.){3}(([01][0-9][0-9])|(2[0-4][0-9])|(25[0-5])|([0-9]{2})|[0-9])', srcin)
            dst=re.search('((([01][0-9][0-9])|(2[0-4][0-9])|(25[0-5])|([0-9]{2})|[0-9])\.){3}(([01][0-9][0-9])|(2[0-4][0-9])|(25[0-5])|([0-9]{2})|[0-9])', dstin)

            if src:
                src=src.group()
                self.fliter.src_ip.append(src)
            else:
                if srcin=='':
                    pass
                else:
                    showerror("Error","Invalid IP Address")
                    return

            if dst:
                dst=dst.group()
                self.fliter.des_ip.append(dst)
            else:
                if dstin=='':
                    pass
                else:
                    showerror("Error","Invalid IP Address")
                    return

            sportin = self.sport.get()
            dportin = self.dstport.get()
            if sportin:
                if re.match('^([1-6][0-5][0-5][0-3][0-5])|([1-9]\d\d\d)|([1-9]\d\d)|([1-9]\d)|\d', sportin):
                    sportin = eval(sportin)
                else:
                    showerror('Error', "Invalid Source Port")
                    return
                self.fliter.src_port.append(sportin)
            else:
                pass

            if dportin:
                if re.match('^([1-6][0-5][0-5][0-3][0-5])|([1-9]\d\d\d)|([1-9]\d\d)|([1-9]\d)|\d', dportin):
                    dportin = eval(dportin)
                else:
                    showerror('Error', "Invalid Dest Port")
                    return
                self.fliter.des_port.append(dportin)
            else:
                pass



            proto = [1, 6, 17]
            j = 0

            for i in self.protoVar:
                result = i.get()
                if result:
                    self.pcap.new_proto_no.append(proto[j])
                j += 1
            if not self.pcap.new_proto_no:
                if not ((self.networkVar[1].get())or(self.networkVar[2].get())):
                    showerror("Warning", "No protocol selected!")
                    return

            self.pcap.start = True

            if self.ifdevice:
                device=self.devicelist.get()
                self.pcap.bind2ip=self.deviceip[device]
                self.fliter.bind=self.pcap.bind2ip
                self.pcap.deviceip=self.deviceip
                self.pcap.device = device.encode()
                self.parent.title(MAIN_TITLE+' - Running on Device: '+device)
            # self.pcap.protocol_num=self.pcap.new_proto_no



            for i in self.pcap.protocol_num:
                if i not in self.pcap.new_proto_no:
                    #infoqueue.put((i, DELETE_THREAD))
                    self.fliter.delete_proto((i,))

            for i in self.pcap.new_proto_no:
                if i not in self.pcap.protocol_num:
                    self.fliter.add_proto((i,))



            self.fliter.ip = True if (self.networkVar[0].get()) else False
            self.fliter.arp = True if (self.networkVar[1].get()) else False
            self.fliter.rarp = True if (self.networkVar[2].get()) else False


            if not self.pcap.threads:
                capth = capthread(2333, 0, self.pcap.device)
                capth.daemon = True
                self.pcap.threads[2333] = capth
                capth.start()
            else:
                infoqueue.put((2333,REFRESH_THREAD))

        elif self.mode==LOAD_FILE:

            self.pcap.start = False
            self.fliter.reinit()
            self.pcap.pcap2show=[]
            #srcm=(self.srcmac.get()).lower()
            #dstm=(self.destmac.get()).lower()

            self.fliter.ip = True if (self.networkVar[0].get()) else False
            self.fliter.arp = True if (self.networkVar[1].get()) else False
            self.fliter.rarp = True if (self.networkVar[2].get()) else False

            sportin=self.sport.get()
            dportin=self.dstport.get()
            if sportin:
                if re.match('^([1-6][0-5][0-5][0-3][0-5])|([1-9]\d\d\d)|([1-9]\d\d)|([1-9]\d)|\d',sportin):
                        sportin=eval(sportin)
                else:
                    showerror('Error', "Invalid Source Port")
                    return
                self.fliter.src_port.append(sportin)
            else:
                pass

            if dportin:
                if re.match('^([1-6][0-5][0-5][0-3][0-5])|([1-9]\d\d\d)|([1-9]\d\d)|([1-9]\d)|\d', dportin):
                    dportin=eval(dportin)
                else:
                    showerror('Error',"Invalid Dest Port")
                    return
                self.fliter.des_port.append(dportin)
            else:
                pass

            srcin=self.srcip.get()
            dstin=self.destip.get()

            # if (re.findall(r'(^([0-9a-f]{1,2}[:]){5}([0-9a-f]{1,2})$)|(^$)', srcm)):

            src=re.search('((([01][0-9][0-9])|(2[0-4][0-9])|(25[0-5])|([0-9]{2})|[0-9])\.){3}(([01][0-9][0-9])|(2[0-4][0-9])|(25[0-5])|([0-9]{2})|[0-9])', srcin)
            dst=re.search('((([01][0-9][0-9])|(2[0-4][0-9])|(25[0-5])|([0-9]{2})|[0-9])\.){3}(([01][0-9][0-9])|(2[0-4][0-9])|(25[0-5])|([0-9]{2})|[0-9])', dstin)

            if src:
                src=src.group()
                self.fliter.src_ip.append(src)
            else:
                if srcin=='':
                    pass
                else:
                    showerror("Error","Invalid IP Address")
                    return

            if dst:
                dst=dst.group()
                self.fliter.des_ip.append(dst)
            else:
                if dstin=='':
                    pass
                else:
                    showerror("Error","Invalid IP Address")
                    return



            proto = ALL_PROTO_NUM
            j = 0

            for i in self.protoVar:
                result = i.get()
                if result:
                    self.pcap.new_proto_no.append(proto[j])
                j += 1
            if not self.pcap.new_proto_no:
                showerror("Warning", "No protocol selected!")
                return

            self.pcap.start = True

            self.fliter.proto=self.pcap.new_proto_no


            for data in self.pcap.pcap:
                flitered = self.fliter.fliter(data)
                if flitered:
                    self.pcap.pcap2show.append(flitered)
                    self.sl.list_insert(data)
                else:
                    pass
            self.pcap.start = True
        else:
            print("Unknown mode for StartBox")
        self.parent.update()
        self.parent.deiconify()
        self.top.destroy()

